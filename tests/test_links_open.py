"""
Audit: on every page, for every viewer, clicking a link must do something correct.

  safe    -> the row carries a client-side OpenUrl action for the exact URL, new tab
  caution -> tapping shows the warning; its button carries OpenUrl for the exact URL
  blocked -> tapping explains why (and never opens)
Also: every URL shown as text has an open/copy control beside it, and every OpenUrl
action on the page targets a real http(s) address in a new tab.

Run:  python tests/test_links_open.py
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.environ["DATA_DIR"] = tempfile.mkdtemp()
os.environ["ADMIN_USERNAMES"] = "alice"

import flet as ft  # noqa: E402
from flet.controls.context import _context_page  # noqa: E402

import auth, db, security, ui  # noqa: E401,E402
from test_ui_render import FakePage  # noqa: E402

CHILD_FIELDS = ("content", "controls", "actions", "destinations", "items", "leading", "title", "trailing")


def walk(root, parents=()):
    """Yield (control, ancestors) for the whole tree."""
    if not isinstance(root, ft.BaseControl):
        return
    yield root, parents
    for name in CHILD_FIELDS:
        v = getattr(root, name, None)
        for child in (v if isinstance(v, list) else [v]):
            yield from walk(child, parents + (root,))


def tree(page):
    for c in page.controls:
        yield from walk(c)


def has_open_or_copy(control) -> bool:
    for c, _ in walk(control):
        a = getattr(c, "action", None)
        if isinstance(a, (ft.OpenUrl, ft.CopyToClipboard)):
            return True
        if isinstance(c, ft.IconButton) and (c.tooltip or "").startswith("Open"):
            return True
    return False


def make_link(owner, url, title, vis, status, reasons=()):
    r = security.ScanResult(url=url, final_url=url, domain=url.split("/")[2], title=title)
    for reason in reasons:
        r.add(status, reason)
    return db.add_link(owner, r, title, "note", vis)


async def main():
    db.init_db()
    alice = auth.register("alice", "alice-password-1")      # owner + admin
    bob = auth.register("bob", "bob-password-123")          # friend
    carol = auth.register("carol", "carol-password-1")      # stranger
    db.send_friend_request(alice["id"], bob["id"]); db.accept_friend(bob["id"], alice["id"])

    links = {}
    for vis in ("private", "friends", "public", "unlisted"):
        links[f"safe-{vis}"] = make_link(alice["id"], f"https://safe-{vis}.example.org/page", f"Safe {vis}", vis, security.SAFE)
    links["warn-friends"] = make_link(alice["id"], "http://8.8.8.8/x", "Caution friends", "friends",
                                      security.WARN, ["Uses a raw IP address instead of a domain name."])
    links["blocked-private"] = make_link(alice["id"], "https://bad.example.org/", "Blocked one", "private",
                                         security.BLOCKED, ["On the blocklist."])
    anon = make_link(None, "https://anon.example.org/", "Anonymous share", "unlisted", security.SAFE)
    cat = db.create_category(alice["id"], "Work")
    db.set_link_category(links["safe-public"], alice["id"], cat)
    for key in ("safe-private", "warn-friends", "safe-friends"):
        db.share_with(links[key], alice["id"], [bob["id"]])
    codes = {"owner-share": db.create_share_code(links["safe-private"], alice["id"], None),
             "warn-share": db.create_share_code(links["warn-friends"], alice["id"], None),
             "anon-share": db.create_share_code(anon, None, db.now() + 86400)}
    db.report_link(links["safe-public"], "ip:9", "Spam")
    db.report_link(links["warn-friends"], "ip:9", "Spam")

    page = FakePage()
    _context_page.set(page)
    app = ui.App(page)
    alerts = []

    async def alert(title, lines, *a, **k):
        alerts.append(title)
    app.alert = alert
    ui.log.exception = lambda m, *a, **k: (_ for _ in ()).throw(AssertionError(m))
    await app.start()

    by_url = {db.get_link(i)["final_url"]: db.get_link(i) for i in list(links.values()) + [anon]}
    routes = ["/", "/explore", "/quick", "/u/alice", "/u/bob", "/links", "/shared", "/friends", "/admin",
              *[f"/s/{c}" for c in codes.values()]]
    viewers = {"visitor": None, "owner+admin": alice, "friend": bob, "stranger": carol}
    problems, checked = [], {"safe": 0, "warn": 0, "blocked": 0, "urls": 0, "actions": 0}

    for who, user in viewers.items():
        app.user = user
        for route in routes:
            page.route = route
            page.dialogs.clear()
            await app.render()
            where = f"{who} {page.route}"

            for c, parents in list(tree(page)):
                # --- link rows
                tip = getattr(c, "tooltip", None) or ""
                if isinstance(c, ft.Container) and (tip.startswith("Open ") and "in a new tab" in tip or tip.startswith("Blocked")):
                    title = next(x.value for x, _ in walk(c) if isinstance(x, ft.Text))
                    link = next((l for l in by_url.values() if (l["title"] or l["domain"]) == title), None)
                    if not link:
                        problems.append(f"{where}: row '{title}' not matched"); continue
                    st = link["status"]
                    if st == security.SAFE:
                        a = c.action
                        if not (isinstance(a, ft.OpenUrl) and a.url == link["final_url"] and a.target == ft.UrlTarget.BLANK):
                            problems.append(f"{where}: safe row '{title}' does not open {link['final_url']}")
                    elif st == security.WARN:
                        page.dialogs.clear(); c.on_click()
                        btn = page.dialogs[-1].actions[1] if page.dialogs else None
                        if not (btn and isinstance(btn.action, ft.OpenUrl) and btn.action.url == link["final_url"]):
                            problems.append(f"{where}: caution row '{title}' warning has no working Open")
                        page.dialogs.clear()
                    else:
                        n = len(alerts)
                        if c.on_click is not None:
                            await c.on_click()
                        if len(alerts) == n or c.action is not None:
                            problems.append(f"{where}: blocked row '{title}' gives no feedback or opens")
                    checked[st if st != security.BLOCKED else "blocked"] += 1

                # --- every OpenUrl action must be a real address in a new tab
                a = getattr(c, "action", None)
                if isinstance(a, ft.OpenUrl):
                    checked["actions"] += 1
                    if not (a.url.startswith(("https://", "http://")) and a.target == ft.UrlTarget.BLANK):
                        problems.append(f"{where}: bad OpenUrl {a.url!r} target={a.target}")

                # --- any URL displayed as text needs an open/copy control nearby
                val = getattr(c, "value", None)
                if isinstance(c, (ft.Text, ft.TextField)) and isinstance(val, str) and val.startswith(("http://", "https://")):
                    if page.dialogs:
                        continue
                    checked["urls"] += 1
                    scope = parents[-2] if len(parents) >= 2 else (parents[-1] if parents else c)
                    if not has_open_or_copy(scope):
                        problems.append(f"{where}: URL text {val!r} has no open/copy control")

    # quick share: the freshly created share link must be openable (scan stubbed: no network)
    async def fake_scan(raw, fetch=None):
        return security.ScanResult(url="https://quick.example.org/", final_url="https://quick.example.org/",
                                   domain="quick.example.org", title="Quick")
    real_scan, security.scan_url = security.scan_url, fake_scan
    for user in (None, alice):
        app.user = user
        page.route = "/quick"; await app.render()
        url_field = next(x for x, _ in tree(page) if isinstance(x, ft.TextField) and x.label == "Link")
        url_field.value = "https://quick.example.org/"
        btn = next(x for x, _ in tree(page) if isinstance(x, ft.Button) and str(x.content).startswith("Check & create"))
        await btn.on_click()
        share_field = next((x for x, _ in tree(page) if isinstance(x, ft.TextField) and x.read_only), None)
        opens = [x.action.url for x, _ in tree(page) if isinstance(getattr(x, "action", None), ft.OpenUrl)]
        if not share_field or share_field.value not in opens:
            problems.append(f"quick share ({'owner' if user else 'visitor'}): new share link can't be opened")
    security.scan_url = real_scan

    # dialogs that show URLs
    app.user = alice
    link = db.get_link(links["safe-private"])
    await app.share_link_dialog(link)
    d = page.dialogs[-1]
    if not any(isinstance(getattr(x, "action", None), ft.OpenUrl) for x, _ in walk(d.content)):
        problems.append("share-link dialog: share URL can't be opened")
    page.dialogs.clear()

    print(f"checked rows: {checked['safe']} safe, {checked['warn']} caution, {checked['blocked']} blocked; "
          f"{checked['urls']} displayed URLs; {checked['actions']} open actions")
    for p in problems:
        print("DEFECT", p)
    assert not problems, f"{len(problems)} link defect(s)"
    assert checked["safe"] and checked["warn"] and checked["blocked"]
    print("ALL LINKS OPEN CORRECTLY ON EVERY PAGE")


if __name__ == "__main__":
    asyncio.run(main())
