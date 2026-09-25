"""Drives real handlers: signup, login, save link (live scan), quick share, friends, report.

Run:  python tests/test_flows.py      (needs internet access to github.com)
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.environ["DATA_DIR"] = tempfile.mkdtemp()

import msgpack  # noqa: E402
import flet as ft  # noqa: E402
from flet.controls.context import _context_page  # noqa: E402
from flet.messaging.protocol import configure_encode_object_for_msgpack  # noqa: E402

import db  # noqa: E402
import ui  # noqa: E402
from test_ui_render import FakePage  # noqa: E402

encode = configure_encode_object_for_msgpack(ft.BaseControl)


def find(root, pred):
    out = []

    def walk(c):
        if isinstance(c, ft.BaseControl):
            if pred(c):
                out.append(c)
            for name in ("content", "controls", "actions", "destinations", "items", "leading", "title", "trailing"):
                v = getattr(c, name, None)
                for child in (v if isinstance(v, list) else [v]):
                    walk(child)
    for r in (root if isinstance(root, list) else [root]):
        walk(r)
    return out


def button(page, text):
    return find(page.controls, lambda c: isinstance(c, (ft.Button, ft.TextButton)) and c.content == text)[0]


def field(page, label):
    return find(page.controls, lambda c: isinstance(c, ft.TextField) and c.label == label)[0]


async def click(ctrl):
    h = ctrl.on_click
    r = h()
    if asyncio.iscoroutine(r):
        await r


async def main():
    db.init_db()
    page = FakePage()
    _context_page.set(page)
    app = ui.App(page)
    app.confirm = lambda *a, **k: asyncio.sleep(0, result=True)
    alerts = []

    async def alert(title, lines, *a, **k):
        alerts.append((title, lines))
    app.alert = alert
    snacks = []
    app.snack = lambda m, error=False: snacks.append(m)
    ui.log.exception = lambda m, *a, **k: (_ for _ in ()).throw(AssertionError(m))

    await app.start()

    # --- sign up
    page.route = "/signup"; await app.render()
    field(page, "Username").value = "sukarna"
    field(page, "Password").value = "a-very-good-pass"
    field(page, "Repeat password").value = "a-very-good-pass"
    await click(button(page, "Create account"))
    assert app.user and page.route == "/links", page.route
    print("ok  signup ->", page.route)

    # --- save a safe link (live scan of github.com)
    field(page, "Link").value = "github.com/flet-dev/flet"
    await click(button(page, "Check & save"))
    links = db.list_user_links(app.user["id"])
    assert len(links) == 1 and links[0]["status"] == "safe", links
    print("ok  saved:", links[0]["title"][:50], "| embeddable:", bool(links[0]["embeddable"]))

    # --- blocked link is refused
    field(page, "Link").value = "http://169.254.169.254/latest/meta-data"
    await click(button(page, "Check & save"))
    assert alerts and "can't be saved" in alerts[-1][0] and len(db.list_user_links(app.user["id"])) == 1
    print("ok  blocked:", alerts[-1][1][0])

    # --- duplicate
    field(page, "Link").value = "https://github.com/flet-dev/flet"
    await click(button(page, "Check & save"))
    assert snacks[-1].startswith("You've already saved"), snacks[-1]
    print("ok  duplicate detected")

    # --- serialize the whole page with Flet's wire encoder
    msgpack.packb(page.controls, default=encode)
    msgpack.packb(page.navigation_bar, default=encode)
    print("ok  page serializes for the client")

    # --- quick share while logged out
    await app.logout()
    page.route = "/quick"; await app.render()
    field(page, "Link").value = "https://github.com/"
    await click(button(page, "Check & create share link"))
    share_field = find(page.controls, lambda c: isinstance(c, ft.TextField) and c.read_only)
    share_url = share_field[0].value
    assert "/s/" in share_url, share_url
    print("ok  anonymous share:", share_url)
    page.route = "/s/" + share_url.rsplit("/", 1)[1]; await app.render()
    assert find(page.controls, lambda c: isinstance(c, ft.Text) and c.value == "A link was shared with you")
    print("ok  share page opens without login")

    # --- login + friend request + share to friend
    from auth import register
    register("friend_1", "friendly-password")
    page.route = "/login?next=/friends"; await app.render()
    field(page, "Username").value = "SUKARNA"
    field(page, "Password").value = "a-very-good-pass"
    await click(button(page, "Sign in"))
    assert page.route == "/friends", page.route
    field(page, "Friend's username").value = "@friend_1"
    await click(button(page, "Send request"))
    print("ok  login next ->", page.route, "|", snacks[-1])

    # wrong password lockout
    await app.logout()
    page.route = "/login"; await app.render()
    for _ in range(9):
        field(page, "Username").value = "sukarna"
        field(page, "Password").value = "nope"
        await click(button(page, "Sign in"))
    err = find(page.controls, lambda c: isinstance(c, ft.Text) and c.value and "Too many" in c.value)
    assert err, "rate limit not hit"
    print("ok  login rate limit")

    # --- report as anonymous visitor
    link = db.list_user_links(1)[0]
    await app.report_dialog(link)
    dlg = page.dialogs[-1]
    await click([a for a in dlg.actions if getattr(a, "content", "") == "Report"][0])
    assert db.get_link(link["id"])["report_count"] == 1
    print("ok  report recorded")
    print("ALL FLOWS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
