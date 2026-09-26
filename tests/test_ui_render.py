"""Renders every route and dialog against a fake Flet page (no browser needed).

Run:  DATA_DIR=/tmp/lv-test python tests/test_ui_render.py
"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
os.environ["ADMIN_USERNAMES"] = "alice"

import flet as ft  # noqa: E402
from flet.controls.context import _context_page  # noqa: E402

import auth, db, security  # noqa: E402,E401
import ui  # noqa: E402


class _Services:
    def register_service(self, s):
        pass


class FakePage:
    def __init__(self):
        self.route, self.client_ip, self.url = "/", "203.0.113.9", "https://links.example.com/"
        self.controls, self.appbar, self.navigation_bar, self.scroll = [], None, None, None
        self.dialogs, self._services, self.on_route_change = [], _Services(), None
        self.title = self.theme = self.theme_mode = self.padding = self.on_close = None
        self.overlay = []

    def run_task(self, fn, *args):
        pass  # heartbeat not needed in tests

    def update(self):
        # walk the tree to make sure everything is a real control
        def walk(c, depth=0):
            assert isinstance(c, ft.BaseControl), type(c)
            for name in ("content", "controls", "actions", "destinations", "items", "leading", "title", "trailing"):
                v = getattr(c, name, None)
                for child in (v if isinstance(v, list) else [v]):
                    if isinstance(child, ft.BaseControl):
                        walk(child, depth + 1)
        for c in self.controls:
            walk(c)

    async def push_route(self, route):
        self.route = route
        await self.on_route_change(None)

    def show_dialog(self, d):
        self.dialogs.append(d)

    def pop_dialog(self):
        if self.dialogs:
            self.dialogs.pop()


async def main():
    db.init_db()
    alice = auth.register("alice", "alice-password-123")
    bob = auth.register("bob", "bob-password-12345")
    db.send_friend_request(alice["id"], bob["id"]); db.accept_friend(bob["id"], alice["id"])
    carol = auth.register("carol", "carol-password-123")
    db.send_friend_request(carol["id"], alice["id"])

    safe = security.ScanResult(url="https://example.com/", final_url="https://example.com/",
                               domain="example.com", title="Example", embeddable=True)
    warn = security.ScanResult(url="http://8.8.8.8/", final_url="http://8.8.8.8/", domain="8.8.8.8")
    warn.add(security.WARN, "Uses a raw IP address instead of a domain name.")
    l1 = db.add_link(alice["id"], safe, "Example", "a note", "public")
    l2 = db.add_link(alice["id"], warn, "", "", "friends")
    l3 = db.add_link(None, safe, "Anon", "", "unlisted")
    db.share_with(l1, alice["id"], [bob["id"]])
    code = db.create_share_code(l3, None, db.now() + 86400)
    code_warn = db.create_share_code(l2, alice["id"], None)
    db.report_link(l1, "ip:1", "Spam")
    cat = db.create_category(alice["id"], "Recipes")
    db.set_link_category(l1, alice["id"], cat)

    def fail(msg, *a, **k):
        raise AssertionError(msg % a if a else msg)
    ui.log.exception = fail  # render() swallows errors; make them fatal here

    page = FakePage()
    _context_page.set(page)
    app = ui.App(page)
    await app.start()

    routes = ["/", "/login", "/signup", "/explore", "/quick", f"/s/{code}", f"/s/{code_warn}",
              "/s/doesnotexist", "/u/alice", "/u/nobody", "/nope", "/links"]
    for user in (None, alice, bob):
        app.user = user
        for r in routes + ["/shared", "/friends", "/admin", "/u/bob"]:
            page.route = r
            await app.render()
            assert page.controls, r
            print(f"ok  {('@' + user['username']) if user else 'anon':7} {r:22} -> {page.route}")

    # dialogs & opening links
    app.user = alice
    link1, link2 = db.get_link(l1), db.get_link(l2)
    for fn in (app.edit_link_dialog, app.share_friends_dialog, app.share_link_dialog, app.report_dialog,
               app.move_dialog):
        await fn(link1)
        assert page.dialogs, fn.__name__
        page.dialogs.clear()
    await app.manage_categories_dialog(); assert page.dialogs; page.dialogs.clear()
    for f in (None, "none", cat):
        app.cat_filter = f; page.route = "/links"; await app.render()
    app.open_browser_button(link2).on_click()        # warning dialog for caution links
    assert page.dialogs; page.dialogs.clear()
    # tapping a link opens it in the browser: safe -> client-side OpenUrl, caution -> warning first
    safe_row = app.link_card(link1)
    taps = [c for c in [safe_row.content.controls[0]] if getattr(c, "action", None)]
    assert taps and taps[0].action.url == link1["final_url"], "safe link must open via OpenUrl"
    warn_row = app.link_card(link2)
    warn_row.content.controls[0].on_click()
    assert page.dialogs and page.dialogs[-1].actions[1].action.url == link2["final_url"]
    page.dialogs.clear()
    await app.save_copy(db.get_link(l3))
    print("ok  dialogs + links open in browser")
    print("ALL ROUTES RENDERED")


if __name__ == "__main__":
    asyncio.run(main())
