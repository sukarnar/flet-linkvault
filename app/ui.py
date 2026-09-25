"""All screens of the app. One `App` instance per browser tab (Flet session)."""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional
from urllib.parse import parse_qs, quote, urlsplit

import flet as ft
import flet_webview as fwv

import auth
import db
import ratelimit
import security
from config import ADMIN_USERNAMES, ANON_SHARE_DAYS, APP_NAME, PUBLIC_BASE_URL, RESCAN_HOURS

log = logging.getLogger("linkvault.ui")

TOKEN_KEY = "linkvault.session"
MAX_TITLE, MAX_NOTE = 200, 1000

VISIBILITY = {
    "private": ("Only me", ft.Icons.LOCK),
    "friends": ("Friends", ft.Icons.PEOPLE),
    "public": ("Public", ft.Icons.PUBLIC),
    "unlisted": ("Anyone with the link", ft.Icons.LINK),
}
STATUS = {
    security.SAFE: ("Checked", ft.Icons.GPP_GOOD, ft.Colors.GREEN_700),
    security.WARN: ("Caution", ft.Icons.GPP_MAYBE, ft.Colors.AMBER_800),
    security.BLOCKED: ("Blocked", ft.Icons.GPP_BAD, ft.Colors.RED_700),
}
REPORT_REASONS = ["Phishing or scam", "Malware or dangerous download", "Spam",
                  "Adult, violent or hateful content", "Other"]


def time_ago(ts: int) -> str:
    d = max(0, db.now() - int(ts))
    for size, unit in ((86400 * 365, "y"), (86400 * 30, "mo"), (86400, "d"), (3600, "h"), (60, "m")):
        if d >= size:
            return f"{d // size}{unit} ago"
    return "just now"


def scan_from_link(link: dict) -> security.ScanResult:
    """Rebuild a ScanResult from a stored link (used when saving someone else's link)."""
    r = security.ScanResult(url=link["url"], final_url=link["final_url"], domain=link["domain"],
                            title=link["title"], embeddable=bool(link["embeddable"]))
    level = link["status"] if link["status"] != security.SAFE else security.WARN
    for reason in link["reasons"]:
        r.add(level, reason)
    return r


class App:
    def __init__(self, page: ft.Page):
        self.page = page
        self.user: Optional[dict] = None
        self.token: Optional[str] = None
        self.prefs = ft.SharedPreferences()
        self._closed = False
        # Invisible control whose value changes every 20 s. Each change is a tiny message
        # to the browser, which lets the watchdog in web_patch.py tell a healthy connection
        # from a dead one, and keeps proxies/NATs from dropping an idle WebSocket.
        self._beat = ft.Text("0", size=1, opacity=0)

    # ================================================================== plumbing
    async def start(self):
        p = self.page
        p.title = APP_NAME
        p.theme = ft.Theme(color_scheme_seed=ft.Colors.INDIGO)
        p.theme_mode = ft.ThemeMode.SYSTEM
        p.padding = ft.Padding.symmetric(horizontal=12, vertical=16)
        p.scroll = ft.ScrollMode.AUTO
        p.on_route_change = self._on_route_change
        p.on_close = self._on_close
        p.overlay.append(self._beat)
        p.run_task(self._heartbeat)
        try:
            self.token = await self.prefs.get(TOKEN_KEY)
        except Exception as e:  # storage unavailable (private mode etc.)
            log.info("shared preferences unavailable: %s", e)
        self.user = auth.resume_session(self.token)
        await self.render()

    async def _on_close(self, e=None):
        self._closed = True

    async def _heartbeat(self):
        n = 0
        while not self._closed:
            await asyncio.sleep(20)
            n += 1
            self._beat.value = str(n)
            try:
                self._beat.update()
            except Exception:
                pass  # disconnected: Flet drops updates until the client reconnects

    async def _on_route_change(self, e):
        await self.render()

    def act(self, fn: Callable[..., Awaitable], *args, **kwargs):
        """Wrap an async function + args into a zero-arg async event handler."""
        async def handler():
            await fn(*args, **kwargs)
        return handler

    async def go(self, route: str):
        if route == self.page.route:
            await self.render()
        else:
            await self.page.push_route(route)

    @property
    def is_admin(self) -> bool:
        return bool(self.user and self.user["username"].lower() in ADMIN_USERNAMES)

    def client_key(self) -> str:
        return f"u:{self.user['id']}" if self.user else f"ip:{self.page.client_ip or 'unknown'}"

    def share_url(self, code: str) -> str:
        base = PUBLIC_BASE_URL
        if not base:
            try:
                parts = urlsplit(self.page.url or "")
                base = f"{parts.scheme}://{parts.netloc}"
            except Exception:
                base = ""
        return f"{base}/s/{code}"

    def snack(self, message: str, error: bool = False):
        self.page.show_dialog(ft.SnackBar(
            ft.Text(message), bgcolor=ft.Colors.RED_700 if error else None, duration=3500))

    def close_dialog(self):
        self.page.pop_dialog()

    async def alert(self, title: str, lines: list[str], icon=ft.Icons.INFO_OUTLINE, color=None):
        done = asyncio.get_running_loop().create_future()

        def close():
            self.page.pop_dialog()
            if not done.done():
                done.set_result(None)

        self.page.show_dialog(ft.AlertDialog(
            icon=ft.Icon(icon, color=color), title=ft.Text(title),
            content=ft.Column([ft.Text(f"• {l}") for l in lines], tight=True, spacing=6),
            actions=[ft.TextButton("OK", on_click=close)],
            on_dismiss=lambda e: done.done() or done.set_result(None),
        ))
        await done

    async def confirm(self, title: str, lines: list[str], ok_text: str = "Continue",
                      danger: bool = False) -> bool:
        done = asyncio.get_running_loop().create_future()

        def finish(value: bool):
            self.page.pop_dialog()
            if not done.done():
                done.set_result(value)

        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text(title),
            content=ft.Column([ft.Text(l) for l in lines], tight=True, spacing=6),
            actions=[
                ft.TextButton("Cancel", on_click=lambda: finish(False)),
                ft.Button(ok_text, on_click=lambda: finish(True),
                          color=ft.Colors.RED_700 if danger else None),
            ],
        ))
        return await done

    # ================================================================== layout
    NAV_IN = [("/links", "My links", ft.Icons.BOOKMARKS), ("/shared", "Shared", ft.Icons.INBOX),
              ("/explore", "Explore", ft.Icons.EXPLORE), ("/friends", "Friends", ft.Icons.GROUP)]
    NAV_OUT = [("/", "Home", ft.Icons.HOME), ("/quick", "Quick share", ft.Icons.BOLT),
               ("/explore", "Explore", ft.Icons.EXPLORE), ("/login", "Sign in", ft.Icons.LOGIN)]

    def _nav(self, path: str) -> ft.NavigationBar:
        items = self.NAV_IN if self.user else self.NAV_OUT
        badges = {}
        if self.user:
            unseen = db.unseen_share_count(self.user["id"])
            incoming = len(db.list_incoming_requests(self.user["id"]))
            badges = {"/shared": unseen, "/friends": incoming}
        selected = next((i for i, (r, _, _) in enumerate(items)
                         if r == path or (r != "/" and path.startswith(r))), None)
        if path == "/signup":
            selected = 3 if not self.user else None

        async def changed(e):
            await self.go(items[e.control.selected_index][0])

        return ft.NavigationBar(
            selected_index=selected if selected is not None else 0,
            destinations=[
                ft.NavigationBarDestination(
                    icon=icon, label=label,
                    badge=str(badges[r]) if badges.get(r) else None)
                for r, label, icon in items
            ],
            on_change=changed,
        )

    def _appbar(self) -> ft.AppBar:
        actions = []
        if self.user:
            actions.append(ft.IconButton(ft.Icons.BOLT, tooltip="Quick share a link",
                                         on_click=self.act(self.go, "/quick")))
            if self.is_admin:
                actions.append(ft.IconButton(ft.Icons.ADMIN_PANEL_SETTINGS, tooltip="Moderation",
                                             on_click=self.act(self.go, "/admin")))
            actions.append(ft.PopupMenuButton(
                icon=ft.Icons.ACCOUNT_CIRCLE, tooltip=self.user["username"],
                items=[
                    ft.PopupMenuItem(content=f"My public profile (@{self.user['username']})",
                                     icon=ft.Icons.PERSON,
                                     on_click=self.act(self.go, f"/u/{self.user['username']}")),
                    ft.PopupMenuItem(content="Sign out", icon=ft.Icons.LOGOUT,
                                     on_click=self.act(self.logout)),
                ],
            ))
        return ft.AppBar(
            leading=ft.Icon(ft.Icons.BOOKMARKS_OUTLINED), leading_width=40,
            title=ft.Text(APP_NAME, weight=ft.FontWeight.BOLD), actions=actions,
        )

    def _frame(self, controls: list[ft.Control]) -> ft.Control:
        """Centered column, full width on phones, ~2/3 width on desktop."""
        return ft.ResponsiveRow(
            [ft.Column(controls, spacing=14, col={"xs": 12, "md": 10, "lg": 8, "xl": 7})],
            alignment=ft.MainAxisAlignment.CENTER,
        )

    async def render(self):
        route = self.page.route or "/"
        split = urlsplit(route)
        path = split.path.rstrip("/") or "/"
        query = {k: v[0] for k, v in parse_qs(split.query).items()}
        parts = [p for p in path.split("/") if p]

        protected = {"/links", "/shared", "/friends", "/admin"}
        if path in protected and not self.user:
            await self.go(f"/login?next={quote(path)}")
            return
        if path in ("/login", "/signup") and self.user:
            await self.go("/links")
            return
        if path == "/" and self.user:
            await self.go("/links")
            return

        try:
            if path == "/":
                content = self.view_home()
            elif path == "/login":
                content = self.view_login(query.get("next", ""))
            elif path == "/signup":
                content = self.view_signup(query.get("next", ""))
            elif path == "/links":
                content = self.view_links()
            elif path == "/shared":
                content = self.view_shared()
            elif path == "/explore":
                content = self.view_explore()
            elif path == "/friends":
                content = self.view_friends()
            elif path == "/quick":
                content = self.view_quick()
            elif path == "/admin":
                content = self.view_admin() if self.is_admin else self.view_not_found()
            elif len(parts) == 2 and parts[0] == "u":
                content = self.view_profile(parts[1])
            elif len(parts) == 2 and parts[0] == "s":
                content = await self.view_share(parts[1])
            else:
                content = self.view_not_found()
        except Exception:
            log.exception("render failed for %s", route)
            content = [ft.Text("Something went wrong loading this page.", color=ft.Colors.ERROR)]

        self.page.scroll = ft.ScrollMode.AUTO
        self.page.appbar = self._appbar()
        self.page.navigation_bar = self._nav(path)
        self.page.controls = [self._frame(content)]
        self.page.update()

    # ================================================================== reusable pieces
    def heading(self, text: str, sub: str = "") -> ft.Control:
        items = [ft.Text(text, size=24, weight=ft.FontWeight.BOLD)]
        if sub:
            items.append(ft.Text(sub, color=ft.Colors.ON_SURFACE_VARIANT))
        return ft.Column(items, spacing=4)

    def empty(self, text: str, icon=ft.Icons.BOOKMARK_OUTLINE) -> ft.Control:
        return ft.Container(
            padding=30, alignment=ft.Alignment.CENTER,
            content=ft.Column([ft.Icon(icon, size=40, color=ft.Colors.OUTLINE),
                               ft.Text(text, color=ft.Colors.ON_SURFACE_VARIANT,
                                       text_align=ft.TextAlign.CENTER)],
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        )

    def card(self, controls: list[ft.Control]) -> ft.Card:
        return ft.Card(content=ft.Container(ft.Column(controls, spacing=10), padding=16))

    def status_chip(self, link: dict) -> ft.Control:
        label, icon, color = STATUS[link["status"]]

        async def show():
            if link["reasons"]:
                await self.alert(f"Safety check: {label}", link["reasons"], icon, color)
            else:
                await self.alert("Safety check passed", [
                    "Valid public web address, not on our blocklist.",
                    "Domain resolves to a public server.",
                    "Redirects (if any) were checked.",
                    f"Last checked {time_ago(link['checked_at'])}.",
                ], icon, color)

        return ft.Container(
            content=ft.Row([ft.Icon(icon, size=16, color=color),
                            ft.Text(label, size=12, color=color, weight=ft.FontWeight.W_600)],
                           spacing=4, tight=True),
            padding=ft.Padding.symmetric(horizontal=8, vertical=4),
            border=ft.Border.all(1, color), border_radius=12,
            on_click=show, ink=True, tooltip="Why?",
        )

    def small_chip(self, text: str, icon, on_click=None) -> ft.Control:
        return ft.Container(
            content=ft.Row([ft.Icon(icon, size=14, color=ft.Colors.ON_SURFACE_VARIANT),
                            ft.Text(text, size=12, color=ft.Colors.ON_SURFACE_VARIANT)],
                           spacing=4, tight=True),
            padding=ft.Padding.symmetric(horizontal=8, vertical=4),
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST, border_radius=12,
            on_click=on_click, ink=on_click is not None,
        )

    def open_browser_button(self, link: dict, compact: bool = True) -> ft.Control:
        url = link["final_url"]
        if link["status"] == security.SAFE:
            if compact:
                return ft.IconButton(ft.Icons.OPEN_IN_NEW, tooltip="Open in browser",
                                     action=ft.OpenUrl(url, target=ft.UrlTarget.BLANK))
            return ft.OutlinedButton("Open in browser", icon=ft.Icons.OPEN_IN_NEW,
                                     action=ft.OpenUrl(url, target=ft.UrlTarget.BLANK))

        # Caution links: show the warning first; the real "open" button lives in the dialog
        def warn_first():
            self.page.show_dialog(ft.AlertDialog(
                icon=ft.Icon(ft.Icons.GPP_MAYBE, color=ft.Colors.AMBER_800),
                title=ft.Text("Proceed with caution"),
                content=ft.Column(
                    [ft.Text(f"• {r}") for r in link["reasons"]]
                    + [ft.Text(url, size=12, selectable=True, color=ft.Colors.ON_SURFACE_VARIANT)],
                    tight=True, spacing=6),
                actions=[
                    ft.TextButton("Cancel", on_click=self.close_dialog),
                    ft.Button("Open anyway", icon=ft.Icons.OPEN_IN_NEW,
                              action=ft.OpenUrl(url, target=ft.UrlTarget.BLANK),
                              on_click=self.close_dialog),
                ],
            ))

        if compact:
            return ft.IconButton(ft.Icons.OPEN_IN_NEW, tooltip="Open in browser", on_click=warn_first)
        return ft.OutlinedButton("Open in browser", icon=ft.Icons.OPEN_IN_NEW, on_click=warn_first)

    def copy_button(self, text: str, tooltip="Copy link") -> ft.Control:
        return ft.IconButton(ft.Icons.CONTENT_COPY, tooltip=tooltip,
                             action=ft.CopyToClipboard(text),
                             on_click=lambda: self.snack("Copied to clipboard"))

    def link_card(self, link: dict, sender: Optional[str] = None,
                  in_inbox: bool = False, show_owner: bool = True) -> ft.Control:
        mine = bool(self.user and link["owner_id"] == self.user["id"])
        title = link["title"] or security.display_domain(link["domain"])
        blocked = link["status"] == security.BLOCKED

        menu_items: list[ft.PopupMenuItem] = []
        if mine:
            menu_items += [
                ft.PopupMenuItem(content="Edit / visibility", icon=ft.Icons.EDIT,
                                 on_click=self.act(self.edit_link_dialog, link)),
                ft.PopupMenuItem(content="Share with friends", icon=ft.Icons.SEND,
                                 on_click=self.act(self.share_friends_dialog, link)),
                ft.PopupMenuItem(content="Get share link (no login needed)", icon=ft.Icons.LINK,
                                 on_click=self.act(self.share_link_dialog, link)),
                ft.PopupMenuItem(content="Re-check safety", icon=ft.Icons.REFRESH,
                                 on_click=self.act(self.rescan, link)),
                ft.PopupMenuItem(content="Delete", icon=ft.Icons.DELETE_OUTLINE,
                                 on_click=self.act(self.delete_link, link)),
            ]
        else:
            if self.user and not blocked:
                menu_items.append(ft.PopupMenuItem(
                    content="Save to my links", icon=ft.Icons.BOOKMARK_ADD,
                    on_click=self.act(self.save_copy, link)))
            if in_inbox:
                menu_items.append(ft.PopupMenuItem(
                    content="Remove from Shared", icon=ft.Icons.CLOSE,
                    on_click=self.act(self.remove_from_inbox, link)))
            menu_items.append(ft.PopupMenuItem(
                content="Report", icon=ft.Icons.FLAG_OUTLINED,
                on_click=self.act(self.report_dialog, link)))

        chips = [self.status_chip(link)]
        if mine:
            vis_label, vis_icon = VISIBILITY[link["visibility"]]
            chips.append(self.small_chip(vis_label, vis_icon, on_click=self.act(self.edit_link_dialog, link)))
        elif show_owner and link.get("owner_name"):
            chips.append(self.small_chip(f"@{link['owner_name']}", ft.Icons.PERSON,
                                         on_click=self.act(self.go, f"/u/{link['owner_name']}")))
        if sender:
            chips.append(self.small_chip(f"from @{sender}", ft.Icons.SEND))

        body = [
            ft.Row([
                ft.Icon(ft.Icons.LANGUAGE, color=ft.Colors.PRIMARY),
                ft.Column([
                    ft.Text(title, weight=ft.FontWeight.W_600, size=16, max_lines=2,
                            overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(f"{security.display_domain(link['domain'])} · {time_ago(link['created_at'])}",
                            size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                ], spacing=2, expand=True),
                ft.PopupMenuButton(icon=ft.Icons.MORE_VERT, items=menu_items),
            ], vertical_alignment=ft.CrossAxisAlignment.START),
        ]
        if link["note"]:
            body.append(ft.Text(link["note"], selectable=True))
        body.append(ft.Row(chips, wrap=True, spacing=6, run_spacing=6))
        if not blocked:
            body.append(ft.Row([
                ft.TextButton("View", icon=ft.Icons.VISIBILITY, on_click=self.act(self.view_link, link)),
                self.open_browser_button(link),
                self.copy_button(link["final_url"]),
            ], spacing=0))
        return self.card(body)

    def link_list(self, links: list[dict], empty_text: str, **card_kwargs) -> ft.Control:
        if not links:
            return self.empty(empty_text)
        return ft.Column([self.link_card(l, **card_kwargs) for l in links], spacing=8)

    def visibility_dropdown(self, value: str, allow_unlisted: bool = True) -> ft.Dropdown:
        return ft.Dropdown(
            label="Who can see it", value=value, width=260,
            options=[ft.DropdownOption(key=k, text=v[0]) for k, v in VISIBILITY.items()
                     if allow_unlisted or k != "unlisted"],
        )

    # ================================================================== link actions
    async def run_scan(self, raw: str, button: ft.Control, ring: ft.ProgressRing,
                       action_text: str) -> Optional[security.ScanResult]:
        button.disabled, ring.visible = True, True
        self.page.update()
        try:
            result = await security.scan_url(raw)
        finally:
            button.disabled, ring.visible = False, False
            self.page.update()
        if result.blocked:
            await self.alert(f"This link can't be {action_text}", result.reasons,
                             ft.Icons.GPP_BAD, ft.Colors.RED_700)
            return None
        if result.status == security.WARN:
            verb = {"saved": "Save", "shared": "Share"}.get(action_text, "Continue")
            ok = await self.confirm("Proceed with caution",
                                    [f"• {r}" for r in result.reasons]
                                    + ["", "People who open it will see these warnings too."],
                                    ok_text=f"{verb} anyway")
            if not ok:
                return None
        return result

    async def view_link(self, link: dict):
        link = await self.ensure_fresh(link)
        if link["status"] == security.BLOCKED:
            await self.alert("This link has been blocked", link["reasons"], ft.Icons.GPP_BAD, ft.Colors.RED_700)
            return
        if link["status"] == security.WARN:
            if not await self.confirm("Proceed with caution", [f"• {r}" for r in link["reasons"]],
                                      ok_text="View anyway"):
                return
        self.show_viewer(link)

    async def ensure_fresh(self, link: dict) -> dict:
        """Re-scan links that haven't been checked recently (sites can turn bad later)."""
        if link.get("admin_locked") or db.now() - link["checked_at"] < RESCAN_HOURS * 3600:
            return link
        result = await security.scan_url(link["url"])
        db.apply_scan(link["id"], result)
        return {**link, **(db.get_link(link["id"]) or {})}

    def show_viewer(self, link: dict):
        url = link["final_url"]
        title = link["title"] or security.display_domain(link["domain"])
        header = ft.Container(
            padding=ft.Padding.symmetric(horizontal=4, vertical=4),
            content=ft.Row([
                ft.IconButton(ft.Icons.ARROW_BACK, tooltip="Back", on_click=self.act(self.render)),
                ft.Column([
                    ft.Text(title, weight=ft.FontWeight.W_600, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text(url, size=11, max_lines=1, overflow=ft.TextOverflow.ELLIPSIS,
                            color=ft.Colors.ON_SURFACE_VARIANT),
                ], spacing=0, expand=True),
                ft.IconButton(ft.Icons.OPEN_IN_NEW, tooltip="Open in browser",
                              action=ft.OpenUrl(url, target=ft.UrlTarget.BLANK)),
                self.copy_button(url),
            ]),
        )
        if link["embeddable"]:
            body = ft.Column([
                ft.Text("Page blank or refusing to load? Some sites block being shown inside "
                        "other apps - use Open in browser.", size=11, color=ft.Colors.ON_SURFACE_VARIANT),
                fwv.WebView(url=url, expand=True),
            ], expand=True, spacing=4)
        else:
            body = ft.Container(
                expand=True, alignment=ft.Alignment.CENTER, padding=24,
                content=ft.Column([
                    ft.Icon(ft.Icons.LINK_OFF, size=48, color=ft.Colors.OUTLINE),
                    ft.Text(f"{security.display_domain(link['domain'])} doesn't allow itself to be "
                            "shown inside other apps.", text_align=ft.TextAlign.CENTER),
                    ft.Button("Open in browser", icon=ft.Icons.OPEN_IN_NEW,
                              action=ft.OpenUrl(url, target=ft.UrlTarget.BLANK)),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, tight=True),
            )
        self.page.scroll = None
        self.page.appbar = None
        self.page.navigation_bar = None
        self.page.controls = [ft.Column([header, ft.Divider(height=1), body], expand=True, spacing=0)]
        self.page.update()

    async def edit_link_dialog(self, link: dict):
        title = ft.TextField(label="Title", value=link["title"], max_length=MAX_TITLE)
        note = ft.TextField(label="Note", value=link["note"], multiline=True, min_lines=2,
                            max_lines=5, max_length=MAX_NOTE)
        vis = self.visibility_dropdown(link["visibility"])

        async def save():
            if vis.value == "public" and link["status"] != security.SAFE:
                self.snack("Only links that passed the safety check can be made public.", error=True)
                return
            db.update_link(link["id"], title=(title.value or "").strip()[:MAX_TITLE],
                           note=(note.value or "").strip()[:MAX_NOTE], visibility=vis.value)
            self.close_dialog()
            self.snack("Saved")
            await self.render()

        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text("Edit link"),
            content=ft.Column([title, note, vis], tight=True, width=420),
            actions=[ft.TextButton("Cancel", on_click=self.close_dialog), ft.Button("Save", on_click=save)],
        ))

    async def share_friends_dialog(self, link: dict):
        friends = db.list_friends(self.user["id"])
        if not friends:
            await self.alert("No friends yet", ["Add friends from the Friends tab to share links with them."])
            return
        boxes = [ft.Checkbox(label=f"@{f['username']}", data=f["id"]) for f in friends]

        async def send():
            ids = [b.data for b in boxes if b.value]
            if not ids:
                self.snack("Pick at least one friend.", error=True)
                return
            if not ratelimit.allow("share", str(self.user["id"])):
                self.snack("You're sharing too fast. Try again later.", error=True)
                return
            valid = {f["id"] for f in db.list_friends(self.user["id"])}
            db.share_with(link["id"], self.user["id"], [i for i in ids if i in valid])
            self.close_dialog()
            self.snack(f"Shared with {len(ids)} friend{'s' if len(ids) > 1 else ''}")

        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text("Share with friends"),
            content=ft.Column(boxes, tight=True, scroll=ft.ScrollMode.AUTO, height=min(300, 48 * len(boxes))),
            actions=[ft.TextButton("Cancel", on_click=self.close_dialog),
                     ft.Button("Send", icon=ft.Icons.SEND, on_click=send)],
        ))

    async def share_link_dialog(self, link: dict):
        if link["status"] == security.BLOCKED:
            self.snack("Blocked links can't be shared.", error=True)
            return
        code = db.create_share_code(link["id"], self.user["id"], None)
        url = self.share_url(code)

        async def revoke():
            if await self.confirm("Revoke share links?",
                                  ["Everyone who has a share link for this bookmark will lose access."],
                                  ok_text="Revoke", danger=True):
                db.revoke_share_codes(link["id"])
                self.snack("Share links revoked")

        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text("Share link"),
            content=ft.Column([
                ft.Text("Anyone with this link can see this bookmark - no account needed."),
                ft.Row([ft.TextField(value=url, read_only=True, expand=True, dense=True),
                        self.copy_button(url)]),
            ], tight=True, width=460),
            actions=[ft.TextButton("Revoke all share links", on_click=revoke),
                     ft.TextButton("Done", on_click=self.close_dialog)],
        ))

    async def rescan(self, link: dict):
        self.snack("Re-checking...")
        result = await security.scan_url(link["url"])
        db.apply_scan(link["id"], result)
        label = STATUS[result.status][0]
        self.snack(f"Safety check: {label}", error=result.blocked)
        await self.render()

    async def delete_link(self, link: dict):
        if await self.confirm("Delete this link?", [link["title"] or link["url"]], "Delete", danger=True):
            db.delete_link(link["id"], self.user["id"])
            self.snack("Deleted")
            await self.render()

    async def save_copy(self, link: dict):
        if db.find_duplicate(self.user["id"], link["url"], link["final_url"]):
            self.snack("It's already in your links.")
            return
        if not ratelimit.allow("add_link", str(self.user["id"])):
            self.snack("You're adding links too fast. Try again later.", error=True)
            return
        db.add_link(self.user["id"], scan_from_link(link) if link["reasons"] else
                    security.ScanResult(url=link["url"], final_url=link["final_url"],
                                        domain=link["domain"], embeddable=bool(link["embeddable"])),
                    link["title"], "", "private")
        self.snack("Saved to your links (only you can see it)")

    async def remove_from_inbox(self, link: dict):
        db.remove_share(link["id"], self.user["id"])
        await self.render()

    async def report_dialog(self, link: dict):
        reason = ft.RadioGroup(value=REPORT_REASONS[0], content=ft.Column(
            [ft.Radio(value=r, label=r) for r in REPORT_REASONS], tight=True))
        details = ft.TextField(label="Details (optional)", max_length=300, multiline=True, max_lines=3)

        async def submit():
            if not ratelimit.allow("report", self.client_key()):
                self.snack("Too many reports. Try again later.", error=True)
                return
            text = reason.value + (f": {details.value.strip()}" if details.value else "")
            new = db.report_link(link["id"], self.client_key(), text)
            self.close_dialog()
            self.snack("Thanks - a moderator will review it." if new else "You've already reported this link.")
            if new:  # re-check immediately; it may have turned bad since it was saved
                asyncio.create_task(self._background_rescan(link))

        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text("Report link"),
            content=ft.Column([reason, details], tight=True, width=420),
            actions=[ft.TextButton("Cancel", on_click=self.close_dialog),
                     ft.Button("Report", icon=ft.Icons.FLAG_OUTLINED, on_click=submit)],
        ))

    async def _background_rescan(self, link: dict):
        try:
            if not link.get("admin_locked"):
                db.apply_scan(link["id"], await security.scan_url(link["url"]))
        except Exception:
            log.exception("rescan failed")

    # ================================================================== auth
    async def login_as(self, user: dict, next_route: str):
        self.token = auth.start_session(user["id"])
        try:
            await self.prefs.set(TOKEN_KEY, self.token)
        except Exception as e:
            log.info("could not persist session: %s", e)
        self.user = user
        safe_next = next_route if next_route.startswith("/") and not next_route.startswith("//") else ""
        await self.go(safe_next or "/links")

    async def logout(self):
        auth.end_session(self.token)
        try:
            await self.prefs.remove(TOKEN_KEY)
        except Exception:
            pass
        self.user, self.token = None, None
        await self.go("/")

    def view_login(self, next_route: str) -> list[ft.Control]:
        username = ft.TextField(label="Username", autofocus=True, autocorrect=False)
        password = ft.TextField(label="Password", password=True, can_reveal_password=True)
        error = ft.Text(color=ft.Colors.ERROR, visible=False)

        async def submit():
            key = f"{self.page.client_ip}:{(username.value or '').lower()}"
            if not ratelimit.allow("login", key):
                error.value, error.visible = "Too many attempts. Wait 15 minutes and try again.", True
                self.page.update()
                return
            user = auth.authenticate((username.value or "").strip(), password.value or "")
            if not user:
                error.value, error.visible = "Wrong username or password.", True
                password.value = ""
                self.page.update()
                return
            await self.login_as(user, next_route)

        password.on_submit = submit
        suffix = f"?next={quote(next_route)}" if next_route else ""
        return [
            self.heading("Sign in", "Save links, share them with friends and build a public collection."),
            self.card([username, password, error,
                       ft.Button("Sign in", icon=ft.Icons.LOGIN, on_click=submit),
                       ft.TextButton("No account? Create one", on_click=self.act(self.go, f"/signup{suffix}"))]),
            ft.TextButton("Or share a link without an account", icon=ft.Icons.BOLT,
                          on_click=self.act(self.go, "/quick")),
        ]

    def view_signup(self, next_route: str) -> list[ft.Control]:
        username = ft.TextField(label="Username", autofocus=True, autocorrect=False,
                                helper="3-24 letters, numbers or _ (shown publicly)")
        password = ft.TextField(label="Password", password=True, can_reveal_password=True,
                                helper="At least 10 characters")
        password2 = ft.TextField(label="Repeat password", password=True, can_reveal_password=True)
        error = ft.Text(color=ft.Colors.ERROR, visible=False)

        def fail(msg: str):
            error.value, error.visible = msg, True
            self.page.update()

        async def submit():
            name = (username.value or "").strip()
            if (msg := auth.validate_username(name)) or (msg := auth.validate_password(password.value or "", name)):
                return fail(msg)
            if password.value != password2.value:
                return fail("The passwords don't match.")
            if not ratelimit.allow("signup", self.page.client_ip or "unknown"):
                return fail("Too many new accounts from your network. Try again later.")
            try:
                user = auth.register(name, password.value)
            except Exception:
                return fail("That username is taken.")
            await self.login_as(user, next_route)

        password2.on_submit = submit
        return [
            self.heading("Create an account"),
            self.card([username, password, password2, error,
                       ft.Button("Create account", icon=ft.Icons.PERSON_ADD, on_click=submit),
                       ft.TextButton("Already have an account? Sign in",
                                     on_click=self.act(self.go, "/login"))]),
        ]

    # ================================================================== pages
    def view_not_found(self) -> list[ft.Control]:
        return [self.empty("Page not found.", ft.Icons.SEARCH_OFF),
                ft.TextButton("Go home", on_click=self.act(self.go, "/"))]

    def view_home(self) -> list[ft.Control]:
        def feature(icon, title, text):
            return ft.Row([ft.Icon(icon, color=ft.Colors.PRIMARY),
                           ft.Column([ft.Text(title, weight=ft.FontWeight.W_600), ft.Text(text)],
                                     spacing=2, expand=True)],
                          vertical_alignment=ft.CrossAxisAlignment.START)

        return [
            ft.Container(height=8),
            ft.Text(APP_NAME, size=34, weight=ft.FontWeight.BOLD),
            ft.Text("Save the websites you like, find them later, and share them safely.", size=16),
            ft.Row([ft.Button("Create free account", icon=ft.Icons.PERSON_ADD,
                              on_click=self.act(self.go, "/signup")),
                    ft.OutlinedButton("Sign in", on_click=self.act(self.go, "/login"))], wrap=True),
            self.card([
                feature(ft.Icons.BOLT, "Share without an account",
                        "Paste a link and get a short share link to send to anyone."),
                ft.Row([ft.FilledTonalButton("Quick share", icon=ft.Icons.BOLT,
                                             on_click=self.act(self.go, "/quick"))]),
            ]),
            self.card([
                feature(ft.Icons.SHIELD, "Every link is safety-checked",
                        "We block dangerous addresses and warn you about suspicious ones before you open them."),
                feature(ft.Icons.PEOPLE, "Private, friends-only or public",
                        "You decide who sees each link."),
                feature(ft.Icons.VISIBILITY, "Built-in viewer",
                        "Preview pages inside the app, or open them in your browser."),
            ]),
            ft.TextButton("Browse public links", icon=ft.Icons.EXPLORE,
                          on_click=self.act(self.go, "/explore")),
        ]

    def view_links(self) -> list[ft.Control]:
        url = ft.TextField(label="Link", hint_text="Paste a web address...", prefix_icon=ft.Icons.LINK,
                           autofocus=True, autocorrect=False, keyboard_type=ft.KeyboardType.URL)
        title = ft.TextField(label="Title (optional - we'll fetch it)", max_length=MAX_TITLE, expand=True)
        note = ft.TextField(label="Note (optional)", multiline=True, max_lines=3, max_length=MAX_NOTE)
        vis = self.visibility_dropdown("private", allow_unlisted=False)
        ring = ft.ProgressRing(width=20, height=20, visible=False)
        save_btn = ft.Button("Check & save", icon=ft.Icons.BOOKMARK_ADD)
        search = ft.TextField(hint_text="Search your links", prefix_icon=ft.Icons.SEARCH, dense=True)
        results = ft.Column()

        def refresh_list():
            results.controls = [self.link_list(db.list_user_links(self.user["id"], search.value or ""),
                                               "No links yet. Paste one above to get started."
                                               if not search.value else "Nothing matches your search.")]

        async def save():
            if not (url.value or "").strip():
                return
            if not ratelimit.allow("add_link", str(self.user["id"])):
                self.snack("You're adding links too fast. Try again later.", error=True)
                return
            result = await self.run_scan(url.value, save_btn, ring, "saved")
            if not result:
                return
            if db.find_duplicate(self.user["id"], result.url, result.final_url):
                self.snack("You've already saved this link.")
                return
            visibility = vis.value
            if visibility == "public" and result.status != security.SAFE:
                visibility = "private"
                self.snack("Saved as private - only links that pass every check can be public.")
            db.add_link(self.user["id"], result, (title.value or "").strip()[:MAX_TITLE] or result.title,
                        (note.value or "").strip()[:MAX_NOTE], visibility)
            url.value = title.value = note.value = ""
            refresh_list()
            self.snack("Link saved")
            self.page.update()

        save_btn.on_click = save
        url.on_submit = save
        search.on_change = lambda: (refresh_list(), self.page.update())
        refresh_list()
        return [
            self.heading("My links"),
            self.card([url, ft.Row([title]), note,
                       ft.Row([vis, save_btn, ring], wrap=True,
                              vertical_alignment=ft.CrossAxisAlignment.CENTER)]),
            search,
            results,
        ]

    def view_shared(self) -> list[ft.Control]:
        links = db.list_shared_with(self.user["id"])
        db.mark_shares_seen(self.user["id"])
        cards = [self.link_card(l, sender=l["sender_name"], in_inbox=True, show_owner=False) for l in links]
        return [self.heading("Shared with me", "Links your friends sent you."),
                ft.Column(cards, spacing=8) if cards else self.empty("Nothing shared with you yet.", ft.Icons.INBOX)]

    def view_explore(self) -> list[ft.Control]:
        search = ft.TextField(hint_text="Search public links", prefix_icon=ft.Icons.SEARCH, dense=True)
        results = ft.Column()

        def refresh():
            results.controls = [self.link_list(db.list_public_links(search.value or ""),
                                               "No public links yet.")]

        search.on_change = lambda: (refresh(), self.page.update())
        refresh()
        return [self.heading("Explore", "Links people have made public."), search, results]

    def view_friends(self) -> list[ft.Control]:
        uid = self.user["id"]
        name = ft.TextField(label="Friend's username", prefix_icon=ft.Icons.PERSON_ADD, expand=True, dense=True)

        async def send():
            target = db.get_user_by_name((name.value or "").strip().lstrip("@"))
            if not target or target["id"] == uid:
                self.snack("No user with that name.", error=True)
                return
            if not ratelimit.allow("friend_request", str(uid)):
                self.snack("Too many requests. Try again later.", error=True)
                return
            outcome = db.send_friend_request(uid, target["id"])
            self.snack({"sent": f"Request sent to @{target['username']}",
                        "accepted": f"You and @{target['username']} are now friends",
                        "exists": "You've already sent a request or are friends."}[outcome])
            await self.render()

        async def accept(rid):
            db.accept_friend(uid, rid)
            await self.render()

        async def remove(fid, label, ask=True):
            if not ask or await self.confirm(f"{label}?", ["They'll no longer see your friends-only links."],
                                             ok_text=label, danger=True):
                db.remove_friendship(uid, fid)
                await self.render()

        name.on_submit = send
        incoming = db.list_incoming_requests(uid)
        outgoing = db.list_outgoing_requests(uid)
        friends = db.list_friends(uid)

        def person(u, trailing):
            return ft.ListTile(leading=ft.Icon(ft.Icons.ACCOUNT_CIRCLE), title=ft.Text(f"@{u['username']}"),
                               trailing=trailing, on_click=self.act(self.go, f"/u/{u['username']}"))

        out = [self.heading("Friends", "Friends can see your friends-only links, and you can send them links."),
               self.card([ft.Row([name, ft.Button("Send request", on_click=send)])])]
        if incoming:
            out.append(ft.Text("Requests", weight=ft.FontWeight.W_600))
            out += [person(u, ft.Row([
                ft.IconButton(ft.Icons.CHECK, tooltip="Accept", on_click=self.act(accept, u["id"])),
                ft.IconButton(ft.Icons.CLOSE, tooltip="Decline", on_click=self.act(remove, u["id"], "Decline", False)),
            ], tight=True)) for u in incoming]
        out.append(ft.Text(f"Your friends ({len(friends)})", weight=ft.FontWeight.W_600))
        out += [person(u, ft.IconButton(ft.Icons.PERSON_REMOVE, tooltip="Remove friend",
                                        on_click=self.act(remove, u["id"], "Remove friend")))
                for u in friends] or [self.empty("No friends yet. Send a request above.", ft.Icons.GROUP)]
        if outgoing:
            out.append(ft.Text("Waiting for reply", weight=ft.FontWeight.W_600))
            out += [person(u, ft.TextButton("Cancel", on_click=self.act(remove, u["id"], "Cancel", False)))
                    for u in outgoing]
        return out

    def view_profile(self, username: str) -> list[ft.Control]:
        owner = db.get_user_by_name(username)
        if not owner:
            return self.view_not_found()
        me = self.user
        is_self = bool(me and me["id"] == owner["id"])
        friends = bool(me and not is_self and db.are_friends(me["id"], owner["id"]))
        links = db.list_profile_links(owner["id"], include_friends=friends or is_self)

        action: Optional[ft.Control] = None
        if me and not is_self:
            rel = db.friendship(me["id"], owner["id"])

            async def add():
                if not ratelimit.allow("friend_request", str(me["id"])):
                    self.snack("Too many requests. Try again later.", error=True)
                    return
                db.send_friend_request(me["id"], owner["id"])
                await self.render()

            if friends:
                action = self.small_chip("Friends", ft.Icons.PEOPLE)
            elif rel and rel["requester_id"] == me["id"]:
                action = self.small_chip("Request sent", ft.Icons.SCHEDULE)
            else:
                action = ft.Button("Accept friend request" if rel else "Add friend",
                                   icon=ft.Icons.PERSON_ADD, on_click=add)

        sub = ("This is how friends see your profile." if is_self else
               "Public and friends-only links." if friends else "Public links.")
        return [
            ft.Row([ft.Icon(ft.Icons.ACCOUNT_CIRCLE, size=48),
                    ft.Column([ft.Text(f"@{owner['username']}", size=24, weight=ft.FontWeight.BOLD),
                               ft.Text(sub, color=ft.Colors.ON_SURFACE_VARIANT)], spacing=0, expand=True)]
                   + ([action] if action else []), wrap=True),
            self.link_list(links, "No links to show.", show_owner=False),
        ]

    async def view_share(self, code: str) -> list[ft.Control]:
        share = db.get_share(code) if len(code) <= 40 else None
        if not share:
            return [self.empty("This share link is invalid or has expired.", ft.Icons.LINK_OFF)]
        if share["hidden"]:
            return [self.empty("This link is under review after reports from other users.", ft.Icons.GPP_MAYBE)]
        share = await self.ensure_fresh(share)
        if share["status"] == security.BLOCKED:
            return [self.empty("This link has been disabled because it was found to be unsafe.", ft.Icons.GPP_BAD)]

        by = f"@{share['shared_by']}" if share.get("shared_by") else "someone (without an account)"
        out = [self.heading("A link was shared with you", f"Shared by {by}.")]
        if share["status"] == security.WARN:
            out.append(ft.Container(
                bgcolor=ft.Colors.with_opacity(0.12, ft.Colors.AMBER), border_radius=8, padding=12,
                content=ft.Row([ft.Icon(ft.Icons.WARNING_AMBER, color=ft.Colors.AMBER_800),
                                ft.Text("Our safety check found something unusual about this link. "
                                        "Tap 'Caution' below to see why.", expand=True)])))
        out.append(self.link_card(share, show_owner=False))
        if share.get("expires_at"):
            out.append(ft.Text(f"This share link expires in {max(1, (share['expires_at'] - db.now()) // 86400)} days.",
                               size=12, color=ft.Colors.ON_SURFACE_VARIANT))
        if not self.user:
            out.append(ft.TextButton("Create an account to save links like this",
                                     on_click=self.act(self.go, f"/signup?next=/s/{code}")))
        return out

    def view_quick(self) -> list[ft.Control]:
        url = ft.TextField(label="Link", hint_text="Paste a web address...", prefix_icon=ft.Icons.LINK,
                           autofocus=True, autocorrect=False, keyboard_type=ft.KeyboardType.URL)
        title = ft.TextField(label="Title (optional)", max_length=MAX_TITLE)
        note = ft.TextField(label="Message (optional)", multiline=True, max_lines=3, max_length=MAX_NOTE)
        ring = ft.ProgressRing(width=20, height=20, visible=False)
        btn = ft.Button("Check & create share link", icon=ft.Icons.BOLT)
        result_area = ft.Column()

        async def create():
            if not (url.value or "").strip():
                return
            if not ratelimit.allow("quick_share", self.page.client_ip or "unknown"):
                self.snack("Too many share links from your network. Try again later.", error=True)
                return
            result = await self.run_scan(url.value, btn, ring, "shared")
            if not result:
                return
            owner = self.user["id"] if self.user else None
            link_id = db.add_link(owner, result, (title.value or "").strip()[:MAX_TITLE] or result.title,
                                  (note.value or "").strip()[:MAX_NOTE], "unlisted")
            expires = None if self.user else db.now() + ANON_SHARE_DAYS * 86400
            share = self.share_url(db.create_share_code(link_id, owner, expires))
            url.value = title.value = note.value = ""
            result_area.controls = [self.card([
                ft.Row([ft.Icon(ft.Icons.CHECK_CIRCLE, color=ft.Colors.GREEN_700),
                        ft.Text("Your share link is ready", weight=ft.FontWeight.W_600)]),
                ft.Row([ft.TextField(value=share, read_only=True, expand=True, dense=True),
                        self.copy_button(share)]),
                ft.Text(f"Expires in {ANON_SHARE_DAYS} days." if expires else
                        "Manage or revoke it any time from My links.",
                        size=12, color=ft.Colors.ON_SURFACE_VARIANT),
            ])]
            self.page.update()

        btn.on_click = create
        url.on_submit = create
        return [
            self.heading("Quick share", "Send a link to anyone. The link is safety-checked, and the "
                                        "person you send it to sees the result before opening it."),
            self.card([url, title, note, ft.Row([btn, ring])]),
            result_area,
        ]

    def view_admin(self) -> list[ft.Control]:
        async def block(link, domain=False):
            if domain:
                if not await self.confirm(f"Block {link['domain']}?",
                                          ["All future links to this domain (and its subdomains) will be refused."],
                                          ok_text="Block domain", danger=True):
                    return
                security.add_to_blocklist(link["domain"])
            db.update_link(link["id"], status=security.BLOCKED, admin_locked=1, hidden=1,
                           reasons=["Blocked by a moderator."] + link["reasons"])
            await self.render()

        async def restore(link):
            db.clear_reports(link["id"])
            db.apply_scan(link["id"], await security.scan_url(link["url"]))
            await self.render()

        rows = []
        for l in db.list_reported_links():
            rows.append(self.card([
                ft.Text(l["title"] or l["domain"], weight=ft.FontWeight.W_600),
                ft.Text(l["final_url"], size=12, selectable=True),
                ft.Text(f"Owner: {'@' + l['owner_name'] if l['owner_name'] else 'anonymous'} · "
                        f"{l['report_count']} report(s) · {'hidden' if l['hidden'] else 'visible'} · "
                        f"status: {l['status']}", size=12),
                *[ft.Text(f"“{r}”", size=12, italic=True) for r in l["report_reasons"]],
                ft.Row([ft.TextButton("Block link", icon=ft.Icons.BLOCK, on_click=self.act(block, l)),
                        ft.TextButton("Block domain", icon=ft.Icons.BLOCK, on_click=self.act(block, l, True)),
                        ft.TextButton("Restore", icon=ft.Icons.RESTORE, on_click=self.act(restore, l))], wrap=True),
            ]))
        return [self.heading("Moderation", "Reported and blocked links."),
                *(rows or [self.empty("Nothing reported.", ft.Icons.VERIFIED_USER)])]
