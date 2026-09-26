"""All screens of the app. One `App` instance per browser tab (Flet session)."""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, Optional
from urllib.parse import parse_qs, quote, urlsplit

import flet as ft

import auth
import db
import ratelimit
import palette
import security
from palette import DISPLAY, STRONG
from config import ADMIN_USERNAMES, ANON_SHARE_DAYS, APP_NAME, PUBLIC_BASE_URL, RESCAN_HOURS

log = logging.getLogger("linkvault.ui")

TOKEN_KEY = "linkvault.session"
THEME_KEY = "linkvault.theme"
THEME_MODES = {"system": (ft.Icons.BRIGHTNESS_AUTO, "Theme: follow system"),
               "light": (ft.Icons.LIGHT_MODE, "Theme: light"),
               "dark": (ft.Icons.DARK_MODE, "Theme: dark")}
MAX_TITLE, MAX_NOTE = 200, 1000
PAGE_SIZE = 100            # links shown before "Show more"
NEW_CATEGORY = "__new__"   # dropdown sentinel

VISIBILITY = {
    "private": ("Only me", ft.Icons.LOCK),
    "friends": ("Friends", ft.Icons.PEOPLE),
    "public": ("Public", ft.Icons.PUBLIC),
    "unlisted": ("Anyone with the link", ft.Icons.LINK),
}
# label, icon, palette key (text colour = key, tint = key + "_bg")
STATUS = {
    security.SAFE: ("Checked", ft.Icons.GPP_GOOD, "safe"),
    security.WARN: ("Caution", ft.Icons.GPP_MAYBE, "caution"),
    security.BLOCKED: ("Blocked", ft.Icons.GPP_BAD, "blocked"),
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
        self.theme_choice = "system"
        self.cat_filter = None        # My links: None = all, "none" = uncategorized, int = category
        self.profile_filter = (None, None)   # (username, category)
        self.limit = PAGE_SIZE
        self.show_details = False
        self.c = palette.LIGHT
        self._closed = False
        # Invisible control whose value changes every 20 s. Each change is a tiny message
        # to the browser, which lets the watchdog in web_patch.py tell a healthy connection
        # from a dead one, and keeps proxies/NATs from dropping an idle WebSocket.
        self._beat = ft.Text("0", size=1, opacity=0)

    # ================================================================== plumbing
    async def start(self):
        p = self.page
        p.title = APP_NAME
        p.fonts = palette.FONTS
        p.theme = palette.make_theme(palette.LIGHT, dark=False)
        p.dark_theme = palette.make_theme(palette.DARK, dark=True)
        p.on_platform_brightness_change = self._on_route_change
        p.padding = ft.Padding.symmetric(horizontal=10, vertical=8)
        p.scroll = ft.ScrollMode.AUTO
        p.on_route_change = self._on_route_change
        p.on_close = self._on_close
        p.overlay.append(self._beat)
        p.run_task(self._heartbeat)
        try:
            self.token = await self.prefs.get(TOKEN_KEY)
            saved = await self.prefs.get(THEME_KEY)
            if saved in THEME_MODES:
                self.theme_choice = saved
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
        self.limit = PAGE_SIZE
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
    def dark(self) -> bool:
        if self.theme_choice == "system":
            return getattr(self.page, "platform_brightness", None) == ft.Brightness.DARK
        return self.theme_choice == "dark"

    def apply_theme(self):
        self.c = palette.DARK if self.dark else palette.LIGHT
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark else ft.ThemeMode.LIGHT
        self.page.bgcolor = self.c["canvas"]

    async def cycle_theme(self):
        order = list(THEME_MODES)
        self.theme_choice = order[(order.index(self.theme_choice) + 1) % len(order)]
        try:
            await self.prefs.set(THEME_KEY, self.theme_choice)
        except Exception:
            pass
        await self.render()

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
            ft.Text(message, color=self.c["canvas"]), bgcolor=self.c["blocked"] if error else self.c["ink"],
            duration=3500, behavior=ft.SnackBarBehavior.FLOATING))

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
                ft.FilledButton(ok_text, on_click=lambda: finish(True),
                          bgcolor=self.c["blocked"] if danger else None),
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
        icon, tip = THEME_MODES[self.theme_choice]
        actions = [ft.IconButton(icon, tooltip=tip, on_click=self.act(self.cycle_theme))]
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
            leading=ft.Icon(ft.Icons.BOOKMARK, color=self.c["ribbon"], size=24), leading_width=40,
            toolbar_height=50,
            title=ft.Text(APP_NAME, font_family=DISPLAY, size=22, color=self.c["ink"]),
            actions=actions, bgcolor=self.c["canvas"], elevation=0, elevation_on_scroll=0,
        )

    def _frame(self, controls: list[ft.Control]) -> ft.Control:
        """Centered column, full width on phones, ~2/3 width on desktop."""
        return ft.ResponsiveRow(
            [ft.Column(controls, spacing=10, col={"xs": 12, "md": 11, "lg": 9, "xl": 8})],
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

        self.apply_theme()
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
        self.apply_theme()
        self.page.appbar = self._appbar()
        self.page.navigation_bar = self._nav(path)
        self.page.controls = [self._frame(content)]
        self.page.update()

    # ================================================================== reusable pieces
    def heading(self, text: str, sub: str = "") -> ft.Control:
        items = [ft.Text(text, size=26, font_family=DISPLAY, color=self.c["ink"])]
        if sub:
            items.append(ft.Text(sub, size=13, color=self.c["muted"]))
        return ft.Column(items, spacing=0)

    def empty(self, text: str, icon=ft.Icons.BOOKMARK_OUTLINE) -> ft.Control:
        return ft.Container(
            padding=30, alignment=ft.Alignment.CENTER,
            content=ft.Column([ft.Icon(icon, size=40, color=ft.Colors.OUTLINE),
                               ft.Text(text, color=ft.Colors.ON_SURFACE_VARIANT,
                                       text_align=ft.TextAlign.CENTER)],
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        )

    def card(self, controls: list[ft.Control]) -> ft.Control:
        return ft.Container(
            ft.Column(controls, spacing=8), padding=12, bgcolor=self.c["surface"],
            border=ft.Border.all(1, self.c["line"]), border_radius=14,
        )

    def ribbon_card(self, controls: list[ft.Control], ribbon: str) -> ft.Control:
        """Card with a bookmark ribbon on its left edge (colour = who can see the link)."""
        return ft.Container(
            bgcolor=self.c["surface"], border=ft.Border.all(1, self.c["line"]), border_radius=14,
            clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
            content=ft.Container(
                ft.Column(controls, spacing=8),
                border=ft.Border(left=ft.BorderSide(5, ribbon)),
                padding=ft.Padding.only(left=16, right=8, top=12, bottom=6),
            ),
        )

    async def show_status(self, link: dict):
        label, icon, key = STATUS[link["status"]]
        if link["reasons"]:
            await self.alert(f"Safety check: {label}", link["reasons"], icon, self.c[key])
        else:
            await self.alert("Safety check passed", [
                "Valid public web address, not on our blocklist.",
                "Domain resolves to a public server.",
                "Redirects (if any) were checked.",
                f"Last checked {time_ago(link['checked_at'])}.",
            ], icon, self.c[key])

    def status_icon(self, link: dict) -> ft.Control:
        label, icon, key = STATUS[link["status"]]
        return ft.IconButton(icon, icon_color=self.c[key], icon_size=18, tooltip=f"Safety: {label}",
                             visual_density=ft.VisualDensity.COMPACT,
                             on_click=self.act(self.show_status, link))

    def small_chip(self, text: str, icon, on_click=None, icon_color=None) -> ft.Control:
        return ft.Container(
            content=ft.Row([ft.Icon(icon, size=14, color=icon_color or self.c["muted"]),
                            ft.Text(text, size=12, color=self.c["muted"])],
                           spacing=4, tight=True),
            padding=ft.Padding.symmetric(horizontal=9, vertical=4),
            border=ft.Border.all(1, self.c["line"]), border_radius=20,
            on_click=on_click, ink=on_click is not None,
        )

    def warn_before_open(self, link: dict):
        """Caution links: show why first; the real open happens from the dialog's button."""
        url = link["final_url"]
        self.page.show_dialog(ft.AlertDialog(
            icon=ft.Icon(ft.Icons.GPP_MAYBE, color=self.c["caution"]),
            title=ft.Text("Proceed with caution"),
            content=ft.Column(
                [ft.Text(f"• {r}") for r in link["reasons"]]
                + [ft.Text(url, size=12, selectable=True, color=self.c["muted"])],
                tight=True, spacing=6),
            actions=[
                ft.TextButton("Cancel", on_click=self.close_dialog),
                ft.FilledButton("Open anyway", icon=ft.Icons.OPEN_IN_NEW,
                                action=ft.OpenUrl(url, target=ft.UrlTarget.BLANK),
                                on_click=self.close_dialog),
            ],
        ))

    def opens_link(self, control: ft.Control, link: dict) -> ft.Control:
        """
        Make `control` open the link in a new browser tab.

        Safe links use a client action: the browser opens the tab inside the click itself,
        so pop-up blockers (and iOS Safari) allow it and there is no server round trip.
        """
        if link["status"] == security.SAFE and link.get("final_url"):
            control.action = ft.OpenUrl(link["final_url"], target=ft.UrlTarget.BLANK)
        elif link["status"] == security.WARN and link.get("final_url"):
            control.on_click = lambda: self.warn_before_open(link)
        else:  # blocked: never open, but say why instead of doing nothing
            control.on_click = self.act(
                self.alert, "This link is blocked",
                link["reasons"] or ["It failed the safety check."], ft.Icons.GPP_BAD, self.c["blocked"])
        return control

    def open_url_button(self, url: str, label: str = "Open") -> ft.Control:
        """For URLs we generated ourselves (share links) - always safe to open."""
        return ft.OutlinedButton(label, icon=ft.Icons.OPEN_IN_NEW,
                                 action=ft.OpenUrl(url, target=ft.UrlTarget.BLANK))

    def open_browser_button(self, link: dict) -> ft.Control:
        return self.opens_link(
            ft.FilledButton("Open in browser", icon=ft.Icons.OPEN_IN_NEW), link)

    def copy_button(self, text: str, tooltip="Copy link") -> ft.Control:
        return ft.IconButton(ft.Icons.CONTENT_COPY, tooltip=tooltip, icon_size=17,
                             visual_density=ft.VisualDensity.COMPACT,
                             action=ft.CopyToClipboard(text),
                             on_click=lambda: self.snack("Copied to clipboard"))

    def link_card(self, link: dict, sender: Optional[str] = None,
                  in_inbox: bool = False, show_owner: bool = True, last: bool = True) -> ft.Control:
        """One compact row: ribbon | title + meta (tap to view) | safety, open, copy, menu."""
        c = self.c
        mine = bool(self.user and link["owner_id"] == self.user["id"])
        title = link["title"] or security.display_domain(link["domain"])
        blocked = link["status"] == security.BLOCKED

        menu_items: list[ft.PopupMenuItem] = []
        if mine:
            menu_items += [
                ft.PopupMenuItem(content="Edit", icon=ft.Icons.EDIT,
                                 on_click=self.act(self.edit_link_dialog, link)),
                ft.PopupMenuItem(content="Move to category", icon=ft.Icons.DRIVE_FILE_MOVE_OUTLINE,
                                 on_click=self.act(self.move_dialog, link)),
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

        def meta_text(text, color=None, icon=None, on_click=None):
            parts = []
            if icon:
                parts.append(ft.Icon(icon, size=13, color=color or c["muted"]))
            parts.append(ft.Text(text, size=12, color=color or c["muted"], max_lines=1,
                                 overflow=ft.TextOverflow.ELLIPSIS))
            row = ft.Row(parts, spacing=3, tight=True)
            return ft.Container(row, on_click=on_click, ink=on_click is not None) if on_click else row

        meta = [meta_text(security.display_domain(link["domain"]), c["primary"])]
        if link.get("category_name"):
            meta.append(meta_text(link["category_name"], icon=ft.Icons.FOLDER_OUTLINED,
                                  on_click=self.act(self.filter_to, link["category_id"]) if mine else None))
        if not mine and show_owner and link.get("owner_name"):
            meta.append(meta_text(f"@{link['owner_name']}", icon=ft.Icons.PERSON_OUTLINE,
                                  on_click=self.act(self.go, f"/u/{link['owner_name']}")))
        if sender:
            meta.append(meta_text(f"from @{sender}", icon=ft.Icons.SEND))
        meta.append(meta_text(time_ago(link["created_at"])))

        text_col = [
            ft.Text(title, font_family=STRONG, size=14, max_lines=1,
                    overflow=ft.TextOverflow.ELLIPSIS, color=c["ink"]),
            ft.Row(meta, spacing=10, wrap=True, run_spacing=0),
        ]
        if link["note"]:
            text_col.append(ft.Text(link["note"], size=12, color=c["muted"], max_lines=1,
                                    overflow=ft.TextOverflow.ELLIPSIS, tooltip=link["note"][:300]))

        main = ft.Container(
            ft.Column(text_col, spacing=1), expand=True, ink=True,
            padding=ft.Padding.symmetric(vertical=7),
            tooltip="Blocked - tap to see why" if blocked
            else f"Open {security.display_domain(link['domain'])} in a new tab",
        )
        self.opens_link(main, link)
        actions = [self.status_icon(link)]
        if not blocked:
            actions.append(self.copy_button(link["final_url"]))
        actions.append(ft.PopupMenuButton(icon=ft.Icons.MORE_VERT, icon_size=18, items=menu_items))

        return ft.Container(
            ft.Row([main, *actions], spacing=0, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.Padding.only(left=12, right=2),
            border=ft.Border(left=ft.BorderSide(4, c["vis_" + link["visibility"]]),
                             bottom=None if last else ft.BorderSide(1, c["line"])),
        )

    def link_list(self, links: list[dict], empty_text: str, total: Optional[int] = None,
                  **card_kwargs) -> ft.Control:
        """Links as one outlined list with hairline separators; paged by PAGE_SIZE."""
        if not links:
            return self.empty(empty_text)
        shown = links[: self.limit]
        rows = [self.link_card(l, last=(i == len(shown) - 1), **card_kwargs) for i, l in enumerate(shown)]
        out = [ft.Container(
            ft.Column(rows, spacing=0), bgcolor=self.c["surface"], border_radius=12,
            border=ft.Border.all(1, self.c["line"]), clip_behavior=ft.ClipBehavior.ANTI_ALIAS)]
        remaining = (total if total is not None else len(links)) - len(shown)
        if remaining > 0:
            async def more():
                self.limit += PAGE_SIZE
                await self.render()
            out.append(ft.Row([ft.TextButton(f"Show more ({remaining})", icon=ft.Icons.EXPAND_MORE,
                                             on_click=more)], alignment=ft.MainAxisAlignment.CENTER))
        return ft.Column(out, spacing=6)

    def visibility_dropdown(self, value: str, allow_unlisted: bool = True) -> ft.Dropdown:
        return ft.Dropdown(
            label="Who can see it", value=value, width=260, dense=True,
            options=[ft.DropdownOption(key=k, text=v[0],
                                       leading_icon=ft.Icon(ft.Icons.BOOKMARK, color=self.c["vis_" + k]))
                     for k, v in VISIBILITY.items()
                     if allow_unlisted or k != "unlisted"],
        )

    # ================================================================== link actions
    # ------------------------------------------------------------------ categories
    def category_dropdown(self, value, label="Category", on_new=None, width=None) -> ft.Dropdown:
        cats = db.list_categories(self.user["id"])
        dd = ft.Dropdown(
            label=label, dense=True, width=width, value=str(value) if value else "",
            leading_icon=ft.Icons.FOLDER_OUTLINED,
            options=[ft.DropdownOption(key="", text="No category")]
            + [ft.DropdownOption(key=str(cat["id"]), text=cat["name"]) for cat in cats]
            + [ft.DropdownOption(key=NEW_CATEGORY, text="New category...")],
        )

        async def selected(e=None):
            if dd.value == NEW_CATEGORY:
                cid = await self.ask_new_category()
                if cid:
                    dd.options.insert(len(dd.options) - 1, ft.DropdownOption(
                        key=str(cid), text=db.get_category_name(cid) or "New"))
                dd.value = str(cid) if cid else ""
                self.page.update()
                if on_new:
                    await on_new(cid)

        dd.on_select = selected
        return dd

    @staticmethod
    def dropdown_category(dd: ft.Dropdown) -> Optional[int]:
        return int(dd.value) if dd.value and dd.value.isdigit() else None

    async def ask_new_category(self) -> Optional[int]:
        """Small modal that returns the new (or existing same-name) category id."""
        done = asyncio.get_running_loop().create_future()
        name = ft.TextField(label="Category name", autofocus=True, max_length=db.MAX_CATEGORY_NAME)
        error = ft.Text(color=self.c["blocked"], visible=False, size=12)

        def finish(value):
            if not done.done():
                done.set_result(value)
            self.page.pop_dialog()

        def create():
            try:
                finish(db.create_category(self.user["id"], name.value or ""))
            except ValueError as e:
                error.value, error.visible = str(e), True
                self.page.update()

        name.on_submit = create
        self.page.show_dialog(ft.AlertDialog(
            modal=True, title=ft.Text("New category"),
            content=ft.Column([name, error], tight=True, width=360),
            actions=[ft.TextButton("Cancel", on_click=lambda: finish(None)),
                     ft.FilledButton("Create", on_click=create)],
        ))
        return await done

    async def filter_to(self, category):
        self.cat_filter = category
        self.limit = PAGE_SIZE
        await self.go("/links")

    async def move_dialog(self, link: dict):
        dd = self.category_dropdown(link.get("category_id"), label="Move to")

        async def save():
            db.set_link_category(link["id"], self.user["id"], self.dropdown_category(dd))
            self.close_dialog()
            self.snack("Moved")
            await self.render()

        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text("Move to category"),
            content=ft.Column([ft.Text(link["title"] or link["domain"], color=self.c["muted"], max_lines=2),
                               dd], tight=True, width=360),
            actions=[ft.TextButton("Cancel", on_click=self.close_dialog),
                     ft.FilledButton("Move", on_click=save)],
        ))

    async def manage_categories_dialog(self):
        uid = self.user["id"]
        body = ft.Column(tight=True, spacing=4, scroll=ft.ScrollMode.AUTO, width=420)
        new_name = ft.TextField(label="New category", dense=True, expand=True,
                                max_length=db.MAX_CATEGORY_NAME)

        def rebuild(message: str = ""):
            rows = []
            for cat in db.list_categories(uid):
                field = ft.TextField(value=cat["name"], dense=True, expand=True,
                                     max_length=db.MAX_CATEGORY_NAME, counter=None)

                def rename(cat=cat, field=field):
                    try:
                        db.rename_category(uid, cat["id"], field.value or "")
                        rebuild("Renamed")
                    except ValueError as e:
                        rebuild(str(e))

                async def remove(cat=cat):
                    if await self.confirm(f"Delete \"{cat['name']}\"?",
                                          [f"Its {cat['n']} link(s) will be kept and become uncategorized."],
                                          ok_text="Delete", danger=True):
                        db.delete_category(uid, cat["id"])
                        if self.cat_filter == cat["id"]:
                            self.cat_filter = None
                    await self.manage_categories_dialog()

                field.on_submit = rename
                rows.append(ft.Row([
                    field, ft.Text(str(cat["n"]), size=12, color=self.c["muted"], width=28),
                    ft.IconButton(ft.Icons.CHECK, tooltip="Save name", on_click=rename,
                                  visual_density=ft.VisualDensity.COMPACT),
                    ft.IconButton(ft.Icons.DELETE_OUTLINE, tooltip="Delete category",
                                  on_click=remove, visual_density=ft.VisualDensity.COMPACT),
                ], spacing=2))
            if not rows:
                rows.append(ft.Text("No categories yet.", color=self.c["muted"]))
            if message:
                rows.append(ft.Text(message, size=12, color=self.c["muted"]))
            body.controls = rows
            self.page.update()

        def add():
            try:
                db.create_category(uid, new_name.value or "")
                new_name.value = ""
                rebuild()
            except ValueError as e:
                rebuild(str(e))

        async def close():
            self.close_dialog()
            await self.render()

        new_name.on_submit = add
        rebuild()
        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text("Categories"),
            content=ft.Column([body, ft.Divider(height=8),
                               ft.Row([new_name, ft.FilledButton("Add", on_click=add)])],
                              tight=True, width=420),
            actions=[ft.TextButton("Done", on_click=close)],
        ))

    def category_bar(self, cats: list[dict], selected, on_pick, total: int,
                     uncategorized: Optional[int] = None, manage: bool = False) -> ft.Control:
        """Horizontally scrolling filter chips: All, each category, Uncategorized."""
        c = self.c

        def chip(label, n, value, icon=None):
            is_sel = selected == value
            return ft.Chip(
                label=ft.Text(f"{label}  {n}", size=13,
                              color=c["on_primary"] if is_sel else c["ink"]),
                leading=ft.Icon(icon, size=15, color=c["on_primary"] if is_sel else c["muted"]) if icon else None,
                selected=is_sel, show_checkmark=False, selected_color=c["primary"],
                bgcolor=c["surface"], border_side=ft.BorderSide(1, c["primary"] if is_sel else c["line"]),
                visual_density=ft.VisualDensity.COMPACT,
                on_click=self.act(on_pick, value),
            )

        chips = [chip("All", total, None)]
        chips += [chip(cat["name"], cat["n"], cat["id"], ft.Icons.FOLDER_OUTLINED) for cat in cats]
        if uncategorized:
            chips.append(chip("Uncategorized", uncategorized, "none", ft.Icons.FOLDER_OFF_OUTLINED))
        if manage:
            chips.append(ft.IconButton(ft.Icons.CREATE_NEW_FOLDER_OUTLINED, tooltip="Manage categories",
                                       icon_size=20, on_click=self.act(self.manage_categories_dialog)))
        return ft.Row(chips, spacing=6, scroll=ft.ScrollMode.AUTO)

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
                             ft.Icons.GPP_BAD, self.c["blocked"])
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

    async def ensure_fresh(self, link: dict) -> dict:
        """Re-scan a link that hasn't been checked recently (used by share pages)."""
        if link.get("admin_locked") or db.now() - link["checked_at"] < RESCAN_HOURS * 3600:
            return link
        result = await security.scan_url(link["url"])
        db.apply_scan(link["id"], result)
        return {**link, **(db.get_link(link["id"]) or {})}

    async def edit_link_dialog(self, link: dict):
        title = ft.TextField(label="Title", value=link["title"], max_length=MAX_TITLE)
        note = ft.TextField(label="Note", value=link["note"], multiline=True, min_lines=2,
                            max_lines=5, max_length=MAX_NOTE)
        vis = self.visibility_dropdown(link["visibility"])
        cat = self.category_dropdown(link.get("category_id"), width=260)

        async def save():
            if vis.value == "public" and link["status"] != security.SAFE:
                self.snack("Only links that passed the safety check can be made public.", error=True)
                return
            db.update_link(link["id"], title=(title.value or "").strip()[:MAX_TITLE],
                           note=(note.value or "").strip()[:MAX_NOTE], visibility=vis.value)
            db.set_link_category(link["id"], self.user["id"], self.dropdown_category(cat))
            self.close_dialog()
            self.snack("Saved")
            await self.render()

        self.page.show_dialog(ft.AlertDialog(
            title=ft.Text("Edit link"),
            content=ft.Column([title, note, cat, vis], tight=True, width=420),
            actions=[ft.TextButton("Cancel", on_click=self.close_dialog), ft.FilledButton("Save", on_click=save)],
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
                     ft.FilledButton("Send", icon=ft.Icons.SEND, on_click=send)],
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
                ft.Row([self.open_url_button(url, "Open share page")]),
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
                    link["title"], "", "private",
                    category_id=db.suggest_category(self.user["id"], link["domain"]))
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
                     ft.FilledButton("Report", icon=ft.Icons.FLAG_OUTLINED, on_click=submit)],
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
                       ft.FilledButton("Sign in", icon=ft.Icons.LOGIN, on_click=submit),
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
                       ft.FilledButton("Create account", icon=ft.Icons.PERSON_ADD, on_click=submit),
                       ft.TextButton("Already have an account? Sign in",
                                     on_click=self.act(self.go, "/login"))]),
        ]

    # ================================================================== pages
    def view_not_found(self) -> list[ft.Control]:
        return [self.empty("Page not found.", ft.Icons.SEARCH_OFF),
                ft.TextButton("Go home", on_click=self.act(self.go, "/"))]

    def view_home(self) -> list[ft.Control]:
        c = self.c

        def ribbon_row(key: str, label: str, text: str) -> ft.Control:
            return ft.Row([
                ft.Container(width=5, height=34, bgcolor=c["vis_" + key], border_radius=3),
                ft.Column([ft.Text(label, font_family=STRONG, color=c["ink"]),
                           ft.Text(text, size=13, color=c["muted"])], spacing=0, expand=True),
            ], spacing=12)

        def point(icon, title, text) -> ft.Control:
            return ft.Row([ft.Icon(icon, color=c["primary"], size=22),
                           ft.Column([ft.Text(title, font_family=STRONG, color=c["ink"]),
                                      ft.Text(text, color=c["muted"])], spacing=2, expand=True)],
                          vertical_alignment=ft.CrossAxisAlignment.START, spacing=12)

        return [
            ft.Container(height=12),
            ft.Text("Keep the websites\nyou want to come back to.", font_family=DISPLAY, size=46,
                    color=c["ink"]),
            ft.Text("Save links, decide who sees each one, and share them after a safety check.",
                    size=17, color=c["muted"]),
            ft.Row([ft.FilledButton("Create free account", icon=ft.Icons.PERSON_ADD,
                                    on_click=self.act(self.go, "/signup")),
                    ft.OutlinedButton("Sign in", on_click=self.act(self.go, "/login"))], wrap=True),
            ft.Container(height=6),
            self.card([
                ft.Text("Every saved link carries a ribbon", font_family=STRONG, size=16, color=c["ink"]),
                ribbon_row("private", "Only me", "Your private reading list."),
                ribbon_row("friends", "Friends", "Visible to people you've added."),
                ribbon_row("public", "Public", "Listed on your profile and in Explore."),
                ribbon_row("unlisted", "Anyone with the link", "Hidden, but shareable without an account."),
            ]),
            self.card([
                point(ft.Icons.SHIELD, "Checked before it's saved",
                      "Dangerous addresses are refused. Suspicious ones are labelled, and you confirm before opening."),
                point(ft.Icons.OPEN_IN_NEW, "Opens in your browser",
                      "Tap any link to open it in a new tab, with its safety result shown first if it needs one."),
                point(ft.Icons.BOLT, "Share without an account",
                      "Paste a link, get a share link, send it to anyone."),
                ft.Row([ft.OutlinedButton("Quick share", icon=ft.Icons.BOLT, on_click=self.act(self.go, "/quick")),
                        ft.TextButton("Browse public links", icon=ft.Icons.EXPLORE,
                                      on_click=self.act(self.go, "/explore"))], wrap=True),
            ]),
        ]

    def view_links(self) -> list[ft.Control]:
        uid = self.user["id"]
        c = self.c
        cats = db.list_categories(uid)
        if self.cat_filter not in (None, "none") and self.cat_filter not in {x["id"] for x in cats}:
            self.cat_filter = None      # category was deleted

        url = ft.TextField(label="Link", hint_text="Paste a web address and press Enter",
                           prefix_icon=ft.Icons.LINK, dense=True, autofocus=True, autocorrect=False,
                           keyboard_type=ft.KeyboardType.URL)
        category = self.category_dropdown(self.cat_filter if isinstance(self.cat_filter, int) else None)
        category.col = {"xs": 6, "md": 3}
        vis = self.visibility_dropdown("private", allow_unlisted=False)
        vis.width, vis.col = None, {"xs": 6, "md": 3}
        url.col = {"xs": 12, "md": 6}
        title = ft.TextField(label="Title (optional, fetched automatically)", dense=True,
                             max_length=MAX_TITLE, counter=None)
        note = ft.TextField(label="Note (optional)", dense=True, multiline=True, max_lines=3,
                            max_length=MAX_NOTE)
        details = ft.Column([title, note], spacing=6, visible=self.show_details)
        ring = ft.ProgressRing(width=18, height=18, stroke_width=2, visible=False)
        save_btn = ft.FilledButton("Save link", icon=ft.Icons.BOOKMARK_ADD)
        toggle = ft.TextButton("Hide title and note" if self.show_details else "Add title and note",
                               icon=ft.Icons.EXPAND_LESS if self.show_details else ft.Icons.EXPAND_MORE)

        def flip():
            self.show_details = details.visible = not details.visible
            toggle.content = "Hide title and note" if details.visible else "Add title and note"
            toggle.icon = ft.Icons.EXPAND_LESS if details.visible else ft.Icons.EXPAND_MORE
            self.page.update()

        toggle.on_click = flip
        search = ft.TextField(hint_text="Search", prefix_icon=ft.Icons.SEARCH, dense=True,
                              col={"xs": 12, "md": 5})
        results = ft.Column(spacing=0)

        def refresh_list():
            q = search.value or ""
            links = db.list_user_links(uid, q, self.cat_filter, limit=self.limit)
            empty = ("Nothing matches your search." if q else
                     "No links in this category yet." if self.cat_filter is not None else
                     "No links yet. Paste one above to get started.")
            results.controls = [self.link_list(links, empty,
                                               total=db.count_user_links(uid, q, self.cat_filter))]

        async def save():
            if not (url.value or "").strip():
                return
            if not ratelimit.allow("add_link", str(uid)):
                self.snack("You're adding links too fast. Try again later.", error=True)
                return
            result = await self.run_scan(url.value, save_btn, ring, "saved")
            if not result:
                return
            if db.find_duplicate(uid, result.url, result.final_url):
                self.snack("You've already saved this link.")
                return
            visibility = vis.value
            if visibility == "public" and result.status != security.SAFE:
                visibility = "private"
                self.snack("Saved as private - only links that pass every check can be public.")
            cat_id = self.dropdown_category(category)
            auto = cat_id is None and db.suggest_category(uid, result.domain)
            db.add_link(uid, result, (title.value or "").strip()[:MAX_TITLE] or result.title,
                        (note.value or "").strip()[:MAX_NOTE], visibility, category_id=cat_id or auto or None)
            url.value = title.value = note.value = ""
            if auto:
                self.snack(f"Saved to {db.get_category_name(auto)} (where your other "
                           f"{security.display_domain(result.domain)} links are)")
            else:
                self.snack("Link saved")
            await self.render()

        save_btn.on_click = save
        url.on_submit = save
        search.on_change = lambda: (refresh_list(), self.page.update())
        refresh_list()

        async def pick(value):
            self.cat_filter = value
            self.limit = PAGE_SIZE
            await self.render()

        all_count = sum(x["n"] for x in cats) + db.uncategorized_count(uid)
        return [
            ft.ResponsiveRow([
                ft.Container(self.heading("My links"), col={"xs": 12, "md": 7}),
                search,
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, run_spacing=6),
            self.card([
                ft.ResponsiveRow([url, category, vis], spacing=8, run_spacing=8),
                details,
                ft.Row([save_btn, ring, toggle], spacing=8, wrap=True,
                       vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ]),
            self.category_bar(cats, self.cat_filter, pick, all_count,
                              uncategorized=db.uncategorized_count(uid), manage=True),
            results,
        ]

    def view_shared(self) -> list[ft.Control]:
        links = db.list_shared_with(self.user["id"])
        db.mark_shares_seen(self.user["id"])
        if not links:
            return [self.heading("Shared with me", "Links your friends sent you."),
                    self.empty("Nothing shared with you yet.", ft.Icons.INBOX)]
        rows = [self.link_card(l, sender=l["sender_name"], in_inbox=True, show_owner=False,
                               last=i == len(links) - 1) for i, l in enumerate(links[: self.limit])]
        return [self.heading("Shared with me", "Links your friends sent you."),
                ft.Container(ft.Column(rows, spacing=0), bgcolor=self.c["surface"], border_radius=12,
                             border=ft.Border.all(1, self.c["line"]), clip_behavior=ft.ClipBehavior.ANTI_ALIAS)]

    def view_explore(self) -> list[ft.Control]:
        search = ft.TextField(hint_text="Search public links", prefix_icon=ft.Icons.SEARCH, dense=True,
                              col={"xs": 12, "md": 5})
        results = ft.Column()

        def refresh():
            results.controls = [self.link_list(db.list_public_links(search.value or ""),
                                               "No public links yet.")]

        search.on_change = lambda: (refresh(), self.page.update())
        refresh()
        return [ft.ResponsiveRow([ft.Container(self.heading("Explore", "Links people have made public."),
                                               col={"xs": 12, "md": 7}), search],
                                 vertical_alignment=ft.CrossAxisAlignment.CENTER, run_spacing=6),
                results]

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
               self.card([ft.Row([name, ft.FilledButton("Send request", on_click=send)])])]
        if incoming:
            out.append(ft.Text("Requests", font_family=STRONG))
            out += [person(u, ft.Row([
                ft.IconButton(ft.Icons.CHECK, tooltip="Accept", on_click=self.act(accept, u["id"])),
                ft.IconButton(ft.Icons.CLOSE, tooltip="Decline", on_click=self.act(remove, u["id"], "Decline", False)),
            ], tight=True)) for u in incoming]
        out.append(ft.Text(f"Your friends ({len(friends)})", font_family=STRONG))
        out += [person(u, ft.IconButton(ft.Icons.PERSON_REMOVE, tooltip="Remove friend",
                                        on_click=self.act(remove, u["id"], "Remove friend")))
                for u in friends] or [self.empty("No friends yet. Send a request above.", ft.Icons.GROUP)]
        if outgoing:
            out.append(ft.Text("Waiting for reply", font_family=STRONG))
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
        see_friends = friends or is_self
        if self.profile_filter[0] != owner["id"]:
            self.profile_filter = (owner["id"], None)
        selected = self.profile_filter[1]
        cats = db.list_categories(owner["id"], visible_only=True, include_friends=see_friends)
        links = db.list_profile_links(owner["id"], include_friends=see_friends, category=selected)
        total = len(db.list_profile_links(owner["id"], include_friends=see_friends))

        async def pick(value):
            self.profile_filter = (owner["id"], value)
            await self.render()

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
            ft.Row([ft.Icon(ft.Icons.ACCOUNT_CIRCLE, size=48, color=self.c["ribbon"]),
                    ft.Column([ft.Text(f"@{owner['username']}", size=30, font_family=DISPLAY, color=self.c["ink"]),
                               ft.Text(sub, color=ft.Colors.ON_SURFACE_VARIANT)], spacing=0, expand=True)]
                   + ([action] if action else []), wrap=True),
            self.category_bar(cats, selected, pick, total) if cats else ft.Container(),
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
                bgcolor=self.c["caution_bg"], border_radius=12, padding=14,
                content=ft.Row([ft.Icon(ft.Icons.WARNING_AMBER, color=self.c["caution"]),
                                ft.Text("Our safety check found something unusual about this link. "
                                        "Tap 'Caution' below to see why.", expand=True,
                                        color=self.c["caution"])])))
        out.append(self.link_list([share], "", show_owner=False))
        out.append(ft.Row([self.open_browser_button(share), self.copy_button(share["final_url"])]))
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
        btn = ft.FilledButton("Check & create share link", icon=ft.Icons.BOLT)
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
                ft.Row([ft.Icon(ft.Icons.CHECK_CIRCLE, color=self.c["safe"]),
                        ft.Text("Your share link is ready", font_family=STRONG)]),
                ft.Row([ft.TextField(value=share, read_only=True, expand=True, dense=True),
                        self.copy_button(share)]),
                ft.Row([self.open_url_button(share, "Open share page")], wrap=True),
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
                ft.Text(l["title"] or l["domain"], font_family=STRONG),
                ft.Row([ft.Text(l["final_url"], size=12, selectable=True, expand=True,
                                color=self.c["primary"]),
                        self.copy_button(l["final_url"]),
                        ft.IconButton(ft.Icons.OPEN_IN_NEW, tooltip="Open (shows the warning first)",
                                      icon_size=18, visual_density=ft.VisualDensity.COMPACT,
                                      on_click=lambda l=l: self.warn_before_open(
                                          {**l, "reasons": [f"Reported {l['report_count']} time(s)."]
                                           + l["reasons"]}))]),
                ft.Text(f"Owner: {'@' + l['owner_name'] if l['owner_name'] else 'anonymous'}", size=12),
                ft.Text(f"{l['report_count']} report(s), {'hidden' if l['hidden'] else 'visible'}, "
                        f"status {l['status']}", size=12, color=self.c["muted"]),
                *[ft.Text(f"“{r}”", size=12, italic=True) for r in l["report_reasons"]],
                ft.Row([ft.TextButton("Block link", icon=ft.Icons.BLOCK, on_click=self.act(block, l)),
                        ft.TextButton("Block domain", icon=ft.Icons.BLOCK, on_click=self.act(block, l, True)),
                        ft.TextButton("Restore", icon=ft.Icons.RESTORE, on_click=self.act(restore, l))], wrap=True),
            ]))
        return [self.heading("Moderation", "Reported and blocked links."),
                *(rows or [self.empty("Nothing reported.", ft.Icons.VERIFIED_USER)])]
