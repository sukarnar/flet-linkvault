"""
LinkVault colour system.

Concept: a personal library of saved sites. Calm, cool paper-and-ink neutrals; one
teal for actions; plum reserved for the bookmark ribbon (the brand mark). Each link card
carries a ribbon on its left edge whose colour says who can see it.
"""
import flet as ft

LIGHT = {
    "canvas":   "#EEF1F4",   # fog - page background
    "surface":  "#FFFFFF",   # cards, bars
    "raised":   "#F6F8FA",   # chips, fields
    "ink":      "#17202E",   # primary text
    "muted":    "#566172",   # secondary text
    "line":     "#D5DBE2",   # outlines
    "primary":  "#136F7A",   # harbour teal - actions, links
    "on_primary": "#FFFFFF",
    "primary_soft": "#D7ECEE",
    "ribbon":   "#9B3D7A",   # plum - brand + public links
    "safe":     "#1B7A4E", "safe_bg":    "#E2F3EA",
    "caution":  "#8F5A0B", "caution_bg": "#FBF0DC",
    "blocked":  "#B0322D", "blocked_bg": "#FBE5E3",
    # ribbon colour per visibility
    "vis_private":  "#8A95A5",
    "vis_friends":  "#136F7A",
    "vis_public":   "#9B3D7A",
    "vis_unlisted": "#C49A45",
}

DARK = {
    "canvas":   "#0F1822",
    "surface":  "#16212D",
    "raised":   "#1D2A38",
    "ink":      "#E5EAF0",
    "muted":    "#9AA6B5",
    "line":     "#2A3848",
    "primary":  "#62C6CE",
    "on_primary": "#062A2E",
    "primary_soft": "#173C43",
    "ribbon":   "#E08BC0",
    "safe":     "#63CF9A", "safe_bg":    "#14342A",
    "caution":  "#E6B657", "caution_bg": "#3A2E14",
    "blocked":  "#F2837C", "blocked_bg": "#3D1D1D",
    "vis_private":  "#6E7B8C",
    "vis_friends":  "#62C6CE",
    "vis_public":   "#E08BC0",
    "vis_unlisted": "#D9B461",
}

BODY = "Figtree"
STRONG = "Figtree SemiBold"
DISPLAY = "Bricolage"
FONTS = {
    BODY: "fonts/Figtree-Regular.ttf",
    STRONG: "fonts/Figtree-SemiBold.ttf",
    DISPLAY: "fonts/Bricolage-Display.ttf",
}


def make_theme(c: dict, dark: bool) -> ft.Theme:
    return ft.Theme(
        font_family=BODY,
        visual_density=ft.VisualDensity.COMPACT,   # denser lists, fields and buttons
        color_scheme=ft.ColorScheme(
            primary=c["primary"], on_primary=c["on_primary"],
            primary_container=c["primary_soft"], on_primary_container=c["ink"],
            secondary=c["ribbon"], on_secondary=c["on_primary"],
            secondary_container=c["primary_soft"], on_secondary_container=c["ink"],
            tertiary=c["ribbon"],
            error=c["blocked"], on_error="#FFFFFF" if not dark else "#2A0D0B",
            surface=c["surface"], on_surface=c["ink"], on_surface_variant=c["muted"],
            outline=c["muted"], outline_variant=c["line"],
            surface_container_lowest=c["surface"], surface_container_low=c["surface"],
            surface_container=c["raised"], surface_container_high=c["raised"],
            surface_container_highest=c["raised"],
            surface_tint="#00000000",   # no pink/teal tint on elevated surfaces
            inverse_surface=c["ink"], on_inverse_surface=c["canvas"], inverse_primary=c["primary"],
        ),
        scaffold_bgcolor=c["canvas"],
        navigation_bar_theme=ft.NavigationBarTheme(
            bgcolor=c["surface"], indicator_color=c["primary_soft"], elevation=0,
        ),
        dialog_theme=ft.DialogTheme(bgcolor=c["surface"]),
    )
