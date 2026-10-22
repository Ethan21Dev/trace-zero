"""TRACE//ZERO palette. Colour is used sparingly: most of the screen stays dark."""

from __future__ import annotations

from rich.style import Style
from textual.theme import Theme

BG = "#0a0c0d"
SURFACE = "#0e1112"
PANEL = "#111516"
TEXT = "#c3cacd"
DIM = "#6e777b"
FAINT = "#3b4245"
BORDER = "#262c2f"
CYAN = "#3cc4cc"
CYAN_DIM = "#21767b"
GREEN = "#79a881"
AMBER = "#d29d44"
RED = "#c55a56"
SEL_BG = "#10282a"
SEL_BG_BLUR = "#171c1e"

S_TEXT = Style(color=TEXT)
S_DIM = Style(color=DIM)
S_FAINT = Style(color=FAINT)
S_CYAN = Style(color=CYAN)
S_CYAN_B = Style(color=CYAN, bold=True)
S_CYAN_DIM = Style(color=CYAN_DIM)
S_GREEN = Style(color=GREEN)
S_AMBER = Style(color=AMBER)
S_RED = Style(color=RED)
S_LABEL = Style(color=DIM)
S_HEAD = Style(color=DIM, bold=True)

SEVERITY_STYLE = {"HIGH": S_RED, "MEDIUM": S_AMBER, "LOW": S_GREEN}

TRACE_ZERO_THEME = Theme(
    name="trace-zero",
    primary=CYAN,
    secondary=GREEN,
    accent=CYAN,
    warning=AMBER,
    error=RED,
    success=GREEN,
    foreground=TEXT,
    background=BG,
    surface=SURFACE,
    panel=PANEL,
    boost="#161b1d",
    dark=True,
    variables={
        "border": BORDER,
        "border-blurred": BORDER,
        "footer-key-foreground": CYAN,
        "input-selection-background": f"{CYAN_DIM} 60%",
        "block-cursor-background": SEL_BG,
        "block-cursor-foreground": TEXT,
        "block-cursor-text-style": "none",
        "scrollbar": FAINT,
        "scrollbar-hover": DIM,
        "scrollbar-active": CYAN_DIM,
        "scrollbar-background": BG,
        "scrollbar-background-hover": BG,
        "scrollbar-background-active": BG,
    },
)
