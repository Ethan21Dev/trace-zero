"""Header and status bar."""

from __future__ import annotations

from rich.text import Text
from textual.widget import Widget

from trace_zero import PRODUCT, TAGLINE
from trace_zero.sanitize import clean
from trace_zero.ui import theme

SEP = " │ "


class HeaderBar(Widget):
    DEFAULT_CSS = """
    HeaderBar { height: 1; background: #0e1112; color: #c3cacd; padding: 0 1; }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.investigation = "-"
        self.capture = "no capture"
        self.status = ("idle", "NO CAPTURE")

    def set_state(self, investigation: str | None = None, capture: str | None = None, status: tuple[str, str] | None = None) -> None:
        if investigation is not None:
            self.investigation = investigation
        if capture is not None:
            self.capture = capture
        if status is not None:
            self.status = status
        self.refresh()

    def render(self) -> Text:
        kind, label = self.status
        style = {
            "ok": theme.S_GREEN,
            "busy": theme.S_AMBER,
            "warn": theme.S_AMBER,
            "error": theme.S_RED,
        }.get(kind, theme.S_DIM)
        dot = {"ok": "●", "busy": "◌", "warn": "▲", "error": "✕"}.get(kind, "○")
        t = Text(no_wrap=True, overflow="ellipsis")
        t.append(PRODUCT, theme.S_CYAN_B)
        t.append(SEP, theme.S_FAINT)
        t.append("INV ", theme.S_DIM)
        t.append(clean(self.investigation, 60), theme.S_TEXT)
        t.append(SEP, theme.S_FAINT)
        t.append("CAP ", theme.S_DIM)
        t.append(clean(self.capture, 80), theme.S_TEXT)
        t.append(SEP, theme.S_FAINT)
        t.append(f"{dot} {label}", style)
        width = self.size.width - 2
        if t.cell_len + len(TAGLINE) + 3 <= width:
            t.append(" " * (width - t.cell_len - len(TAGLINE)))
            t.append(TAGLINE, theme.S_FAINT)
        return t


class StatusBar(Widget):
    DEFAULT_CSS = """
    StatusBar { height: 1; background: #0e1112; padding: 0 1; }
    StatusBar.two-line { height: 2; }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.keys: list[tuple[str, str]] = []
        self.filter_text = ""
        self.range_text = ""
        self.app_status = "READY"

    def set_state(self, keys: list[tuple[str, str]] | None = None, filter_text: str | None = None, range_text: str | None = None, app_status: str | None = None) -> None:
        if keys is not None:
            self.keys = keys
        if filter_text is not None:
            self.filter_text = filter_text
        if range_text is not None:
            self.range_text = range_text
        if app_status is not None:
            self.app_status = app_status
        self.set_class(self.size.width < 170, "two-line")
        self.refresh(layout=True)

    def on_resize(self) -> None:
        self.set_class(self.size.width < 170, "two-line")

    def _keys_text(self) -> Text:
        t = Text(no_wrap=True, overflow="ellipsis")
        for i, (key, desc) in enumerate(self.keys):
            if i:
                t.append("  ")
            t.append(key, theme.S_CYAN)
            t.append(f" {desc}", theme.S_DIM)
        return t

    def _state_text(self) -> Text:
        t = Text(no_wrap=True, overflow="ellipsis")
        t.append("FILTER ", theme.S_DIM)
        if self.filter_text:
            t.append(clean(self.filter_text, 80), theme.S_AMBER)
        else:
            t.append("none", theme.S_FAINT)
        t.append(SEP, theme.S_FAINT)
        t.append("RANGE ", theme.S_DIM)
        t.append(self.range_text or "-", theme.S_TEXT)
        t.append(SEP, theme.S_FAINT)
        t.append(self.app_status, theme.S_GREEN if self.app_status == "READY" else theme.S_AMBER)
        return t

    def render(self) -> Text:
        keys, state = self._keys_text(), self._state_text()
        width = self.size.width - 2
        if self.has_class("two-line"):
            keys.truncate(width, overflow="ellipsis")
            return Text.assemble(keys, "\n", state, no_wrap=True)
        room = max(0, width - state.cell_len - 2)
        keys.truncate(room, overflow="ellipsis")
        keys.append(" " * max(0, room - keys.cell_len + 2))
        keys.append_text(state)
        return keys
