"""Virtualised, keyboard-driven table.

Rows are produced on demand by a callback, so the table never materialises
more than the visible lines. A packet list of a million frames costs the same
to display as one of ten.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable
from dataclasses import dataclass

from rich.segment import Segment
from rich.style import Style
from rich.text import Text
from textual import events
from textual.binding import Binding
from textual.message import Message
from textual.strip import Strip
from textual.widget import Widget

from trace_zero.ui import theme

Cell = str | Text


@dataclass(frozen=True)
class Col:
    label: str
    width: int = 0  # 0 = flexible
    align: str = "left"
    min_width: int = 6


class VirtualTable(Widget, can_focus=True):
    DEFAULT_CSS = """
    VirtualTable { height: 1fr; width: 1fr; }
    """

    BINDINGS = [
        Binding("up", "cursor(-1)", "Up", show=False),
        Binding("down", "cursor(1)", "Down", show=False),
        Binding("pageup", "page(-1)", "Page up", show=False),
        Binding("pagedown", "page(1)", "Page down", show=False),
        Binding("ctrl+home", "edge(0)", "First row", show=False),
        Binding("ctrl+end", "edge(1)", "Last row", show=False),
        Binding("enter", "activate", "Open", show=False),
    ]

    class Highlighted(Message):
        def __init__(self, table: VirtualTable, index: int, key: Hashable | None) -> None:
            super().__init__()
            self.table = table
            self.index = index
            self.key = key

        @property
        def control(self) -> VirtualTable:
            return self.table

    class Activated(Message):
        def __init__(self, table: VirtualTable, index: int, key: Hashable | None) -> None:
            super().__init__()
            self.table = table
            self.index = index
            self.key = key

        @property
        def control(self) -> VirtualTable:
            return self.table

    def __init__(self, columns: list[Col] | None = None, *, empty_text: str = "no data", id: str | None = None, classes: str | None = None) -> None:
        super().__init__(id=id, classes=classes)
        self.columns: list[Col] = columns or []
        self.count = 0
        self.row_fn: Callable[[int], list[Cell]] = lambda i: []
        self.key_fn: Callable[[int], Hashable] = lambda i: i
        self.style_fn: Callable[[int], Style | None] | None = None
        self.cursor = 0
        self.top = 0
        self.empty_text = empty_text
        self.sort_label: str | None = None
        self._last_emitted: tuple[int, Hashable | None] | None = None

    # -- data --------------------------------------------------------------------
    def set_data(
        self,
        count: int,
        row_fn: Callable[[int], list[Cell]],
        key_fn: Callable[[int], Hashable] | None = None,
        *,
        columns: list[Col] | None = None,
        keep_key: Hashable | None = None,
        locate: Callable[[Hashable], int | None] | None = None,
        follow_end: bool = False,
        style_fn: Callable[[int], Style | None] | None = None,
        empty_text: str | None = None,
        notify: bool = True,
    ) -> None:
        if columns is not None:
            self.columns = columns
        if empty_text is not None:
            self.empty_text = empty_text
        self.count = count
        self.row_fn = row_fn
        self.key_fn = key_fn or (lambda i: i)
        self.style_fn = style_fn
        target = None
        if follow_end and count:
            target = count - 1
        elif keep_key is not None and count:
            if locate is not None:
                target = locate(keep_key)
            elif count <= 20000:
                target = next((i for i in range(count) if self.key_fn(i) == keep_key), None)
        if target is None:
            target = min(self.cursor, max(0, count - 1))
        self._set_cursor(target, notify=notify)
        self.refresh()

    def current_key(self) -> Hashable | None:
        if not self.count:
            return None
        return self.key_fn(self.cursor)

    def at_end(self) -> bool:
        return self.count == 0 or self.cursor >= self.count - 1

    # -- navigation ----------------------------------------------------------------
    @property
    def body_height(self) -> int:
        return max(1, self.size.height - 1)

    def _set_cursor(self, index: int, notify: bool = True) -> None:
        index = max(0, min(index, self.count - 1)) if self.count else 0
        self.cursor = index
        h = self.body_height
        if index < self.top:
            self.top = index
        elif index >= self.top + h:
            self.top = index - h + 1
        self.top = max(0, min(self.top, max(0, self.count - h)))
        self.refresh()
        if notify:
            key = self.current_key()
            marker = (index, key)
            if marker != self._last_emitted:
                self._last_emitted = marker
                self.post_message(self.Highlighted(self, index, key))

    def move_to(self, index: int) -> None:
        self._set_cursor(index)

    def action_cursor(self, delta: int) -> None:
        self._set_cursor(self.cursor + delta)

    def action_page(self, direction: int) -> None:
        self._set_cursor(self.cursor + direction * max(1, self.body_height - 1))

    def action_edge(self, end: int) -> None:
        self._set_cursor(self.count - 1 if end else 0)

    def action_activate(self) -> None:
        if self.count:
            self.post_message(self.Activated(self, self.cursor, self.current_key()))

    def on_resize(self, event: events.Resize) -> None:
        self._set_cursor(self.cursor, notify=False)

    def on_mouse_scroll_down(self, event: events.MouseScrollDown) -> None:
        self.top = max(0, min(self.top + 3, max(0, self.count - self.body_height)))
        event.stop()
        self.refresh()

    def on_mouse_scroll_up(self, event: events.MouseScrollUp) -> None:
        self.top = max(0, self.top - 3)
        event.stop()
        self.refresh()

    def on_click(self, event: events.Click) -> None:
        row = event.y - 1 + self.top
        if event.y >= 1 and 0 <= row < self.count:
            self.focus()
            if event.chain >= 2 and row == self.cursor:
                self.action_activate()
            else:
                self._set_cursor(row)

    # -- rendering -------------------------------------------------------------------
    def _widths(self, total: int) -> list[int]:
        cols = self.columns
        if not cols:
            return []
        fixed = sum(c.width for c in cols if c.width)
        gaps = len(cols) - 1
        flex = [c for c in cols if not c.width]
        remaining = total - fixed - gaps
        widths = []
        for c in cols:
            if c.width:
                widths.append(c.width)
            else:
                widths.append(max(c.min_width, remaining // max(1, len(flex))))
        return widths

    def _line(self, cells: list[Cell], widths: list[int], base: Style) -> Text:
        line = Text(style=base, no_wrap=True, end="")
        for i, (col, w) in enumerate(zip(self.columns, widths)):
            if i:
                line.append(" ")
            cell = cells[i] if i < len(cells) else ""
            t = cell.copy() if isinstance(cell, Text) else Text(str(cell))
            t.no_wrap = True
            t.truncate(w, overflow="ellipsis")
            pad = w - t.cell_len
            if pad > 0:
                if col.align == "right":
                    t = Text(" " * pad) + t
                else:
                    t.append(" " * pad)
            line.append_text(t)
        return line

    def render_line(self, y: int) -> Strip:
        width = self.size.width
        base = self.rich_style
        console = self.app.console
        widths = self._widths(width)
        if y == 0:
            labels: list[Cell] = []
            for c in self.columns:
                labels.append(Text(c.label, style=theme.S_HEAD))
            text = self._line(labels, widths, base)
            text.rstrip()
            if self.count:
                # Row position, only when it fits without hiding a column label.
                pos = Text(f" {self.cursor + 1:,}/{self.count:,}", style=theme.S_FAINT)
                if text.cell_len + pos.cell_len < width:
                    text.pad_right(width - text.cell_len - pos.cell_len)
                    text.append_text(pos)
            return Strip(list(text.render(console)), ).adjust_cell_length(width, base)
        row = self.top + y - 1
        if row >= self.count:
            if self.count == 0 and y == 1:
                text = Text(" " + self.empty_text, style=theme.S_DIM, no_wrap=True)
                text.truncate(width)
                return Strip(list(text.render(console))).adjust_cell_length(width, base)
            return Strip([Segment(" " * width, base)], width)
        try:
            cells = self.row_fn(row)
        except Exception:  # noqa: BLE001 - a bad row must not break rendering
            cells = [Text("<row unavailable>", style=theme.S_RED)]
        row_style = base
        if self.style_fn is not None:
            extra = self.style_fn(row)
            if extra is not None:
                row_style = base + extra
        text = self._line(cells, widths, row_style)
        if text.cell_len < width:
            text.append(" " * (width - text.cell_len))
        if row == self.cursor:
            bg = theme.SEL_BG if self.has_focus else theme.SEL_BG_BLUR
            text.stylize(Style(bgcolor=bg))
        return Strip(list(text.render(console))).adjust_cell_length(width, base).crop(0, width)

    def on_focus(self) -> None:
        self.refresh()

    def on_blur(self) -> None:
        self.refresh()
