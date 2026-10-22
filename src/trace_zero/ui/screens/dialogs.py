"""Modal dialogs."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import DirectoryTree, Input, Static, TextArea

from trace_zero import PRODUCT, TAGLINE
from trace_zero.analysis.filters import FilterError, compile_filter
from trace_zero.config import Limits
from trace_zero.models import fmt_ts
from trace_zero.parsing.reader import CAPTURE_SUFFIXES, CaptureError, validate_capture_path
from trace_zero.sanitize import clean
from trace_zero.storage import Investigation
from trace_zero.ui import theme
from trace_zero.ui.keymap import FILTER_HELP, KEYMAP
from trace_zero.ui.widgets.table import Col, VirtualTable

DIALOG_CSS = """
{name} { align: center middle; background: #000000 55%; }
{name} > #frame {
    width: 84; max-width: 96%; height: auto; max-height: 92%;
    border: solid #21767b; border-title-color: #3cc4cc; border-title-style: bold;
    background: #0e1112; padding: 0 1;
}
{name} .hint { color: #6e777b; height: auto; }
{name} .error { color: #c55a56; height: auto; }
{name} .ok { color: #79a881; height: auto; }
{name} Input { border: tall #262c2f; background: #0a0c0d; margin: 1 0 0 0; }
{name} Input:focus { border: tall #21767b; }
"""


def _css(name: str) -> str:
    return DIALOG_CSS.replace("{name}", name)


class HelpScreen(ModalScreen[None]):
    DEFAULT_CSS = _css("HelpScreen") + """
    HelpScreen > #frame { width: 100; height: 90%; }
    HelpScreen #help-body { height: 1fr; }
    """
    BINDINGS = [
        Binding("escape,q,question_mark,f1", "dismiss", "close"),
        Binding("up", "scroll(-1)", show=False),
        Binding("down", "scroll(1)", show=False),
    ]

    def __init__(self, context: str = "") -> None:
        super().__init__()
        self.context = context

    def compose(self) -> ComposeResult:
        head = Text()
        head.append(PRODUCT, theme.S_CYAN_B)
        head.append(f"  {TAGLINE}", theme.S_FAINT)
        if self.context:
            head.append(f"\ncurrent view: {self.context}", theme.S_DIM)
        parts: list = [head]

        def grid(title: str, rows: list[tuple[str, str]]) -> None:
            parts.append(Text(f"\n{title}", style=theme.S_CYAN))
            table = Table.grid(padding=(0, 2))
            table.add_column(width=26, no_wrap=True)
            table.add_column(ratio=1)
            for key, desc in rows:
                table.add_row(Text(f"  {key}", style=theme.S_TEXT), Text(desc, style=theme.S_DIM))
            parts.append(table)

        for section, keys in KEYMAP:
            grid(section, keys)
        grid("FILTER SYNTAX  (press /)", FILTER_HELP)
        grid(
            "READING THE MAP",
            [
                ("\u25cf  \u25cb  \u25c9", "observed in window / seen earlier, not in window / selected"),
                ("\u25b8 \u25c2 \u25b4 \u25be", "direction packets were observed travelling"),
                ("\u00b7\u00b7\u00b7  \u2500\u2500", "link observed / link of the selected host"),
                ("", "Everything shown is a historical observation from the capture, not live state."),
            ],
        )
        with Vertical(id="frame") as frame:
            frame.border_title = "KEYBOARD REFERENCE"
            with VerticalScroll(id="help-body"):
                yield Static(Group(*parts))
            yield Static("esc / q / ? close  \u2502  up/down scroll", classes="hint")

    def action_scroll(self, delta: int) -> None:
        self.query_one("#help-body", VerticalScroll).scroll_relative(y=delta)


class CaptureTree(DirectoryTree):
    def filter_paths(self, paths: Iterable[Path]) -> Iterable[Path]:
        out = []
        for p in paths:
            if p.name.startswith("."):
                continue
            try:
                if p.is_dir() or p.suffix.lower() in CAPTURE_SUFFIXES:
                    out.append(p)
            except OSError:
                continue
        return out


class OpenCaptureScreen(ModalScreen[str | None]):
    DEFAULT_CSS = _css("OpenCaptureScreen") + """
    OpenCaptureScreen > #frame { height: 80%; }
    OpenCaptureScreen CaptureTree { height: 1fr; border: solid #262c2f; background: #0a0c0d; margin-top: 1; }
    OpenCaptureScreen CaptureTree:focus { border: solid #21767b; }
    """
    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(self, start: Path, limits: Limits) -> None:
        super().__init__()
        self.start = start
        self.limits = limits

    def compose(self) -> ComposeResult:
        with Vertical(id="frame") as frame:
            frame.border_title = "OPEN CAPTURE"
            yield Static("Path to a .pcap / .pcapng file. Files are opened read-only.", classes="hint")
            yield Input(placeholder="/path/to/capture.pcapng", id="path")
            yield Static("", id="msg", classes="error", markup=False)
            yield CaptureTree(self.start, id="tree")
            yield Static("enter open  │  tab switch input/tree  │  esc cancel", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#path", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _try(self, raw: str) -> None:
        msg = self.query_one("#msg", Static)
        candidate = Path(raw.strip()).expanduser() if raw.strip() else None
        if candidate is not None and candidate.is_dir():
            self.query_one("#tree", CaptureTree).path = candidate
            msg.update("")
            return
        try:
            path, _fmt = validate_capture_path(raw, self.limits)
        except CaptureError as exc:
            msg.update(clean(str(exc)))
            return
        self.dismiss(str(path))

    @on(Input.Submitted, "#path")
    def submitted(self, event: Input.Submitted) -> None:
        self._try(event.value)

    @on(DirectoryTree.FileSelected)
    def file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self.query_one("#path", Input).value = str(event.path)
        self._try(str(event.path))


class FilterScreen(ModalScreen[str | None]):
    """Filter entry with history (up/down), saved filters (tab to the list) and ctrl+s to save."""

    DEFAULT_CSS = _css("FilterScreen") + """
    FilterScreen #saved { height: auto; max-height: 8; margin-top: 1; }
    """
    BINDINGS = [
        Binding("escape", "cancel", "cancel"),
        Binding("up", "history(1)", "older", show=False),
        Binding("down", "history(-1)", "newer", show=False),
        Binding("ctrl+s", "save", "save filter"),
        Binding("delete", "delete_saved", "delete saved", show=False),
    ]

    def __init__(
        self,
        initial: str,
        t0: float,
        history: Iterable[str] = (),
        saved: Iterable[tuple[str, str]] = (),
        on_save=None,
        on_delete=None,
    ) -> None:
        """``on_save(name, expression)`` returns an error message or None; ``on_delete(name)``."""
        super().__init__()
        self.initial = initial
        self.t0 = t0
        self.history = [h for h in history if h]
        self.saved = list(saved)
        self.on_save = on_save
        self.on_delete = on_delete
        self.history_pos = -1
        self.draft = initial

    def compose(self) -> ComposeResult:
        help_text = Text()
        for key, desc in FILTER_HELP:
            help_text.append(f"{key:<26}", theme.S_TEXT)
            help_text.append(f"{desc}\n", theme.S_DIM)
        with Vertical(id="frame") as frame:
            frame.border_title = "SEARCH / FILTER"
            yield Input(value=self.initial, placeholder="e.g. host:10.0.0.5 proto:tcp flags:S", id="expr")
            yield Static("", id="msg", classes="hint", markup=False)
            yield VirtualTable([Col("SAVED FILTER", 22), Col("EXPRESSION")], id="saved")
            yield Static(help_text, classes="hint")
            yield Static(
                "enter apply (empty clears)  \u2502  up/down history  \u2502  ctrl+s save  \u2502  tab saved list (del removes)  \u2502  esc cancel",
                classes="hint",
            )

    def on_mount(self) -> None:
        self._fill_saved()
        self.query_one("#expr", Input).focus()
        self._validate(self.initial)

    def _fill_saved(self) -> None:
        table = self.query_one("#saved", VirtualTable)
        saved = self.saved
        table.set_data(len(saved), lambda i: [Text(saved[i][0], style=theme.S_CYAN), saved[i][1]], lambda i: saved[i][0], notify=False)
        table.display = bool(saved)
        table.styles.height = min(len(saved), 7) + 1

    def _validate(self, text: str) -> bool:
        msg = self.query_one("#msg", Static)
        try:
            flt = compile_filter(text, self.t0)
        except FilterError as exc:
            msg.set_classes("error")
            msg.update(clean(f"\u2715 {exc}"))
            return False
        msg.set_classes("ok")
        msg.update("\u2713 valid" if flt else "empty expression clears the filter")
        return True

    def _set_text(self, text: str) -> None:
        expr = self.query_one("#expr", Input)
        expr.value = text
        expr.cursor_position = len(text)

    @on(Input.Changed, "#expr")
    def changed(self, event: Input.Changed) -> None:
        if self.history_pos == -1:
            self.draft = event.value
        self._validate(event.value)

    @on(Input.Submitted, "#expr")
    def submitted(self, event: Input.Submitted) -> None:
        if self._validate(event.value):
            self.dismiss(event.value.strip())

    @on(VirtualTable.Activated, "#saved")
    def saved_chosen(self, event: VirtualTable.Activated) -> None:
        expression = dict(self.saved).get(event.key)
        if expression is not None and self._validate(expression):
            self.dismiss(expression)

    def action_history(self, step: int) -> None:
        if not isinstance(self.focused, Input) or not self.history:
            return
        pos = max(-1, min(len(self.history) - 1, self.history_pos + step))
        if pos == self.history_pos:
            return
        self.history_pos = pos
        self._set_text(self.draft if pos == -1 else self.history[pos])

    def action_save(self) -> None:
        text = self.query_one("#expr", Input).value.strip()
        if not text or not self._validate(text):
            self.app.notify("enter a valid, non-empty filter to save", severity="warning")
            return
        if self.on_save is None:
            return

        def named(name: str | None) -> None:
            if not name:
                return
            error = self.on_save(name, text)
            if error:
                self.app.notify(error, severity="error")
                return
            self.saved = sorted({**dict(self.saved), name.strip(): text}.items())
            self._fill_saved()
            self.app.notify(f"saved filter '{name.strip()}'")

        self.app.push_screen(PromptScreen("SAVE FILTER", f"name for: {text}", max_length=60), named)

    def action_delete_saved(self) -> None:
        table = self.query_one("#saved", VirtualTable)
        if self.focused is not table or table.current_key() is None:
            return
        name = str(table.current_key())
        if self.on_delete is not None:
            self.on_delete(name)
        self.saved = [(n, e) for n, e in self.saved if n != name]
        self._fill_saved()
        self.query_one("#expr", Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)


class ChoiceScreen(ModalScreen[str | None]):
    """Pick one option with up/down + enter, or its hotkey."""

    DEFAULT_CSS = _css("ChoiceScreen") + """
    ChoiceScreen > #frame { width: 70; }
    ChoiceScreen VirtualTable { height: auto; max-height: 14; margin-top: 1; }
    """
    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(self, title: str, label: str, options: list[tuple[str, str, str]]) -> None:
        """options: (value, hotkey, description)."""
        super().__init__()
        self.title_text = title
        self.label = label
        self.options = options

    def compose(self) -> ComposeResult:
        with Vertical(id="frame") as frame:
            frame.border_title = self.title_text
            yield Static(self.label, classes="hint", markup=False)
            yield VirtualTable([Col("KEY", 5), Col("CHOICE")], id="choices")
            yield Static("enter / hotkey choose  \u2502  esc cancel", classes="hint")

    def on_mount(self) -> None:
        table = self.query_one(VirtualTable)
        opts = self.options
        table.set_data(len(opts), lambda i: [Text(opts[i][1], style=theme.S_CYAN), opts[i][2]], lambda i: opts[i][0], notify=False)
        table.styles.height = len(opts) + 1
        table.focus()

    def on_key(self, event) -> None:
        for value, hotkey, _desc in self.options:
            if event.character and event.character == hotkey:
                event.stop()
                self.dismiss(value)
                return

    @on(VirtualTable.Activated)
    def activated(self, event: VirtualTable.Activated) -> None:
        self.dismiss(event.key)

    def action_cancel(self) -> None:
        self.dismiss(None)


class PromptScreen(ModalScreen[str | None]):
    DEFAULT_CSS = _css("PromptScreen")
    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(self, title: str, label: str, initial: str = "", max_length: int = 0, allow_empty: bool = False) -> None:
        super().__init__()
        self.title_text = title
        self.label = label
        self.initial = initial
        self.max_length = max_length
        self.allow_empty = allow_empty

    def compose(self) -> ComposeResult:
        with Vertical(id="frame") as frame:
            frame.border_title = self.title_text
            yield Static(self.label, classes="hint", markup=False)
            yield Input(value=self.initial, id="value", max_length=self.max_length)
            yield Static("enter confirm  │  esc cancel", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#value", Input).focus()

    @on(Input.Submitted, "#value")
    def submitted(self, event: Input.Submitted) -> None:
        if event.value.strip() or self.allow_empty:
            self.dismiss(event.value.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class NoteScreen(ModalScreen[str | None]):
    DEFAULT_CSS = _css("NoteScreen") + """
    NoteScreen TextArea { height: 10; border: tall #262c2f; background: #0a0c0d; margin-top: 1; }
    NoteScreen TextArea:focus { border: tall #21767b; }
    """
    BINDINGS = [Binding("escape", "cancel", "cancel"), Binding("ctrl+s", "save", "save", priority=True)]

    def __init__(self, target: str) -> None:
        super().__init__()
        self.target = target

    def compose(self) -> ComposeResult:
        with Vertical(id="frame") as frame:
            frame.border_title = "ANALYST NOTE"
            yield Static(f"About: {clean(self.target, 120)}", classes="hint", markup=False)
            yield Static("Notes are recorded as analyst interpretation, separate from capture data.", classes="hint")
            yield TextArea(id="body", soft_wrap=True)
            yield Static("", id="msg", classes="error", markup=False)
            yield Static("ctrl+s save  │  esc cancel", classes="hint")

    def on_mount(self) -> None:
        self.query_one("#body", TextArea).focus()

    def action_save(self) -> None:
        body = self.query_one("#body", TextArea).text.strip()
        if not body:
            self.query_one("#msg", Static).update("note is empty")
            return
        self.dismiss(body)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ConfirmScreen(ModalScreen[bool]):
    DEFAULT_CSS = _css("ConfirmScreen") + "ConfirmScreen > #frame { width: 60; }"
    BINDINGS = [Binding("y,enter", "answer(True)", "yes"), Binding("n,escape", "answer(False)", "no")]

    def __init__(self, question: str) -> None:
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical(id="frame") as frame:
            frame.border_title = "CONFIRM"
            yield Static(clean(self.question, 300), markup=False)
            yield Static("y / enter confirm  │  n / esc cancel", classes="hint")

    def action_answer(self, value: bool) -> None:
        self.dismiss(value)


class InvestigationsScreen(ModalScreen[tuple[str, int | None] | None]):
    DEFAULT_CSS = _css("InvestigationsScreen") + """
    InvestigationsScreen > #frame { height: 70%; }
    InvestigationsScreen VirtualTable { height: 1fr; margin-top: 1; }
    """
    BINDINGS = [
        Binding("escape,q", "cancel", "close"),
        Binding("n", "new", "new"),
        Binding("r", "rename", "rename"),
    ]

    def __init__(self, items: list[Investigation], counts: dict[int, int], current: int) -> None:
        super().__init__()
        self.items = items
        self.counts = counts
        self.current = current

    def compose(self) -> ComposeResult:
        with Vertical(id="frame") as frame:
            frame.border_title = "INVESTIGATIONS"
            yield VirtualTable(
                [Col("", 2), Col("NAME"), Col("CAPTURES", 9, "right"), Col("UPDATED (UTC)", 20)],
                id="inv-table",
            )
            yield Static("enter switch  │  n new  │  r rename  │  esc close", classes="hint")

    def on_mount(self) -> None:
        table = self.query_one(VirtualTable)

        def row(i: int) -> list:
            inv = self.items[i]
            mark = Text("◉", style=theme.S_CYAN) if inv.id == self.current else ""
            return [mark, clean(inv.name), str(self.counts.get(inv.id, 0)), fmt_ts(inv.updated_at, True)[:19]]

        table.set_data(len(self.items), row, lambda i: self.items[i].id, keep_key=self.current, notify=False)
        table.focus()

    @on(VirtualTable.Activated)
    def activated(self, event: VirtualTable.Activated) -> None:
        self.dismiss(("switch", event.key))

    def action_new(self) -> None:
        self.dismiss(("new", None))

    def action_rename(self) -> None:
        self.dismiss(("rename", self.query_one(VirtualTable).current_key()))

    def action_cancel(self) -> None:
        self.dismiss(None)
