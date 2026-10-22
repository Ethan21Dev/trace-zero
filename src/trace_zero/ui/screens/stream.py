"""Follow-stream view: reassembled conversation of one flow."""

from __future__ import annotations

from pathlib import Path

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static
from textual.worker import get_current_worker

from trace_zero.analysis.flows import STATE_HELP, Flow
from trace_zero.analysis.streams import Stream, printable_lines
from trace_zero.export.report import atomic_write_bytes, slug
from trace_zero.models import fmt_bytes, fmt_ts
from trace_zero.parsing.reader import CaptureError
from trace_zero.sanitize import clean, hexdump
from trace_zero.ui import theme
from trace_zero.ui.screens.dialogs import _css

MAX_LINES = 4000


class FollowStreamScreen(ModalScreen[str | None]):
    DEFAULT_CSS = _css("FollowStreamScreen") + """
    FollowStreamScreen > #frame { width: 96%; height: 94%; max-width: 100%; }
    FollowStreamScreen #stream-body { height: 1fr; }
    """
    BINDINGS = [
        Binding("escape,q", "close", "close"),
        Binding("x", "toggle_hex", "hex/text"),
        Binding("s", "save", "save bytes"),
        Binding("p", "packets", "show packets"),
        Binding("up", "scroll(-1)", show=False),
        Binding("down", "scroll(1)", show=False),
        Binding("pageup", "scroll(-20)", show=False),
        Binding("pagedown", "scroll(20)", show=False),
    ]

    def __init__(self, session, flow: Flow) -> None:
        super().__init__()
        self.session = session
        self.flow = flow
        self.stream: Stream | None = None
        self.error: str | None = None
        self.hex = False

    def compose(self) -> ComposeResult:
        with Vertical(id="frame") as frame:
            frame.border_title = f"FOLLOW {self.flow.proto} STREAM"
            with VerticalScroll(id="stream-body"):
                yield Static(Text("re-reading frames from the capture…", style=theme.S_DIM), id="stream")
            yield Static(
                "x hex/text  │  s save raw bytes  │  p show these packets  │  ↑↓ pgup pgdn scroll  │  esc close",
                classes="hint",
            )

    def on_mount(self) -> None:
        self.run_worker(self._load, thread=True, exclusive=True, group="stream")

    def _load(self) -> None:
        worker = get_current_worker()
        try:
            stream = self.session.follow(self.flow)
            error = None
        except CaptureError as exc:
            stream, error = None, str(exc)
        except OSError as exc:
            stream, error = None, f"cannot read capture: {exc}"
        if not worker.is_cancelled:
            self.app.call_from_thread(self._loaded, stream, error)

    def _loaded(self, stream: Stream | None, error: str | None) -> None:
        self.stream, self.error = stream, error
        self._redraw()

    def _redraw(self) -> None:
        self.query_one("#stream", Static).update(self.render_stream())

    def render_stream(self) -> Group:
        f = self.flow
        parts: list = []
        head = Text()
        head.append(f"{f.endpoint('a')}", theme.S_CYAN)
        head.append("  ⇄  ", theme.S_FAINT)
        head.append(f"{f.endpoint('b')}", theme.S_TEXT)
        head.append(f"   {f.state}", theme.S_AMBER if f.state in ("reset", "refused", "no reply") else theme.S_GREEN)
        head.append(f" — {STATE_HELP.get(f.state, '')}", theme.S_DIM)
        head.append(f"\n{fmt_ts(f.first, True)} → {fmt_ts(f.last, True)}  │  {f.packets:,} packets  │  {len(f.frames)} frames re-read on demand", theme.S_DIM)
        if not f.initiator_known:
            head.append("\ninitiator not proven by the capture: 'client' is the first sender observed", theme.S_AMBER)
        parts.append(head)
        if self.error:
            parts.append(Text(f"\n{clean(self.error, 300)}", style=theme.S_RED))
            return Group(*parts)
        s = self.stream
        if s is None:
            parts.append(Text("\nloading…", style=theme.S_DIM))
            return Group(*parts)
        stats = Text()
        stats.append(f"\nclient → server {fmt_bytes(len(s.data('a')))}   server → client {fmt_bytes(len(s.data('b')))}", theme.S_TEXT)
        parts.append(stats)
        for issue in s.issues():
            parts.append(Text(f"! {issue}", style=theme.S_AMBER))
        for title, rows in s.decoded:
            parts.append(Text(f"\n{clean(title, 200)}", style=theme.S_CYAN))
            grid = Table.grid(padding=(0, 2))
            grid.add_column(width=22, no_wrap=True, style=theme.S_LABEL)
            grid.add_column(ratio=1, overflow="fold")
            for k, v in rows[:60]:
                grid.add_row(Text("  " + clean(k, 60)), Text(clean(v, 400)))
            parts.append(grid)
        parts.append(Text("\nCONVERSATION  reassembled payload — untrusted, displayed inertly", style=theme.S_CYAN))
        if not s.chunks:
            parts.append(Text("  no payload bytes in this flow", style=theme.S_DIM))
        lines_out = 0
        groups: list[tuple[str, list]] = []
        for c in s.chunks:
            if groups and groups[-1][0] == c.direction and not c.note:
                groups[-1][1].append(c)
            else:
                groups.append((c.direction, [c]))
        for direction, chunks in groups:
            if lines_out >= MAX_LINES:
                parts.append(Text(f"… display limited to {MAX_LINES:,} lines; press s to save the full stream", style=theme.S_AMBER))
                break
            data = b"".join(c.data for c in chunks)
            who = f"client {f.endpoint('a')}" if direction == "a" else f"server {f.endpoint('b')}"
            style = theme.S_CYAN if direction == "a" else theme.S_TEXT
            arrow = "\u25b6" if direction == "a" else "\u25c0"
            hdr = Text(f"\n{arrow} {who}  #{chunks[0].frame}  {fmt_ts(chunks[0].ts)}  {len(data):,} B", style=theme.S_DIM)
            for c in chunks:
                if c.note:
                    hdr.append(f"  {c.note}", theme.S_AMBER)
            parts.append(hdr)
            body = hexdump(data[:65536]) if self.hex else printable_lines(data[:65536])
            for line in body[: MAX_LINES - lines_out]:
                parts.append(Text("  " + line, style=style if not self.hex else theme.S_DIM, no_wrap=self.hex))
            lines_out += len(body)
        return Group(*parts)

    def action_toggle_hex(self) -> None:
        self.hex = not self.hex
        self._redraw()

    def action_scroll(self, delta: int) -> None:
        self.query_one("#stream-body", VerticalScroll).scroll_relative(y=delta, animate=False)

    def action_save(self) -> None:
        if self.stream is None:
            return
        directory = Path(self.session.config.export_dir).expanduser()
        base = slug(f"stream-{self.flow.proto}-{self.flow.a}-{self.flow.a_port}-{self.flow.b}-{self.flow.b_port}")
        written = []
        try:
            for direction, label in (("a", "client"), ("b", "server")):
                data = self.stream.data(direction)
                if data:
                    path = directory / f"{base}.{label}.bin"
                    atomic_write_bytes(path, data)
                    written.append(str(path))
        except OSError as exc:
            self.app.notify(f"save failed: {exc}", severity="error")
            return
        self.session.store.log(self.session.investigation.id, "export", f"saved stream bytes: {', '.join(Path(w).name for w in written)}")
        self.app.notify("\n".join(written) or "no payload to save", title="stream saved", timeout=8)

    def action_packets(self) -> None:
        self.dismiss("packets")

    def action_close(self) -> None:
        self.dismiss(None)
