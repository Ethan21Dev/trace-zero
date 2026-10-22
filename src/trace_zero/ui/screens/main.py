"""The TRACE//ZERO workspace."""

from __future__ import annotations

import logging
import time
from bisect import bisect_left
from functools import partial
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import ContentSwitcher, Static
from textual.worker import Worker, get_current_worker

from trace_zero import PRODUCT, TAGLINE
from trace_zero.analysis.anomaly import SEVERITY_ORDER
from trace_zero.analysis.diff import diff_windows
from trace_zero.analysis.filters import FilterError, PacketFilter, frames_filter
from trace_zero.analysis.flows import build_flows, flows_in_window
from trace_zero.analysis.index import H_BYTES_IN, H_BYTES_OUT, H_PKTS_IN, H_PKTS_OUT, CaptureView, WindowStats, ip_sort_key
from trace_zero.analysis.timeline import WindowMode
from trace_zero.export import export_all
from trace_zero.export.report import slug
from trace_zero.models import fmt_bytes, fmt_duration, fmt_rel, fmt_ts
from trace_zero.parsing.reader import CaptureError, ParseCancelled, read_frame_bytes, validate_capture_path
from trace_zero.parsing.scapy_bridge import dissect_frame
from trace_zero.sanitize import clean
from trace_zero.session import LoadedCapture, Selection, Session, load_capture
from trace_zero.storage import StorageError
from trace_zero.ui import inspect, theme
from trace_zero.ui.mapgeo import MapEdge, MapNode
from trace_zero.ui.screens.dialogs import (
    ChoiceScreen,
    ConfirmScreen,
    FilterScreen,
    HelpScreen,
    InvestigationsScreen,
    NoteScreen,
    OpenCaptureScreen,
    PromptScreen,
)
from trace_zero.ui.screens.stream import FollowStreamScreen
from trace_zero.ui.widgets.chrome import HeaderBar, StatusBar
from trace_zero.ui.widgets.netmap import MapCanvas
from trace_zero.ui.widgets.table import Col, VirtualTable
from trace_zero.ui.widgets.timeline import TimelinePanel, TimelineSnapshot

log = logging.getLogger("trace_zero")

COMPACT_WIDTH = 130
MIN_W, MIN_H = 60, 16
SYNC_FILTER_LIMIT = 50_000

HOST_COLS = [Col("HOST"), Col("PKTS", 7, "right"), Col("BYTES", 8, "right")]
PEER_COLS = [Col("", 2), Col("PEER / LINK"), Col("PKTS →/←", 13, "right"), Col("BYTES", 9, "right"), Col("PROTO", 12), Col("BEFORE CUR", 10, "right")]
PACKET_COLS = [Col("NO", 7, "right"), Col("TIME UTC", 12), Col("SOURCE", 15), Col("DESTINATION", 15), Col("PROTO", 6), Col("LEN", 5, "right"), Col("INFO", min_width=12)]
FINDING_COLS = [Col("SEV", 6), Col("RULE", 4), Col("TRIAGE", 6), Col("FIRST UTC", 12), Col("CONF", 4), Col("FINDING", min_width=16), Col("HOSTS", 18)]
JOURNAL_COLS = [Col("WHEN (UTC)", 19), Col("TYPE", 8), Col("TARGET", 24), Col("DETAIL", min_width=10)]
DIFF_COLS = [Col("CHANGE", 12), Col("ITEM", min_width=18), Col("A", 10, "right"), Col("B", 10, "right"), Col("DETAIL", 14)]
FLOW_COLS = [Col("STATE", 9), Col("PROTO", 5), Col("CLIENT → SERVER", min_width=20), Col("PKTS →/←", 9, "right"), Col("BYTES", 8, "right"), Col("DUR", 8, "right"), Col("APP", 4)]

VIEW_TITLES = {"map": "NETWORK MAP", "flows": "FLOWS", "packets": "PACKETS", "findings": "FINDINGS", "diff": "WINDOW DIFF", "journal": "JOURNAL", "empty": TAGLINE}
FLOW_SORTS = ["time", "bytes", "packets", "state"]
VIEW_FOCUS = {"map": "#peers-table", "flows": "#view-flows", "packets": "#view-packets", "findings": "#view-findings", "diff": "#view-diff", "journal": "#view-journal"}
PACKET_SORTS = ["time", "no", "src", "dst", "proto", "len"]
HOST_SORTS = ["bytes", "pkts", "address"]
FINDING_SORTS = ["severity", "time", "rule", "status"]


def _splash() -> Text:
    t = Text(justify="center")
    t.append(f"{PRODUCT}\n", theme.S_CYAN_B)
    t.append(f"{TAGLINE}\n\n", theme.S_FAINT)
    t.append("o", theme.S_CYAN)
    t.append("  open a PCAP / PCAPNG capture\n", theme.S_DIM)
    t.append("?", theme.S_CYAN)
    t.append("  keyboard reference\n\n", theme.S_DIM)
    t.append("offline analysis │ read-only evidence │ no network access", theme.S_FAINT)
    return t


class MainScreen(Screen):
    BINDINGS = [
        Binding("question_mark,f1", "help", "help"),
        Binding("q", "back", "back/quit"),
        Binding("o", "open", "open"),
        Binding("slash", "filter", "filter"),
        Binding("h", "view('hosts')", "hosts"),
        Binding("n", "view('map')", "map"),
        Binding("c", "view('flows')", "flows"),
        Binding("p", "view('packets')", "packets"),
        Binding("f", "view('findings')", "findings"),
        Binding("b", "view('journal')", "journal"),
        Binding("t", "view('timeline')", "timeline"),
        Binding("i", "view('inspector')", "inspector"),
        Binding("space", "play", "play/pause", priority=True),
        Binding("left", "step(-1)", "step back", priority=True),
        Binding("right", "step(1)", "step forward", priority=True),
        Binding("shift+left", "packet_step(-1)", "prev packet", priority=True),
        Binding("shift+right", "packet_step(1)", "next packet", priority=True),
        Binding("less_than_sign", "event_step(-1)", "prev event"),
        Binding("greater_than_sign", "event_step(1)", "next event"),
        Binding("home", "jump(0)", "start", priority=True),
        Binding("end", "jump(1)", "end", priority=True),
        Binding("plus,equals_sign", "speed(1)", "faster"),
        Binding("minus", "speed(-1)", "slower"),
        Binding("w", "window_mode", "window mode"),
        Binding("left_square_bracket", "width(-1)", "narrower"),
        Binding("right_square_bracket", "width(1)", "wider"),
        Binding("escape", "escape", "clear"),
        Binding("m", "bookmark", "bookmark"),
        Binding("a", "annotate", "note"),
        Binding("x", "raw", "raw bytes"),
        Binding("s", "sort", "sort"),
        Binding("S,shift+s", "sort_reverse", "reverse sort"),
        Binding("e", "export", "export"),
        Binding("X,shift+x", "export_pcap", "export packets"),
        Binding("T,shift+t", "triage", "triage finding"),
        Binding("d", "diff", "compare windows"),
        Binding("D,shift+d", "clear_diff", "clear baseline"),
        Binding("k", "add_mark", "mark time"),
        Binding("left_curly_bracket", "mark_step(-1)", "previous mark"),
        Binding("right_curly_bracket", "mark_step(1)", "next mark"),
        Binding("z", "suppress", "suppress rule"),
        Binding("Z,shift+z", "toggle_suppressed", "show suppressed"),
        Binding("r", "rename", "rename"),
        Binding("ctrl+n", "new_investigation", "new investigation"),
        Binding("l", "investigations", "investigations"),
        Binding("delete", "delete_item", "delete"),
        Binding("enter", "open_selected", "open", show=False),
    ]

    def __init__(self, session: Session, initial_capture: str | None = None) -> None:
        super().__init__()
        self.session = session
        self.initial_capture = initial_capture
        self.center_view = "empty"
        self.compact_panel = "center"
        self.compact = False
        self.history: list[tuple[str, str]] = []
        self.focus_host: str | None = None
        self.show_raw = False
        self.raw_cache: dict[int, dict] = {}
        self.stats: WindowStats | None = None
        self.packet_rows: list[int] = []
        self.packet_sort = ("time", False)
        self.host_sort = ("bytes", False)
        self.finding_sort = ("severity", False)
        self.flow_sort = ("time", False)
        self.show_suppressed = False
        self.diff_base: tuple[float, float] | None = None
        self._diff_cache: tuple | None = None
        self.flow_rows: list = []
        self.finding_rows: list = []
        self.journal_rows: list[tuple] = []
        self.peer_rows: list[dict] = []
        self.bookmarked: set[tuple[str, str]] = set()
        self.sig_times: list[float] = []
        self.event_labels: dict[float, str] = {}
        self.finding_times: list[float] = []
        self.mark_times: list[float] = []
        self.loading: Worker | None = None
        self.load_status = ""
        self.busy = ""
        self._last_tick = 0.0
        self._last_progress = 0.0

    # ------------------------------------------------------------------ layout
    def compose(self) -> ComposeResult:
        yield HeaderBar(id="header")
        with Horizontal(id="body"):
            with Vertical(id="hosts-panel", classes="panel"):
                yield VirtualTable(HOST_COLS, id="hosts-table", empty_text="no hosts observed in window")
            with Vertical(id="center-panel", classes="panel"):
                yield Static(id="tabs")
                with ContentSwitcher(initial="view-empty", id="switcher"):
                    yield Static(_splash(), id="view-empty")
                    with Vertical(id="view-map"):
                        yield MapCanvas(id="map-canvas")
                        yield VirtualTable(PEER_COLS, id="peers-table", empty_text="no links in window")
                    yield VirtualTable(FLOW_COLS, id="view-flows", empty_text="no flows in window")
                    yield VirtualTable(PACKET_COLS, id="view-packets", empty_text="no packets in window")
                    yield VirtualTable(FINDING_COLS, id="view-findings", empty_text="no heuristic fired for this capture")
                    yield VirtualTable(DIFF_COLS, id="view-diff", empty_text="press d to use the current window as baseline A")
                    yield VirtualTable(JOURNAL_COLS, id="view-journal", empty_text="no bookmarks, notes or activity yet")
            with VerticalScroll(id="inspector-panel", classes="panel"):
                yield Static(id="inspector")
        with Vertical(id="timeline-panel", classes="panel"):
            yield TimelinePanel(id="timeline")
        yield StatusBar(id="status")
        yield Static(id="too-small")

    def on_mount(self) -> None:
        self.query_one("#hosts-panel").border_title = "HOSTS"
        self.query_one("#inspector-panel").border_title = "INSPECTOR"
        self.query_one("#timeline-panel").border_title = "TIMELINE"
        self.query_one("#center-panel").border_title = VIEW_TITLES["empty"]
        self.play_timer = self.set_interval(0.1, self._tick, pause=True)
        self._apply_layout()
        self._refresh_chrome()
        self._refresh_inspector()
        self._refresh_tabs()
        if self.initial_capture:
            self.start_load(self.initial_capture)

    def on_resize(self) -> None:
        self._apply_layout()
        if self.session.capture is not None:
            self.refresh_all()

    def _apply_layout(self) -> None:
        w, h = self.size.width, self.size.height
        tiny = w < MIN_W or h < MIN_H
        too_small = self.query_one("#too-small", Static)
        too_small.display = tiny
        for wid in ("#body", "#timeline-panel", "#status"):
            self.query_one(wid).display = not tiny
        if tiny:
            too_small.update(Text(f"{PRODUCT}\nterminal too small: {w}x{h}\nneed at least {MIN_W}x{MIN_H}", style=theme.S_AMBER, justify="center"))
            return
        self.compact = w < COMPACT_WIDTH
        body = self.query_one("#body")
        body.set_class(self.compact, "compact")
        hosts = self.query_one("#hosts-panel")
        center = self.query_one("#center-panel")
        insp = self.query_one("#inspector-panel")
        if self.compact:
            hosts.display = self.compact_panel == "hosts"
            center.display = self.compact_panel == "center"
            insp.display = self.compact_panel == "inspector"
        else:
            hosts.display = center.display = insp.display = True
            hosts_w, insp_w = (36, 56) if w >= 190 else ((31, 48) if w >= 160 else (30, 42))
            hosts.styles.width = hosts_w
            insp.styles.width = insp_w
        tl = self.query_one("#timeline-panel")
        tl.styles.height = 8 if h >= 32 else (6 if h >= 22 else 4)
        self._refresh_tabs()

    # ------------------------------------------------------------------ loading
    def start_load(self, path: str) -> None:
        try:
            validate_capture_path(path, self.session.config.limits)
        except CaptureError as exc:
            self._load_failed(str(exc))
            return
        if self.loading is not None and self.loading.is_running:
            self.loading.cancel()
        self.timeline_pause()
        name = Path(path).name
        self.load_status = name
        self.query_one(HeaderBar).set_state(capture=name, status=("busy", "VALIDATING"))
        self.busy = "LOADING"
        self._refresh_chrome()
        self.loading = self.run_worker(partial(self._load_worker, path), thread=True, exclusive=True, group="load", name="load-capture")

    def _load_worker(self, path: str) -> None:
        worker = get_current_worker()

        def progress(stage: str, n: int, done: int, total: int) -> None:
            now = time.monotonic()
            if now - self._last_progress < 0.08 and stage in ("parsing", "hashing"):
                return
            self._last_progress = now
            self.app.call_from_thread(self._on_progress, stage, n, done, total)

        try:
            loaded = load_capture(path, self.session.config, progress, lambda: worker.is_cancelled)
        except ParseCancelled:
            self.app.call_from_thread(self._load_cancelled)
            return
        except CaptureError as exc:
            self.app.call_from_thread(self._load_failed, str(exc))
            return
        except MemoryError:
            self.app.call_from_thread(self._load_failed, "out of memory - lower [limits] max_packets or split the capture")
            return
        except Exception as exc:  # noqa: BLE001 - surface, log, keep the app alive
            log.exception("unexpected import failure")
            self.app.call_from_thread(self._load_failed, f"unexpected error while importing ({type(exc).__name__}: {exc})")
            return
        if worker.is_cancelled:
            self.app.call_from_thread(self._load_cancelled)
            return
        self.app.call_from_thread(self._on_loaded, loaded)

    def _on_progress(self, stage: str, n: int, done: int, total: int) -> None:
        pct = int(done * 100 / total) if total else 100
        label = {"hashing": "HASHING", "parsing": "PARSING", "indexing": "INDEXING", "analysing": "ANALYSING", "flows": "FLOWS", "cache": "FROM CACHE"}.get(stage, stage.upper())
        detail = f"{label} {pct}%" + (f"  {n:,} pkts" if n else "")
        self.query_one(HeaderBar).set_state(status=("busy", detail + "  (esc cancels)"))
        self.busy = detail
        self._refresh_status()

    def _load_cancelled(self) -> None:
        self.busy = ""
        self.loading = None
        self._restore_header()
        self.app.notify("import cancelled", severity="warning")
        self._refresh_chrome()

    def _load_failed(self, message: str) -> None:
        self.busy = ""
        self.loading = None
        self.query_one(HeaderBar).set_state(status=("error", "IMPORT FAILED"))
        self.app.notify(clean(message, 300), title="cannot import capture", severity="error", timeout=8)
        self._refresh_status()

    def _restore_header(self) -> None:
        cap = self.session.capture
        header = self.query_one(HeaderBar)
        if cap is None:
            header.set_state(capture="no capture", status=("idle", "NO CAPTURE"))
            return
        r = cap.result
        status = ("warn", f"TRUNCATED {len(r.packets):,} pkts") if r.truncated else ("ok", f"ANALYSED {len(r.packets):,} pkts")
        header.set_state(capture=f"{r.file.name}  {fmt_bytes(r.file.size)}", status=status)

    def _on_loaded(self, loaded: LoadedCapture) -> None:
        self.busy = ""
        self.loading = None
        try:
            self.session.attach(loaded)
        except StorageError as exc:
            self.app.notify(f"capture loaded but not recorded: {exc}", severity="warning")
        self.focus_host = None
        self.raw_cache.clear()
        self.show_raw = False
        self.history.clear()
        idx = loaded.index
        self._rebuild_event_markers()
        self._reload_bookmarks()
        self._restore_header()
        r = loaded.result
        if self.center_view == "empty":
            self._switch_center("map", record=False)
        self.refresh_all()
        if not self.compact:
            self.query_one("#hosts-table", VirtualTable).focus()
        msg = f"{len(r.packets):,} packets · {len(idx.hosts):,} hosts · {len(loaded.findings)} possible anomalies · {r.elapsed_s:.1f}s"
        if r.cached:
            msg += " \u00b7 restored from cache (verified by SHA-256)"
        if not r.packets:
            self.app.notify("the capture contains no packets", title=r.file.name, severity="warning")
        elif r.truncated:
            self.app.notify(f"{msg}\nimport truncated: {r.stop_reason}", title=r.file.name, severity="warning", timeout=8)
        else:
            self.app.notify(msg, title=r.file.name)

    def _rebuild_event_markers(self) -> None:
        """Significant times for < / >: first observations, visible findings and named marks."""
        s = self.session
        if s.capture is None:
            self.sig_times, self.event_labels, self.finding_times, self.mark_times = [], {}, [], []
            return
        labels: dict[float, list[str]] = {}
        for e in s.capture.index.events:
            labels.setdefault(e.ts, []).append(e.label)
        visible = [f for f, _status, _sup in s.visible_findings()]
        for f in visible:
            labels.setdefault(f.first_ts, []).append(f"possible anomaly: {f.title}")
        marks = s.marks()
        for m in marks:
            labels.setdefault(m.ts, []).insert(0, f"MARK {m.label}")
        self.sig_times = sorted(labels)
        self.event_labels = {t: "; ".join(v[:2]) + (f" (+{len(v) - 2})" if len(v) > 2 else "") for t, v in labels.items()}
        self.finding_times = [f.first_ts for f in visible]
        self.mark_times = [m.ts for m in marks]

    # ------------------------------------------------------------------ refresh
    def refresh_all(self) -> None:
        s = self.session
        if s.capture is None:
            self._refresh_chrome()
            return
        self.stats = s.window_stats()
        self._refresh_hosts()
        self._refresh_map()
        self._refresh_center()
        self._refresh_inspector()
        self._refresh_timeline()
        self._refresh_chrome()

    def _refresh_center(self) -> None:
        view = self.center_view
        if view == "packets":
            self._refresh_packets()
        elif view == "flows":
            self._refresh_flows()
        elif view == "findings":
            self._refresh_findings()
        elif view == "journal":
            self._refresh_journal()
        elif view == "diff":
            self._refresh_diff()
        elif view == "map":
            self._refresh_map()

    def _refresh_chrome(self) -> None:
        self.query_one(HeaderBar).set_state(investigation=self.session.investigation.name)
        self._refresh_status()

    def _refresh_tabs(self) -> None:
        tabs = [("map", "n", "MAP"), ("flows", "c", "FLOWS"), ("packets", "p", "PACKETS"), ("findings", "f", "FINDINGS"), ("diff", "d", "DIFF"), ("journal", "b", "JOURNAL")]
        if self.compact:
            tabs = [("hosts", "h", "HOSTS")] + tabs + [("inspector", "i", "INSPECT")]
        active = self.center_view if (not self.compact or self.compact_panel == "center") else self.compact_panel
        t = Text(no_wrap=True, overflow="ellipsis")
        for i, (name, key, label) in enumerate(tabs):
            if i:
                t.append("  ")
            on_ = name == active
            t.append(key, theme.S_CYAN if not on_ else theme.S_CYAN_B)
            t.append(f" {label}", theme.S_TEXT if on_ else theme.S_FAINT)
            if name == "findings" and self.session.capture and self.session.capture.findings:
                t.append(f" {len(self.session.capture.findings)}", theme.S_AMBER)
        self.query_one("#tabs", Static).update(t)

    def _refresh_status(self) -> None:
        s = self.session
        status = self.query_one(StatusBar)
        keys: list[tuple[str, str]]
        if s.capture is None:
            keys = [("o", "open"), ("?", "help"), ("l", "investigations"), ("a", "note"), ("q", "quit")]
            if self.busy:
                keys = [("esc", "cancel import")] + keys
            status.set_state(keys=keys, filter_text="", range_text="-", app_status=self.busy or "READY")
            return
        tl = s.timeline
        keys = [("?", "help"), ("/", "filter"), ("space", "pause" if tl.playing else "play"), ("←→", "step"), ("⇧←→", "packet"), ("<>", "event")]
        focused = self.focused
        fid = focused.id if focused is not None else ""
        if fid == "view-packets":
            keys += [("enter", "inspect"), ("x", "raw"), ("m", "mark"), ("a", "note"), ("s", f"sort:{self.packet_sort[0]}")]
        elif fid == "hosts-table":
            keys += [("enter", "map"), ("m", "mark"), ("a", "note"), ("s", f"sort:{self.host_sort[0]}")]
        elif fid == "view-findings":
            keys += [("enter", "evidence"), ("T", "triage"), ("z", "suppress"), ("Z", "show suppressed"), ("a", "note"), ("s", f"sort:{self.finding_sort[0]}")]
        elif fid == "view-journal":
            keys += [("enter", "go to"), ("del", "delete")]
        elif fid == "view-diff":
            keys += [("enter", "go to"), ("d", "rebase A"), ("D", "clear"), ("k", "mark"), ("{ }", "marks")]
        elif fid == "view-flows":
            keys += [("enter", "follow stream"), ("m", "mark"), ("a", "note"), ("s", f"sort:{self.flow_sort[0]}")]
        elif fid == "peers-table":
            keys += [("enter", "inspect link"), ("m", "mark"), ("a", "note")]
        elif fid == "timeline":
            keys += [("w", "mode"), ("[ ]", "width"), ("+ -", "speed"), ("home/end", "jump"), ("k", "mark"), ("{ }", "marks"), ("d", "diff")]
        else:
            keys += [("h n c p f b", "views"), ("w", "mode"), ("+ -", "speed")]
        keys += [("e", "export"), ("q", "back" if self.history else "quit")]
        lo, hi = tl.window()
        rng = f"{fmt_ts(lo)} → {fmt_ts(hi)} ({fmt_duration(hi - lo)})"
        app_status = self.busy or (f"REPLAY {tl.speed:g}x" if tl.playing else "READY")
        status.set_state(keys=keys, filter_text=s.filter.display if s.filter else "", range_text=rng, app_status=app_status)

    def on_descendant_focus(self) -> None:
        self._refresh_status()

    # hosts -------------------------------------------------------------------------
    def _refresh_hosts(self) -> None:
        table = self.query_one("#hosts-table", VirtualTable)
        stats = self.stats
        rows = stats.host_rows() if stats else []
        key, rev = self.host_sort
        if key == "pkts":
            rows.sort(key=lambda kv: (-(kv[1][H_PKTS_OUT] + kv[1][H_PKTS_IN]), ip_sort_key(kv[0])))
        elif key == "address":
            rows.sort(key=lambda kv: ip_sort_key(kv[0]))
        if rev:
            rows.reverse()
        self.host_rows = rows

        def row(i: int) -> list:
            ip, h = rows[i]
            label = Text(ip, style=theme.S_CYAN_B if ip == self.focus_host else theme.S_TEXT)
            if ("host", ip) in self.bookmarked:
                label = Text("■ ", style=theme.S_AMBER) + label
            return [label, f"{h[H_PKTS_OUT] + h[H_PKTS_IN]:,}", fmt_bytes(h[H_BYTES_OUT] + h[H_BYTES_IN])]

        keep = self.focus_host or table.current_key()
        index = {ip: i for i, (ip, _h) in enumerate(rows)}
        table.set_data(len(rows), row, lambda i: rows[i][0], keep_key=keep, locate=index.get, notify=False)
        total = len(self.session.capture.index.hosts) if self.session.capture else 0
        self.query_one("#hosts-panel").border_title = f"HOSTS {len(rows)}/{total}"

    # map ---------------------------------------------------------------------------
    def _refresh_map(self) -> None:
        s = self.session
        canvas = self.query_one("#map-canvas", MapCanvas)
        stats = self.stats
        if stats is None or s.view is None:
            return
        idx = s.capture.index
        full = s.view.window(idx.t0, idx.t1)
        tl = s.timeline
        lo, hi = tl.window()
        h = max(3, canvas.size.height - 1)
        max_nodes = max(4, min(28, h * 2))
        ranked = [ip for ip, _ in full.host_rows()]
        chosen = ranked[:max_nodes]
        if self.focus_host and self.focus_host not in chosen and self.focus_host in full.hosts:
            chosen = chosen[: max_nodes - 1] + [self.focus_host]
        chosen_set = set(chosen)
        nodes = []
        for ip in chosen:
            first_seen = full.hosts[ip][4]
            if first_seen > tl.cursor:
                continue  # not yet observed at this point in time
            state = "active" if ip in stats.hosts else "dormant"
            nodes.append(MapNode(ip, state, ip == self.focus_host))
        visible = {n.ip for n in nodes}
        recent_span = max(0.05 * (hi - lo), 0.5)
        pairs: dict[tuple[str, str], list] = {}
        for (a, b), e in stats.edges.items():
            if a not in visible or b not in visible or a == b:
                continue
            key = (a, b) if ip_sort_key(a) <= ip_sort_key(b) else (b, a)
            slot = pairs.setdefault(key, [False, False, 0.0])
            if (a, b) == key:
                slot[0] = True
            else:
                slot[1] = True
            slot[2] = max(slot[2], e[3])
        edges = [
            MapEdge(a, b, ab, ba, tl.cursor - last <= recent_span, self.focus_host in (a, b))
            for (a, b), (ab, ba, last) in pairs.items()
        ]
        hidden = len([ip for ip in stats.hosts if ip not in chosen_set])
        cap = Text(no_wrap=True)
        cap.append(f"{len(stats.hosts)} hosts · {len(stats.pairs())} links in window", theme.S_DIM)
        if hidden:
            cap.append(f" · {hidden} smaller hosts not drawn", theme.S_FAINT)
        cap.append(" · historical observations, not live state", theme.S_FAINT)
        canvas.set_graph(nodes, edges, cap)
        self._refresh_peers()

    def _refresh_peers(self) -> None:
        stats = self.stats
        table = self.query_one("#peers-table", VirtualTable)
        cursor = self.session.timeline.cursor
        if stats is None:
            return
        if self.focus_host:
            rows = []
            for r in stats.peers(self.focus_host):
                a, b = sorted((self.focus_host, r["peer"]), key=ip_sort_key)
                rows.append(
                    {
                        "dir": "⇄" if r["out_pkts"] and r["in_pkts"] else ("→" if r["out_pkts"] else "←"),
                        "label": r["peer"],
                        "pkts": f"{r['out_pkts']:,}/{r['in_pkts']:,}",
                        "bytes": r["bytes"],
                        "protos": r["protos"],
                        "last": r["last"],
                        "ref": f"{a}|{b}",
                    }
                )
            title = f"links of {self.focus_host}"
        else:
            rows = [
                {
                    "dir": "⇄" if r["ab"] and r["ba"] else "→",
                    "label": f"{r['a']} — {r['b']}" if r["ab"] and r["ba"] else (f"{r['a']} → {r['b']}" if r["ab"] else f"{r['b']} → {r['a']}"),
                    "pkts": f"{r['ab']:,}/{r['ba']:,}",
                    "bytes": r["bytes"],
                    "protos": r["protos"],
                    "last": r["last"],
                    "ref": f"{r['a']}|{r['b']}",
                }
                for r in stats.pairs()
            ]
            title = "all links"
        self.peer_rows = rows

        def row(i: int) -> list:
            r = rows[i]
            protos = ",".join(p for p, _ in r["protos"].most_common(2))
            mark = ("conversation", r["ref"]) in self.bookmarked
            return [
                Text(r["dir"], style=theme.S_CYAN),
                Text(("■ " if mark else "") + r["label"], style=theme.S_AMBER if mark else theme.S_TEXT),
                r["pkts"],
                fmt_bytes(r["bytes"]),
                protos,
                Text(fmt_duration(cursor - r["last"]), style=theme.S_DIM),
            ]

        index = {r["ref"]: i for i, r in enumerate(rows)}
        table.set_data(len(rows), row, lambda i: rows[i]["ref"], keep_key=table.current_key(), locate=index.get, notify=False)
        self.query_one("#center-panel").border_title = f"{VIEW_TITLES[self.center_view]}" + (f" · {title}" if self.center_view == "map" else "")

    # packets -----------------------------------------------------------------------
    def _refresh_packets(self) -> None:
        s = self.session
        table = self.query_one("#view-packets", VirtualTable)
        if self.stats is None or s.view is None:
            return
        view: CaptureView = s.view
        pk = s.capture.index.packets
        rows = list(view.slice_rows(self.stats.i0, self.stats.i1))
        key, rev = self.packet_sort
        if key != "time":
            keyfn = {
                "no": lambda i: pk[i].no,
                "src": lambda i: (ip_sort_key(pk[i].src) if pk[i].src else (99, 0), pk[i].no),
                "dst": lambda i: (ip_sort_key(pk[i].dst) if pk[i].dst else (99, 0), pk[i].no),
                "proto": lambda i: (pk[i].proto, pk[i].no),
                "len": lambda i: (pk[i].wirelen, pk[i].no),
            }[key]
            rows.sort(key=keyfn)
        if rev:
            rows.reverse()
        self.packet_rows = rows

        def row(i: int) -> list:
            p = pk[rows[i]]
            no = Text(f"{p.no}", style=theme.S_DIM)
            if ("packet", str(p.no)) in self.bookmarked:
                no = Text("■", style=theme.S_AMBER) + no
            info = Text(clean(p.info, 300), style=theme.S_AMBER if p.errors or (p.dns and p.dns.malformed) else theme.S_TEXT)
            return [
                no,
                Text(fmt_ts(p.ts), style=theme.S_DIM),
                p.src or (p.eth_src or "-"),
                p.dst or (p.eth_dst or "-"),
                Text(p.proto, style=theme.S_CYAN if p.app else theme.S_TEXT),
                str(p.wirelen),
                info,
            ]

        sel = s.selection
        keep = int(sel.ref) if sel is not None and sel.kind == "packet" else table.current_key()
        follow = key == "time" and not rev and (s.timeline.playing or (table.at_end() and not (sel and sel.kind == "packet")))

        def locate(no) -> int | None:
            if key == "time" and not rev:
                p = s.capture.index.packet(no)
                if p is None:
                    return None
                pos = bisect_left(view.ts, p.ts, self.stats.i0, self.stats.i1)
                while pos < self.stats.i1 and pk[view.rows[pos]].no != no:
                    pos += 1
                return pos - self.stats.i0 if pos < self.stats.i1 else None
            for i, r in enumerate(rows):
                if pk[r].no == no:
                    return i
            return None

        table.set_data(len(rows), row, lambda i: pk[rows[i]].no, keep_key=keep, locate=locate, follow_end=follow, notify=False)
        label = f"PACKETS {len(rows):,} in window"
        if s.filter:
            label += " (filtered)"
        if key != "time" or rev:
            label += f" · sorted by {key}{' desc' if rev else ''}"
        self.query_one("#center-panel").border_title = label

    # findings ----------------------------------------------------------------------
    def _refresh_findings(self) -> None:
        s = self.session
        table = self.query_one("#view-findings", VirtualTable)
        entries = s.visible_findings(include_suppressed=self.show_suppressed)
        hidden = len(s.capture.findings) - len(s.visible_findings(include_suppressed=False)) if not self.show_suppressed else 0
        key, rev = self.finding_sort
        status_order = {"escalated": 0, None: 1, "open": 1, "benign": 2}
        if key == "severity":
            entries.sort(key=lambda e: (SEVERITY_ORDER[e[0].severity], e[0].first_ts))
        elif key == "time":
            entries.sort(key=lambda e: (e[0].first_ts, SEVERITY_ORDER[e[0].severity]))
        elif key == "status":
            entries.sort(key=lambda e: (status_order[e[1][0] if e[1] else None], SEVERITY_ORDER[e[0].severity], e[0].first_ts))
        else:
            entries.sort(key=lambda e: (e[0].rule, e[0].first_ts))
        if rev:
            entries.reverse()
        self.finding_rows = [e[0] for e in entries]
        cursor = s.timeline.cursor
        status_style = {"escalated": theme.S_RED, "benign": theme.S_GREEN, "open": theme.S_TEXT}

        def row(i: int) -> list:
            f, status, sup = entries[i]
            mark = ("finding", f.id) in self.bookmarked
            label = "SUPPR" if sup is not None else (status[0].upper()[:5] if status else "new")
            return [
                Text(f.severity, style=theme.SEVERITY_STYLE[f.severity]),
                f.rule[3:],
                Text(label, style=theme.S_FAINT if sup is not None else status_style.get(status[0] if status else "", theme.S_DIM)),
                fmt_ts(f.first_ts),
                {"MEDIUM": "MED"}.get(f.confidence, f.confidence),
                Text(("\u25a0 " if mark else "") + f.title, style=theme.S_AMBER if mark else theme.S_TEXT),
                ", ".join(f.hosts[:3]) + (" \u2026" if len(f.hosts) > 3 else ""),
            ]

        def style(i: int):
            f, status, sup = entries[i]
            return theme.S_FAINT if (f.first_ts > cursor or sup is not None or (status and status[0] == "benign")) else None

        sel = s.selection
        keep = sel.ref if sel is not None and sel.kind == "finding" else table.current_key()
        index = {e[0].id: i for i, e in enumerate(entries)}
        table.set_data(len(entries), row, lambda i: entries[i][0].id, keep_key=keep, locate=index.get, style_fn=style, notify=False)
        observed = sum(1 for e in entries if e[0].first_ts <= cursor)
        title = f"FINDINGS \u00b7 {len(entries)} possible anomalies \u00b7 {observed} observed by cursor"
        if hidden:
            title += f" \u00b7 {hidden} suppressed (Z shows)"
        self.query_one("#center-panel").border_title = title

    # journal -----------------------------------------------------------------------
    def _refresh_journal(self) -> None:
        s = self.session
        store, inv = s.store, s.investigation
        rows: list[tuple] = []
        if s.capture is not None:
            for b in store.bookmarks(inv.id, s.sha):
                rows.append((b.created_at, "BOOKMARK", f"{b.kind} {b.ref}", b.label or "", ("bookmark", b.id, b.kind, b.ref)))
        for n in store.notes(inv.id, s.sha if s.capture else None):
            rows.append((n.created_at, "NOTE", f"{n.target_kind} {n.target_ref}".strip(), n.body.replace("\n", " "), ("note", n.id, n.target_kind, n.target_ref)))
        for e in store.events(inv.id, 300):
            rows.append((e.at, "LOG", e.kind, e.message, ("event", e.id, None, None)))
        for sup in store.suppressions(inv.id):
            rows.append((sup.created_at, "SUPPRESS", f"{sup.rule} {sup.host or '(any host)'}", sup.reason, ("suppression", sup.id, None, None)))
        if s.capture is not None:
            for m in s.marks():
                rows.append((m.created_at, "MARK", f"T{fmt_rel(m.ts - s.capture.index.t0)}", m.label, ("mark", m.id, "mark", str(m.ts))))
        rows.sort(key=lambda r: (r[0], r[4][0], r[4][1]))
        self.journal_rows = rows
        table = self.query_one("#view-journal", VirtualTable)

        def row(i: int) -> list:
            at, typ, target, detail, _ = rows[i]
            style = {"BOOKMARK": theme.S_CYAN, "NOTE": theme.S_AMBER, "LOG": theme.S_DIM, "SUPPRESS": theme.S_AMBER, "MARK": theme.S_GREEN}[typ]
            return [Text(fmt_ts(at, True)[:19], style=theme.S_DIM), Text(typ, style=style), clean(target, 80), Text(clean(detail, 300), style=theme.S_AMBER if typ == "NOTE" else theme.S_TEXT)]

        table.set_data(len(rows), row, lambda i: rows[i][4][:2], keep_key=table.current_key(), notify=False)
        # Plain Text: the investigation name is user-typed and must not be parsed as markup.
        self.query_one("#center-panel").border_title = Text(f"JOURNAL · {clean(s.investigation.name, 60)} · notes are analyst interpretation")

    # inspector ---------------------------------------------------------------------
    def _refresh_inspector(self) -> None:
        s = self.session
        panel = self.query_one("#inspector-panel")
        target = self.query_one("#inspector", Static)
        sel = s.selection
        try:
            if s.capture is None:
                content, title = inspect.overview(s), "INSPECTOR"
            elif sel is None and self.focus_host:
                content, title = inspect.host(s, self.focus_host, self.stats), "INSPECTOR · HOST"
            elif sel is None:
                content, title = inspect.overview(s), "INSPECTOR · CAPTURE"
            elif sel.kind == "host":
                content, title = inspect.host(s, sel.ref, self.stats), "INSPECTOR · HOST"
            elif sel.kind == "packet":
                p = s.capture.index.packet(int(sel.ref))
                raw = self.raw_cache.get(p.no) if (self.show_raw and p is not None) else None
                # Hex rows sized to the text area: a row of n bytes is 9 + 4n cells plus a 2-cell indent.
                per_line = max(4, min(16, (target.size.width - 11) // 4 // 4 * 4))
                content = inspect.packet(s, p, raw, per_line) if p else Text("frame not found")
                title = "INSPECTOR · PACKET"
            elif sel.kind == "finding":
                f = s.capture.finding(sel.ref)
                content = inspect.finding(s, f) if f else Text("finding not found")
                title = "INSPECTOR · FINDING"
            elif sel.kind == "flow":
                flow = s.flow(sel.ref)
                content = inspect.flow(s, flow) if flow else Text("flow is not in the current filtered view")
                title = "INSPECTOR · FLOW"
            else:
                content, title = inspect.conversation(s, sel.ref, self.stats), "INSPECTOR · CONVERSATION"
        except Exception as exc:  # noqa: BLE001 - inspector must not take the UI down
            log.exception("inspector render failed")
            content, title = Text(f"cannot display item: {type(exc).__name__}", style=theme.S_RED), "INSPECTOR"
        target.update(content)
        panel.border_title = title

    # timeline ----------------------------------------------------------------------
    def _refresh_timeline(self) -> None:
        s = self.session
        panel = self.query_one(TimelinePanel)
        if s.capture is None or s.view is None:
            panel.update_snapshot(None)
            return
        tl = s.timeline
        bins = max(10, panel.size.width)
        counts = s.view.histogram(tl.t0, tl.t1, bins)
        stats = self.stats
        label = self.event_labels.get(tl.cursor)
        snap = TimelineSnapshot(
            timeline=tl,
            counts=counts,
            finding_times=self.finding_times,
            mark_times=self.mark_times,
            baseline=self.diff_base,
            window_packets=stats.packets if stats else 0,
            window_bytes=stats.bytes if stats else 0,
            event_label=label,
            filtered=s.filter is not None,
        )
        panel.update_snapshot(snap)
        mode = "SLIDING" if tl.mode is WindowMode.SLIDING else "CUMULATIVE"
        self.query_one("#timeline-panel").border_title = f"TIMELINE · {mode} · {fmt_duration(tl.span)} captured"

    # ------------------------------------------------------------------ view switching
    def _switch_center(self, view: str, record: bool = True) -> None:
        if record:
            self._push_history()
        self.center_view = view
        self.query_one("#switcher", ContentSwitcher).current = f"view-{view}"
        self.query_one("#center-panel").border_title = VIEW_TITLES[view]
        if self.compact:
            self.compact_panel = "center"
            self._apply_layout()
        self._refresh_tabs()
        if self.session.capture is not None:
            self._refresh_center()

    def _push_history(self) -> None:
        state = (self.center_view, self.compact_panel)
        if not self.history or self.history[-1] != state:
            self.history.append(state)
            del self.history[:-20]

    def action_view(self, name: str) -> None:
        if name in VIEW_FOCUS:
            if self.session.capture is None and name != "journal":
                self.app.notify("open a capture first (o)", severity="warning")
                return
            if self.center_view != name or (self.compact and self.compact_panel != "center"):
                self._switch_center(name)
            self.query_one(VIEW_FOCUS[name]).focus()
        elif name == "hosts":
            if self.compact and self.compact_panel != "hosts":
                self._push_history()
                self.compact_panel = "hosts"
                self._apply_layout()
            self.query_one("#hosts-table").focus()
        elif name == "inspector":
            if self.compact and self.compact_panel != "inspector":
                self._push_history()
                self.compact_panel = "inspector"
                self._apply_layout()
            self.query_one("#inspector-panel").focus()
        elif name == "timeline":
            self.query_one(TimelinePanel).focus()
        self._refresh_tabs()
        self._refresh_status()

    def action_back(self) -> None:
        if self.history:
            view, panel = self.history.pop()
            if view != self.center_view:
                self._switch_center(view, record=False)
            # Restore the panel after switching: _switch_center selects the centre panel.
            self.compact_panel = panel
            self._apply_layout()
            focus = {"hosts": "#hosts-table", "inspector": "#inspector-panel"}.get(panel) if self.compact else None
            if focus is None:
                focus = VIEW_FOCUS.get(view)
            if focus:
                self.query_one(focus).focus()
            self._refresh_status()
            return
        self.app.exit()

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen(VIEW_TITLES.get(self.center_view, "")))

    # ------------------------------------------------------------------ selection events
    @on(VirtualTable.Highlighted, "#hosts-table")
    def host_highlighted(self, event: VirtualTable.Highlighted) -> None:
        if event.key is None:
            return
        self.focus_host = event.key
        self.session.selection = Selection("host", event.key)
        self._refresh_selection()

    @on(VirtualTable.Activated, "#hosts-table")
    def host_activated(self, event: VirtualTable.Activated) -> None:
        self.focus_host = event.key
        self.session.selection = Selection("host", event.key)
        if self.center_view != "map" or self.compact:
            self._switch_center("map")
        self.query_one("#peers-table").focus()
        self._refresh_selection()

    @on(VirtualTable.Highlighted, "#peers-table")
    def peer_highlighted(self, event: VirtualTable.Highlighted) -> None:
        if event.key is not None:
            self.session.selection = Selection("conversation", event.key)
            self._refresh_inspector()

    @on(VirtualTable.Activated, "#peers-table")
    def peer_activated(self, event: VirtualTable.Activated) -> None:
        self.session.selection = Selection("conversation", event.key)
        self._refresh_inspector()
        if self.compact:
            self.action_view("inspector")

    @on(VirtualTable.Highlighted, "#view-packets")
    def packet_highlighted(self, event: VirtualTable.Highlighted) -> None:
        if event.key is not None:
            self.session.selection = Selection("packet", str(event.key))
            self._refresh_inspector()

    @on(VirtualTable.Activated, "#view-packets")
    def packet_activated(self, event: VirtualTable.Activated) -> None:
        self.session.selection = Selection("packet", str(event.key))
        self._refresh_inspector()
        self.action_view("inspector")

    @on(VirtualTable.Highlighted, "#view-flows")
    def flow_highlighted(self, event: VirtualTable.Highlighted) -> None:
        if event.key is not None:
            self.session.selection = Selection("flow", event.key)
            self._refresh_inspector()

    @on(VirtualTable.Activated, "#view-flows")
    def flow_activated(self, event: VirtualTable.Activated) -> None:
        self.session.selection = Selection("flow", event.key)
        self.follow_stream(event.key)

    def follow_stream(self, ref: str) -> None:
        flow = self.session.flow(ref)
        if flow is None:
            return
        self.timeline_pause()

        def done(result: str | None) -> None:
            if result == "packets":
                self._set_filter(frames_filter(set(flow.frames), "flow"), f"flow {flow.endpoint('a')} \u21c4 {flow.endpoint('b')}")
                self.session.timeline.set_cursor(max(self.session.timeline.cursor, flow.last))
                self.session.timeline.mode = WindowMode.CUMULATIVE
                self._switch_center("packets")
                self.refresh_all()
                self.query_one("#view-packets").focus()

        self.app.push_screen(FollowStreamScreen(self.session, flow), done)

    @on(VirtualTable.Highlighted, "#view-findings")
    def finding_highlighted(self, event: VirtualTable.Highlighted) -> None:
        if event.key is not None:
            self.session.selection = Selection("finding", event.key)
            self._refresh_inspector()

    @on(VirtualTable.Activated, "#view-findings")
    def finding_activated(self, event: VirtualTable.Activated) -> None:
        self.show_evidence(event.key)

    @on(VirtualTable.Activated, "#view-diff")
    def diff_activated(self, event: VirtualTable.Activated) -> None:
        row = next((r for r in (self._diff_cache[1].rows if self._diff_cache else []) if (r.change, r.item) == event.key), None)
        if row is None or row.kind == "none":
            return
        self.goto(row.kind, row.ref)

    @on(VirtualTable.Activated, "#view-journal")
    def journal_activated(self, event: VirtualTable.Activated) -> None:
        row = next((r for r in self.journal_rows if r[4][:2] == event.key), None)
        if row is None:
            return
        _typ, _id, kind, ref = row[4]
        if not kind or kind == "investigation" or self.session.capture is None:
            return
        self.goto(kind, ref)

    def goto(self, kind: str, ref: str) -> None:
        s = self.session
        if kind == "mark":
            self.timeline_pause()
            s.timeline.set_cursor(float(ref))
            self.refresh_all()
            return
        if kind == "packet":
            p = s.capture.index.packet(int(ref))
            if p is None:
                self.app.notify(f"frame {ref} is not in this capture", severity="warning")
                return
            if s.filter is not None and not s.filter(p):
                self._set_filter(None, None)
            lo, hi = s.timeline.window()
            if not lo <= p.ts <= hi:
                s.timeline.set_cursor(p.ts)
            s.selection = Selection("packet", ref)
            self._switch_center("packets")
            self.refresh_all()
            self.query_one("#view-packets").focus()
        elif kind == "host":
            self.focus_host = ref
            s.selection = Selection("host", ref)
            self._switch_center("map")
            self.refresh_all()
            self.query_one("#hosts-table").focus()
        elif kind == "finding":
            s.selection = Selection("finding", ref)
            self._switch_center("findings")
            self.refresh_all()
            self.query_one("#view-findings").focus()
        elif kind == "conversation":
            s.selection = Selection("conversation", ref)
            self.focus_host = ref.split("|")[0]
            self._switch_center("map")
            self.refresh_all()
        elif kind == "flow":
            flow = s.flow(ref)
            if flow is None:
                self.app.notify("that flow is not in the current filtered view", severity="warning")
                return
            if s.timeline.cursor < flow.first:
                s.timeline.set_cursor(flow.last)
            s.selection = Selection("flow", ref)
            self._switch_center("flows")
            self.refresh_all()
            self.query_one("#view-flows").focus()

    def show_evidence(self, finding_id: str) -> None:
        s = self.session
        f = s.capture.finding(finding_id) if s.capture else None
        if f is None:
            return
        flt = s.evidence_filter(f)
        s.timeline.mode = WindowMode.CUMULATIVE
        s.timeline.set_cursor(max(s.timeline.cursor, f.last_ts))
        s.timeline.playing = False
        self.play_timer.pause()
        s.selection = Selection("finding", f.id)
        self._set_filter(flt, f"evidence for {f.rule}: {f.frame_count} frames")
        self._switch_center("packets")
        self.query_one("#view-packets").focus()
        self.app.notify("showing supporting frames · shift+← / shift+→ step through them · esc clears", title=f.rule)

    def _refresh_selection(self) -> None:
        self._refresh_hosts()
        self._refresh_map()
        self._refresh_inspector()

    def action_open_selected(self) -> None:
        sel = self.session.selection
        if sel is not None and sel.kind == "finding":
            self.show_evidence(sel.ref)
        elif sel is not None and sel.kind == "flow":
            self.follow_stream(sel.ref)

    # flows -------------------------------------------------------------------------
    def _refresh_flows(self) -> None:
        s = self.session
        table = self.query_one("#view-flows", VirtualTable)
        if s.view is None:
            return
        if s.view.flows_cache is None and len(s.view) > SYNC_FILTER_LIMIT:
            self.query_one("#center-panel").border_title = "FLOWS \u00b7 building flow table\u2026"
            self._flows_worker(s.view)
            return
        tl = s.timeline
        lo, hi = tl.window()
        flows = [f for f in flows_in_window(s.flows(), lo, hi) if f.first <= tl.cursor]
        key, rev = self.flow_sort
        if key == "bytes":
            flows.sort(key=lambda f: (-f.bytes, f.first))
        elif key == "packets":
            flows.sort(key=lambda f: (-f.packets, f.first))
        elif key == "state":
            flows.sort(key=lambda f: (f.state, f.first))
        if rev:
            flows.reverse()
        self.flow_rows = flows
        cursor = tl.cursor
        warn = {"reset", "refused", "no reply", "half-open"}

        def row(i: int) -> list:
            f = flows[i]
            mark = ("flow", f.ref) in self.bookmarked
            dur = fmt_duration(f.duration) + ("+" if f.last > cursor else "")
            arrow = " \u2192 " if f.initiator_known else " \u2014 "
            ends = Text(f.a, style=theme.S_CYAN if f.initiator_known else theme.S_TEXT)
            ends.append(arrow, theme.S_FAINT)
            ends.append(f.endpoint("b"))
            return [
                Text(("\u25a0 " if mark else "") + f.state, style=theme.S_AMBER if (mark or f.state in warn) else theme.S_TEXT),
                f.proto,
                ends,
                f"{f.pkts_ab:,}/{f.pkts_ba:,}",
                fmt_bytes(f.bytes),
                Text(dur, style=theme.S_DIM),
                f.app or "",
            ]

        sel = s.selection
        keep = sel.ref if sel is not None and sel.kind == "flow" else table.current_key()
        index = {f.ref: i for i, f in enumerate(flows)}
        table.set_data(len(flows), row, lambda i: flows[i].ref, keep_key=keep, locate=index.get, notify=False)
        title = f"FLOWS {len(flows):,} in window" + (" (filtered)" if s.filter else "")
        if key != "time" or rev:
            title += f" \u00b7 sorted by {key}{' desc' if rev else ''}"
        self.query_one("#center-panel").border_title = title + " \u00b7 \u2192 initiator proven, \u2014 not proven"

    # ------------------------------------------------------------------ actions: files & filters
    def action_open(self) -> None:
        cap = self.session.capture
        start = Path(cap.result.file.path).parent if cap else Path.cwd()

        def done(path: str | None) -> None:
            if path:
                self.start_load(path)

        self.app.push_screen(OpenCaptureScreen(start, self.session.config.limits), done)

    def action_filter(self) -> None:
        s = self.session
        if s.capture is None:
            self.app.notify("open a capture first (o)", severity="warning")
            return
        initial = s.filter.text if s.filter is not None and s.filter.frame_set is None else ""

        def done(text: str | None) -> None:
            if text is None:
                return
            try:
                flt = s.compile(text)
            except FilterError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self._set_filter(flt, None)

        self.app.push_screen(FilterScreen(initial, s.capture.index.t0), done)

    def _set_filter(self, flt: PacketFilter | None, label: str | None) -> None:
        s = self.session
        if flt is not None and label:
            flt.label = label
        if len(s.capture.index.packets) <= SYNC_FILTER_LIMIT or flt is None:
            view = s.build_view(flt)
            self._apply_filter(flt, view)
        else:
            self.busy = "FILTERING"
            self._refresh_status()
            self._filter_worker(flt)

    @work(thread=True, exclusive=True, group="flows")
    def _flows_worker(self, view: CaptureView) -> None:
        flows = build_flows(self.session.capture.index.packets, view.rows)
        if not get_current_worker().is_cancelled:
            self.app.call_from_thread(self._flows_built, view, flows)

    def _flows_built(self, view: CaptureView, flows) -> None:
        view.flows_cache = flows
        if self.session.view is view and self.center_view == "flows":
            self._refresh_flows()

    @work(thread=True, exclusive=True, group="filter")
    def _filter_worker(self, flt: PacketFilter) -> None:
        view = self.session.build_view(flt)
        if not get_current_worker().is_cancelled:
            self.app.call_from_thread(self._apply_filter, flt, view)

    def _apply_filter(self, flt: PacketFilter | None, view: CaptureView) -> None:
        self.busy = ""
        self.session.apply_view(flt, view)
        if flt is not None:
            self.app.notify(f"{len(view):,} packets match · {flt.display}", title="filter")
        self.refresh_all()

    def action_escape(self) -> None:
        if self.loading is not None and self.loading.is_running:
            self.loading.cancel()
            return
        s = self.session
        if s.selection is not None or self.focus_host is not None:
            s.selection = None
            self.focus_host = None
            self.show_raw = False
            self.refresh_all()
            return
        if s.filter is not None:
            self._set_filter(None, None)
            self.app.notify("filter cleared")

    # ------------------------------------------------------------------ actions: time machine
    def _has_timeline(self) -> bool:
        return self.session.capture is not None and self.session.timeline is not None and bool(self.session.capture.result.packets)

    def timeline_pause(self) -> None:
        if self.session.timeline is not None:
            self.session.timeline.playing = False
        if hasattr(self, "play_timer"):
            self.play_timer.pause()

    def action_play(self) -> None:
        if not self._has_timeline():
            return
        tl = self.session.timeline
        tl.toggle_play()
        if tl.playing:
            self._last_tick = time.monotonic()
            self.play_timer.resume()
        else:
            self.play_timer.pause()
        self.refresh_all()

    def _tick(self) -> None:
        tl = self.session.timeline
        if tl is None or not tl.playing:
            self.play_timer.pause()
            return
        now = time.monotonic()
        dt, self._last_tick = now - self._last_tick, now
        tl.advance(min(dt, 0.5))
        if not tl.playing:
            self.play_timer.pause()
        self.refresh_all()

    def action_step(self, steps: int) -> None:
        if not self._has_timeline():
            return
        self.timeline_pause()
        self.session.timeline.move(steps)
        self.refresh_all()

    def action_packet_step(self, direction: int) -> None:
        if not self._has_timeline():
            return
        s = self.session
        view = s.view
        if not len(view):
            return
        self.timeline_pause()
        pos = None
        sel = s.selection
        if sel is not None and sel.kind == "packet":
            p = s.capture.index.packet(int(sel.ref))
            if p is not None:
                i = bisect_left(view.ts, p.ts)
                while i < len(view.rows) and s.capture.index.packets[view.rows[i]].no != p.no and view.ts[i] == p.ts:
                    i += 1
                if i < len(view.rows) and s.capture.index.packets[view.rows[i]].no == p.no:
                    pos = i
        if pos is None:
            last = view.last_position_at(s.timeline.cursor)
            pos = (last if last is not None else -1) + (1 if direction > 0 else 0)
            if direction < 0 and last is not None:
                pos = last if (sel is None or sel.kind != "packet") else last - 1
        else:
            pos += direction
        if pos < 0 or pos >= len(view):
            self.app.notify("no more packets in this direction", severity="information", timeout=2)
            return
        p = view.packet_at(pos)
        s.timeline.set_cursor(p.ts)
        s.selection = Selection("packet", str(p.no))
        self.refresh_all()

    def action_event_step(self, direction: int) -> None:
        if not self._has_timeline():
            return
        self.timeline_pause()
        tl = self.session.timeline
        moved = tl.to_next(self.sig_times) if direction > 0 else tl.to_prev(self.sig_times)
        if not moved:
            self.app.notify("no further significant events", timeout=2)
        self.refresh_all()

    def action_jump(self, end: int) -> None:
        if not self._has_timeline():
            return
        self.timeline_pause()
        tl = self.session.timeline
        tl.jump_end() if end else tl.jump_start()
        self.refresh_all()

    def action_speed(self, delta: int) -> None:
        if not self._has_timeline():
            return
        self.session.timeline.change_speed(delta)
        self.refresh_all()

    def action_window_mode(self) -> None:
        if not self._has_timeline():
            return
        tl = self.session.timeline
        tl.toggle_mode()
        self.app.notify(f"window: {tl.mode.value}" + (f" {fmt_duration(tl.width)}" if tl.mode is WindowMode.SLIDING else ""), timeout=2)
        self.refresh_all()

    def action_width(self, delta: int) -> None:
        if not self._has_timeline():
            return
        tl = self.session.timeline
        tl.change_width(delta)
        if tl.mode is not WindowMode.SLIDING:
            self.app.notify(f"width {fmt_duration(tl.width)} applies in SLIDING mode (press w)", timeout=3)
        self.refresh_all()

    # ------------------------------------------------------------------ actions: investigation
    def _current_target(self) -> Selection | None:
        s = self.session
        if s.selection is not None:
            return s.selection
        if self.focus_host:
            return Selection("host", self.focus_host)
        return None

    def _reload_bookmarks(self) -> None:
        s = self.session
        if s.capture is None:
            self.bookmarked = set()
            return
        self.bookmarked = {(b.kind, b.ref) for b in s.store.bookmarks(s.investigation.id, s.sha)}

    def action_bookmark(self) -> None:
        s = self.session
        target = self._current_target()
        if s.capture is None or target is None:
            self.app.notify("select a host, packet, finding or link first", severity="warning")
            return
        label = ""
        if target.kind == "packet":
            p = s.capture.index.packet(int(target.ref))
            label = clean(f"{p.src} -> {p.dst} {p.proto} {p.info}", 180) if p else ""
        elif target.kind == "finding":
            f = s.capture.finding(target.ref)
            label = f.title if f else ""
        elif target.kind == "flow":
            flow = s.flow(target.ref)
            label = f"{flow.proto} {flow.endpoint('a')} -> {flow.endpoint('b')} {flow.state}" if flow else ""
        try:
            now = s.toggle_bookmark(target, label)
        except StorageError as exc:
            self.app.notify(str(exc), severity="error")
            return
        self._reload_bookmarks()
        self.app.notify(("bookmarked " if now else "bookmark removed: ") + target.label, timeout=2)
        self.refresh_all()

    def action_annotate(self) -> None:
        target = self._current_target()
        label = target.label if target else f"investigation '{self.session.investigation.name}'"
        if target is not None and target.kind == "finding" and self.session.capture:
            f = self.session.capture.finding(target.ref)
            label = f"{f.rule} {f.title}" if f else label

        def done(body: str | None) -> None:
            if not body:
                return
            try:
                self.session.add_note(target, body)
            except StorageError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self.app.notify("note saved", timeout=2)
            self.refresh_all()
            if self.center_view == "journal":
                self._refresh_journal()

        self.app.push_screen(NoteScreen(label), done)

    def action_raw(self) -> None:
        s = self.session
        sel = s.selection
        if s.capture is None or sel is None or sel.kind != "packet":
            self.app.notify("select a packet first (p)", severity="warning")
            return
        self.show_raw = not self.show_raw
        no = int(sel.ref)
        if self.show_raw and no not in self.raw_cache:
            self.raw_cache[no] = {"loading": True}
            self._raw_worker(s.capture.result.file, no, s.config.limits.max_raw_bytes)
        self._refresh_inspector()

    @work(thread=True, group="raw")
    def _raw_worker(self, info, no: int, max_bytes: int) -> None:
        result: dict
        try:
            data, linktype = read_frame_bytes(info, no)
            clipped = len(data) if len(data) > max_bytes else 0
            data = data[:max_bytes]
            layers: list[tuple[str, list[tuple[str, str]]]] = []
            note = None
            try:
                pkt = dissect_frame(data, linktype)
                layer = pkt
                fields = 0
                while layer is not None and layer.name != "NoPayload" and len(layers) < 12 and fields < 400:
                    rows = []
                    for fld in layer.fields_desc:
                        try:
                            value = fld.i2repr(layer, layer.getfieldval(fld.name))
                        except Exception:  # noqa: BLE001
                            value = "<not representable>"
                        rows.append((clean(fld.name, 40), clean(value, 240)))
                    fields += len(rows)
                    layers.append((clean(layer.name, 60), rows))
                    layer = layer.payload if layer.payload else None
                if pkt is None:
                    note = "no scapy dissector for this link type"
            except Exception as exc:  # noqa: BLE001 - untrusted input
                note = f"scapy could not dissect this frame ({type(exc).__name__})"
            result = {"data": data, "layers": layers, "note": note, "clipped": clipped}
        except CaptureError as exc:
            result = {"error": str(exc)}
        except OSError as exc:
            result = {"error": f"cannot read capture: {exc}"}
        self.app.call_from_thread(self._raw_loaded, no, result)

    def _raw_loaded(self, no: int, result: dict) -> None:
        self.raw_cache[no] = result
        if len(self.raw_cache) > 64:
            self.raw_cache.pop(next(iter(self.raw_cache)))
        self._refresh_inspector()

    def action_sort(self) -> None:
        self._cycle_sort(reverse=False)

    def action_sort_reverse(self) -> None:
        self._cycle_sort(reverse=True)

    def _cycle_sort(self, reverse: bool) -> None:
        fid = self.focused.id if self.focused is not None else ""
        if fid == "view-packets":
            key, rev = self.packet_sort
            self.packet_sort = (key, not rev) if reverse else (PACKET_SORTS[(PACKET_SORTS.index(key) + 1) % len(PACKET_SORTS)], False)
            self._refresh_packets()
        elif fid == "hosts-table":
            key, rev = self.host_sort
            self.host_sort = (key, not rev) if reverse else (HOST_SORTS[(HOST_SORTS.index(key) + 1) % len(HOST_SORTS)], False)
            self._refresh_hosts()
        elif fid == "view-flows":
            key, rev = self.flow_sort
            self.flow_sort = (key, not rev) if reverse else (FLOW_SORTS[(FLOW_SORTS.index(key) + 1) % len(FLOW_SORTS)], False)
            self._refresh_flows()
        elif fid == "view-findings":
            key, rev = self.finding_sort
            self.finding_sort = (key, not rev) if reverse else (FINDING_SORTS[(FINDING_SORTS.index(key) + 1) % len(FINDING_SORTS)], False)
            self._refresh_findings()
        else:
            self.app.notify("focus the host, packet or findings list to sort", timeout=2)
            return
        self._refresh_status()

    def action_export(self) -> None:
        s = self.session

        def done(directory: str | None) -> None:
            if not directory:
                return
            try:
                json_path, html_path = export_all(s, Path(directory).expanduser())
            except (OSError, StorageError) as exc:
                self.app.notify(f"export failed: {exc}", severity="error")
                return
            self.app.notify(f"{json_path}\n{html_path}", title="exported", timeout=10)
            if self.center_view == "journal":
                self._refresh_journal()

        self.app.push_screen(PromptScreen("EXPORT", "Directory for the JSON summary and HTML report:", str(s.config.export_dir)), done)

    def action_export_pcap(self) -> None:
        s = self.session
        if s.capture is None:
            self.app.notify("open a capture first (o)", severity="warning")
            return
        count = len(s.window_frames())
        if not count:
            self.app.notify("no packets in the current view to export", severity="warning")
            return
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        default = Path(s.config.export_dir).expanduser() / f"{slug(s.investigation.name)}-{stamp}-packets.pcapng"

        def done(target: str | None) -> None:
            if target:
                self.busy = "EXPORTING"
                self._refresh_status()
                self._pcap_worker(Path(target).expanduser())

        self.app.push_screen(
            PromptScreen("EXPORT PACKETS", f"Write the {count:,} packets currently shown (filter + time window) to PCAPNG:", str(default)),
            done,
        )

    @work(thread=True, exclusive=True, group="pcap")
    def _pcap_worker(self, target: Path) -> None:
        try:
            count, expr, notes = self.session.export_packets(target)
            result = (count, expr, notes, None)
        except (CaptureError, OSError) as exc:
            result = (0, "", [], str(exc))
        self.app.call_from_thread(self._pcap_done, target, *result)

    def _pcap_done(self, target: Path, count: int, expr: str, notes: list[str], error: str | None) -> None:
        self.busy = ""
        self._refresh_status()
        if error:
            self.app.notify(f"packet export failed: {error}", severity="error")
            return
        self.session.store.log(self.session.investigation.id, "export", f"exported {count} packets to {target.name}; Wireshark filter: {expr or '(none)'}")
        if expr:
            self.app.copy_to_clipboard(expr)
        msg = f"{count:,} packets -> {target}"
        if expr:
            msg += f"\nWireshark filter (copied to clipboard):\n{expr}"
        for note in notes:
            msg += f"\nnote: {note}"
        self.app.notify(msg, title="packets exported", timeout=15)
        if self.center_view == "journal":
            self._refresh_journal()

    # -- window diff and marks ---------------------------------------------------------------
    def action_diff(self) -> None:
        if not self._has_timeline():
            return
        window = self.session.timeline.window()
        if self.diff_base is None or self.center_view == "diff":
            self.diff_base = window
            self._diff_cache = None
            self.app.notify(
                f"baseline A = {fmt_ts(window[0])} \u2192 {fmt_ts(window[1])}; move the timeline: window B follows the cursor",
                title="window diff",
                timeout=5,
            )
        if self.center_view != "diff":
            self._switch_center("diff")
        self.query_one("#view-diff").focus()
        self.refresh_all()

    def action_clear_diff(self) -> None:
        self.diff_base = None
        self._diff_cache = None
        self.refresh_all()

    def _refresh_diff(self) -> None:
        s = self.session
        table = self.query_one("#view-diff", VirtualTable)
        if self.diff_base is None or s.view is None:
            table.set_data(0, lambda i: [], notify=False)
            self.query_one("#center-panel").border_title = "WINDOW DIFF \u00b7 press d to set baseline A"
            return
        b = s.timeline.window()
        key = (id(s.view), self.diff_base, b)
        if self._diff_cache is None or self._diff_cache[0] != key:
            self._diff_cache = (key, diff_windows(s.view, self.diff_base, b))
        d = self._diff_cache[1]
        rows = d.rows
        styles = {"NEW HOST": theme.S_CYAN, "NEW LINK": theme.S_CYAN, "NEW SERVICE": theme.S_AMBER, "GONE HOST": theme.S_DIM,
                  "GONE LINK": theme.S_DIM, "GONE SERVICE": theme.S_DIM, "MORE": theme.S_AMBER, "LESS": theme.S_GREEN}

        def row(i: int) -> list:
            r = rows[i]
            return [Text(r.change, style=styles.get(r.change, theme.S_TEXT)), clean(r.item, 80), r.a, r.b, Text(clean(r.detail, 120), style=theme.S_DIM)]

        table.set_data(len(rows), row, lambda i: (rows[i].change, rows[i].item), keep_key=table.current_key(), notify=False)
        a = self.diff_base
        title = (
            f"WINDOW DIFF \u00b7 A {fmt_ts(a[0])}\u2192{fmt_ts(a[1])} ({d.a_packets:,} pkts) vs "
            f"B {fmt_ts(b[0])}\u2192{fmt_ts(b[1])} ({d.b_packets:,} pkts)"
        )
        if d.services_truncated:
            title += " \u00b7 services sampled"
        self.query_one("#center-panel").border_title = title

    def action_add_mark(self) -> None:
        if not self._has_timeline():
            return
        t = self.session.timeline.cursor
        default = f"mark at T{fmt_rel(t - self.session.capture.index.t0)}"

        def done(label: str | None) -> None:
            if not label:
                return
            try:
                self.session.add_mark(t, label)
            except StorageError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self._rebuild_event_markers()
            self.app.notify(f"marked {fmt_ts(t, True)}: {label}", timeout=3)
            self.refresh_all()

        self.app.push_screen(PromptScreen("TIMELINE MARK", f"Label for {fmt_ts(t, True)} (analyst interpretation):", default, 120), done)

    def action_mark_step(self, direction: int) -> None:
        if not self._has_timeline():
            return
        self.timeline_pause()
        tl = self.session.timeline
        times = sorted(self.mark_times)
        moved = tl.to_next(times) if direction > 0 else tl.to_prev(times)
        if not moved:
            self.app.notify("no further timeline marks (k adds one)", timeout=2)
        self.refresh_all()

    # -- triage --------------------------------------------------------------------------
    def _selected_finding(self):
        sel = self.session.selection
        if self.session.capture is None or sel is None or sel.kind != "finding":
            self.app.notify("select a finding first (f)", severity="warning")
            return None
        return self.session.capture.finding(sel.ref)

    def action_triage(self) -> None:
        f = self._selected_finding()
        if f is None:
            return
        options = [
            ("open", "o", "OPEN \u2014 still being reviewed"),
            ("benign", "b", "BENIGN \u2014 explained, no further action"),
            ("escalated", "e", "ESCALATED \u2014 needs follow-up / incident"),
        ]

        def chosen(status: str | None) -> None:
            if status is None:
                return

            def reasoned(reason: str | None) -> None:
                if reason is None:
                    return
                try:
                    self.session.set_status(f.id, status, reason)
                except StorageError as exc:
                    self.app.notify(str(exc), severity="error")
                    return
                self.app.notify(f"{f.rule} marked {status}", timeout=2)
                self.refresh_all()

            self.app.push_screen(PromptScreen("TRIAGE REASON", f"Why is this {status}? (optional, recorded as analyst interpretation)", "", 500, allow_empty=True), reasoned)

        self.app.push_screen(ChoiceScreen("TRIAGE", clean(f.title, 120), options), chosen)

    def action_suppress(self) -> None:
        f = self._selected_finding()
        if f is None:
            return
        options = [("", "a", f"{f.rule} for any host \u2014 '{f.rule_name}'")]
        options += [(h, str(i + 1), f"{f.rule} only when it involves {h}") for i, h in enumerate(f.hosts[:8])]

        def chosen(host: str | None) -> None:
            if host is None:
                return

            def reasoned(reason: str | None) -> None:
                if not reason:
                    return
                try:
                    self.session.store.add_suppression(self.session.investigation.id, f.rule, host, reason)
                except StorageError as exc:
                    self.app.notify(str(exc), severity="error")
                    return
                self.app.notify(f"suppressed {f.rule} {host or '(any host)'} \u2014 Z shows suppressed findings, journal lists rules", timeout=4)
                self._rebuild_event_markers()
                self.refresh_all()

            self.app.push_screen(PromptScreen("SUPPRESSION REASON", "A reason is required; it is exported with the report.", "", 500), reasoned)

        self.app.push_screen(ChoiceScreen("SUPPRESS FINDINGS", "Hide matching findings in this investigation (reversible from the journal).", options), chosen)

    def action_toggle_suppressed(self) -> None:
        self.show_suppressed = not self.show_suppressed
        self.app.notify("showing suppressed findings" if self.show_suppressed else "hiding suppressed findings", timeout=2)
        if self.center_view != "findings":
            self._switch_center("findings")
        self.refresh_all()

    def action_rename(self) -> None:
        def done(name: str | None) -> None:
            if not name:
                return
            try:
                self.session.rename(name)
            except StorageError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self._refresh_chrome()

        self.app.push_screen(PromptScreen("RENAME INVESTIGATION", "New name:", self.session.investigation.name, 80), done)

    def action_new_investigation(self) -> None:
        def done(name: str | None) -> None:
            if not name:
                return
            try:
                inv = self.session.store.create_investigation(name)
            except StorageError as exc:
                self.app.notify(str(exc), severity="error")
                return
            self._switch_investigation(inv)

        self.app.push_screen(PromptScreen("NEW INVESTIGATION", "Name:", time.strftime("INV-%Y%m%d-%H%M", time.gmtime()), 80), done)

    def _switch_investigation(self, inv) -> None:
        self.session.switch(inv)
        self._reload_bookmarks()
        self.app.notify(f"investigation: {inv.name}", timeout=3)
        self.refresh_all()
        self._refresh_chrome()
        if self.center_view == "journal":
            self._refresh_journal()

    def action_investigations(self) -> None:
        store = self.session.store
        items = store.list_investigations()
        counts = {inv.id: len(store.captures(inv.id)) for inv in items}

        def done(result: tuple[str, int | None] | None) -> None:
            if result is None:
                return
            action, inv_id = result
            if action == "new":
                self.action_new_investigation()
            elif action == "rename" and inv_id is not None:
                if inv_id != self.session.investigation.id:
                    self._switch_investigation(store.get_investigation(inv_id))
                self.action_rename()
            elif action == "switch" and inv_id is not None:
                inv = store.get_investigation(inv_id)
                self._switch_investigation(inv)
                if self.session.capture is None:
                    caps = store.captures(inv.id)
                    if caps:
                        self.start_load(caps[0]["path"])

        self.app.push_screen(InvestigationsScreen(items, counts, self.session.investigation.id), done)

    def action_delete_item(self) -> None:
        if self.center_view != "journal" or (self.focused is None or self.focused.id != "view-journal"):
            return
        table = self.query_one("#view-journal", VirtualTable)
        key = table.current_key()
        row = next((r for r in self.journal_rows if r[4][:2] == key), None)
        if row is None or row[4][0] == "event":
            self.app.notify("only bookmarks, notes, marks and suppressions can be deleted", timeout=2)
            return
        typ, item_id = row[4][0], row[4][1]

        def done(ok: bool | None) -> None:
            if not ok:
                return
            store, inv = self.session.store, self.session.investigation
            if typ == "bookmark":
                store.delete_bookmark(inv.id, item_id)
            elif typ == "suppression":
                store.delete_suppression(inv.id, item_id)
            elif typ == "mark":
                store.delete_mark(inv.id, item_id)
            else:
                store.delete_note(inv.id, item_id)
            self._rebuild_event_markers()
            self._reload_bookmarks()
            self.refresh_all()
            self._refresh_journal()

        self.app.push_screen(ConfirmScreen(f"Delete this {typ}? {clean(row[3], 120)}"), done)
