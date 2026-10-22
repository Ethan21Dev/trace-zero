"""Application state independent of the terminal UI.

``Session`` ties together the investigation store, the loaded capture, the
active filter, the timeline and the current selection. The TUI renders it;
the headless CLI and the test suite drive it directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from trace_zero.analysis.anomaly import Finding, detect
from trace_zero.analysis.filters import PacketFilter, compile_filter, frames_filter
from trace_zero.analysis.flows import Flow, build_flows
from trace_zero.analysis.index import CaptureIndex, CaptureView, WindowStats
from trace_zero.analysis.timeline import Timeline
from trace_zero.config import Config
from trace_zero.models import ParseResult
from trace_zero.analysis.streams import Stream, reassemble
from trace_zero.analysis.wireshark import to_wireshark
from trace_zero.parsing.writer import export_frames
from trace_zero.parsing.reader import CancelFn, ProgressFn, read_capture, read_frames
from trace_zero.storage import Investigation, Store


@dataclass
class LoadedCapture:
    result: ParseResult
    index: CaptureIndex
    findings: list[Finding]

    @property
    def sha(self) -> str:
        return self.result.file.sha256

    def finding(self, fid: str) -> Finding | None:
        return next((f for f in self.findings if f.id == fid), None)


def load_capture(path: str | Path, config: Config, progress: ProgressFn | None = None, cancelled: CancelFn | None = None) -> LoadedCapture:
    """Parse, index and analyse a capture. Safe to call from a worker thread."""
    result = read_capture(path, config.limits, progress, cancelled)
    if progress:
        progress("indexing", len(result.packets), result.file.size, result.file.size)
    index = CaptureIndex(result)
    if progress:
        progress("analysing", len(result.packets), result.file.size, result.file.size)
    findings = detect(index, config.anomaly)
    if progress:
        progress("flows", len(result.packets), result.file.size, result.file.size)
    # Precompute the flow table for the unfiltered view while still off the UI thread.
    index.view(None, key="").flows_cache = build_flows(index.packets, index.order)
    return LoadedCapture(result, index, findings)


@dataclass(frozen=True)
class Selection:
    kind: str  # host | packet | finding | conversation
    ref: str

    @property
    def label(self) -> str:
        if self.kind == "packet":
            return f"frame #{self.ref}"
        if self.kind == "conversation":
            return self.ref.replace("|", " <-> ")
        if self.kind == "flow":
            proto, a, ap, b, bp, _first = (self.ref.split("|") + [""] * 6)[:6]
            return f"{proto} {a}:{ap} <-> {b}:{bp}".replace(":None", "")
        return self.ref


class Session:
    def __init__(self, config: Config, store: Store, investigation: Investigation) -> None:
        self.config = config
        self.store = store
        self.investigation = investigation
        self.capture: LoadedCapture | None = None
        self.filter: PacketFilter | None = None
        self.view: CaptureView | None = None
        self.timeline: Timeline | None = None
        self.selection: Selection | None = None

    # -- capture lifecycle -------------------------------------------------------
    def attach(self, loaded: LoadedCapture) -> None:
        self.capture = loaded
        idx = loaded.index
        self.filter = None
        self.view = idx.view(None, key="")
        self.timeline = Timeline.for_span(idx.t0, idx.t1)
        self.selection = None
        r = loaded.result
        self.store.record_capture(
            self.investigation.id, r.file, len(r.packets), idx.t0 if r.packets else None, idx.t1 if r.packets else None, r.truncated
        )
        self.store.log(
            self.investigation.id,
            "capture",
            f"imported {r.file.name} ({len(r.packets):,} packets, sha256 {r.file.sha256[:16]}...)"
            + (f" - TRUNCATED: {r.stop_reason}" if r.truncated else ""),
        )
        if loaded.findings:
            self.store.log(self.investigation.id, "analysis", f"{len(loaded.findings)} possible anomalies flagged by heuristics")

    @property
    def sha(self) -> str:
        return self.capture.sha if self.capture else ""

    # -- filtering ---------------------------------------------------------------
    def compile(self, text: str) -> PacketFilter | None:
        t0 = self.capture.index.t0 if self.capture else 0.0
        return compile_filter(text, t0)

    def build_view(self, flt: PacketFilter | None) -> CaptureView:
        """Build (or fetch) the view for a filter. May be slow; safe in a worker."""
        assert self.capture is not None
        idx = self.capture.index
        key = self.filter_key(flt)
        cached = idx.cached_view(key)
        if cached is not None:
            return cached
        view = CaptureView(idx, flt)
        idx.cache_view(key, view)
        return view

    @staticmethod
    def filter_key(flt: PacketFilter | None) -> str:
        if flt is None:
            return ""
        if flt.frame_set is not None:
            return f"frames:{flt.text}:{hash(flt.frame_set)}"
        return flt.text

    def apply_view(self, flt: PacketFilter | None, view: CaptureView) -> None:
        self.filter = flt
        self.view = view
        if flt is not None:
            self.store.log(self.investigation.id, "filter", f"filter applied: {flt.display}")

    # -- flows and streams ---------------------------------------------------------------
    def flows(self) -> list[Flow]:
        """Flows of the current (filtered) view, built once per view."""
        assert self.capture is not None and self.view is not None
        cached = getattr(self.view, "flows_cache", None)
        if cached is None:
            cached = build_flows(self.capture.index.packets, self.view.rows)
            self.view.flows_cache = cached
        return cached

    def flow(self, ref: str) -> Flow | None:
        return next((f for f in self.flows() if f.ref == ref), None)

    def frame_bytes(self, frames: set[int]) -> dict[int, tuple[bytes, int]]:
        """Re-read raw frames from the capture file(s). Safe in a worker thread."""
        assert self.capture is not None
        return read_frames(self.capture.result.file, frames)

    def follow(self, flow: Flow) -> Stream:
        idx = self.capture.index
        frames = self.frame_bytes(set(flow.frames))
        timestamps = {no: idx.packet(no).ts for no in flow.frames if idx.packet(no) is not None}
        return reassemble(flow, frames, timestamps)

    # -- packet export ---------------------------------------------------------------------
    def window_frames(self) -> list[int]:
        """Frame numbers currently shown: active filter intersected with the time window."""
        stats = self.window_stats()
        if stats is None:
            return []
        pk = self.capture.index.packets
        return [pk[i].no for i in self.view.slice_rows(stats.i0, stats.i1)]

    def wireshark_filter(self) -> tuple[str, list[str]]:
        t0 = self.capture.index.t0 if self.capture else 0.0
        expr, notes = to_wireshark(self.filter, t0)
        if self.timeline is not None and self.capture is not None:
            lo, hi = self.timeline.window()
            if (lo, hi) != (self.capture.index.t0, self.capture.index.t1):
                window = f"frame.time_epoch >= {lo:.6f} && frame.time_epoch <= {hi:.6f}"
                expr = f"({expr}) && {window}" if expr else window
        return expr, notes

    def export_packets(self, path: Path) -> tuple[int, str, list[str]]:
        """Write the packets currently shown to a new PCAPNG. Safe in a worker thread."""
        assert self.capture is not None
        frames = set(self.window_frames())
        expr, notes = self.wireshark_filter()
        r = self.capture.result
        comment = (
            f"Exported by TRACE//ZERO from {r.file.name} (sha256 {r.file.sha256}); "
            f"investigation '{self.investigation.name}'; selection: {expr or 'all packets'}"
        )
        count = export_frames(r.file, frames, Path(path), comment)
        return count, expr, notes

    def evidence_filter(self, finding: Finding) -> PacketFilter:
        return frames_filter(set(finding.frames), f"evidence:{finding.id}")

    # -- time machine ------------------------------------------------------------
    def window_stats(self) -> WindowStats | None:
        if self.view is None or self.timeline is None:
            return None
        lo, hi = self.timeline.window()
        return self.view.window(lo, hi)

    def significant_times(self) -> list[float]:
        if self.capture is None:
            return []
        times = {e.ts for e in self.capture.index.events}
        times.update(f.first_ts for f in self.capture.findings)
        return sorted(times)

    def event_at(self, t: float) -> str | None:
        if self.capture is None:
            return None
        labels = [e.label for e in self.capture.index.events if e.ts == t]
        labels += [f"possible anomaly: {f.title}" for f in self.capture.findings if f.first_ts == t]
        return "; ".join(labels[:3]) if labels else None

    # -- finding triage ---------------------------------------------------------------------
    def triage(self) -> dict[str, tuple[str, str]]:
        if self.capture is None:
            return {}
        return self.store.finding_statuses(self.investigation.id, self.sha)

    def set_status(self, finding_id: str, status: str, reason: str = "") -> None:
        self.store.set_finding_status(self.investigation.id, self.sha, finding_id, status, reason)

    def suppressions(self):
        return self.store.suppressions(self.investigation.id)

    def suppression_for(self, finding: Finding, sups=None):
        for sup in sups if sups is not None else self.suppressions():
            if sup.matches(finding.rule, finding.hosts):
                return sup
        return None

    def visible_findings(self, include_suppressed: bool = False) -> list[tuple[Finding, tuple[str, str] | None, object]]:
        """(finding, (status, reason) or None, matching suppression or None)."""
        if self.capture is None:
            return []
        statuses = self.triage()
        sups = self.suppressions()
        out = []
        for f in self.capture.findings:
            sup = self.suppression_for(f, sups)
            if sup is not None and not include_suppressed:
                continue
            out.append((f, statuses.get(f.id), sup))
        return out

    # -- timeline marks -------------------------------------------------------------------
    def marks(self):
        if self.capture is None:
            return []
        return self.store.marks(self.investigation.id, self.sha)

    def add_mark(self, ts: float, label: str) -> int:
        return self.store.add_mark(self.investigation.id, self.sha, ts, label)

    # -- analyst data ------------------------------------------------------------
    def toggle_bookmark(self, sel: Selection, label: str = "") -> bool:
        return self.store.toggle_bookmark(self.investigation.id, self.sha, sel.kind, sel.ref, label)

    def is_bookmarked(self, sel: Selection) -> bool:
        return self.store.is_bookmarked(self.investigation.id, self.sha, sel.kind, sel.ref)

    def add_note(self, sel: Selection | None, body: str):
        if sel is None:
            return self.store.add_note(self.investigation.id, self.sha, "investigation", "", body)
        return self.store.add_note(self.investigation.id, self.sha, sel.kind, sel.ref, body)

    def notes_for(self, sel: Selection):
        return self.store.notes(self.investigation.id, self.sha, sel.kind, sel.ref)

    def rename(self, name: str) -> None:
        self.investigation = self.store.rename_investigation(self.investigation.id, name)

    def switch(self, inv: Investigation) -> None:
        self.investigation = inv
        self.store.touch(inv.id)
        if self.capture is not None:
            r = self.capture.result
            idx = self.capture.index
            self.store.record_capture(inv.id, r.file, len(r.packets), idx.t0, idx.t1, r.truncated)
