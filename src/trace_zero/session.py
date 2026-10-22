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
from trace_zero.analysis.index import CaptureIndex, CaptureView, WindowStats
from trace_zero.analysis.timeline import Timeline
from trace_zero.config import Config
from trace_zero.models import ParseResult
from trace_zero.parsing.reader import CancelFn, ProgressFn, read_capture
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
