"""Application state independent of the terminal UI.

``Session`` ties together the investigation store, the loaded capture, the
active filter, the timeline and the current selection. The TUI renders it;
the headless CLI and the test suite drive it directly.
"""

from __future__ import annotations

import gc
import hashlib
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from trace_zero.analysis.anomaly import Finding, detect
from trace_zero import custody
from trace_zero.cache import CaptureCache
from trace_zero.live.model import LiveCapture, LiveUpdate
from trace_zero.enrich import Enrichment
from trace_zero.analysis.filters import PacketFilter, compile_filter, frames_filter
from trace_zero.analysis.flows import Flow, build_flows
from trace_zero.analysis.index import CaptureIndex, CaptureView, WindowStats
from trace_zero.analysis.timeline import Timeline
from trace_zero.config import Config
from trace_zero.models import FileInfo, ParseResult
from trace_zero.analysis.streams import Stream, reassemble
from trace_zero.analysis.wireshark import to_wireshark
from trace_zero.parsing.writer import export_sources, write_records
from trace_zero.parsing.reader import CancelFn, CaptureError, ProgressFn, file_info, read_capture, read_frames, validate_capture_path
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


@contextmanager
def _gc_paused():
    """Restoring from cache allocates hundreds of thousands of objects that all stay alive;
    the cyclic GC would rescan them repeatedly for nothing. (Not used while parsing: scapy's
    DNS dissection creates reference cycles that must be collected.)"""
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def _parse_or_restore(path, config: Config, cache: CaptureCache, progress, cancelled) -> ParseResult:
    resolved, fmt = validate_capture_path(path, config.limits)
    info = file_info(resolved, fmt, progress, cancelled)
    with _gc_paused():
        restored = cache.load_packets(info, config.limits)
    if restored is not None:
        if progress:
            progress("cache", 0, info.size, info.size)
        packets, linktypes, warnings, truncated, stop_reason = restored
        return ParseResult(info, packets, linktypes, warnings, truncated, stop_reason, 0.0, cached=True)
    result = read_capture(resolved, config.limits, progress, cancelled, info=info)
    cache.store_packets(info, config.limits, result)
    return result


def _analyse(result: ParseResult, config: Config, cache: CaptureCache, progress, started: float) -> LoadedCapture:
    info = result.file
    if progress:
        progress("indexing", len(result.packets), info.size, info.size)
    index = None
    if result.cached:
        snapshot = cache.load_index(info, config.limits)
        if snapshot is not None:
            try:
                with _gc_paused():
                    index = CaptureIndex(result, snapshot=snapshot)
            except (KeyError, TypeError, ValueError):
                index = None  # stale or damaged snapshot: rebuild below
    if index is None:
        index = CaptureIndex(result)
        cache.store_index(info, config.limits, index)
    analysis = cache.load_analysis(info, config.limits, config.anomaly) if result.cached else None
    if analysis is not None:
        findings, flows = analysis
    else:
        if progress:
            progress("analysing", len(result.packets), info.size, info.size)
        findings = detect(index, config.anomaly)
        if progress:
            progress("flows", len(result.packets), info.size, info.size)
        flows = build_flows(index.packets, index.order)
        cache.store_analysis(info, config.limits, config.anomaly, findings, flows)
    # Flow table for the unfiltered view, computed (or restored) off the UI thread.
    index.view(None, key="").flows_cache = flows
    result.elapsed_s = time.monotonic() - started
    return LoadedCapture(result, index, findings)


def load_capture(
    path: str | Path,
    config: Config,
    progress: ProgressFn | None = None,
    cancelled: CancelFn | None = None,
    use_cache: bool = True,
) -> LoadedCapture:
    """Parse, index and analyse a capture. Safe to call from a worker thread.

    With the cache enabled, a capture whose SHA-256 was seen before is restored
    without parsing; findings and flows are reused when the heuristic settings
    are unchanged.
    """
    started = time.monotonic()
    cache = CaptureCache(config.cache_dir, config.limits.cache_max_mb if use_cache else 0)
    result = _parse_or_restore(path, config, cache, progress, cancelled)
    return _analyse(result, config, cache, progress, started)


def merge_results(results: list[ParseResult]) -> ParseResult:
    """Combine several captures into one timeline.

    Frames are renumbered consecutively (capture 1 first); each source keeps its
    own file identity for raw re-reads and exports. The combined identity is a
    SHA-256 over the sorted source hashes, so bookmarks reattach whenever the same
    set of captures is opened again, in any order.
    """
    packets: list = []
    sources = []
    warnings: list[str] = []
    linktypes: set[int] = set()
    for r in results:
        offset = len(packets)
        for p in r.packets:
            p.no += offset
        packets.extend(r.packets)
        sources.append((r.file, offset, len(r.packets)))
        linktypes |= r.linktypes
        warnings += [f"{r.file.name}: {w}" for w in r.warnings]
    names = [r.file.name for r in results]
    combined_sha = hashlib.sha256("".join(sorted(r.file.sha256 for r in results)).encode()).hexdigest()
    info = FileInfo(
        path=results[0].file.path,
        name=f"{names[0]} +{len(names) - 1} more",
        size=sum(r.file.size for r in results),
        sha256=combined_sha,
        mtime_ns=0,
        fmt="multi",
    )
    truncated = [r for r in results if r.truncated]
    return ParseResult(
        info,
        packets,
        linktypes,
        warnings,
        bool(truncated),
        "; ".join(f"{r.file.name}: {r.stop_reason}" for r in truncated) or None,
        0.0,
        cached=all(r.cached for r in results),
        sources=sources,
    )


def load_captures(
    paths: list[str | Path],
    config: Config,
    progress: ProgressFn | None = None,
    cancelled: CancelFn | None = None,
    use_cache: bool = True,
) -> LoadedCapture:
    """Load one or more captures onto a single timeline."""
    if len(paths) == 1:
        return load_capture(paths[0], config, progress, cancelled, use_cache)
    started = time.monotonic()
    cache = CaptureCache(config.cache_dir, config.limits.cache_max_mb if use_cache else 0)
    seen: set[str] = set()
    results = []
    for path in paths:
        r = _parse_or_restore(path, config, cache, progress, cancelled)
        if r.file.sha256 in seen:
            continue  # the same evidence twice adds nothing but duplicate packets
        seen.add(r.file.sha256)
        results.append(r)
    merged = merge_results(results) if len(results) > 1 else results[0]
    if merged.packets and len(merged.packets) > config.limits.max_packets:
        raise CaptureError(f"combined captures hold {len(merged.packets):,} packets; the limit is {config.limits.max_packets:,}")
    return _analyse(merged, config, cache, progress, started)


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
        # Chain-of-custody notes raised when the current capture was attached.
        self.custody_warnings: list[str] = []
        # Live mode: the followed capture while it is still being written.
        self.live: LiveCapture | None = None
        # Offline reference data (MAC vendors, geolocation/ASN) - optional, user-supplied files.
        self.enrichment, self.enrichment_problems = Enrichment.from_paths(config.oui_path, list(config.mmdb_paths))

    # -- capture lifecycle -------------------------------------------------------
    def attach(self, loaded: LoadedCapture) -> None:
        self.capture = loaded
        idx = loaded.index
        self.filter = None
        self.view = idx.view(None, key="")
        self.timeline = Timeline.for_span(idx.t0, idx.t1)
        self.selection = None
        r = loaded.result
        self.custody_warnings = []
        for info, _offset, _count in r.source_list():
            for sha, at, inv_name in custody.changed_since_last_import(self.store.prior_hashes(info.path), info.sha256):
                when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(at))
                self.custody_warnings.append(
                    f"{info.name}: content differs from the import on {when} (investigation '{inv_name}', sha256 {sha[:16]}...); "
                    f"the file at this path changed"
                )
        for warning in self.custody_warnings:
            self.store.log(self.investigation.id, "custody", warning)
        for info, _offset, count in r.source_list():
            self.store.record_capture(self.investigation.id, info, count, idx.t0 if r.packets else None, idx.t1 if r.packets else None, r.truncated)
        detail = ", ".join(f"{i.name} (sha256 {i.sha256[:16]}...)" for i, _o, _c in r.source_list())
        self.store.log(
            self.investigation.id,
            "capture",
            f"imported {detail}: {len(r.packets):,} packets" + (f" - TRUNCATED: {r.stop_reason}" if r.truncated else ""),
        )
        if loaded.findings:
            self.store.log(self.investigation.id, "analysis", f"{len(loaded.findings)} possible anomalies flagged by heuristics")

    # -- live mode ---------------------------------------------------------------------
    def start_live(self, live: LiveCapture) -> None:
        self.live = live
        self.store.log(self.investigation.id, "live", f"live mode started: {live.describe()}; provisional id {live.provisional_sha}")

    def apply_live(self, update: LiveUpdate) -> None:
        """Show a newer live snapshot, keeping filter, selection and timeline position.

        A timeline cursor that was at the end keeps following the newest packets.
        """
        loaded, idx = update.loaded, update.loaded.index
        first = self.capture is None or not self.capture.result.live
        self.capture = loaded
        self.view = update.view
        if first or self.timeline is None:
            self.filter = None
            self.view = idx.view(None, key="")
            self.timeline = Timeline.for_span(idx.t0, idx.t1)
            self.selection = None
            return
        tl = self.timeline
        following = tl.cursor >= tl.t1
        tl.t0, tl.t1 = idx.t0, idx.t1
        tl.cursor = idx.t1 if following else min(max(tl.cursor, idx.t0), idx.t1)

    def finish_live(self, final: LoadedCapture) -> None:
        """Replace the live snapshot with the offline analysis of the finished file.

        Everything recorded under the provisional id moves to the file's real SHA-256.
        """
        live = self.live
        self.live = None
        moved = self.store.rekey_capture(self.investigation.id, live.provisional_sha, final.sha) if live else 0
        flt_text = self.filter.text if self.filter is not None and self.filter.frame_set is None else ""
        self.attach(final)
        r = final.result
        self.store.log(
            self.investigation.id,
            "live",
            f"live capture finished: {r.file.name}, {len(r.packets):,} packets, sha256 {r.file.sha256}"
            + (f"; {moved} item(s) moved from the provisional id" if moved else ""),
        )
        if flt_text:
            try:
                flt = self.compile(flt_text)
                self.apply_view(flt, self.build_view(flt))
            except Exception:  # noqa: BLE001 - the filter compiled before; never fail finalisation over it
                pass

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
        if self.capture.result.live and self.live is not None:
            return self.live.follower.frame_bytes(frames)
        out: dict[int, tuple[bytes, int]] = {}
        for info, offset, count in self.capture.result.source_list():
            local = {n - offset for n in frames if offset < n <= offset + count}
            if local:
                out.update({n + offset: v for n, v in read_frames(info, local).items()})
        return out

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
        if self.capture is not None and self.capture.result.sources and "frame.number" in expr:
            order = " ".join(i.name for i, _o, _c in self.capture.result.sources)
            notes = notes + [f"frame numbers follow the merged timeline; reproduce it with: mergecap -a -w merged.pcapng {order}"]
        return expr, notes

    def export_packets(self, path: Path, journal: bool = True) -> tuple[int, str, list[str]]:
        """Write the packets currently shown to a new PCAPNG with a ``.sha256`` sidecar.

        Safe in a worker thread with ``journal=False``; then call ``journal_export``
        on the main thread (the investigation database is bound to it).
        """
        assert self.capture is not None
        frames = set(self.window_frames())
        expr, notes = self.wireshark_filter()
        r = self.capture.result
        comment = (
            f"Exported by TRACE//ZERO from {', '.join(f'{i.name} (sha256 {i.sha256})' for i, _o, _c in r.source_list())}; "
            f"investigation '{self.investigation.name}'; selection: {expr or 'all packets'}"
        )
        if r.live and self.live is not None:
            if Path(path).resolve() == self.live.path:
                raise CaptureError("refusing to overwrite the source capture")
            comment += "; exported during live capture (source still growing)"
            count = write_records(self.live.follower.frame_records(frames), Path(path), comment)
        else:
            parts = [(info, frames, offset) for info, offset, _count in r.source_list()]
            count = export_sources(parts, Path(path), comment)
        digest = custody.write_digest(path)
        if journal:
            self.journal_export(Path(path), digest, f"{count:,} packets; Wireshark filter: {expr or '(none)'}")
        return count, expr, notes

    # -- chain of custody ----------------------------------------------------------------------
    def record_export(self, path: Path, what: str) -> str:
        """Write the ``.sha256`` sidecar for an exported file and journal its digest."""
        digest = custody.write_digest(path)
        self.journal_export(path, digest, what)
        return digest

    def journal_export(self, path: Path, digest: str, what: str) -> None:
        self.store.log(self.investigation.id, "export", f"{Path(path).name} sha256 {digest} - {what}")

    def evidence(self) -> list[tuple[str, str, str]]:
        """(name, path, recorded sha256) of every capture on the current timeline."""
        if self.capture is None:
            return []
        return [(i.name, i.path, i.sha256) for i, _o, _c in self.capture.result.source_list()]

    def verify_evidence(self, cancelled=None, journal: bool = True) -> list[custody.Verification]:
        """Re-hash the evidence files. With ``journal=False`` it is safe in a worker
        thread; pass the results to ``journal_verification`` on the main thread."""
        results = custody.verify(self.evidence(), cancelled)
        if journal:
            self.journal_verification(results)
        return results

    def journal_verification(self, results: list[custody.Verification]) -> None:
        for v in results:
            self.store.log(self.investigation.id, "verify", v.describe())

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
