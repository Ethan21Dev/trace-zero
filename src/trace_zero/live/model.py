"""Live capture state: a followed file, its provisional identity, periodic analysis snapshots.

While a file grows it has no final SHA-256, so the investigation keys the
capture by a provisional identity (``live:<random>``). Bookmarks, notes,
marks and triage made during live mode are moved to the real hash when the
capture is finalised: the finished file is then hashed and analysed by the
normal offline pipeline, exactly as if it had been opened afterwards.

Each refresh re-indexes and re-analyses everything received so far rather
than updating the index in place. That keeps live results identical to an
offline analysis of the same bytes; the refresh interval adapts to how long
an analysis takes, so large captures refresh less often instead of
blocking.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from trace_zero.analysis.anomaly import detect
from trace_zero.analysis.flows import build_flows
from trace_zero.analysis.index import CaptureIndex, CaptureView
from trace_zero.config import Config
from trace_zero.models import FileInfo, ParseResult
from trace_zero.parsing.follow import CaptureFollower

MIN_INTERVAL = 1.0  # seconds between refreshes
MAX_INTERVAL = 30.0


@dataclass
class LiveUpdate:
    """One analysed snapshot of the live capture (built in a worker thread)."""

    loaded: object  # session.LoadedCapture (imported lazily to avoid a cycle)
    view: CaptureView
    new_packets: int
    analysis_s: float


class LiveCapture:
    def __init__(self, path: str | Path, config: Config, process=None) -> None:
        self.config = config
        self.follower = CaptureFollower(path, config.limits)
        self.process = process  # live.tool.CaptureProcess when TRACE//ZERO started the tool
        # This computer's addresses, known when TRACE//ZERO started the capture on a connected adapter.
        self.local_addresses = frozenset(getattr(process, "local_addresses", ()) or ())
        self.provisional_sha = "live:" + uuid.uuid4().hex
        self.started_at = time.time()
        self.interval = MIN_INTERVAL
        self.snapshots = 0

    @property
    def path(self) -> Path:
        return self.follower.path

    @property
    def tool_running(self) -> bool:
        return self.process is not None and self.process.running

    def describe(self) -> str:
        if self.process is not None:
            how = f"{self.process.tool.kind} on {self.process.interface}" + (f" filter '{self.process.bpf}'" if self.process.bpf else "")
        else:
            how = "following a file written by another program"
        return f"{self.path.name} ({how})"

    def refresh(self, flt=None) -> LiveUpdate | None:
        """Read new records and, if there are any, analyse everything received so far.

        Safe in a worker thread; never touches the investigation database.
        """
        from trace_zero.session import LoadedCapture

        new = 0
        while True:  # drain the backlog in bounded chunks
            got = self.follower.poll()
            new += got
            if not got or self.follower.stopped:
                break
        if not new and self.snapshots:
            return None
        f = self.follower
        if not f.packets:
            return None
        started = time.monotonic()
        result = ParseResult(
            file=FileInfo(path=str(f.path), name=f.path.name, size=f.offset, sha256=self.provisional_sha, mtime_ns=0, fmt=f.fmt or "pcapng"),
            packets=list(f.packets),
            linktypes=set(f.linktypes),
            warnings=list(f.warnings),
            truncated=f.stopped is not None,
            stop_reason=f.stopped,
            elapsed_s=0.0,
            live=True,
        )
        index = CaptureIndex(result)
        findings = detect(index, self.config.anomaly)
        flows = build_flows(index.packets, index.order)
        full = index.view(None, key="")
        full.flows_cache = flows
        view = full if flt is None else CaptureView(index, flt)
        elapsed = time.monotonic() - started
        result.elapsed_s = elapsed
        # Refresh no more often than about four analyses' worth of time.
        self.interval = min(MAX_INTERVAL, max(MIN_INTERVAL, 4 * elapsed))
        self.snapshots += 1
        return LiveUpdate(LoadedCapture(result, index, findings), view, new, elapsed)

    def stop_tool(self) -> int | None:
        if self.process is None:
            return None
        return self.process.stop()
