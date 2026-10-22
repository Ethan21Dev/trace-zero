"""Offline PCAP / PCAPNG import.

The capture file is opened read-only and never modified. Files are validated
(regular file, size limit, magic bytes) before scapy sees them, and every read
scapy performs goes through ``_GuardedFile`` so a hostile length field cannot
trigger an enormous allocation.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import time
from collections.abc import Callable
from pathlib import Path

from trace_zero.config import Limits
from trace_zero.models import FileInfo, ParseResult, PacketRecord
from trace_zero.parsing.decoder import decode_frame
from trace_zero.parsing.scapy_bridge import (
    RawPcapNgReader,
    RawPcapReader,
    Scapy_Exception,
    collect_warnings,
)

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4",
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x4d\x3c\xb2\xa1",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".cap", ".dmp"}
_MAX_SINGLE_READ = 64 * 1024 * 1024
_MAX_FRAME = 262_144

ProgressFn = Callable[[str, int, int, int], None]  # stage, packets, bytes_done, bytes_total
CancelFn = Callable[[], bool]


class CaptureError(Exception):
    """A capture cannot be imported. The message is safe to show to the user."""


class ParseCancelled(Exception):
    """The user cancelled an import."""


class _GuardedFile:
    """File proxy that bounds individual reads and notices partial records."""

    def __init__(self, fh) -> None:
        self._fh = fh
        self.partial_read = False

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0 or n > _MAX_SINGLE_READ:
            raise OSError(f"refusing oversized read ({n} bytes); capture record length is implausible")
        data = self._fh.read(n)
        if 0 < len(data) < n:
            self.partial_read = True
        return data

    def __getattr__(self, name: str):
        return getattr(self._fh, name)


def sniff_format(path: Path) -> str:
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        raise CaptureError(f"cannot read file: {exc.strerror or exc}") from exc
    if len(magic) == 0:
        raise CaptureError("file is empty (0 bytes)")
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    if magic[:2] == b"\x1f\x8b":
        raise CaptureError("compressed (gzip) captures are not supported; decompress the file first")
    if len(magic) < 4:
        raise CaptureError("file is too short to be a capture")
    raise CaptureError(f"not a PCAP or PCAPNG file (unrecognised header {magic.hex()})")


def validate_capture_path(raw: str | os.PathLike[str], limits: Limits) -> tuple[Path, str]:
    """Validate a user-supplied path. Returns (resolved path, format)."""
    text = os.fspath(raw).strip()
    if not text:
        raise CaptureError("no file selected")
    if "\x00" in text:
        raise CaptureError("invalid path")
    path = Path(text).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError:
        raise CaptureError(f"file not found: {path}") from None
    except (OSError, RuntimeError) as exc:
        raise CaptureError(f"cannot resolve path: {exc}") from exc
    try:
        st = resolved.stat()
    except OSError as exc:
        raise CaptureError(f"cannot stat file: {exc.strerror or exc}") from exc
    if stat.S_ISDIR(st.st_mode):
        raise CaptureError("path is a directory, not a capture file")
    if not stat.S_ISREG(st.st_mode):
        raise CaptureError("path is not a regular file (devices, pipes and sockets are refused)")
    limit = limits.max_file_mb * 1024 * 1024
    if st.st_size > limit:
        raise CaptureError(
            f"file is {st.st_size / 1048576:.0f} MB; the configured limit is {limits.max_file_mb} MB "
            "(raise [limits] max_file_mb to override)"
        )
    if not os.access(resolved, os.R_OK):
        raise CaptureError("file is not readable (permission denied)")
    return resolved, sniff_format(resolved)


def file_info(path: Path, fmt: str, progress: ProgressFn | None = None, cancelled: CancelFn | None = None) -> FileInfo:
    st = path.stat()
    digest = hashlib.sha256()
    done = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(4 * 1024 * 1024):
            digest.update(chunk)
            done += len(chunk)
            if cancelled and cancelled():
                raise ParseCancelled()
            if progress:
                progress("hashing", 0, done, st.st_size)
    return FileInfo(
        path=str(path),
        name=path.name,
        size=st.st_size,
        sha256=digest.hexdigest(),
        mtime_ns=st.st_mtime_ns,
        fmt=fmt,
    )


def _open_reader(fh: _GuardedFile, path: Path, fmt: str):
    magic = fh.read(4)
    cls = RawPcapNgReader if fmt == "pcapng" else RawPcapReader
    try:
        # Mirror scapy's PcapReader_metaclass.__call__, but hand it our guarded handle
        # instead of letting scapy open (and possibly gunzip) the path itself.
        reader = cls.__new__(cls, cls.__name__, cls.__bases__, cls.__dict__)
        reader.__init__(str(path), fh, magic)
        return reader
    except (Scapy_Exception, struct.error, OSError, EOFError) as exc:
        raise CaptureError(f"invalid {fmt} header: {exc}") from exc


def _timestamp(reader, meta, fmt: str) -> float | None:
    if fmt == "pcapng":
        if meta.tshigh is None or meta.tslow is None:
            return None
        resol = meta.tsresol or 1_000_000
        return ((meta.tshigh << 32) | meta.tslow) / resol
    divisor = 1e9 if getattr(reader, "nano", False) else 1e6
    return meta.sec + meta.usec / divisor


def read_capture(
    raw_path: str | os.PathLike[str],
    limits: Limits | None = None,
    progress: ProgressFn | None = None,
    cancelled: CancelFn | None = None,
) -> ParseResult:
    """Import a capture. Raises CaptureError or ParseCancelled."""
    limits = limits or Limits()
    path, fmt = validate_capture_path(raw_path, limits)
    started = time.monotonic()
    info = file_info(path, fmt, progress, cancelled)
    packets: list[PacketRecord] = []
    warnings: list[str] = []
    linktypes: set[int] = set()
    truncated = False
    stop_reason: str | None = None
    missing_ts = 0
    try:
        raw_fh = open(path, "rb")
    except OSError as exc:
        raise CaptureError(f"cannot open file: {exc.strerror or exc}") from exc
    with raw_fh, collect_warnings(warnings):
        fh = _GuardedFile(raw_fh)
        reader = _open_reader(fh, path, fmt)
        static_linktype = getattr(reader, "linktype", None)
        no = 0
        last_ts = 0.0
        while True:
            try:
                data, meta = reader._read_packet(size=_MAX_FRAME)
            except EOFError:
                break
            except (Scapy_Exception, struct.error, OSError, ValueError, IndexError, KeyError) as exc:
                warnings.append(f"capture damaged after packet {no}: {exc}")
                truncated, stop_reason = True, "damaged capture"
                break
            no += 1
            linktype = getattr(meta, "linktype", None)
            if linktype is None:
                linktype = static_linktype if static_linktype is not None else -1
            linktypes.add(linktype)
            ts = _timestamp(reader, meta, fmt)
            if ts is None:
                missing_ts += 1
                ts = last_ts
            last_ts = ts
            wirelen = getattr(meta, "wirelen", None) or len(data)
            rec = decode_frame(no, ts, data, wirelen, linktype, limits.max_dns_payload)
            declared_caplen = getattr(meta, "caplen", None)
            if declared_caplen is not None and len(data) < min(declared_caplen, _MAX_FRAME):
                rec.errors = rec.errors + ("record cut short: capture file ends mid-packet",)
                truncated, stop_reason = True, "file ends mid-packet"
            packets.append(rec)
            if no >= limits.max_packets:
                truncated, stop_reason = True, f"packet limit reached ({limits.max_packets:,})"
                warnings.append(f"import stopped at the configured packet limit ({limits.max_packets:,})")
                break
            if no % limits.batch_size == 0:
                if cancelled and cancelled():
                    raise ParseCancelled()
                if progress:
                    progress("parsing", no, raw_fh.tell(), info.size)
        position = raw_fh.tell()
    if fh.partial_read and stop_reason is None:
        truncated, stop_reason = True, "file ends mid-record"
        warnings.append("capture ends with an incomplete record (file truncated?); trailing bytes ignored")
    elif stop_reason is None and position < info.size:
        truncated, stop_reason = True, "damaged capture"
        warnings.append(f"parsing stopped at byte {position:,} of {info.size:,}; remaining data is not decodable")
    if missing_ts:
        warnings.append(f"{missing_ts} packet(s) carry no timestamp (pcapng simple packet blocks); ordered after the preceding packet")
    if progress:
        progress("parsing", len(packets), info.size, info.size)
    return ParseResult(
        file=info,
        packets=packets,
        linktypes=linktypes,
        warnings=warnings,
        truncated=truncated,
        stop_reason=stop_reason,
        elapsed_s=time.monotonic() - started,
    )


def read_frame_bytes(info: FileInfo, no: int) -> tuple[bytes, int]:
    """Re-read the raw bytes of frame ``no`` (1-based) for on-demand inspection."""
    path = Path(info.path)
    try:
        st = path.stat()
    except OSError as exc:
        raise CaptureError(f"capture no longer accessible: {exc.strerror or exc}") from exc
    if st.st_size != info.size or st.st_mtime_ns != info.mtime_ns:
        raise CaptureError("capture file changed on disk since import; re-open it to inspect raw bytes")
    with open(path, "rb") as raw_fh:
        fh = _GuardedFile(raw_fh)
        reader = _open_reader(fh, path, info.fmt)
        static_linktype = getattr(reader, "linktype", -1)
        for current in range(1, no + 1):
            try:
                data, meta = reader._read_packet(size=_MAX_FRAME)
            except (EOFError, Scapy_Exception, struct.error, OSError) as exc:
                raise CaptureError(f"frame {no} could not be re-read") from exc
            if current == no:
                linktype = getattr(meta, "linktype", None)
                return data, linktype if linktype is not None else static_linktype
    raise CaptureError(f"frame {no} not found")


def read_frames(info: FileInfo, wanted: set[int] | frozenset[int], limit_bytes: int = 256 * 1024 * 1024) -> dict[int, tuple[bytes, int]]:
    """Re-read several frames (1-based numbers) in one pass. Stops after the highest wanted frame."""
    path = Path(info.path)
    try:
        st = path.stat()
    except OSError as exc:
        raise CaptureError(f"capture no longer accessible: {exc.strerror or exc}") from exc
    if st.st_size != info.size or st.st_mtime_ns != info.mtime_ns:
        raise CaptureError("capture file changed on disk since import; re-open it to read packet contents")
    out: dict[int, tuple[bytes, int]] = {}
    if not wanted:
        return out
    last = max(wanted)
    total = 0
    with open(path, "rb") as raw_fh:
        reader = _open_reader(_GuardedFile(raw_fh), path, info.fmt)
        static_linktype = getattr(reader, "linktype", -1)
        for current in range(1, last + 1):
            try:
                data, meta = reader._read_packet(size=_MAX_FRAME)
            except (EOFError, Scapy_Exception, struct.error, OSError):
                break
            if current in wanted:
                linktype = getattr(meta, "linktype", None)
                out[current] = (data, linktype if linktype is not None else static_linktype)
                total += len(data)
                if total > limit_bytes:
                    break
    return out
