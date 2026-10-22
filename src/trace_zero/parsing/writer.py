"""Export selected frames from the original capture to a new PCAPNG file.

Frames are copied byte-for-byte from the source capture (never re-encoded),
with their original timestamps at nanosecond resolution, original wire
lengths and link types. The section header carries a provenance comment
(source file, its SHA-256 and the selection that produced the export).
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from trace_zero.models import FileInfo
from trace_zero.parsing.reader import _MAX_FRAME, CaptureError, _GuardedFile, _open_reader
from trace_zero.parsing.scapy_bridge import Scapy_Exception

_LE = "<"


def _pad(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 4)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack(_LE + "HH", code, len(value)) + _pad(value)


def _block(btype: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack(_LE + "II", btype, total) + body + struct.pack(_LE + "I", total)


def section_header(comment: str) -> bytes:
    opts = _option(1, comment.encode("utf-8")[:4000]) + _option(4, b"TRACE//ZERO") + _option(0, b"")
    body = struct.pack(_LE + "IHHq", 0x1A2B3C4D, 1, 0, -1) + opts
    return _block(0x0A0D0D0A, body)


def interface_block(linktype: int, snaplen: int = 262144) -> bytes:
    opts = _option(9, b"\x09") + _option(0, b"")  # if_tsresol = 10^-9
    return _block(0x00000001, struct.pack(_LE + "HHI", linktype, 0, snaplen) + opts)


def packet_block(iface: int, ts_ns: int, data: bytes, wirelen: int) -> bytes:
    body = struct.pack(_LE + "IIIII", iface, (ts_ns >> 32) & 0xFFFFFFFF, ts_ns & 0xFFFFFFFF, len(data), wirelen) + _pad(data)
    return _block(0x00000006, body)


def _timestamp_ns(reader, meta, fmt: str) -> int | None:
    if fmt == "pcapng":
        if meta.tshigh is None or meta.tslow is None:
            return None
        units = (meta.tshigh << 32) | meta.tslow
        resol = meta.tsresol or 1_000_000
        return units * 1_000_000_000 // resol
    scale = 1 if getattr(reader, "nano", False) else 1000
    return meta.sec * 1_000_000_000 + meta.usec * scale


def export_frames(info: FileInfo, wanted: set[int] | frozenset[int], out_path: Path, comment: str, frame_offset: int = 0) -> int:
    """Copy frames whose number (``frame_offset`` + position in file) is in ``wanted``."""
    return export_sources([(info, wanted, frame_offset)], out_path, comment)


def export_sources(parts: list[tuple[FileInfo, set[int] | frozenset[int], int]], out_path: Path, comment: str) -> int:
    """Copy selected frames from one or more source captures into a single PCAPNG.

    ``parts`` holds (source file, wanted timeline frame numbers, frame offset of that
    source). Returns the number of frames written. The output is written atomically
    and may never be one of the source captures.
    """
    out_path = Path(out_path)
    for info, _wanted, _offset in parts:
        src = Path(info.path)
        if out_path.resolve() == src.resolve():
            raise CaptureError("refusing to overwrite the source capture")
        try:
            st = src.stat()
        except OSError as exc:
            raise CaptureError(f"capture no longer accessible: {exc.strerror or exc}") from exc
        if st.st_size != info.size or st.st_mtime_ns != info.mtime_ns:
            raise CaptureError(f"{info.name} changed on disk since import; re-open it before exporting")

    def records():
        for info, wanted, offset in parts:
            yield from _source_records(info, wanted, offset)

    return write_records(records(), out_path, comment)


def write_records(records, out_path: Path, comment: str) -> int:
    """Write (linktype, timestamp ns, data, wire length) records to a new PCAPNG, atomically."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tz-", suffix=".pcapng", dir=str(out_path.parent))
    written = 0
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(section_header(comment))
            interfaces: dict[int, int] = {}
            for linktype, ts, data, wirelen in records:
                iface = interfaces.get(linktype)
                if iface is None:
                    iface = interfaces[linktype] = len(interfaces)
                    out.write(interface_block(linktype))
                out.write(packet_block(iface, ts, data, max(wirelen, len(data))))
                written += 1
        os.replace(tmp, out_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return written


def _source_records(info: FileInfo, wanted, offset: int):
    src = Path(info.path)
    mine = [n for n in wanted if n > offset]
    if not mine:
        return
    last_wanted = max(mine)
    with open(src, "rb") as raw_fh:
        reader = _open_reader(_GuardedFile(raw_fh), src, info.fmt)
        static_linktype = getattr(reader, "linktype", None)
        no = offset
        prev_ts = 0
        while no < last_wanted:
            try:
                data, meta = reader._read_packet(size=_MAX_FRAME)
            except EOFError:
                break
            except (Scapy_Exception, struct.error, OSError) as exc:
                raise CaptureError(f"{info.name} became unreadable at frame {no - offset + 1}: {exc}") from exc
            no += 1
            ts = _timestamp_ns(reader, meta, info.fmt)
            ts = prev_ts if ts is None else ts
            prev_ts = ts
            if no not in wanted:
                continue
            linktype = getattr(meta, "linktype", None)
            if linktype is None:
                linktype = static_linktype if static_linktype is not None else 147
            yield linktype, ts, data, getattr(meta, "wirelen", None) or len(data)
