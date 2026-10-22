"""Incremental reader for a capture file that is still being written.

A capture tool (dumpcap, tcpdump, or anything else writing PCAP/PCAPNG)
appends records to a file; ``CaptureFollower.poll`` reads only the complete
records that appeared since the previous poll. An incomplete record at the
end is left alone until the rest of it has been written.

Scapy's readers are built for finished files and cannot resume, so the
framing here is implemented directly. It is deliberately small and strict:
every length is checked before it is used, block lengths are capped, and any
structural damage stops following with a warning instead of guessing.
Frames are decoded by the same ``decode_frame`` as an offline import, so the
packets are identical to what re-opening the finished file produces.

The follower records each frame's byte offset in the file. Bytes before the
end of the last complete record never change in an append-only file, so raw
frames can be re-read while capture continues.
"""

from __future__ import annotations

import os
import struct
from array import array
from dataclasses import dataclass
from pathlib import Path

from trace_zero.config import Limits
from trace_zero.models import PacketRecord
from trace_zero.parsing.decoder import decode_frame
from trace_zero.parsing.reader import _MAX_FRAME, CaptureError

_MAX_BLOCK = 64 * 1024 * 1024  # same cap as the offline reader's guarded file
_READ_CHUNK = 8 * 1024 * 1024  # bytes per poll; keeps each poll short on a large backlog

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_BYTE_ORDER_MAGIC = 0x1A2B3C4D


class FollowError(CaptureError):
    """The followed file cannot be read further (damaged, truncated, replaced)."""


@dataclass
class _Interface:
    linktype: int
    snaplen: int
    tsresol: int  # timestamp units per second


class CaptureFollower:
    """Reads newly appended records of a growing PCAP or PCAPNG file."""

    def __init__(self, path: str | os.PathLike[str], limits: Limits | None = None) -> None:
        self.path = Path(path).expanduser().resolve()
        self.limits = limits or Limits()
        if not self.path.is_file():
            raise CaptureError(f"not a regular file: {self.path}")
        self.fmt: str | None = None  # "pcap" / "pcapng" once the header has been read
        self.offset = 0  # end of the last complete record consumed
        self.packets: list[PacketRecord] = []
        self.linktypes: set[int] = set()
        self.warnings: list[str] = []
        self.stopped: str | None = None  # why following ended (limit, damage), if it did
        self.missing_ts = 0
        # Per frame (index = frame number - 1): where its bytes are, for raw re-reads.
        self._data_offset = array("q")
        self._data_len = array("l")
        self._ts_ns = array("q")
        self._wirelen = array("l")
        self._linktype = array("l")
        self._last_ts = 0.0
        self._last_ts_ns = 0
        # format state
        self._endian = "<"
        self._nano = False
        self._pcap_linktype = -1
        self._interfaces: list[_Interface] = []

    # -- public ------------------------------------------------------------------------
    @property
    def count(self) -> int:
        return len(self.packets)

    def size_on_disk(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError as exc:
            raise FollowError(f"capture file is no longer accessible: {exc.strerror or exc}") from exc

    def poll(self, max_bytes: int = _READ_CHUNK) -> int:
        """Consume complete records appended since the last call. Returns the number of new packets."""
        if self.stopped is not None:
            return 0
        size = self.size_on_disk()
        if size < self.offset:
            self._stop(f"file shrank from {self.offset:,} to {size:,} bytes (rotated or overwritten); following stopped")
            raise FollowError(self.stopped)
        if size == self.offset:
            return 0
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.offset)
                buf = fh.read(min(size - self.offset, max_bytes))
        except OSError as exc:
            raise FollowError(f"cannot read capture file: {exc.strerror or exc}") from exc
        before = len(self.packets)
        consumed = self._parse(buf)
        self.offset += consumed
        return len(self.packets) - before

    def frame_bytes(self, wanted) -> dict[int, tuple[bytes, int]]:
        """Raw bytes and link type of the given frame numbers, read from the file."""
        out: dict[int, tuple[bytes, int]] = {}
        nums = sorted(n for n in wanted if 1 <= n <= len(self._data_offset))
        if not nums:
            return out
        if self.size_on_disk() < self.offset:
            raise FollowError("capture file shrank; raw bytes can no longer be read")
        with open(self.path, "rb") as fh:
            for n in nums:
                i = n - 1
                fh.seek(self._data_offset[i])
                data = fh.read(self._data_len[i])
                if len(data) != self._data_len[i]:
                    raise FollowError(f"frame {n} is no longer complete in the capture file")
                out[n] = (data, self._linktype[i])
        return out

    def frame_records(self, wanted):
        """(linktype, timestamp ns, data, wire length) per wanted frame, in frame order (for exports)."""
        raw = self.frame_bytes(wanted)
        for n in sorted(raw):
            data, linktype = raw[n]
            yield linktype, self._ts_ns[n - 1], data, self._wirelen[n - 1]

    # -- parsing -------------------------------------------------------------------------
    def _stop(self, reason: str) -> None:
        if self.stopped is None:
            self.stopped = reason
            self.warnings.append(reason)

    def _parse(self, buf: bytes) -> int:
        pos = 0
        if self.fmt is None:
            if len(buf) < 4:
                return 0
            magic = buf[:4]
            if magic in _PCAP_MAGICS:
                if len(buf) < 24:
                    return 0
                self._endian, self._nano = _PCAP_MAGICS[magic]
                self._pcap_linktype = struct.unpack_from(self._endian + "I", buf, 20)[0] & 0x0FFFFFFF
                self.fmt = "pcap"
                pos = 24
            elif magic == _PCAPNG_SHB:
                self.fmt = "pcapng"
            else:
                self._stop("not a PCAP or PCAPNG file (unrecognised header); following stopped")
                raise FollowError(self.stopped)
        parse = self._parse_pcap if self.fmt == "pcap" else self._parse_pcapng
        while pos < len(buf) and self.stopped is None:
            used = parse(buf, pos)
            if used == 0:
                break  # incomplete record: wait for more data
            pos += used
        return pos

    def _parse_pcap(self, buf: bytes, pos: int) -> int:
        if len(buf) - pos < 16:
            return 0
        sec, frac, incl, orig = struct.unpack_from(self._endian + "IIII", buf, pos)
        if incl > _MAX_BLOCK:
            self._stop(f"record at byte {self.offset + pos:,} declares {incl:,} bytes; capture damaged, following stopped")
            return 0
        if len(buf) - pos < 16 + incl:
            return 0
        data_at = pos + 16
        keep = min(incl, _MAX_FRAME)
        ts = sec + frac / (1e9 if self._nano else 1e6)
        ts_ns = sec * 1_000_000_000 + frac * (1 if self._nano else 1000)
        self._add(buf, data_at, keep, ts, ts_ns, orig or incl, self._pcap_linktype)
        return 16 + incl

    def _parse_pcapng(self, buf: bytes, pos: int) -> int:
        if len(buf) - pos < 12:
            return 0
        btype_raw = buf[pos : pos + 4]
        if btype_raw == _PCAPNG_SHB:
            # The byte-order magic decides how every later length is read.
            bom = buf[pos + 8 : pos + 12]
            if bom == struct.pack("<I", _BYTE_ORDER_MAGIC):
                self._endian = "<"
            elif bom == struct.pack(">I", _BYTE_ORDER_MAGIC):
                self._endian = ">"
            else:
                self._stop("invalid PCAPNG section header; following stopped")
                return 0
        e = self._endian
        btype, blen = struct.unpack_from(e + "II", buf, pos)
        if blen < 12 or blen % 4 or blen > _MAX_BLOCK:
            self._stop(f"invalid PCAPNG block length {blen} at byte {self.offset + pos:,}; capture damaged, following stopped")
            return 0
        if len(buf) - pos < blen:
            return 0
        (trailer,) = struct.unpack_from(e + "I", buf, pos + blen - 4)
        if trailer != blen:
            self._stop(f"PCAPNG block at byte {self.offset + pos:,} has mismatched lengths; capture damaged, following stopped")
            return 0
        body = pos + 8
        body_len = blen - 12
        if btype == 0x0A0D0D0A:
            self._interfaces = []  # a new section starts a new interface list
        elif btype == 0x00000001:
            self._read_idb(buf, body, body_len)
        elif btype == 0x00000006:
            self._read_epb(buf, body, body_len, pos)
        elif btype == 0x00000003:
            self._read_spb(buf, body, body_len, pos)
        elif btype == 0x00000002:
            self._read_obsolete_pb(buf, body, body_len, pos)
        # other block types (name resolution, statistics, custom, ...) carry no packets
        return blen

    def _read_idb(self, buf: bytes, body: int, body_len: int) -> None:
        if body_len < 8:
            self._stop("PCAPNG interface block too short; following stopped")
            return
        e = self._endian
        linktype, _reserved, snaplen = struct.unpack_from(e + "HHI", buf, body)
        tsresol = 1_000_000
        opt = body + 8
        end = body + body_len
        while opt + 4 <= end:
            code, length = struct.unpack_from(e + "HH", buf, opt)
            if code == 0:
                break
            if opt + 4 + length > end:
                break
            if code == 9 and length >= 1:
                v = buf[opt + 4]
                tsresol = (2 if v & 0x80 else 10) ** (v & 0x7F)
            opt += 4 + length + (-length % 4)
        self._interfaces.append(_Interface(linktype, snaplen, max(1, tsresol)))

    def _iface(self, intid: int, at: int) -> _Interface | None:
        if intid >= len(self._interfaces):
            self._stop(f"packet at byte {self.offset + at:,} refers to undeclared interface {intid}; following stopped")
            return None
        return self._interfaces[intid]

    def _ts(self, iface: _Interface, high: int, low: int) -> tuple[float, int]:
        units = (high << 32) | low
        return units / iface.tsresol, units * 1_000_000_000 // iface.tsresol

    def _read_epb(self, buf: bytes, body: int, body_len: int, at: int) -> None:
        if body_len < 20:
            self._stop("PCAPNG packet block too short; following stopped")
            return
        intid, high, low, caplen, wirelen = struct.unpack_from(self._endian + "IIIII", buf, body)
        iface = self._iface(intid, at)
        if iface is None:
            return
        caplen = min(caplen, body_len - 20)
        ts, ts_ns = self._ts(iface, high, low)
        self._add(buf, body + 20, min(caplen, _MAX_FRAME), ts, ts_ns, wirelen or caplen, iface.linktype)

    def _read_obsolete_pb(self, buf: bytes, body: int, body_len: int, at: int) -> None:
        if body_len < 20:
            self._stop("PCAPNG packet block too short; following stopped")
            return
        intid, _drops, high, low, caplen, wirelen = struct.unpack_from(self._endian + "HHIIII", buf, body)
        iface = self._iface(intid, at)
        if iface is None:
            return
        caplen = min(caplen, body_len - 20)
        ts, ts_ns = self._ts(iface, high, low)
        self._add(buf, body + 20, min(caplen, _MAX_FRAME), ts, ts_ns, wirelen or caplen, iface.linktype)

    def _read_spb(self, buf: bytes, body: int, body_len: int, at: int) -> None:
        if body_len < 4:
            self._stop("PCAPNG simple packet block too short; following stopped")
            return
        iface = self._iface(0, at)
        if iface is None:
            return
        (wirelen,) = struct.unpack_from(self._endian + "I", buf, body)
        caplen = min(wirelen, body_len - 4, iface.snaplen or wirelen)
        # Simple packet blocks have no timestamp: ordered after the preceding packet.
        self.missing_ts += 1
        self._add(buf, body + 4, min(caplen, _MAX_FRAME), self._last_ts, self._last_ts_ns, wirelen, iface.linktype)

    def _add(self, buf: bytes, at: int, length: int, ts: float, ts_ns: int, wirelen: int, linktype: int) -> None:
        if len(self.packets) >= self.limits.max_packets:
            self._stop(f"packet limit reached ({self.limits.max_packets:,}); following stopped")
            return
        no = len(self.packets) + 1
        data = bytes(buf[at : at + length])
        rec = decode_frame(no, ts, data, wirelen, linktype, self.limits.max_dns_payload)
        self.packets.append(rec)
        self.linktypes.add(linktype)
        self._data_offset.append(self.offset + at)
        self._data_len.append(length)
        self._ts_ns.append(ts_ns)
        self._wirelen.append(max(wirelen, length))
        self._linktype.append(linktype)
        self._last_ts, self._last_ts_ns = ts, ts_ns
