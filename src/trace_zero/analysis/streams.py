"""Stream reassembly ("follow stream") for one flow.

Raw frames are re-read from the capture on demand. TCP payloads are ordered by
sequence number per direction; retransmitted bytes are dropped (and counted),
retransmissions whose bytes *differ* from the first copy are flagged, and gaps
are recorded rather than papered over. The assembled bytes are then decoded at
the application layer: HTTP messages with full headers, TLS handshakes spanning
segments, and length-prefixed DNS over TCP.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from trace_zero.analysis.flows import Flow
from trace_zero.parsing.decoder import HTTP_METHODS, decode_with_payload
from trace_zero.parsing.scapy_bridge import DNS
from trace_zero.parsing.tls import TLS_VERSIONS, parse_tls
from trace_zero.sanitize import clean

MAX_STREAM_BYTES = 8 * 1024 * 1024
_MOD = 1 << 32


@dataclass
class Chunk:
    direction: str  # "a" (initiator side) or "b"
    ts: float
    frame: int
    data: bytes
    note: str | None = None


@dataclass
class Stream:
    flow: Flow
    chunks: list[Chunk] = field(default_factory=list)
    gaps: int = 0
    gap_bytes: int = 0
    retransmitted: int = 0
    conflicting: int = 0
    missing_frames: int = 0
    snapped_frames: int = 0
    clipped: bool = False
    decoded: list[tuple[str, list[tuple[str, str]]]] = field(default_factory=list)

    def data(self, direction: str) -> bytes:
        return b"".join(c.data for c in self.chunks if c.direction == direction)

    @property
    def total(self) -> int:
        return sum(len(c.data) for c in self.chunks)

    def issues(self) -> list[str]:
        out = []
        if self.missing_frames:
            out.append(f"{self.missing_frames} frame(s) could not be re-read")
        if self.snapped_frames:
            out.append(f"{self.snapped_frames} frame(s) were truncated by the capture snap length")
        if self.gaps:
            out.append(f"{self.gaps} gap(s), {self.gap_bytes:,} bytes never captured")
        if self.retransmitted:
            out.append(f"{self.retransmitted} retransmitted segment(s) ignored")
        if self.conflicting:
            out.append(f"{self.conflicting} retransmission(s) carried DIFFERENT bytes than the original (first copy kept)")
        if self.clipped:
            out.append(f"stream clipped at {MAX_STREAM_BYTES // 1048576} MiB")
        return out


def reassemble(flow: Flow, frames: dict[int, tuple[bytes, int]], timestamps: dict[int, float]) -> Stream:
    stream = Stream(flow)
    segments: dict[str, list[tuple[int, int, float, bytes, int]]] = {"a": [], "b": []}
    syn_seq: dict[str, int] = {}
    for order, no in enumerate(flow.frames):
        raw = frames.get(no)
        if raw is None:
            stream.missing_frames += 1
            continue
        data, linktype = raw
        rec, payload = decode_with_payload(no, timestamps.get(no, 0.0), data, linktype)
        direction = "a" if (rec.src == flow.a and rec.sport == flow.a_port) else "b"
        if rec.payload_len is not None and payload is not None and len(payload) < rec.payload_len:
            stream.snapped_frames += 1
        if flow.proto == "TCP" and rec.tcp_seq is not None:
            if rec.tcp_flags is not None and rec.tcp_flags & 0x02:
                syn_seq[direction] = rec.tcp_seq
            if payload:
                segments[direction].append((rec.tcp_seq, order, rec.ts, payload, no))
        elif payload:
            stream.chunks.append(Chunk(direction, rec.ts, no, payload))
    if flow.proto == "TCP":
        pieces: list[tuple[int, Chunk]] = []
        budget = MAX_STREAM_BYTES
        for direction, segs in segments.items():
            if not segs:
                continue
            base = (syn_seq[direction] + 1) % _MOD if direction in syn_seq else segs[0][0]
            assembled = bytearray()
            nxt = 0
            ordered = sorted(segs, key=lambda s: ((s[0] - base) % _MOD, s[1]))
            for seq, order, ts, payload, no in ordered:
                rel = (seq - base) % _MOD
                if rel >= _MOD // 2:
                    stream.retransmitted += 1  # bytes from before the stream start
                    continue
                end = rel + len(payload)
                note = None
                if end <= nxt:
                    stream.retransmitted += 1
                    if bytes(assembled[rel:end]) != payload:
                        stream.conflicting += 1
                    continue
                if rel > nxt:
                    stream.gaps += 1
                    stream.gap_bytes += rel - nxt
                    note = f"[{rel - nxt:,} bytes missing from capture]"
                    assembled.extend(b"\x00" * (rel - nxt))  # placeholder keeps offsets aligned
                    nxt = rel
                new = payload[nxt - rel :]
                if rel < nxt and bytes(assembled[rel:nxt]) != payload[: nxt - rel]:
                    stream.conflicting += 1
                if len(new) > budget:
                    new = new[:budget]
                    stream.clipped = True
                budget -= len(new)
                assembled.extend(new)
                nxt += len(new)
                pieces.append((order, Chunk(direction, ts, no, new, note)))
                if budget <= 0:
                    break
        pieces.sort(key=lambda x: x[0])
        stream.chunks = [c for _o, c in pieces]
    stream.decoded = decode_application(flow, stream)
    return stream


# --- application decoding --------------------------------------------------------------
def _is_http_start(head: bytes) -> bool:
    return head.startswith(b"HTTP/1.") or head.startswith(HTTP_METHODS)


def _http_messages(data: bytes, limit: int = 20) -> list[tuple[str, list[tuple[str, str]]]]:
    out = []
    pos = 0
    while pos < len(data) and len(out) < limit:
        head_end = data.find(b"\r\n\r\n", pos, pos + 65536)
        if not _is_http_start(data[pos : pos + 16]):
            break
        if head_end < 0:
            out.append(("(headers incomplete in capture)", [("start", clean(data[pos : pos + 200], 200))]))
            break
        lines = data[pos:head_end].split(b"\r\n")
        start = clean(lines[0].decode("latin-1"), 300)
        headers = []
        length = 0
        chunked = False
        for line in lines[1:60]:
            k, _, v = line.partition(b":")
            key = clean(k.decode("latin-1").strip(), 60)
            val = clean(v.decode("latin-1").strip(), 300)
            headers.append((key, val))
            if key.lower() == "content-length" and val.isdigit():
                length = int(val)
            if key.lower() == "transfer-encoding" and "chunked" in val.lower():
                chunked = True
        body_note = "chunked body (not de-chunked)" if chunked else f"{length:,} byte body"
        out.append((start, headers + [("(body)", body_note)]))
        if chunked:
            break
        pos = head_end + 4 + length
    return out


def _dns_tcp(data: bytes, limit: int = 50) -> list[str]:
    out = []
    pos = 0
    while pos + 2 <= len(data) and len(out) < limit:
        n = int.from_bytes(data[pos : pos + 2], "big")
        msg = data[pos + 2 : pos + 2 + n]
        pos += 2 + n
        if len(msg) < 12:
            break
        try:
            d = DNS(msg)
            q = d.qd[0] if d.qd else None
            qname = clean(q.qname.decode("utf-8", "backslashreplace"), 200) if q is not None else "?"
            kind = "response" if d.qr else "query"
            answers = len(d.an or [])
            out.append(f"{kind} {qname} ({answers} answers)")
        except Exception:  # noqa: BLE001 - untrusted bytes
            out.append("undecodable DNS message")
    return out


def decode_application(flow: Flow, stream: Stream) -> list[tuple[str, list[tuple[str, str]]]]:
    sections: list[tuple[str, list[tuple[str, str]]]] = []
    a, b = stream.data("a"), stream.data("b")
    for label, data in (("client → server", a), ("server → client", b)):
        if not data:
            continue
        if flow.proto == "TCP" and 53 in (flow.a_port, flow.b_port):
            msgs = _dns_tcp(data)
            if msgs:
                sections.append((f"DNS over TCP ({label})", [(str(i + 1), m) for i, m in enumerate(msgs)]))
            continue
        tls = parse_tls(data)
        if tls is not None and tls.messages:
            rows = [("messages", ", ".join(tls.messages[:12]))]
            for key, value in (
                ("SNI", tls.sni),
                ("ALPN", ", ".join(tls.alpn) if tls.alpn else None),
                ("JA4", tls.ja4),
                ("JA3", tls.ja3),
                ("version", TLS_VERSIONS.get(tls.server_version, None) if tls.server_version else None),
                ("cipher", f"0x{tls.cipher:04x}" if tls.cipher is not None else None),
                ("JA3S", tls.ja3s),
                ("cert subject", tls.cert_subject_cn),
                ("cert issuer", tls.cert_issuer_cn),
                ("cert SAN", ", ".join(tls.cert_san[:8]) if tls.cert_san else None),
            ):
                if value:
                    rows.append((key, value))
            sections.append((f"TLS ({label})", rows))
            continue
        for start, headers in _http_messages(data):
            sections.append((f"HTTP ({label}) {start}", headers))
    return sections


def printable_lines(data: bytes, width: int = 0) -> list[str]:
    """Bytes as display text: decoded leniently, control characters escaped, split on newlines."""
    text = data.decode("utf-8", errors="backslashreplace")
    lines = []
    for raw in text.split("\n"):
        line = clean(raw.rstrip("\r"), 4000)
        if width and len(line) > width:
            lines.extend(line[i : i + width] for i in range(0, len(line), width))
        else:
            lines.append(line)
    return lines
