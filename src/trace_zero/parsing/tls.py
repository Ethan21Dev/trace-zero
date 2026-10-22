"""TLS handshake parsing: ClientHello / ServerHello / Certificate, JA3, JA3S, JA4.

Operates on raw bytes that start at a TLS record boundary - a single TCP
segment or a reassembled stream. Every read is bounds-checked; anything
inconsistent stops parsing and is reported rather than guessed.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from trace_zero.sanitize import clean

_U16 = struct.Struct("!H")

TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
_JA4_VERSIONS = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


def is_grease(v: int) -> bool:
    """RFC 8701 GREASE values (0x0a0a, 0x1a1a, ... 0xfafa)."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


@dataclass(slots=True)
class TlsInfo:
    messages: tuple[str, ...] = ()
    record_version: int | None = None
    # ClientHello
    sni: str | None = None
    alpn: tuple[str, ...] = ()
    client_versions: tuple[int, ...] = ()
    ja3: str | None = None
    ja3_string: str | None = None
    ja4: str | None = None
    # ServerHello
    server_version: int | None = None
    cipher: int | None = None
    ja3s: str | None = None
    ja3s_string: str | None = None
    # Certificate (TLS <= 1.2 only; TLS 1.3 encrypts it)
    cert_subject_cn: str | None = None
    cert_issuer_cn: str | None = None
    cert_san: tuple[str, ...] = ()
    cert_count: int = 0
    errors: tuple[str, ...] = ()

    @property
    def summary(self) -> str:
        parts = []
        if "ClientHello" in self.messages:
            parts.append(f"ClientHello SNI={self.sni}" if self.sni else "ClientHello (no SNI)")
        if "ServerHello" in self.messages:
            v = TLS_VERSIONS.get(self.server_version or 0, "?")
            parts.append(f"ServerHello {v} cipher=0x{(self.cipher or 0):04x}")
        if self.cert_subject_cn or self.cert_count:
            parts.append(f"Certificate CN={self.cert_subject_cn or '?'}")
        if not parts and self.messages:
            parts.append(" ".join(self.messages))
        return "; ".join(parts) or "TLS record"


class _Reader:
    def __init__(self, data: bytes, pos: int = 0, end: int | None = None) -> None:
        self.data = data
        self.pos = pos
        self.end = len(data) if end is None else min(end, len(data))

    def need(self, n: int) -> None:
        if self.pos + n > self.end:
            raise ValueError("truncated")

    def u8(self) -> int:
        self.need(1)
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        self.need(2)
        v = _U16.unpack_from(self.data, self.pos)[0]
        self.pos += 2
        return v

    def u24(self) -> int:
        self.need(3)
        v = int.from_bytes(self.data[self.pos : self.pos + 3], "big")
        self.pos += 3
        return v

    def take(self, n: int) -> bytes:
        self.need(n)
        v = self.data[self.pos : self.pos + n]
        self.pos += n
        return v

    def sub(self, n: int) -> _Reader:
        self.need(n)
        r = _Reader(self.data, self.pos, self.pos + n)
        self.pos += n
        return r

    @property
    def left(self) -> int:
        return self.end - self.pos


def looks_like_tls(payload: bytes) -> bool:
    return len(payload) >= 6 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03 and payload[2] <= 0x04


def parse_tls(payload: bytes, max_records: int = 32) -> TlsInfo | None:
    """Parse TLS records from the start of ``payload``. Returns None if it is not TLS."""
    if not looks_like_tls(payload):
        return None
    info = TlsInfo()
    messages: list[str] = []
    errors: list[str] = []
    hs_buffer = b""
    pos = 0
    for _ in range(max_records):
        if pos + 5 > len(payload):
            break
        ctype, version, length = payload[pos], _U16.unpack_from(payload, pos + 1)[0], _U16.unpack_from(payload, pos + 3)[0]
        if ctype not in (0x14, 0x15, 0x16, 0x17) or version >> 8 != 3:
            break
        if info.record_version is None:
            info.record_version = version
        body = payload[pos + 5 : pos + 5 + length]
        truncated = len(body) < length
        pos += 5 + length
        if ctype == 0x16:
            hs_buffer += body
        elif ctype == 0x14:
            messages.append("ChangeCipherSpec")
        elif ctype == 0x15:
            messages.append("Alert")
        elif ctype == 0x17:
            messages.append("ApplicationData")
        if truncated:
            break
    # Handshake messages may span records; walk the concatenated handshake stream.
    r = _Reader(hs_buffer)
    while r.left >= 4:
        htype = r.u8()
        hlen = r.u24()
        if hlen > r.left:
            body = _Reader(hs_buffer, r.pos, r.end)
            partial = True
            r.pos = r.end
        else:
            body = r.sub(hlen)
            partial = False
        name = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange", 14: "ServerHelloDone", 16: "ClientKeyExchange", 4: "NewSessionTicket"}.get(htype, f"handshake-{htype}")
        messages.append(name + (" (partial)" if partial else ""))
        try:
            if htype == 1 and not partial:
                _client_hello(body, info)
            elif htype == 2 and not partial:
                _server_hello(body, info)
            elif htype == 11:
                _certificate(body, info)
        except (ValueError, IndexError, struct.error):
            errors.append(f"{name} not fully decodable")
        if htype not in (1, 2, 11, 12, 14, 16, 4, 13, 15, 20):
            # Encrypted handshake (TLS 1.3 after ServerHello) looks like garbage; stop.
            break
    info.messages = tuple(messages)
    info.errors = tuple(errors)
    return info


def _extensions(r: _Reader) -> list[tuple[int, _Reader]]:
    if r.left < 2:
        return []
    total = r.u16()
    er = r.sub(min(total, r.left))
    out = []
    while er.left >= 4:
        etype = er.u16()
        elen = er.u16()
        out.append((etype, er.sub(min(elen, er.left))))
    return out


def _client_hello(r: _Reader, info: TlsInfo) -> None:
    hello_version = r.u16()
    r.take(32)
    r.take(r.u8())
    cs_len = r.u16()
    cs = r.sub(cs_len)
    ciphers = [cs.u16() for _ in range(cs_len // 2)]
    r.take(r.u8())  # compression methods
    exts = _extensions(r)
    ext_types = [t for t, _ in exts]
    groups: list[int] = []
    point_formats: list[int] = []
    sig_algs: list[int] = []
    alpn: list[str] = []
    versions: list[int] = []
    for etype, er in exts:
        if etype == 0 and er.left >= 5:
            er.u16()
            er.u8()
            name = er.take(er.u16())
            info.sni = clean(name.decode("utf-8", "backslashreplace"), 255)
        elif etype == 10 and er.left >= 2:
            n = er.u16()
            groups = [er.u16() for _ in range(min(n, er.left) // 2)]
        elif etype == 11 and er.left >= 1:
            n = er.u8()
            point_formats = list(er.take(min(n, er.left)))
        elif etype == 13 and er.left >= 2:
            n = er.u16()
            sig_algs = [er.u16() for _ in range(min(n, er.left) // 2)]
        elif etype == 16 and er.left >= 2:
            lst = er.sub(min(er.u16(), er.left))
            while lst.left >= 1:
                alpn.append(clean(lst.take(min(lst.u8(), lst.left)).decode("ascii", "backslashreplace"), 64))
        elif etype == 43 and er.left >= 1:
            n = er.u8()
            versions = [er.u16() for _ in range(min(n, er.left) // 2)]
    info.alpn = tuple(alpn)
    info.client_versions = tuple(v for v in versions if not is_grease(v))
    # JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats (GREASE removed)
    nog = lambda vals: [v for v in vals if not is_grease(v)]  # noqa: E731
    ja3 = ",".join(
        [
            str(hello_version),
            "-".join(map(str, nog(ciphers))),
            "-".join(map(str, nog(ext_types))),
            "-".join(map(str, nog(groups))),
            "-".join(map(str, point_formats)),
        ]
    )
    info.ja3_string = ja3
    info.ja3 = hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest()
    info.ja4 = _ja4(hello_version, nog(ciphers), nog(ext_types), sig_algs, info.client_versions, info.sni is not None, alpn)


def _ja4(hello_version: int, ciphers: list[int], exts: list[int], sig_algs: list[int], versions: tuple[int, ...], has_sni: bool, alpn: list[str]) -> str:
    version = max(versions) if versions else hello_version
    ver = _JA4_VERSIONS.get(version, "00")
    if alpn and alpn[0]:
        first = alpn[0]
        a = first[0] + first[-1]
        if not (a.isascii() and a.isalnum()):
            hx = first.encode("utf-8", "backslashreplace").hex()
            a = hx[0] + hx[-1]
    else:
        a = "00"
    part_a = f"t{ver}{'d' if has_sni else 'i'}{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{a}"
    part_b = hashlib.sha256(",".join(f"{c:04x}" for c in sorted(ciphers)).encode()).hexdigest()[:12] if ciphers else "000000000000"
    ext_sorted = sorted(e for e in exts if e not in (0x0000, 0x0010))
    text_c = ",".join(f"{e:04x}" for e in ext_sorted)
    if sig_algs:
        text_c += "_" + ",".join(f"{s:04x}" for s in sig_algs)
    part_c = hashlib.sha256(text_c.encode()).hexdigest()[:12] if ext_sorted else "000000000000"
    return f"{part_a}_{part_b}_{part_c}"


def _server_hello(r: _Reader, info: TlsInfo) -> None:
    version = r.u16()
    r.take(32)
    r.take(r.u8())
    cipher = r.u16()
    r.u8()
    exts = _extensions(r)
    selected = version
    for etype, er in exts:
        if etype == 43 and er.left >= 2:
            selected = er.u16()
    info.server_version = selected
    info.cipher = cipher
    ja3s = f"{version},{cipher},{'-'.join(str(t) for t, _ in exts)}"
    info.ja3s_string = ja3s
    info.ja3s = hashlib.md5(ja3s.encode(), usedforsecurity=False).hexdigest()


def _certificate(r: _Reader, info: TlsInfo) -> None:
    total = r.u24()
    lst = r.sub(min(total, r.left))
    first = True
    while lst.left >= 3:
        n = lst.u24()
        if n > lst.left:
            break
        der = lst.take(n)
        info.cert_count += 1
        if first:
            first = False
            subject, issuer, san = parse_certificate(der)
            info.cert_subject_cn = subject
            info.cert_issuer_cn = issuer
            info.cert_san = tuple(san[:20])


# --- minimal DER ------------------------------------------------------------------
_OID_CN = bytes.fromhex("550403")
_OID_SAN = bytes.fromhex("551d11")


def _tlv(data: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """Returns (tag, value_start, value_end)."""
    if pos + 2 > end:
        raise ValueError("der truncated")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or nbytes > 4 or pos + nbytes > end:
            raise ValueError("der length")
        length = int.from_bytes(data[pos : pos + nbytes], "big")
        pos += nbytes
    if pos + length > end:
        raise ValueError("der overflow")
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    pos = start
    while pos < end and len(out) < 256:
        tag, vs, ve = _tlv(data, pos, end)
        out.append((tag, vs, ve))
        pos = ve
    return out


def _name_cn(data: bytes, start: int, end: int) -> str | None:
    for _t, rs, re_ in _children(data, start, end):  # SET
        for _t2, as_, ae in _children(data, rs, re_):  # AttributeTypeAndValue SEQUENCE
            parts = _children(data, as_, ae)
            if len(parts) == 2 and data[parts[0][1] : parts[0][2]] == _OID_CN:
                return clean(data[parts[1][1] : parts[1][2]].decode("utf-8", "backslashreplace"), 255)
    return None


def parse_certificate(der: bytes) -> tuple[str | None, str | None, list[str]]:
    """Extract (subject CN, issuer CN, SAN DNS names) from an X.509 certificate."""
    try:
        _t, cs, ce = _tlv(der, 0, len(der))
        tbs_tag, ts, te = _children(der, cs, ce)[0]
        fields = _children(der, ts, te)
        i = 1 if fields and fields[0][0] == 0xA0 else 0  # optional [0] version
        # serial, signature, issuer, validity, subject
        issuer = fields[i + 2]
        subject = fields[i + 4]
        san: list[str] = []
        for tag, vs, ve in fields[i + 5 :]:
            if tag == 0xA3:  # extensions
                for _t, xs, xe in _children(der, vs, ve):
                    for _t2, es, ee in _children(der, xs, xe):
                        parts = _children(der, es, ee)
                        if parts and der[parts[0][1] : parts[0][2]] == _OID_SAN:
                            octet = parts[-1]
                            _t3, ss, se = _tlv(der, octet[1], octet[2])
                            for gtag, gs, ge in _children(der, ss, se):
                                if gtag == 0x82:  # dNSName
                                    san.append(clean(der[gs:ge].decode("ascii", "backslashreplace"), 255))
        return _name_cn(der, subject[1], subject[2]), _name_cn(der, issuer[1], issuer[2]), san
    except (ValueError, IndexError):
        return None, None, []


__all__ = ["TLS_VERSIONS", "TlsInfo", "is_grease", "looks_like_tls", "parse_certificate", "parse_tls"]
