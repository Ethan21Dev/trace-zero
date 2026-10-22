"""Bounds-checked frame decoder.

Bulk import uses this fast decoder for link, network and transport layers
(scapy's full dissection is roughly 100x slower), and scapy's DNS layer for
DNS payloads. Every read is bounds-checked; malformed data produces an entry
in ``PacketRecord.errors`` instead of an exception or a guessed value.
"""

from __future__ import annotations

import socket
import struct

from trace_zero.models import DnsAnswer, DnsInfo, PacketRecord
from trace_zero.parsing.scapy_bridge import DNS, Raw
from trace_zero.sanitize import clean

_U16 = struct.Struct("!H")
_IPV4_HDR = struct.Struct("!BHHHBBH")  # tos, total_len, id, frag, ttl, proto, csum
_TCP_HDR = struct.Struct("!HHIIHH")
_UDP_HDR = struct.Struct("!HHH")
_SLL_PROTO = struct.Struct("!H")

DNS_PORTS = {53: "DNS", 5353: "MDNS", 5355: "LLMNR"}
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")

_ip_cache: dict[bytes, str] = {}
_mac_cache: dict[bytes, str] = {}


def _ip(raw: bytes) -> str:
    s = _ip_cache.get(raw)
    if s is None:
        family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
        s = socket.inet_ntop(family, raw)
        if len(_ip_cache) < 1_000_000:
            _ip_cache[raw] = s
    return s


def _mac(raw: bytes) -> str:
    s = _mac_cache.get(raw)
    if s is None:
        s = ":".join(f"{b:02x}" for b in raw)
        if len(_mac_cache) < 200_000:
            _mac_cache[raw] = s
    return s


def decode_frame(
    no: int,
    ts: float,
    data: bytes,
    wirelen: int,
    linktype: int,
    max_dns_payload: int = 4096,
) -> PacketRecord:
    rec = PacketRecord(no=no, ts=ts, wirelen=wirelen, caplen=len(data), linktype=linktype)
    errors: list[str] = []
    try:
        _decode_link(rec, data, linktype, errors, max_dns_payload)
    except Exception as exc:  # noqa: BLE001 - a single frame must never abort an import
        errors.append(f"decoder error ({type(exc).__name__})")
    if errors:
        rec.errors = tuple(errors)
    return rec


def _decode_link(rec: PacketRecord, data: bytes, linktype: int, errors: list[str], max_dns: int) -> None:
    n = len(data)
    if linktype == 1:  # Ethernet
        if n < 14:
            errors.append("truncated Ethernet header")
            return
        rec.eth_dst = _mac(data[0:6])
        rec.eth_src = _mac(data[6:12])
        etype = _U16.unpack_from(data, 12)[0]
        off = 14
        tags = 0
        while etype in (0x8100, 0x88A8, 0x9100) and tags < 2:
            if n < off + 4:
                errors.append("truncated VLAN tag")
                return
            if rec.vlan is None:
                rec.vlan = _U16.unpack_from(data, off)[0] & 0x0FFF
            etype = _U16.unpack_from(data, off + 2)[0]
            off += 4
            tags += 1
        if etype < 0x0600:
            rec.app_info = "IEEE 802.3 LLC frame (not decoded)"
            return
        rec.ethertype = etype
        _decode_ethertype(rec, data, off, etype, errors, max_dns)
    elif linktype in (0, 108):  # BSD loopback / OpenBSD loop
        if n < 4:
            errors.append("truncated loopback header")
            return
        if linktype == 108:
            family = struct.unpack_from("!I", data, 0)[0]
        else:
            family = struct.unpack_from("<I", data, 0)[0]
            if family > 0xFFFF:
                family = struct.unpack_from(">I", data, 0)[0]
        if family == 2:
            _decode_ipv4(rec, data, 4, errors, max_dns)
        elif family in (10, 24, 28, 30):
            _decode_ipv6(rec, data, 4, errors, max_dns)
        else:
            rec.app_info = f"loopback family {family} (not decoded)"
    elif linktype in (12, 14, 101):  # raw IP
        if n < 1:
            errors.append("empty raw IP frame")
            return
        version = data[0] >> 4
        if version == 4:
            _decode_ipv4(rec, data, 0, errors, max_dns)
        elif version == 6:
            _decode_ipv6(rec, data, 0, errors, max_dns)
        else:
            errors.append(f"raw frame with IP version {version}")
    elif linktype == 228:
        _decode_ipv4(rec, data, 0, errors, max_dns)
    elif linktype == 229:
        _decode_ipv6(rec, data, 0, errors, max_dns)
    elif linktype == 113:  # Linux cooked capture v1
        if n < 16:
            errors.append("truncated SLL header")
            return
        halen = _U16.unpack_from(data, 4)[0]
        if halen == 6:
            rec.eth_src = _mac(data[6:12])
        etype = _SLL_PROTO.unpack_from(data, 14)[0]
        rec.ethertype = etype
        _decode_ethertype(rec, data, 16, etype, errors, max_dns)
    elif linktype == 276:  # Linux cooked capture v2
        if n < 20:
            errors.append("truncated SLL2 header")
            return
        etype = _SLL_PROTO.unpack_from(data, 0)[0]
        if data[11] == 6:
            rec.eth_src = _mac(data[12:18])
        rec.ethertype = etype
        _decode_ethertype(rec, data, 20, etype, errors, max_dns)
    # Other link types are recorded with timing and length only.


def _decode_ethertype(rec: PacketRecord, data: bytes, off: int, etype: int, errors: list[str], max_dns: int) -> None:
    if etype == 0x0800:
        _decode_ipv4(rec, data, off, errors, max_dns)
    elif etype == 0x86DD:
        _decode_ipv6(rec, data, off, errors, max_dns)
    elif etype == 0x0806:
        _decode_arp(rec, data, off, errors)


def _decode_arp(rec: PacketRecord, data: bytes, off: int, errors: list[str]) -> None:
    rec.net = "ARP"
    if len(data) < off + 8:
        errors.append("truncated ARP header")
        return
    htype, ptype = struct.unpack_from("!HH", data, off)
    hlen, plen = data[off + 4], data[off + 5]
    rec.arp_op = _U16.unpack_from(data, off + 6)[0]
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        rec.app_info = f"ARP htype={htype} ptype=0x{ptype:04x} (addresses not decoded)"
        return
    if len(data) < off + 28:
        errors.append("truncated ARP body")
        return
    base = off + 8
    sha = data[base : base + 6]
    spa = data[base + 6 : base + 10]
    tpa = data[base + 16 : base + 20]
    rec.eth_src = rec.eth_src or _mac(sha)
    rec.src = _ip(spa)
    rec.dst = _ip(tpa)


def _decode_ipv4(rec: PacketRecord, data: bytes, off: int, errors: list[str], max_dns: int) -> None:
    n = len(data)
    if n < off + 20:
        errors.append("truncated IPv4 header")
        rec.net = "IPv4"
        return
    vihl = data[off]
    version, ihl = vihl >> 4, (vihl & 0x0F) * 4
    rec.net = "IPv4"
    if version != 4:
        errors.append(f"IPv4 header carries version {version}")
        return
    if ihl < 20:
        errors.append(f"invalid IPv4 header length {ihl}")
        return
    _tos, total_len, ip_id, frag, ttl, proto, _csum = _IPV4_HDR.unpack_from(data, off + 1)
    rec.src = _ip(data[off + 12 : off + 16])
    rec.dst = _ip(data[off + 16 : off + 20])
    rec.ttl = ttl
    rec.ip_id = ip_id
    rec.ip_proto = proto
    if n < off + ihl:
        errors.append("truncated IPv4 options")
        return
    if total_len < ihl:
        errors.append(f"invalid IPv4 total length {total_len}")
        declared_end = n
    else:
        declared_end = off + total_len
    frag_off = frag & 0x1FFF
    if frag_off or frag & 0x2000:
        rec.fragment = True
    if frag_off:
        return  # non-first fragment: no transport header present
    _decode_l4(rec, data, off + ihl, declared_end, proto, errors, max_dns)


_IPV6_EXT_SIMPLE = {0, 43, 60}


def _decode_ipv6(rec: PacketRecord, data: bytes, off: int, errors: list[str], max_dns: int) -> None:
    n = len(data)
    rec.net = "IPv6"
    if n < off + 40:
        errors.append("truncated IPv6 header")
        return
    version = data[off] >> 4
    if version != 6:
        errors.append(f"IPv6 header carries version {version}")
        return
    plen = _U16.unpack_from(data, off + 4)[0]
    nh = data[off + 6]
    rec.ttl = data[off + 7]
    rec.src = _ip(data[off + 8 : off + 24])
    rec.dst = _ip(data[off + 24 : off + 40])
    p = off + 40
    declared_end = p + plen if plen else n
    for _ in range(8):
        if nh in _IPV6_EXT_SIMPLE or nh == 51:
            if n < p + 2:
                errors.append("truncated IPv6 extension header")
                rec.ip_proto = nh
                return
            nxt = data[p]
            hlen = (data[p + 1] + 2) * 4 if nh == 51 else (data[p + 1] + 1) * 8
            p += hlen
            nh = nxt
        elif nh == 44:
            if n < p + 8:
                errors.append("truncated IPv6 fragment header")
                rec.ip_proto = nh
                return
            nxt = data[p]
            fo = _U16.unpack_from(data, p + 2)[0]
            rec.fragment = True
            p += 8
            nh = nxt
            if fo >> 3:
                rec.ip_proto = nh
                return
        else:
            break
    rec.ip_proto = nh
    _decode_l4(rec, data, p, declared_end, nh, errors, max_dns)


def _decode_l4(
    rec: PacketRecord,
    data: bytes,
    p: int,
    declared_end: int,
    proto: int,
    errors: list[str],
    max_dns: int,
) -> None:
    cap_end = min(declared_end, len(data))
    if proto == 6:
        rec.transport = "TCP"
        if cap_end - p < 20:
            errors.append("truncated TCP header")
            return
        sport, dport, seq, ack, offflags, win = _TCP_HDR.unpack_from(data, p)
        doff = (offflags >> 12) * 4
        rec.sport, rec.dport = sport, dport
        rec.tcp_seq, rec.tcp_ack, rec.tcp_win = seq, ack, win
        rec.tcp_flags = offflags & 0xFF
        if doff < 20:
            errors.append(f"invalid TCP data offset {doff}")
            return
        start = p + doff
        rec.payload_len = max(0, declared_end - start)
        if start < cap_end:
            payload = data[start:cap_end]
            if 53 in (sport, dport) and len(payload) > 2:
                _decode_dns(rec, payload[2:], "DNS", errors, max_dns)
            else:
                _decode_tcp_app(rec, payload)
    elif proto == 17:
        rec.transport = "UDP"
        if cap_end - p < 8:
            errors.append("truncated UDP header")
            return
        sport, dport, ulen = _UDP_HDR.unpack_from(data, p)
        rec.sport, rec.dport = sport, dport
        if ulen >= 8:
            rec.payload_len = ulen - 8
            end = min(cap_end, p + ulen)
        else:
            errors.append(f"invalid UDP length {ulen}")
            rec.payload_len = max(0, declared_end - p - 8)
            end = cap_end
        label = DNS_PORTS.get(dport) or DNS_PORTS.get(sport)
        if label and end > p + 8:
            _decode_dns(rec, data[p + 8 : end], label, errors, max_dns)
    elif proto in (1, 58):
        rec.transport = "ICMP" if proto == 1 else "ICMPv6"
        if cap_end - p < 4:
            errors.append(f"truncated {rec.transport} header")
            return
        rec.icmp_type = data[p]
        rec.icmp_code = data[p + 1]
        rec.payload_len = max(0, declared_end - p - 4)
    else:
        rec.payload_len = max(0, declared_end - p)


def _decode_dns(rec: PacketRecord, payload: bytes, label: str, errors: list[str], max_dns: int) -> None:
    if len(payload) < 12:
        errors.append(f"{label} payload too short for a header")
        return
    if len(payload) > max_dns:
        errors.append(f"{label} payload larger than {max_dns} bytes (not decoded)")
        return
    try:
        msg = DNS(payload)
    except Exception as exc:  # noqa: BLE001 - untrusted bytes
        errors.append(f"{label} not decodable ({type(exc).__name__})")
        return
    qd = list(msg.qd or [])
    an = list(msg.an or [])
    malformed = None
    if msg.qdcount != len(qd) or msg.ancount != len(an) or msg.haslayer(Raw):
        malformed = "record counts do not match payload"
    qname = qtype = None
    if qd:
        q = qd[0]
        try:
            qname = clean(_name(q.qname), 255)
            qtype = clean(q.get_field("qtype").i2repr(q, q.qtype), 16)
        except Exception:  # noqa: BLE001
            malformed = malformed or "question not decodable"
    answers = []
    for rr in an[:32]:
        try:
            rtype = clean(rr.get_field("type").i2repr(rr, rr.type), 16)
            rdata = getattr(rr, "rdata", None)
            if isinstance(rdata, (bytes, bytearray)):
                value = clean(_name(bytes(rdata)), 255)
            elif isinstance(rdata, list):
                value = clean(" ".join(_name(x) if isinstance(x, bytes) else str(x) for x in rdata), 255)
            elif rdata is None:
                value = "(not decoded)"
            else:
                value = clean(rdata, 255)
            answers.append(DnsAnswer(clean(_name(rr.rrname), 255), rtype, value, getattr(rr, "ttl", None)))
        except Exception:  # noqa: BLE001
            malformed = malformed or "answer not decodable"
    rec.app = label
    rec.dns = DnsInfo(
        txid=int(msg.id),
        is_response=bool(msg.qr),
        opcode=int(msg.opcode),
        rcode=int(msg.rcode),
        truncated=bool(msg.tc),
        qname=qname,
        qtype=qtype,
        qdcount=int(msg.qdcount),
        ancount=int(msg.ancount),
        answers=tuple(answers),
        malformed=malformed,
    )


def _name(value: bytes | str) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="backslashreplace")
    return value[:-1] if value.endswith(".") and len(value) > 1 else value


def _decode_tcp_app(rec: PacketRecord, payload: bytes) -> None:
    if payload.startswith(HTTP_METHODS):
        head = payload[:4096]
        line_end = head.find(b"\r\n")
        request_line = head[: line_end if line_end >= 0 else 256]
        parts = request_line.split(b" ")
        method = parts[0]
        target = parts[1] if len(parts) > 1 else b""
        host = b""
        for line in head.split(b"\r\n")[1:40]:
            if line[:5].lower() == b"host:":
                host = line[5:].strip()
                break
        rec.app = "HTTP"
        rec.app_info = clean(f"{method.decode('ascii', 'replace')} {_bytes_text(host)}{_bytes_text(target)}", 200)
    elif payload.startswith(b"HTTP/1."):
        line_end = payload.find(b"\r\n", 0, 512)
        status = payload[: line_end if line_end >= 0 else 64]
        rec.app = "HTTP"
        rec.app_info = clean(_bytes_text(status), 120)
    elif len(payload) >= 6 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] in (1, 2):
        if payload[5] == 1:
            sni = _tls_sni(payload)
            rec.app = "TLS"
            if sni is None:
                rec.app_info = "ClientHello (SNI not present or not decodable)"
            else:
                rec.app_info = clean(f"ClientHello SNI={sni}", 200)
        else:
            rec.app = "TLS"
            rec.app_info = "ServerHello"


def _bytes_text(b: bytes) -> str:
    return b.decode("utf-8", errors="backslashreplace")


def _tls_sni(payload: bytes) -> str | None:
    """Extract server_name from a TLS ClientHello. Returns None on any inconsistency."""
    try:
        p = 5  # record header
        if payload[p] != 1:
            return None
        hs_len = int.from_bytes(payload[p + 1 : p + 4], "big")
        end = min(len(payload), p + 4 + hs_len)
        p += 4 + 2 + 32  # handshake header, client_version, random
        if p >= end:
            return None
        p += 1 + payload[p]  # session id
        cs_len = _U16.unpack_from(payload, p)[0]
        p += 2 + cs_len
        p += 1 + payload[p]  # compression methods
        ext_total = _U16.unpack_from(payload, p)[0]
        p += 2
        ext_end = min(end, p + ext_total)
        while p + 4 <= ext_end:
            etype, elen = struct.unpack_from("!HH", payload, p)
            p += 4
            if etype == 0 and p + 5 <= ext_end:
                name_len = _U16.unpack_from(payload, p + 3)[0]
                name = payload[p + 5 : p + 5 + name_len]
                if len(name) != name_len:
                    return None
                return clean(_bytes_text(name), 255)
            p += elen
    except (IndexError, struct.error):
        return None
    return None
