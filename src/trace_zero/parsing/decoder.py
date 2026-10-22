"""Bounds-checked frame decoder.

Bulk import uses this fast decoder for link, network and transport layers
(scapy's full dissection is roughly 100x slower), and scapy's DNS layer for
DNS payloads. Every read is bounds-checked; malformed data produces an entry
in ``PacketRecord.errors`` instead of an exception or a guessed value.
"""

from __future__ import annotations

import socket
import struct
import threading

from trace_zero.models import DhcpInfo, DnsAnswer, DnsInfo, PacketRecord
from trace_zero.parsing.scapy_bridge import DNS, Raw
from trace_zero.parsing.tls import looks_like_tls, parse_tls
from trace_zero.sanitize import clean

_U16 = struct.Struct("!H")
_IPV4_HDR = struct.Struct("!BHHHBBH")  # tos, total_len, id, frag, ttl, proto, csum
_TCP_HDR = struct.Struct("!HHIIHH")
_UDP_HDR = struct.Struct("!HHH")
_SLL_PROTO = struct.Struct("!H")

DNS_PORTS = {53: "DNS", 5353: "MDNS", 5355: "LLMNR"}
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")

_local = threading.local()


def _sink(payload: bytes) -> None:
    sink = getattr(_local, "sink", None)
    if sink is not None:
        sink.append(payload)


def decode_with_payload(no: int, ts: float, data: bytes, linktype: int) -> tuple[PacketRecord, bytes | None]:
    """Decode a frame and also return its TCP/UDP payload bytes (captured part only)."""
    _local.sink = []
    try:
        rec = decode_frame(no, ts, data, len(data), linktype)
        payload = _local.sink[0] if _local.sink else None
    finally:
        _local.sink = None
    return rec, payload


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
    rec.arp_hw = _mac(sha)
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
        _sink(data[start:cap_end] if start < cap_end else b"")
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
        _sink(data[p + 8 : end] if end > p + 8 else b"")
        label = DNS_PORTS.get(dport) or DNS_PORTS.get(sport)
        if label and end > p + 8:
            _decode_dns(rec, data[p + 8 : end], label, errors, max_dns)
        elif {sport, dport} <= {67, 68} and end > p + 8:
            _decode_dhcp(rec, data[p + 8 : end], errors)
    elif proto in (1, 58):
        rec.transport = "ICMP" if proto == 1 else "ICMPv6"
        if cap_end - p < 4:
            errors.append(f"truncated {rec.transport} header")
            return
        rec.icmp_type = data[p]
        rec.icmp_code = data[p + 1]
        rec.payload_len = max(0, declared_end - p - 4)
        if (proto == 1 and rec.icmp_type in (3, 4, 5, 11, 12)) or (proto == 58 and rec.icmp_type in (1, 2, 3, 4)):
            rec.icmp_orig = _quoted_packet(data, p + 8, cap_end, proto == 58)
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
    elif payload[:1] == b"\x16" and looks_like_tls(payload):
        # Only handshake records are labelled: a bare 0x17 0x03 prefix is too weak a signal.
        info = parse_tls(payload)
        if info is not None and info.messages:
            rec.app = "TLS"
            rec.tls = info
            rec.app_info = clean(info.summary, 200)


def _bytes_text(b: bytes) -> str:
    return b.decode("utf-8", errors="backslashreplace")


_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _quoted_packet(data: bytes, q: int, end: int, v6: bool) -> tuple | None:
    """Decode the original packet quoted inside an ICMP error (header + first 8 bytes)."""
    try:
        if v6:
            if end - q < 40 or data[q] >> 4 != 6:
                return None
            nh = data[q + 6]
            src, dst = _ip(data[q + 8 : q + 24]), _ip(data[q + 24 : q + 40])
            l4 = q + 40
        else:
            if end - q < 20 or data[q] >> 4 != 4:
                return None
            ihl = (data[q] & 0x0F) * 4
            if ihl < 20:
                return None
            nh = data[q + 9]
            src, dst = _ip(data[q + 12 : q + 16]), _ip(data[q + 16 : q + 20])
            l4 = q + ihl
        sport = dport = None
        if nh in (6, 17) and end - l4 >= 4:
            sport, dport = struct.unpack_from("!HH", data, l4)
        return (_PROTO_NAMES.get(nh, f"IP/{nh}"), src, sport, dst, dport)
    except (IndexError, struct.error, ValueError):
        return None


_DHCP_COOKIE = b"\x63\x82\x53\x63"


def _decode_dhcp(rec: PacketRecord, payload: bytes, errors: list[str]) -> None:
    if len(payload) < 236:
        errors.append("DHCP/BOOTP payload too short")
        return
    op, htype, hlen = payload[0], payload[1], payload[2]
    xid = struct.unpack_from("!I", payload, 4)[0]
    ciaddr, yiaddr = _ip(payload[12:16]), _ip(payload[16:20])
    mac = _mac(payload[28:34]) if htype == 1 and hlen == 6 else None
    info = DhcpInfo(op=op, xid=xid, msg_type=None, client_mac=mac, ciaddr=ciaddr, yiaddr=yiaddr)
    if payload[236:240] == _DHCP_COOKIE:
        pos = 240
        for _ in range(255):
            if pos >= len(payload):
                break
            code = payload[pos]
            if code == 0:
                pos += 1
                continue
            if code == 255 or pos + 1 >= len(payload):
                break
            length = payload[pos + 1]
            val = payload[pos + 2 : pos + 2 + length]
            pos += 2 + length
            if len(val) < length:
                errors.append("DHCP option truncated")
                break
            if code == 53 and length >= 1:
                info.msg_type = val[0]
            elif code == 12:
                info.hostname = clean(_bytes_text(val), 64)
            elif code == 50 and length == 4:
                info.requested_ip = _ip(val)
            elif code == 54 and length == 4:
                info.server_id = _ip(val)
            elif code == 60:
                info.vendor_class = clean(_bytes_text(val), 64)
            elif code == 51 and length == 4:
                info.lease_s = struct.unpack("!I", val)[0]
    rec.app = "DHCP"
    rec.dhcp = info
    rec.app_info = clean(info.summary, 200)
