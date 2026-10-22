"""TLS (JA3/JA3S/JA4, certificates), DHCP and ICMP-error decoding."""

from __future__ import annotations

import hashlib
import struct

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6DestUnreach, IPv6
from scapy.packet import Raw

from trace_zero.parsing.decoder import decode_frame
from trace_zero.parsing.tls import is_grease, parse_certificate, parse_tls

from .conftest import ETH


# --- builders -------------------------------------------------------------------------
def u16(v: int) -> bytes:
    return v.to_bytes(2, "big")


def ext(etype: int, body: bytes) -> bytes:
    return u16(etype) + u16(len(body)) + body


def handshake(htype: int, body: bytes) -> bytes:
    return bytes([htype]) + len(body).to_bytes(3, "big") + body


def record(hs: bytes, ctype: int = 0x16) -> bytes:
    return bytes([ctype]) + b"\x03\x01" + u16(len(hs)) + hs


def client_hello(ciphers: list[int], exts: list[bytes], version: int = 0x0303) -> bytes:
    cs = b"".join(u16(c) for c in ciphers)
    ex = b"".join(exts)
    body = u16(version) + bytes(32) + b"\x00" + u16(len(cs)) + cs + b"\x01\x00" + u16(len(ex)) + ex
    return handshake(1, body)


def sni_ext(name: str) -> bytes:
    n = name.encode()
    return ext(0, u16(len(n) + 3) + b"\x00" + u16(len(n)) + n)


def alpn_ext(*protos: str) -> bytes:
    lst = b"".join(bytes([len(p)]) + p.encode() for p in protos)
    return ext(16, u16(len(lst)) + lst)


def u16_list_ext(etype: int, values: list[int], len_bytes: int = 2) -> bytes:
    body = b"".join(u16(v) for v in values)
    return ext(etype, len(body).to_bytes(len_bytes, "big") + body)


# DER helpers
def der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def seq(*parts: bytes) -> bytes:
    return der(0x30, b"".join(parts))


def name(cn: str) -> bytes:
    return seq(der(0x31, seq(der(0x06, bytes.fromhex("550403")), der(0x0C, cn.encode()))))


def certificate(subject: str, issuer: str, sans: list[str]) -> bytes:
    san = seq(*[der(0x82, s.encode()) for s in sans])
    extensions = der(0xA3, seq(seq(der(0x06, bytes.fromhex("551d11")), der(0x04, san))))
    alg = seq(der(0x06, bytes.fromhex("2a864886f70d01010b")), b"\x05\x00")
    validity = seq(der(0x17, b"260101000000Z"), der(0x17, b"270101000000Z"))
    spki = seq(alg, der(0x03, b"\x00" + b"\x01" * 8))
    tbs = seq(der(0xA0, der(0x02, b"\x02")), der(0x02, b"\x01\x23"), alg, name(issuer), validity, name(subject), spki, extensions)
    return seq(tbs, alg, der(0x03, b"\x00" + b"\xaa" * 16))


# --- JA4 / JA3 -----------------------------------------------------------------------------
JA4_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
JA4_SIGALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def ja4_reference_hello() -> bytes:
    """Field values of the published JA4 example t13d1516h2_8daaf6152771_e5627efa2ab1."""
    exts = [
        ext(0x0A0A, b""),  # GREASE, must be ignored
        sni_ext("example.org"),
        ext(0x0017, b""),
        ext(0xFF01, b"\x00"),
        u16_list_ext(0x000A, [0x001D, 0x0017]),
        ext(0x000B, b"\x01\x00"),
        ext(0x0023, b""),
        alpn_ext("h2", "http/1.1"),
        ext(0x0005, b"\x01\x00\x00\x00\x00"),
        u16_list_ext(0x000D, JA4_SIGALGS),
        ext(0x0012, b""),
        ext(0x0033, u16(0)),
        ext(0x002D, b"\x01\x01"),
        ext(0x002B, b"\x04" + u16(0x0304) + u16(0x0303)),
        ext(0x001B, b"\x02\x00\x02"),
        ext(0x4469, b""),
        ext(0x0015, b"\x00\x00"),
    ]
    return record(client_hello([0x2A2A] + JA4_CIPHERS, exts))


def test_ja4_matches_published_example():
    info = parse_tls(ja4_reference_hello())
    assert info.ja4 == "t13d1516h2_8daaf6152771_e5627efa2ab1"
    assert info.sni == "example.org" and info.alpn == ("h2", "http/1.1")
    assert 0x0304 in info.client_versions


def test_ja3_string_and_hash():
    hello = record(
        client_hello(
            [0x1A1A, 0xC02B, 0x002F],
            [sni_ext("a.example"), u16_list_ext(10, [0x2A2A, 29, 23]), ext(11, b"\x01\x00"), ext(0x3A3A, b"")],
        )
    )
    info = parse_tls(hello)
    assert info.ja3_string == "771,49195-47,0-10-11,29-23,0"
    assert info.ja3 == hashlib.md5(b"771,49195-47,0-10-11,29-23,0").hexdigest()


def test_grease_detection():
    assert all(is_grease(v) for v in (0x0A0A, 0x1A1A, 0xFAFA))
    assert not any(is_grease(v) for v in (0x0A0B, 0x1301, 0x0000))


def test_server_hello_certificate_in_one_segment():
    sh_body = u16(0x0303) + bytes(32) + b"\x00" + u16(0xC02F) + b"\x00"
    sh_exts = ext(0xFF01, b"\x00") + ext(0x0017, b"")
    sh = handshake(2, sh_body + u16(len(sh_exts)) + sh_exts)
    cert = certificate("svc.example.org", "Example Test CA", ["svc.example.org", "alt.example.org"])
    cert_list = len(cert).to_bytes(3, "big") + cert
    cert_msg = handshake(11, len(cert_list).to_bytes(3, "big") + cert_list)
    info = parse_tls(record(sh + cert_msg))
    assert info.server_version == 0x0303 and info.cipher == 0xC02F
    assert info.ja3s_string == "771,49199,65281-23"
    assert info.ja3s == hashlib.md5(b"771,49199,65281-23").hexdigest()
    assert info.cert_subject_cn == "svc.example.org" and info.cert_issuer_cn == "Example Test CA"
    assert info.cert_san == ("svc.example.org", "alt.example.org")
    assert "Certificate CN=svc.example.org" in info.summary


def test_tls13_server_hello_selected_version():
    sh_body = u16(0x0303) + bytes(32) + b"\x00" + u16(0x1301) + b"\x00"
    sh_exts = ext(0x002B, u16(0x0304)) + ext(0x0033, u16(0x001D) + u16(4) + b"\x00" * 4)
    info = parse_tls(record(handshake(2, sh_body + u16(len(sh_exts)) + sh_exts)))
    assert info.server_version == 0x0304


def test_handshake_split_across_records():
    hs = client_hello([0x1301], [sni_ext("split.example")])
    data = record(hs[:20]) + record(hs[20:])
    assert parse_tls(data).sni == "split.example"


def test_truncated_and_garbage_tls():
    full = ja4_reference_hello()
    for cut in range(0, len(full), 7):
        info = parse_tls(full[:cut])
        assert info is None or info.ja4 is None or cut == len(full)
    assert parse_tls(b"\x16\x03\x01\xff\xff" + b"\x00" * 50) is not None  # no crash
    assert parse_tls(b"GET / HTTP/1.1\r\n") is None
    assert parse_certificate(b"\x30\x82\xff\xff") == (None, None, [])


def test_tls_on_the_wire_is_labelled():
    frame = bytes(ETH() / IP() / TCP(sport=40000, dport=443, flags="PA") / Raw(ja4_reference_hello()))
    p = decode_frame(1, 0.0, frame, len(frame), 1)
    assert p.app == "TLS" and p.tls.ja4.startswith("t13d1516h2")
    assert p.app_info == "ClientHello SNI=example.org"


# --- DHCP --------------------------------------------------------------------------------
def dhcp_payload(msg_type: int, xid: int, mac: bytes, yiaddr: str = "0.0.0.0", options: bytes = b"") -> bytes:
    import socket

    # RFC 2131: op htype hlen hops | xid | secs flags | ciaddr | yiaddr | siaddr | giaddr | chaddr[16] | sname+file[192]
    hdr = bytes([1 if msg_type in (1, 3) else 2, 1, 6, 0]) + struct.pack("!I", xid) + b"\x00" * 4
    hdr += socket.inet_aton("0.0.0.0") + socket.inet_aton(yiaddr) + b"\x00" * 8
    hdr += mac + b"\x00" * 10 + b"\x00" * 192
    assert len(hdr) == 236
    opts = bytes([53, 1, msg_type]) + options + b"\xff"
    return hdr + b"\x63\x82\x53\x63" + opts


def test_dhcp_request_and_ack():
    mac = bytes.fromhex("02000000000b")
    req = dhcp_payload(3, 0xABCD, mac, options=bytes([12, 9]) + b"ws-11-lab" + bytes([50, 4, 10, 20, 0, 11]))
    f = bytes(ETH() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(req))
    p = decode_frame(1, 0.0, f, len(f), 1)
    assert p.app == "DHCP" and p.dhcp.type_name == "REQUEST"
    assert p.dhcp.hostname == "ws-11-lab" and p.dhcp.requested_ip == "10.20.0.11" and p.dhcp.client_mac == "02:00:00:00:00:0b"
    ack = dhcp_payload(5, 0xABCD, mac, yiaddr="10.20.0.11", options=bytes([54, 4, 10, 20, 0, 1, 51, 4, 0, 0, 14, 16]))
    f = bytes(ETH() / IP(src="10.20.0.1", dst="10.20.0.11") / UDP(sport=67, dport=68) / Raw(ack))
    p = decode_frame(2, 0.0, f, len(f), 1)
    assert p.dhcp.type_name == "ACK" and p.dhcp.yiaddr == "10.20.0.11" and p.dhcp.server_id == "10.20.0.1" and p.dhcp.lease_s == 3600
    assert "assigned 10.20.0.11" in p.info


def test_dhcp_malformed():
    f = bytes(ETH() / IP() / UDP(sport=68, dport=67) / Raw(b"\x01" * 50))
    p = decode_frame(1, 0.0, f, len(f), 1)
    assert p.dhcp is None and any("DHCP" in e for e in p.errors)
    bad_opt = dhcp_payload(1, 1, bytes(6))[:-1] + bytes([12, 200]) + b"short"
    f = bytes(ETH() / IP() / UDP(sport=68, dport=67) / Raw(bad_opt))
    p = decode_frame(1, 0.0, f, len(f), 1)
    assert p.dhcp is not None and any("truncated" in e for e in p.errors)


# --- ICMP errors ------------------------------------------------------------------------
def test_icmp_port_unreachable_quotes_original_flow():
    original = IP(src="10.20.0.11", dst="10.20.0.53") / UDP(sport=40001, dport=53)
    f = bytes(ETH() / IP(src="10.20.0.53", dst="10.20.0.11") / ICMP(type=3, code=3) / bytes(original)[:28])
    p = decode_frame(1, 0.0, f, len(f), 1)
    assert p.icmp_orig == ("UDP", "10.20.0.11", 40001, "10.20.0.53", 53)
    assert "for UDP 10.20.0.11:40001 -> 10.20.0.53:53" in p.info


def test_icmpv6_unreachable_quotes_original_flow():
    original = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=50000, dport=443)
    f = bytes(ETH() / IPv6(src="2001:db8::2", dst="2001:db8::1") / ICMPv6DestUnreach(code=4) / bytes(original)[:48])
    p = decode_frame(1, 0.0, f, len(f), 1)
    assert p.icmp_orig == ("TCP", "2001:db8::1", 50000, "2001:db8::2", 443)


def test_icmp_echo_has_no_quote():
    f = bytes(ETH() / IP() / ICMP(type=8) / Raw(b"\x45" * 30))
    assert decode_frame(1, 0.0, f, len(f), 1).icmp_orig is None


def test_host_metadata_from_dhcp_and_tls(tmp_path):
    from trace_zero.analysis.index import CaptureIndex
    from trace_zero.parsing.reader import read_capture

    from .conftest import write_pcap

    mac = bytes.fromhex("02000000000b")
    req = dhcp_payload(3, 7, mac, options=bytes([12, 9]) + b"ws-11-lab")
    ack = dhcp_payload(5, 7, mac, yiaddr="10.20.0.11")
    other = dhcp_payload(3, 8, bytes.fromhex("02000000000c"), options=bytes([12, 5]) + b"ghost")  # no ACK -> no name
    frames = [
        (1.0, bytes(ETH() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(req))),
        (1.1, bytes(ETH() / IP(src="10.20.0.1", dst="10.20.0.11") / UDP(sport=67, dport=68) / Raw(ack))),
        (1.2, bytes(ETH() / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(other))),
        (2.0, bytes(ETH() / IP(src="10.20.0.11", dst="203.0.113.10") / TCP(sport=40000, dport=443, flags="PA") / Raw(ja4_reference_hello()))),
    ]
    idx = CaptureIndex(read_capture(write_pcap(tmp_path / "meta.pcap", frames)))
    ws = idx.hosts["10.20.0.11"]
    assert ws.dhcp_names == {"ws-11-lab": 1}
    assert ws.tls_client_fps["t13d1516h2_8daaf6152771_e5627efa2ab1"] == 1
    assert idx.hosts["203.0.113.10"].tls_names == {"example.org": 4}
    assert not any(m.dhcp_names.get("ghost") for m in idx.hosts.values())
