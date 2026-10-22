"""Tiny MaxMind DB writer for tests (format: https://maxmind.github.io/MaxMind-DB/)."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

MARKER = b"\xab\xcd\xefMaxMind.com"


def _ctrl(dtype: int, size: int) -> bytes:
    ext = b""
    if dtype > 7:
        ext = bytes([dtype - 7])
        dtype = 0
    if size < 29:
        return bytes([(dtype << 5) | size]) + ext
    if size < 285:
        return bytes([(dtype << 5) | 29]) + ext + bytes([size - 29])
    if size < 65821:
        return bytes([(dtype << 5) | 30]) + ext + (size - 285).to_bytes(2, "big")
    return bytes([(dtype << 5) | 31]) + ext + (size - 65821).to_bytes(3, "big")


def encode(value) -> bytes:
    if isinstance(value, bool):
        return _ctrl(14, int(value))
    if isinstance(value, str):
        raw = value.encode()
        return _ctrl(2, len(raw)) + raw
    if isinstance(value, float):
        return _ctrl(3, 8) + struct.pack(">d", value)
    if isinstance(value, int):
        if value < 0:
            raw = value.to_bytes(4, "big", signed=True)
            return _ctrl(8, 4) + raw
        if value < 1 << 32:
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
            return _ctrl(6, len(raw)) + raw
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return _ctrl(9, len(raw)) + raw
    if isinstance(value, dict):
        out = _ctrl(7, len(value))
        for k, v in value.items():
            out += encode(k) + encode(v)
        return out
    if isinstance(value, list):
        out = _ctrl(11, len(value))
        for v in value:
            out += encode(v)
        return out
    if isinstance(value, Pointer):
        return bytes([(1 << 5) | (0 << 3) | ((value.offset >> 8) & 7), value.offset & 0xFF])
    raise TypeError(type(value))


class Pointer:
    def __init__(self, offset: int) -> None:
        assert offset < 2048
        self.offset = offset


def write_mmdb(path: Path, entries: list[tuple[str, object]], ip_version: int = 6, db_type: str = "Test-City", shared_strings: dict | None = None) -> Path:
    """entries: (network, record). shared_strings are written first so records can point at them."""
    data = bytearray()
    for s in (shared_strings or {}).values():
        data += encode(s)
    nodes: list[list] = [[None, None]]
    for net, rec in entries:
        n = ipaddress.ip_network(net)
        if ip_version == 6 and n.version == 4:
            bits = "0" * 96 + format(int(n.network_address), "032b")
            plen = 96 + n.prefixlen
        else:
            width = 32 if n.version == 4 else 128
            bits = format(int(n.network_address), f"0{width}b")
            plen = n.prefixlen
        offset = len(data)
        data += encode(rec)
        node = 0
        for i in range(plen - 1):
            b = int(bits[i])
            nxt = nodes[node][b]
            if nxt is None or nxt[0] != "node":
                nodes.append([None, None])
                nodes[node][b] = ("node", len(nodes) - 1)
                nxt = nodes[node][b]
            node = nxt[1]
        nodes[node][int(bits[plen - 1])] = ("data", offset)
    count = len(nodes)

    def value(rec) -> int:
        if rec is None:
            return count
        if rec[0] == "node":
            return rec[1]
        return count + 16 + rec[1]

    tree = b"".join(value(l).to_bytes(3, "big") + value(r).to_bytes(3, "big") for l, r in nodes)
    meta = {
        "node_count": count,
        "record_size": 24,
        "ip_version": ip_version,
        "database_type": db_type,
        "languages": ["en"],
        "binary_format_major_version": 2,
        "binary_format_minor_version": 0,
        "build_epoch": 1767225600,
        "description": {"en": "unit test database"},
    }
    path.write_bytes(tree + bytes(16) + bytes(data) + MARKER + encode(meta))
    return path
