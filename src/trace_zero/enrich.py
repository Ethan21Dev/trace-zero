"""Offline reference data: MAC vendors and IP geolocation / ASN.

Nothing here touches the network. Data comes from files the analyst supplies:

* an IEEE ``oui.csv`` or a Wireshark ``manuf`` file for MAC vendor names;
* MaxMind-format ``.mmdb`` databases (for example GeoLite2-Country, -City, -ASN)
  read by a small pure-Python reader.

Enrichment is *reference data*, not capture data: it is labelled with its
source everywhere it is shown and kept apart from observed facts in exports.
Database files are treated as untrusted input: every read is bounds-checked,
recursion and pointer chains are limited, and malformed files are rejected.
"""

from __future__ import annotations

import csv
import ipaddress
import struct
from dataclasses import dataclass, field
from pathlib import Path

from trace_zero.sanitize import clean

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"
_MAX_DEPTH = 32
_MAX_FILE = 512 * 1024 * 1024


class EnrichmentError(Exception):
    pass


# --- MAC addresses -------------------------------------------------------------------
def mac_kind(mac: str) -> str | None:
    """Facts encoded in the address itself (IEEE 802 bits)."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return None
    if mac.lower() == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    if first & 0x01:
        return "multicast group address"
    if first & 0x02:
        return "locally administered (randomised, virtual or manually set)"
    return None


class OuiTable:
    """Vendor prefixes from IEEE oui.csv (MA-L/MA-M/MA-S) or Wireshark manuf files."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.source = self.path.name
        self.prefixes: dict[int, dict[str, str]] = {}  # bits -> hex prefix -> vendor
        try:
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise EnrichmentError(f"cannot read OUI file {path}: {exc}") from exc
        if text.lstrip().lower().startswith("registry,assignment"):
            self._load_ieee(text)
        else:
            self._load_manuf(text)
        if not self.prefixes:
            raise EnrichmentError(f"no vendor prefixes found in {path}")

    def _add(self, hex_prefix: str, bits: int, vendor: str) -> None:
        self.prefixes.setdefault(bits, {})[hex_prefix.lower()] = clean(vendor.strip(), 80)

    def _load_ieee(self, text: str) -> None:
        for row in csv.reader(text.splitlines()[1:]):
            if len(row) >= 3 and row[1]:
                bits = {"MA-L": 24, "MA-M": 28, "MA-S": 36}.get(row[0].strip(), 4 * len(row[1].strip()))
                self._add(row[1].strip(), bits, row[2])

    def _load_manuf(self, text: str) -> None:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            raw, short = parts[0], parts[1]
            vendor = parts[2] if len(parts) > 2 and parts[2] else short
            prefix, _, mask = raw.partition("/")
            hexs = prefix.replace(":", "").replace("-", "").replace(".", "")
            bits = int(mask) if mask.isdigit() else 4 * len(hexs)
            self._add(hexs[: (bits + 3) // 4], bits, vendor)

    def vendor(self, mac: str) -> str | None:
        hexs = mac.replace(":", "").lower()
        for bits in sorted(self.prefixes, reverse=True):
            vendor = self.prefixes[bits].get(hexs[: (bits + 3) // 4])
            if vendor:
                return vendor
        return None


# --- MaxMind DB ----------------------------------------------------------------------
class MMDBReader:
    """Minimal reader for the MaxMind DB format (https://maxmind.github.io/MaxMind-DB/)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        try:
            size = self.path.stat().st_size
            if size > _MAX_FILE:
                raise EnrichmentError(f"{path.name} is larger than {_MAX_FILE // 1048576} MB")
            self.buf = self.path.read_bytes()
        except OSError as exc:
            raise EnrichmentError(f"cannot read {path}: {exc}") from exc
        idx = self.buf.rfind(METADATA_MARKER, max(0, len(self.buf) - 128 * 1024))
        if idx < 0:
            raise EnrichmentError(f"{self.path.name} is not a MaxMind DB file (metadata marker missing)")
        meta_start = idx + len(METADATA_MARKER)
        self._data_start = meta_start  # metadata is decoded relative to its own start
        meta, _ = self._decode(meta_start, 0, base=meta_start)
        if not isinstance(meta, dict):
            raise EnrichmentError("invalid MaxMind DB metadata")
        try:
            self.node_count = int(meta["node_count"])
            self.record_size = int(meta["record_size"])
            self.ip_version = int(meta["ip_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EnrichmentError("incomplete MaxMind DB metadata") from exc
        if self.record_size not in (24, 28, 32) or self.ip_version not in (4, 6):
            raise EnrichmentError("unsupported MaxMind DB record size or IP version")
        self.database_type = clean(meta.get("database_type", "unknown"), 60)
        self.build_epoch = int(meta.get("build_epoch", 0) or 0)
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_count * self.node_bytes
        self._data_start = self.tree_size + 16
        if self._data_start > idx:
            raise EnrichmentError("MaxMind DB search tree exceeds file")
        self._ipv4_start = 0
        if self.ip_version == 6:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._record(node, 0)
            self._ipv4_start = node

    def _record(self, node: int, bit: int) -> int:
        off = node * self.node_bytes
        b = self.buf
        if off + self.node_bytes > self.tree_size:
            raise EnrichmentError("search tree node out of range")
        if self.record_size == 24:
            o = off + bit * 3
            return int.from_bytes(b[o : o + 3], "big")
        if self.record_size == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | int.from_bytes(b[off : off + 3], "big")
            return ((b[off + 3] & 0x0F) << 24) | int.from_bytes(b[off + 4 : off + 7], "big")
        o = off + bit * 4
        return int.from_bytes(b[o : o + 4], "big")

    def lookup(self, ip: str) -> dict | None:
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and self.ip_version == 4:
            return None
        packed = addr.packed
        bits = len(packed) * 8
        node = self._ipv4_start if addr.version == 4 and self.ip_version == 6 else 0
        for i in range(bits):
            if node >= self.node_count:
                break
            bit = (packed[i >> 3] >> (7 - (i & 7))) & 1
            node = self._record(node, bit)
        if node == self.node_count:
            return None
        if node < self.node_count:
            return None
        offset = node - self.node_count - 16
        value, _ = self._decode(self._data_start + offset, 0, base=self._data_start)
        return value if isinstance(value, dict) else None

    def _decode(self, pos: int, depth: int, base: int):
        if depth > _MAX_DEPTH:
            raise EnrichmentError("MaxMind DB data nested too deeply")
        b = self.buf
        if pos >= len(b):
            raise EnrichmentError("data offset out of range")
        ctrl = b[pos]
        pos += 1
        dtype = ctrl >> 5
        if dtype == 1:  # pointer
            ss, vvv = (ctrl >> 3) & 3, ctrl & 7
            if ss == 0:
                ptr = (vvv << 8) | b[pos]
                pos += 1
            elif ss == 1:
                ptr = ((vvv << 16) | int.from_bytes(b[pos : pos + 2], "big")) + 2048
                pos += 2
            elif ss == 2:
                ptr = ((vvv << 24) | int.from_bytes(b[pos : pos + 3], "big")) + 526336
                pos += 3
            else:
                ptr = int.from_bytes(b[pos : pos + 4], "big")
                pos += 4
            value, _ = self._decode(base + ptr, depth + 1, base)
            return value, pos
        if dtype == 0:
            dtype = 7 + b[pos]
            pos += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + b[pos]
            pos += 1
        elif size == 30:
            size = 285 + int.from_bytes(b[pos : pos + 2], "big")
            pos += 2
        elif size == 31:
            size = 65821 + int.from_bytes(b[pos : pos + 3], "big")
            pos += 3
        if dtype == 2:
            return clean(b[pos : pos + size].decode("utf-8", "replace"), 200), pos + size
        if dtype == 7:
            out = {}
            for _ in range(size):
                key, pos = self._decode(pos, depth + 1, base)
                val, pos = self._decode(pos, depth + 1, base)
                out[str(key)] = val
            return out, pos
        if dtype == 11:
            arr = []
            for _ in range(min(size, 10000)):
                val, pos = self._decode(pos, depth + 1, base)
                arr.append(val)
            return arr, pos
        if dtype in (5, 6, 9, 10):
            return int.from_bytes(b[pos : pos + size], "big"), pos + size
        if dtype == 8:
            return int.from_bytes(b[pos : pos + size].rjust(4, b"\x00"), "big", signed=True), pos + size
        if dtype == 3:
            return struct.unpack(">d", b[pos : pos + 8])[0], pos + 8
        if dtype == 15:
            return struct.unpack(">f", b[pos : pos + 4])[0], pos + 4
        if dtype == 14:
            return bool(size), pos
        if dtype == 4:
            return b[pos : pos + size].hex(), pos + size
        raise EnrichmentError(f"unsupported MaxMind DB data type {dtype}")


# --- facade --------------------------------------------------------------------------
@dataclass(eq=False)
class Enrichment:
    oui: OuiTable | None = None
    databases: tuple[MMDBReader, ...] = ()
    _ip_cache: dict[str, tuple[tuple[str, str], ...]] = field(default_factory=dict, repr=False)

    @classmethod
    def from_paths(cls, oui_path: Path | None, mmdb_paths: list[Path]) -> tuple[Enrichment, list[str]]:
        """Load what is available; returns (enrichment, problems) without raising."""
        problems = []
        oui = None
        if oui_path:
            try:
                oui = OuiTable(oui_path)
            except EnrichmentError as exc:
                problems.append(str(exc))
        dbs = []
        for p in mmdb_paths:
            try:
                dbs.append(MMDBReader(p))
            except EnrichmentError as exc:
                problems.append(str(exc))
        return cls(oui, tuple(dbs)), problems

    @property
    def active(self) -> bool:
        return self.oui is not None or bool(self.databases)

    def vendor(self, mac: str) -> str | None:
        return self.oui.vendor(mac) if self.oui else None

    def ip_facts(self, ip: str) -> tuple[tuple[str, str], ...]:
        cached = self._ip_cache.get(ip)
        if cached is None:
            cached = self._ip_facts(ip)
            if len(self._ip_cache) < 100_000:
                self._ip_cache[ip] = cached
        return cached

    def _ip_facts(self, ip: str) -> tuple[tuple[str, str], ...]:
        from trace_zero.analysis.index import classify_ip

        # Local, multicast and special addresses are never looked up. (Documentation ranges are
        # looked up: the ipaddress module calls them private, but they are not local networks.)
        if classify_ip(ip) not in ("public", "documentation range"):
            return ()
        out: list[tuple[str, str]] = []
        for db in self.databases:
            try:
                rec = db.lookup(ip)
            except (EnrichmentError, IndexError, struct.error, ValueError):
                continue
            if not rec:
                continue
            src = db.database_type
            country = rec.get("country") or rec.get("registered_country")
            if isinstance(country, dict):
                name = (country.get("names") or {}).get("en") if isinstance(country.get("names"), dict) else None
                code = country.get("iso_code")
                if code or name:
                    out.append(("country", f"{code or ''} {name or ''}".strip() + f"  [{src}]"))
            city = rec.get("city")
            if isinstance(city, dict) and isinstance(city.get("names"), dict) and city["names"].get("en"):
                out.append(("city", f"{city['names']['en']}  [{src}]"))
            asn = rec.get("autonomous_system_number")
            if asn is not None:
                org = rec.get("autonomous_system_organization", "")
                out.append(("network (ASN)", f"AS{asn} {org}".strip() + f"  [{src}]"))
        return tuple(out)

    def describe_host(self, ip: str, macs: list[str]) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []
        for mac in macs[:3]:
            kind = mac_kind(mac)
            vendor = self.vendor(mac)
            if vendor:
                rows.append(("MAC vendor", f"{vendor} ({mac})  [{self.oui.source}]"))
            if kind:
                rows.append(("MAC type", f"{kind} ({mac})"))
        rows.extend(self.ip_facts(ip))
        return rows

    def sources(self) -> list[str]:
        out = []
        if self.oui:
            out.append(f"MAC vendors: {self.oui.path}")
        for db in self.databases:
            out.append(f"{db.database_type}: {db.path} (built {db.build_epoch})")
        return out
