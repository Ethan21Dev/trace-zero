"""Offline enrichment: MAC vendors and MaxMind DB lookups."""

from __future__ import annotations

import pytest

from trace_zero.enrich import Enrichment, EnrichmentError, MMDBReader, OuiTable, mac_kind

from .mmdb_writer import Pointer, write_mmdb

CITY = [
    ("203.0.113.0/24", {"country": {"iso_code": "NL", "names": {"en": "Netherlands"}}, "city": {"names": {"en": "Amsterdam"}}}),
    ("198.51.100.0/25", {"country": {"iso_code": "DE", "names": {"en": "Germany"}}, "location": {"latitude": 52.52, "longitude": 13.4}}),
    ("2001:db8:ff::/48", {"country": {"iso_code": "JP", "names": {"en": "Japan"}}}),
]
ASN = [("203.0.113.0/24", {"autonomous_system_number": 64500, "autonomous_system_organization": "Example Transit"})]


def test_mac_kind():
    assert mac_kind("02:00:00:00:00:66").startswith("locally administered")
    assert mac_kind("01:00:5e:00:00:fb").startswith("multicast")
    assert mac_kind("ff:ff:ff:ff:ff:ff") == "broadcast"
    assert mac_kind("00:1b:21:aa:bb:cc") is None


def test_oui_ieee_csv_and_manuf(tmp_path):
    ieee = tmp_path / "oui.csv"
    ieee.write_text(
        'Registry,Assignment,Organization Name,Organization Address\n'
        'MA-L,001B21,"Intel Corporate","Lot 8, Jalan Hi-Tech 2/3 Kulim Kedah MY 09000"\n'
        'MA-M,70B3D5F,"Small Vendor","Nowhere"\n'
    )
    t = OuiTable(ieee)
    assert t.vendor("00:1b:21:aa:bb:cc") == "Intel Corporate"
    assert t.vendor("70:b3:d5:f1:00:01") == "Small Vendor"
    assert t.vendor("aa:bb:cc:dd:ee:ff") is None
    manuf = tmp_path / "manuf"
    manuf.write_text("# comment\n00:00:0C\tCisco\tCisco Systems, Inc\n00:50:C2:00:00:00/36\tTiny\tTiny Devices\n")
    m = OuiTable(manuf)
    assert m.vendor("00:00:0c:12:34:56") == "Cisco Systems, Inc"
    assert m.vendor("00:50:c2:00:10:23") is None and m.vendor("00:50:c2:00:01:23") == "Tiny Devices"  # /36 = 9 hex digits
    bad = tmp_path / "empty.csv"
    bad.write_text("nothing here")
    with pytest.raises(EnrichmentError):
        OuiTable(bad)


@pytest.mark.parametrize("ip_version", [4, 6])
def test_mmdb_lookup(tmp_path, ip_version):
    entries = [e for e in CITY if ip_version == 6 or ":" not in e[0]]
    db = MMDBReader(write_mmdb(tmp_path / "city.mmdb", entries, ip_version=ip_version))
    assert db.lookup("203.0.113.77")["city"]["names"]["en"] == "Amsterdam"
    assert db.lookup("198.51.100.5")["location"]["latitude"] == pytest.approx(52.52)
    assert db.lookup("198.51.100.200") is None  # outside the /25
    assert db.lookup("192.0.2.1") is None
    if ip_version == 6:
        assert db.lookup("2001:db8:ff::10")["country"]["iso_code"] == "JP"
    else:
        assert db.lookup("2001:db8:ff::10") is None


def test_pointers_are_followed(tmp_path):
    entries = [("203.0.113.0/24", {"autonomous_system_organization": Pointer(0), "autonomous_system_number": 64500})]
    db = MMDBReader(write_mmdb(tmp_path / "p.mmdb", entries, shared_strings={"org": "Shared Org Name"}))
    assert db.lookup("203.0.113.1")["autonomous_system_organization"] == "Shared Org Name"


def test_matches_reference_reader(tmp_path):
    maxminddb = pytest.importorskip("maxminddb")
    path = write_mmdb(tmp_path / "ref.mmdb", CITY)
    ours = MMDBReader(path)
    with maxminddb.open_database(str(path), mode=maxminddb.MODE_FILE) as ref:
        for ip in ("203.0.113.77", "198.51.100.5", "198.51.100.200", "2001:db8:ff::10", "8.8.8.8"):
            assert ours.lookup(ip) == ref.get(ip)
        assert ref.metadata().node_count == ours.node_count


@pytest.mark.parametrize("payload", [b"", b"garbage" * 100, b"\x00" * 64 + b"\xab\xcd\xefMaxMind.com" + b"\xe0", b"\xab\xcd\xefMaxMind.com\xff\xff\xff"])
def test_malformed_mmdb_rejected(tmp_path, payload):
    f = tmp_path / "bad.mmdb"
    f.write_bytes(payload)
    with pytest.raises(EnrichmentError):
        MMDBReader(f)


def test_corrupt_tree_does_not_crash(tmp_path):
    path = write_mmdb(tmp_path / "c.mmdb", CITY)
    data = bytearray(path.read_bytes())
    data[0:3] = b"\xff\xff\xff"  # first record points far outside the data section
    path.write_bytes(bytes(data))
    e = Enrichment(None, (MMDBReader(path),))
    assert e.ip_facts("203.0.113.77") == ()


def test_facade_describes_host(tmp_path):
    city = write_mmdb(tmp_path / "city.mmdb", CITY, db_type="GeoLite2-City")
    asn = write_mmdb(tmp_path / "asn.mmdb", ASN, db_type="GeoLite2-ASN")
    oui = tmp_path / "oui.csv"
    oui.write_text("Registry,Assignment,Organization Name,Organization Address\nMA-L,020000,Example NIC,x\n")
    e, problems = Enrichment.from_paths(oui, [city, asn, tmp_path / "missing.mmdb"])
    assert len(problems) == 1 and "missing.mmdb" in problems[0]
    rows = dict(e.describe_host("203.0.113.10", ["02:00:00:00:00:01"]))
    assert rows["country"].startswith("NL Netherlands") and "[GeoLite2-City]" in rows["country"]
    assert rows["network (ASN)"].startswith("AS64500 Example Transit")
    assert rows["MAC vendor"].startswith("Example NIC")
    assert rows["MAC type"].startswith("locally administered")
    assert e.ip_facts("10.20.0.11") == ()  # private addresses are never looked up
