"""Heuristics fire on the seeded scenarios, explain themselves, and stay quiet on benign traffic."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import Ether

from trace_zero.analysis.anomaly import RULES, detect
from trace_zero.analysis.index import CaptureIndex
from trace_zero.config import AnomalyConfig, Config
from trace_zero.parsing.reader import read_capture
from trace_zero.session import load_capture

from .conftest import ETH, write_pcap


def by_rule(findings, rule):
    return [f for f in findings if f.rule == rule]


def test_all_rules_fire_on_sample(loaded_sample):
    fs = loaded_sample.findings
    assert {f.rule for f in fs} == set(RULES)
    r1 = by_rule(fs, "TZ-R1")[0]
    assert set(r1.hosts) == {"10.20.0.13", "10.20.0.80"} and "3389" in r1.title
    assert r1.metrics["refused"] == 12 and r1.confidence == "HIGH"
    r2 = by_rule(fs, "TZ-R2")[0]
    assert r2.hosts[0] == "10.20.0.14" and r2.metrics["distinct_ports"] >= 40
    r3 = by_rule(fs, "TZ-R3")[0]
    assert "198.51.100.7" in r3.hosts and "10.20.0.12" in r3.hosts
    r4 = by_rule(fs, "TZ-R4")[0]
    assert r4.hosts[0] == "10.20.0.11" and r4.metrics["nxdomain"] >= 70
    beacon = [f for f in by_rule(fs, "TZ-R5") if "192.0.2.44" in f.hosts]
    assert beacon and beacon[0].metrics["interval_cv"] < 0.1


def test_findings_are_explainable_and_referenced(loaded_sample):
    idx = loaded_sample.index
    for f in loaded_sample.findings:
        assert f.severity in ("LOW", "MEDIUM", "HIGH")
        assert f.confidence in ("LOW", "MEDIUM", "HIGH") and f.confidence_reason
        assert f.explanation and f.rule in RULES
        assert f.first_ts <= f.last_ts and f.timestamps
        assert f.frames and f.frame_count >= len(f.frames)
        for no in f.frames:
            p = idx.packet(no)
            assert p is not None
        d = f.to_dict()
        assert "possible anomaly" in d["classification"] and "not proof" in d["classification"]


def test_evidence_frames_support_the_claim(loaded_sample):
    idx = loaded_sample.index
    r1 = by_rule(loaded_sample.findings, "TZ-R1")[0]
    syns = [idx.packet(n) for n in r1.frames if idx.packet(n).is_syn]
    assert len(syns) == r1.metrics["attempts_in_window"]
    assert all(p.dport == 3389 and p.src == "10.20.0.13" for p in syns)


def test_detection_is_deterministic(sample_pcap):
    a = load_capture(sample_pcap, Config()).findings
    b = load_capture(sample_pcap, Config()).findings
    assert [f.id for f in a] == [f.id for f in b]


def test_benign_capture_has_no_findings(tmp_path):
    frames = []
    t = 1000.0
    for i in range(120):
        sport = 40000 + i
        frames.append((t, bytes(ETH() / IP(src="10.0.0.5", dst="192.0.2.10") / TCP(sport=sport, dport=443, flags="S"))))
        frames.append((t + 0.01, bytes(ETH() / IP(src="192.0.2.10", dst="10.0.0.5") / TCP(sport=443, dport=sport, flags="SA"))))
        frames.append((t + 0.02, bytes(ETH() / IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=sport, dport=53) / DNS(qd=DNSQR(qname="www.example.com")))))
        t += 7.3 + (i % 5)
    f = write_pcap(tmp_path / "benign.pcap", frames)
    idx = CaptureIndex(read_capture(f))
    assert detect(idx) == []


def test_thresholds_are_configurable(loaded_sample):
    strict = AnomalyConfig(
        repeat_min_attempts=50, fanout_min_ports=100, dns_min_queries=500, spike_min_bytes=10**9, pair_min_contacts=10**6,
        outbound_min_bytes=10**9, late_min_bytes=10**9, dns_unsolicited_min=100,
    )
    remaining = detect(loaded_sample.index, strict)
    # Rules without volume thresholds still report what they saw: MAC conflicts, conflicting DNS answers, SNI mismatch.
    assert {f.rule for f in remaining} == {"TZ-R6", "TZ-R7", "TZ-R10"}
    assert all(f.metrics.get("conflicting", 1) for f in remaining if f.rule == "TZ-R7")


def test_unanswered_attempts_get_lower_confidence(tmp_path):
    frames = [
        (1000.0 + i, bytes(ETH() / IP(src="10.0.0.7", dst="10.0.0.8") / TCP(sport=50000 + i, dport=22, flags="S")))
        for i in range(8)
    ]
    idx = CaptureIndex(read_capture(write_pcap(tmp_path / "u.pcap", frames)))
    r1 = by_rule(detect(idx), "TZ-R1")
    assert r1 and r1[0].confidence == "MEDIUM" and r1[0].metrics["unanswered"] == 8
    assert "return traffic" in r1[0].confidence_reason


def test_empty_capture(tmp_path):
    idx = CaptureIndex(read_capture(write_pcap(tmp_path / "e.pcap", [])))
    assert detect(idx) == []


def test_new_rules_on_sample(loaded_sample):
    fs = loaded_sample.findings
    r6 = by_rule(fs, "TZ-R6")[0]
    assert r6.hosts == ("10.20.0.1",) and set(r6.metrics["macs"]) == {"02:00:00:00:00:01", "02:00:00:00:00:66"}
    r7 = {f.hosts[0]: f for f in by_rule(fs, "TZ-R7")}
    assert r7["10.20.0.13"].metrics["conflicting"] == 1 and r7["10.20.0.13"].severity == "HIGH"
    assert r7["10.20.0.12"].metrics["unmatched"] == 1
    r8 = by_rule(fs, "TZ-R8")[0]
    assert r8.hosts == ("10.20.0.13", "203.0.113.99") and r8.metrics["bytes_out"] > 500_000
    r9 = by_rule(fs, "TZ-R9")[0]
    assert r9.metrics["destinations"] == ["203.0.113.99"]
    r10 = by_rule(fs, "TZ-R10")[0]
    assert r10.metrics["sni"] == "updates.example.com" and r10.metrics["contacted"] == ["198.51.100.66"]


def test_one_sided_dns_capture_is_not_flagged(tmp_path):
    # Only responses, never a query from this client: a capture-point limitation, not an anomaly.
    from scapy.layers.dns import DNSRR

    frames = [
        (1000.0 + i, bytes(ETH() / IP(src="10.0.0.53", dst="10.0.0.5") / UDP(sport=53, dport=40000 + i)
                         / DNS(id=i, qr=1, qd=DNSQR(qname="a.example"), an=[DNSRR(rrname="a.example", rdata="192.0.2.1")])))
        for i in range(5)
    ]
    idx = CaptureIndex(read_capture(write_pcap(tmp_path / "one.pcap", frames)))
    assert by_rule(detect(idx), "TZ-R7") == []


def test_balanced_external_traffic_is_not_outbound(tmp_path):
    frames = []
    for i in range(400):
        frames.append((1000.0 + i * 0.1, bytes(ETH() / IP(src="10.0.0.5", dst="192.0.2.80") / TCP(sport=40000, dport=443, flags="A") / Raw(b"x" * 1400))))
        frames.append((1000.05 + i * 0.1, bytes(ETH() / IP(src="192.0.2.80", dst="10.0.0.5") / TCP(sport=443, dport=40000, flags="A") / Raw(b"y" * 1400))))
    idx = CaptureIndex(read_capture(write_pcap(tmp_path / "bal.pcap", frames)))
    assert by_rule(detect(idx), "TZ-R8") == []
