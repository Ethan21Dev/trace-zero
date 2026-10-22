"""Several captures (e.g. two sensors) merged onto one timeline."""

from __future__ import annotations

import json

from scapy.layers.inet import IP, TCP, UDP

from trace_zero.cli import main
from trace_zero.config import Config
from trace_zero.export import build_report
from trace_zero.parsing.reader import read_capture
from trace_zero.session import Session, load_capture, load_captures
from trace_zero.storage import Store
from trace_zero.ui.app import TraceZeroApp
from trace_zero.ui.screens.dialogs import OpenCaptureScreen

from .conftest import ETH, write_pcap


FRAMES_A = [(1000.0 + i, bytes(ETH() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53 + i) / b"a")) for i in range(3)]
FRAMES_B = [
    (1000.5, bytes(ETH() / IP(src="10.9.0.7", dst="10.9.0.8") / TCP(sport=4444, dport=80, flags="S"))),
    (1001.5, bytes(ETH() / IP(src="10.9.0.8", dst="10.9.0.7") / TCP(sport=80, dport=4444, flags="SA"))),
]


def _sensor_a(tmp_path):
    return write_pcap(tmp_path / "sensor-a.pcap", FRAMES_A)


def _sensor_b(tmp_path):
    return write_pcap(tmp_path / "sensor-b.pcap", FRAMES_B)


def test_merge_renumbers_and_keeps_sources(tmp_path):
    a, b = _sensor_a(tmp_path), _sensor_b(tmp_path)
    cfg = Config(cache_dir=tmp_path / "cache")
    loaded = load_captures([a, b], cfg)
    r = loaded.result
    assert [p.no for p in r.packets] == [1, 2, 3, 4, 5]
    assert [(i.name, o, c) for i, o, c in r.sources] == [("sensor-a.pcap", 0, 3), ("sensor-b.pcap", 3, 2)]
    assert r.file.fmt == "multi" and r.file.name == "sensor-a.pcap +1 more"
    assert r.locate(4)[0].name == "sensor-b.pcap" and r.locate(4)[1] == 1
    # One timeline: hosts from both sensors, events interleaved in time.
    assert {"10.0.0.1", "10.9.0.7"} <= set(loaded.index.hosts)
    assert [p.no for p in (loaded.index.packets[i] for i in loaded.index.order)] == [1, 4, 2, 5, 3]


def test_combined_identity_ignores_order_and_dedupes(tmp_path):
    a, b = _sensor_a(tmp_path), _sensor_b(tmp_path)
    cfg = Config(cache_dir=tmp_path / "cache")
    ab = load_captures([a, b], cfg).result
    ba = load_captures([b, a], cfg).result
    assert ab.file.sha256 == ba.file.sha256
    assert ab.file.sha256 not in {i.sha256 for i, _o, _c in ab.sources}
    # The same evidence twice is a single capture, not doubled packets.
    twice = load_captures([a, a], cfg).result
    assert len(twice.packets) == 3 and not twice.sources
    assert twice.file.sha256 == load_capture(a, cfg).result.file.sha256


def test_merged_frames_are_reread_from_the_right_file(tmp_path):
    a, b = _sensor_a(tmp_path), _sensor_b(tmp_path)
    cfg = Config(db_path=tmp_path / "t.db", cache_dir=tmp_path / "cache")
    store = Store(cfg.db_path)
    s = Session(cfg, store, store.open_or_create("multi"))
    s.attach(load_captures([a, b], cfg))
    raw = s.frame_bytes({2, 4})
    assert raw[2] == (FRAMES_A[1][1], 1)
    assert raw[4] == (FRAMES_B[0][1], 1)  # first frame of sensor b, not frame 4 of sensor a
    out = tmp_path / "both.pcapng"
    count, _expr, _notes = s.export_packets(out)
    assert count == 5
    back = read_capture(out, cfg.limits)
    assert len(back.packets) == 5
    assert {p.src for p in back.packets} >= {"10.0.0.1", "10.9.0.7"}
    # Every source is recorded as evidence in the investigation.
    names = {c["filename"] for c in store.captures(s.investigation.id)}
    assert names == {"sensor-a.pcap", "sensor-b.pcap"}
    report = build_report(s)
    assert [c["filename"] for c in report["capture"]["sources"]] == ["sensor-a.pcap", "sensor-b.pcap"]
    assert report["capture"]["sources"][1]["first_frame"] == 4
    store.close()


def test_cli_headless_accepts_several_captures(tmp_path, capsys):
    a, b = _sensor_a(tmp_path), _sensor_b(tmp_path)
    out = tmp_path / "r.json"
    assert main([str(a), str(b), "--headless", "--db", str(tmp_path / "d.db"), "--json", str(out)]) == 0
    text = capsys.readouterr().out
    assert "packets        5" in text and "frames 4-5" in text
    assert len(json.loads(out.read_text())["capture"]["sources"]) == 2


async def test_shift_o_adds_a_capture_to_the_timeline(tmp_path):
    a, b = _sensor_a(tmp_path), _sensor_b(tmp_path)
    cfg = Config(db_path=tmp_path / "ui.db", export_dir=tmp_path / "exports", cache_dir=tmp_path / "cache")
    store = Store(cfg.db_path)
    session = Session(cfg, store, store.open_or_create("ui-multi"))
    app = TraceZeroApp(session, str(a))
    async with app.run_test(size=(160, 48)) as pilot:
        for _ in range(200):
            if session.capture is not None:
                break
            await pilot.pause(0.05)
        await app.workers.wait_for_complete()
        assert len(session.capture.result.packets) == 3
        await pilot.press("O")
        await pilot.pause()
        assert isinstance(app.screen, OpenCaptureScreen)
        app.screen.dismiss(str(b))
        for _ in range(200):
            await pilot.pause(0.05)
            if session.capture is not None and len(session.capture.result.packets) == 5:
                break
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert len(session.capture.result.sources) == 2
        assert "+1 more" in str(app.main.query_one("#header").capture)
    store.close()


def test_frame_number_filters_explain_merge_order(tmp_path):
    a, b = _sensor_a(tmp_path), _sensor_b(tmp_path)
    cfg = Config(db_path=tmp_path / "t.db", cache_dir=tmp_path / "cache")
    store = Store(cfg.db_path)
    s = Session(cfg, store, store.open_or_create("multi"))
    s.attach(load_captures([a, b], cfg))
    flt = s.compile("no:4")
    s.apply_view(flt, s.build_view(flt))
    expr, notes = s.wireshark_filter()
    assert "frame.number" in expr
    assert any("mergecap -a" in n and "sensor-a.pcap sensor-b.pcap" in n for n in notes)
    store.close()
