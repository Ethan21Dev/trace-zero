"""Live mode: following a growing capture, snapshots, finalisation, capture-tool launcher."""

from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP

from trace_zero.config import Config, Limits
from trace_zero.live import LiveCapture
from trace_zero.live.tool import (
    CaptureProcess,
    CaptureTool,
    CaptureToolError,
    Interface,
    build_command,
    find_tool,
    list_interfaces,
    parse_interface_list,
    validate_filter,
)
from trace_zero.parsing.follow import CaptureFollower, FollowError
from trace_zero.parsing.reader import read_capture, read_frames
from trace_zero.session import Selection, Session, load_capture
from trace_zero.storage import Store

from .conftest import ETH, pcap_bytes


def _fields(p):
    return repr({s: getattr(p, s) for s in type(p).__slots__})


def _grow(src: bytes, dst: Path, steps: list[int]):
    """Yield after appending each chunk of ``src`` to ``dst``."""
    dst.write_bytes(b"")
    pos = 0
    i = 0
    while pos < len(src):
        step = steps[i % len(steps)]
        with open(dst, "ab") as fh:
            fh.write(src[pos : pos + step])
        pos += step
        i += 1
        yield


@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_follower_matches_offline_reader_however_the_file_grows(tmp_path, sample_dir, fmt):
    src = sample_dir / f"sample.{fmt}"
    grow = tmp_path / f"grow.{fmt}"
    f = None
    for _ in _grow(src.read_bytes(), grow, [1, 7, 333, 4096, 65536]):
        f = f or CaptureFollower(grow)
        f.poll()
    f.poll()
    offline = read_capture(src)
    assert len(f.packets) == len(offline.packets) == 3324
    assert all(_fields(a) == _fields(b) for a, b in zip(f.packets, offline.packets))
    assert f.linktypes == offline.linktypes and not f.warnings and f.stopped is None
    frames = {1, 500, 3324}
    assert f.frame_bytes(frames) == read_frames(offline.file, frames)


def test_follower_waits_for_incomplete_records(tmp_path):
    frame = bytes(ETH() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2) / (b"x" * 20))
    data = pcap_bytes([(1.0, frame), (2.0, frame)])
    path = tmp_path / "p.pcap"
    path.write_bytes(data[:10])  # not even a full header
    f = CaptureFollower(path)
    assert f.poll() == 0 and f.offset == 0
    path.write_bytes(data[: 24 + 16 + len(frame) + 5])  # first record + part of the second
    assert f.poll() == 1 and f.offset == 24 + 16 + len(frame)
    path.write_bytes(data)
    assert f.poll() == 1 and f.count == 2 and f.offset == len(data)
    assert f.poll() == 0


def test_follower_stops_on_damage_shrink_and_limits(tmp_path):
    frame = bytes(ETH() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1, dport=2))
    data = pcap_bytes([(1.0, frame), (2.0, frame), (3.0, frame)])
    path = tmp_path / "p.pcap"
    path.write_bytes(data)
    f = CaptureFollower(path)
    f.poll()
    path.write_bytes(data[:30])  # rotated / overwritten
    with pytest.raises(FollowError, match="shrank"):
        f.poll()
    # hostile record length
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(data[:24] + struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 60))
    g = CaptureFollower(bad)
    assert g.poll() == 0 and g.stopped and "damaged" in g.stopped
    # hostile pcapng block length
    ng = tmp_path / "bad.pcapng"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 28) + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28) + struct.pack("<III", 6, 5, 0))
    h = CaptureFollower(ng)
    h.poll()
    assert h.stopped and "block length" in h.stopped
    # not a capture
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"hello world, not a capture")
    with pytest.raises(FollowError, match="not a PCAP"):
        CaptureFollower(junk).poll()
    # packet limit
    lim = CaptureFollower(_write(tmp_path / "p2.pcap", data), Limits(max_packets=2))
    lim.poll()
    assert lim.count == 2 and lim.stopped and "limit" in lim.stopped


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _session(tmp_path, name="live"):
    cfg = Config(db_path=tmp_path / "l.db", export_dir=tmp_path / "exports", cache_dir=tmp_path / "cache")
    store = Store(cfg.db_path)
    return cfg, store, Session(cfg, store, store.open_or_create(name))


def test_live_snapshots_follow_the_file_and_finalise_to_the_offline_result(tmp_path, sample_pcap):
    cfg, store, s = _session(tmp_path)
    full = sample_pcap.read_bytes()
    path = tmp_path / "live.pcap"
    half = 24 + (len(full) - 24) // 2
    path.write_bytes(full[:half])
    live = LiveCapture(path, cfg)
    s.start_live(live)
    first = live.refresh()
    s.apply_live(first)
    n1 = len(s.capture.result.packets)
    assert 0 < n1 < 3324 and s.capture.result.live and s.sha == live.provisional_sha
    assert s.timeline.cursor == s.timeline.t1  # following the newest data
    # work done during live mode: bookmark, mark, triage
    host = Selection("host", "10.20.0.12")
    s.toggle_bookmark(host, "watch")
    s.add_mark(s.timeline.t0 + 1, "early")
    assert live.refresh() is None  # nothing new yet
    with open(path, "ab") as fh:
        fh.write(full[half:])
    update = live.refresh()
    assert update.new_packets == 3324 - n1
    s.apply_live(update)
    assert len(s.capture.result.packets) == 3324 and s.timeline.cursor == s.timeline.t1
    # raw bytes and exports work while the file is (notionally) still growing
    offline = read_capture(sample_pcap)
    assert s.frame_bytes({1, 3324}) == read_frames(offline.file, {1, 3324})
    out = tmp_path / "exports" / "live-export.pcapng"
    count, _expr, _notes = s.export_packets(out)
    assert count == 3324 and len(read_capture(out).packets) == 3324
    with pytest.raises(Exception, match="overwrite"):
        s.export_packets(path)
    # finalise: offline analysis of the finished file, items moved to the real hash
    final = load_capture(path, cfg)
    s.finish_live(final)
    assert s.live is None and not s.capture.result.live
    assert s.sha == final.sha == offline.file.sha256
    assert s.is_bookmarked(host)
    assert [m.label for m in s.marks()] == ["early"]
    kinds = [e.kind for e in store.events(s.investigation.id)]
    assert kinds.count("live") == 2
    assert {f.id for f in s.capture.findings} == {f.id for f in load_capture(sample_pcap, cfg).findings}
    store.close()


def test_rekey_does_not_clobber_existing_rows(tmp_path):
    _cfg, store, s = _session(tmp_path)
    inv = s.investigation.id
    store.toggle_bookmark(inv, "old", "host", "a")
    store.toggle_bookmark(inv, "new", "host", "a")
    store.toggle_bookmark(inv, "old", "host", "b")
    assert store.rekey_capture(inv, "old", "new") == 1
    assert sorted(b.ref for b in store.bookmarks(inv, "new")) == ["a", "b"]
    assert store.bookmarks(inv, "old") == []
    store.close()


# -- capture tool ------------------------------------------------------------------------
DUMPCAP_D = """1. eth0
2. any
3. lo (Loopback)
4. \\Device\\NPF_{6B4C2A7E-0000-4E3B-9F1A-2C3D4E5F6A7B} (Ethernet 2)
"""
TCPDUMP_D = """1.eth0 [Up, Running, Connected]
2.any (Pseudo-device that captures on all interfaces) [Up, Running]
3.lo [Up, Running, Loopback]
"""


def test_interface_list_parsing():
    names = [i.name for i in parse_interface_list(DUMPCAP_D)]
    assert names == ["eth0", "any", "lo", "\\Device\\NPF_{6B4C2A7E-0000-4E3B-9F1A-2C3D4E5F6A7B}"]
    assert parse_interface_list(DUMPCAP_D)[2].description == "(Loopback)"
    assert [i.name for i in parse_interface_list(TCPDUMP_D)] == ["eth0", "any", "lo"]
    assert parse_interface_list("dumpcap: There are no interfaces on which a capture can be done") == []


def test_capture_commands_are_passive_argument_lists(tmp_path):
    out = tmp_path / "c.pcapng"
    d = build_command(CaptureTool("dumpcap", "/usr/bin/dumpcap"), "eth0", out, "tcp port 443", 1000, 64)
    assert d == ["/usr/bin/dumpcap", "-i", "eth0", "-p", "-q", "-w", str(out), "-c", "1000", "-a", "filesize:65536", "-f", "tcp port 443"]
    t = build_command(CaptureTool("tcpdump", "/usr/sbin/tcpdump"), "eth0", out, "udp port 53")
    assert t == ["/usr/sbin/tcpdump", "-i", "eth0", "-p", "-n", "-U", "-w", str(out), "udp port 53"]
    for bad in ("-w /etc/passwd", "port 53\nhost x", "x" * 1001):
        with pytest.raises(CaptureToolError):
            validate_filter(bad)
    with pytest.raises(CaptureToolError):
        build_command(CaptureTool("dumpcap", "dumpcap"), "-i", out)


def test_configured_tool_path_must_exist(tmp_path):
    with pytest.raises(CaptureToolError, match="not found"):
        find_tool(tmp_path / "nope" / "dumpcap")
    fake = tmp_path / "tcpdump"
    fake.write_text("")
    assert find_tool(fake) == CaptureTool("tcpdump", str(fake))


FAKE_TOOL = """\
#!{python}
# Stand-in for dumpcap: writes a pcap with one packet every 50 ms until interrupted.
import signal, struct, sys, time
args = sys.argv[1:]
if args == ["-D"]:
    print("1. fake0 (Test interface)")
    sys.exit(0)
out = args[args.index("-w") + 1]
if args[args.index("-i") + 1] != "fake0":
    sys.stderr.write("fake: no such interface\\n"); sys.exit(2)
frame = bytes.fromhex({frame!r})
stop = False
def handler(*_):
    global stop
    stop = True
signal.signal(signal.SIGINT, handler)
with open(out, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)); fh.flush()
    n = 0
    while not stop:
        n += 1
        fh.write(struct.pack("<IIII", 1000 + n, 0, len(frame), len(frame)) + frame); fh.flush()
        time.sleep(0.05)
sys.stderr.write(f"fake: captured {{n}} packets\\n")
"""


@pytest.fixture
def fake_tool(tmp_path):
    if sys.platform == "win32":
        pytest.skip("the stand-in capture tool is a POSIX script")
    frame = bytes(ETH() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))
    path = tmp_path / "fake-dumpcap"
    path.write_text(FAKE_TOOL.format(python=sys.executable, frame=frame.hex()))
    path.chmod(0o755)
    return CaptureTool("dumpcap", str(path))


def test_capture_process_lifecycle_with_stand_in_tool(tmp_path, fake_tool):
    assert [i.name for i in list_interfaces(fake_tool)] == ["fake0"]
    out = tmp_path / "cap" / "live.pcap"
    proc = CaptureProcess(fake_tool, "fake0", out, tmp_path / "tool.log")
    proc.start()
    assert proc.running
    cfg, store, s = _session(tmp_path)
    live = LiveCapture(out, cfg, proc)
    s.start_live(live)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        update = live.refresh()
        if update is not None:
            s.apply_live(update)
        if s.capture is not None and len(s.capture.result.packets) >= 5:
            break
        time.sleep(0.05)
    assert len(s.capture.result.packets) >= 5
    assert live.stop_tool() == 0 and not proc.running
    assert "captured" in proc.log_tail()
    final = load_capture(out, cfg)
    s.finish_live(final)
    assert len(s.capture.result.packets) >= 5 and not s.capture.result.live
    # never overwrite: a second capture into the same file is refused
    with pytest.raises(CaptureToolError, match="overwrite"):
        CaptureProcess(fake_tool, "fake0", out, tmp_path / "tool.log").start()
    # a failing tool reports its own message
    with pytest.raises(CaptureToolError, match="no such interface"):
        CaptureProcess(fake_tool, "nope0", tmp_path / "x.pcap", tmp_path / "tool.log").start(wait_for_file=3)
    store.close()


def _dumpcap_can_capture_loopback(tmp_path) -> CaptureTool | None:
    path = shutil.which("dumpcap")
    if not path:
        return None
    try:
        probe = subprocess.run([path, "-i", "lo", "-p", "-q", "-a", "duration:1", "-w", str(tmp_path / "probe.pcapng")], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return CaptureTool("dumpcap", path) if probe.returncode == 0 else None


@pytest.mark.skipif(sys.platform != "linux", reason="loopback interface name is Linux-specific")
def test_real_dumpcap_on_loopback(tmp_path):
    tool = _dumpcap_can_capture_loopback(tmp_path)
    if tool is None:
        pytest.skip("dumpcap is not installed or may not capture here")
    out = tmp_path / "lo.pcapng"
    proc = CaptureProcess(tool, "lo", out, tmp_path / "dumpcap.log", bpf="udp port 47999")
    proc.start()
    cfg, store, s = _session(tmp_path)
    live = LiveCapture(out, cfg, proc)
    s.start_live(live)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            sock.sendto(b"trace-zero live test", ("127.0.0.1", 47999))  # loopback only
            update = live.refresh()
            if update is not None:
                s.apply_live(update)
            if s.capture is not None and len(s.capture.result.packets) >= 3:
                break
            time.sleep(0.2)
    finally:
        sock.close()
    live.stop_tool()
    assert s.capture is not None and len(s.capture.result.packets) >= 3
    assert all(p.dport == 47999 for p in s.capture.result.packets)
    s.finish_live(load_capture(out, cfg))
    assert s.sha == read_capture(out).file.sha256
    store.close()


# -- TUI -----------------------------------------------------------------------------------
def _app(tmp_path, live=None):
    from trace_zero.ui.app import TraceZeroApp

    cfg, store, s = _session(tmp_path, "live-ui")
    return TraceZeroApp(s, None, live), s, store


async def _until(pilot, cond, timeout=15.0):
    waited = 0.0
    while not cond() and waited < timeout:
        await pilot.pause(0.1)
        waited += 0.1
    assert cond(), "condition not reached"


async def test_tui_follows_a_growing_file_and_finalises(tmp_path, sample_pcap):
    from trace_zero.ui.screens.dialogs import ChoiceScreen, ConfirmScreen, OpenCaptureScreen, PromptScreen

    full = sample_pcap.read_bytes()
    path = tmp_path / "growing.pcap"
    path.write_bytes(full[:24])  # header only: nothing to show yet
    app, s, store = _app(tmp_path)
    async with app.run_test(size=(160, 48)) as pilot:
        main = app.main
        await pilot.press("F")
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("f")
        assert isinstance(app.screen, OpenCaptureScreen) and app.screen.follow
        app.screen.query_one("#path").value = str(path)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert s.live is not None and s.capture is None
        assert main.query_one("#header").status == ("live", "LIVE waiting for packets")
        # the file grows in three steps; the workspace follows
        third = (len(full) - 24) // 3
        for step in (1, 2):
            with open(path, "ab") as fh:
                fh.write(full[24 + (step - 1) * third : 24 + step * third])
            floor = 24 + (step - 1) * third
            await _until(pilot, lambda: s.capture is not None and s.live.follower.offset > floor and len(s.capture.result.packets) == s.live.follower.count)
        mid = len(s.capture.result.packets)
        assert s.capture.result.live and main.query_one("#header").status[0] == "live"
        assert s.timeline.cursor == s.timeline.t1
        # the analyst can work during live mode: a bookmark on a host
        await pilot.press("h")
        await pilot.press("down")
        sel = s.selection
        assert sel is not None and sel.kind == "host"
        await pilot.press("m")
        assert s.is_bookmarked(sel) and store.bookmarks(s.investigation.id, live_id := s.sha) and live_id.startswith("live:")
        with open(path, "ab") as fh:
            fh.write(full[24 + 2 * third :])
        await _until(pilot, lambda: s.capture is not None and len(s.capture.result.packets) == 3324)
        assert len(s.capture.result.packets) > mid
        # opening something else is refused while live
        await pilot.press("o")
        await pilot.pause()
        assert not isinstance(app.screen, PromptScreen) and s.live is not None
        # F again stops: confirm, then the finished file is hashed and analysed offline
        await pilot.press("F")
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.press("y")
        await _until(pilot, lambda: s.live is None and s.capture is not None and not s.capture.result.live)
        await app.workers.wait_for_complete()
        assert s.sha == read_capture(path).file.sha256
        assert main.query_one("#header").status[0] == "ok"
        assert [b.ref for b in store.bookmarks(s.investigation.id, s.sha)] == [sel.ref], "bookmark moved to the final hash"
        assert store.bookmarks(s.investigation.id, live_id) == []
        kinds = [e.kind for e in store.events(s.investigation.id)]
        assert kinds.count("live") == 2 and "capture" in kinds
    store.close()


async def test_tui_capture_tool_end_finalises_and_quit_stops_tool(tmp_path, fake_tool):
    out = tmp_path / "cap.pcap"
    proc = CaptureProcess(fake_tool, "fake0", out, tmp_path / "tool.log")
    proc.start()
    app, s, store = _app(tmp_path, (str(out), proc))
    async with app.run_test(size=(160, 48)) as pilot:
        await _until(pilot, lambda: s.capture is not None and len(s.capture.result.packets) >= 3)
        # the tool ending on its own (limit reached, killed, interface gone) finalises the capture
        proc.stop()
        await _until(pilot, lambda: s.live is None and s.capture is not None and not s.capture.result.live)
        assert len(s.capture.result.packets) >= 3
    proc2 = CaptureProcess(fake_tool, "fake0", tmp_path / "cap2.pcap", tmp_path / "tool.log")
    proc2.start()
    app2, s2, store2 = _app(tmp_path / "second", (str(proc2.out_path), proc2))
    async with app2.run_test(size=(160, 48)) as pilot:
        await _until(pilot, lambda: s2.capture is not None)
        await pilot.press("ctrl+q")
        await pilot.pause()
    assert not proc2.running, "quitting must not leave the capture tool running"
    store.close()
    store2.close()


def test_cli_live_options(tmp_path, fake_tool, capsys):
    from trace_zero.cli import main

    cfg = tmp_path / "c.toml"
    cfg.write_text(f'[paths]\ncapture_tool = "{fake_tool.path}"\ndb = "{(tmp_path / "x.db").as_posix()}"\n')
    assert main(["--list-interfaces", "--config", str(cfg)]) == 0
    assert "fake0" in capsys.readouterr().out
    cap = tmp_path / "a.pcap"
    cap.write_bytes(pcap_bytes([]))
    assert main([str(cap), "--follow", str(cap), "--config", str(cfg)]) == 2
    assert main(["--follow", str(tmp_path / "missing.pcap"), "--config", str(cfg)]) == 1
    assert main(["--capture", "nope0", "--config", str(cfg)]) == 1
    assert "does not list interface" in capsys.readouterr().err


def test_report_marks_live_exports(tmp_path, sample_pcap):
    from trace_zero.export import build_report, render_html

    cfg, store, s = _session(tmp_path)
    path = tmp_path / "live.pcap"
    path.write_bytes(sample_pcap.read_bytes()[:20000])
    live = LiveCapture(path, cfg)
    s.start_live(live)
    s.apply_live(live.refresh())
    report = build_report(s)
    assert report["capture"]["live_in_progress"] is True
    assert report["capture"]["sha256"].startswith("live:")
    assert "no final SHA-256 yet" in render_html(report)
    store.close()


async def test_starting_live_clears_the_previous_capture(tmp_path, sample_pcap):
    from trace_zero.ui.widgets.table import VirtualTable

    path = tmp_path / "empty-yet.pcap"
    path.write_bytes(sample_pcap.read_bytes()[:24])
    app, s, store = _app(tmp_path)
    async with app.run_test(size=(160, 48)) as pilot:
        main = app.main
        main.start_load(str(sample_pcap))
        await _until(pilot, lambda: s.capture is not None)
        await app.workers.wait_for_complete()
        main.start_live(str(path))
        await pilot.pause(0.5)
        assert s.capture is None and main.center_view == "empty"
        assert main.query_one("#hosts-table", VirtualTable).count == 0
        main.stop_live("test over")
        await _until(pilot, lambda: s.live is None)
    store.close()


async def test_follow_browser_accepts_a_file_that_is_still_empty(tmp_path):
    """A writer that has only just started has written nothing yet; following must still start."""
    from trace_zero.ui.screens.dialogs import OpenCaptureScreen

    empty = tmp_path / "just-started.pcapng"
    empty.write_bytes(b"")
    app, s, store = _app(tmp_path)
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.press("F", "f")
        assert isinstance(app.screen, OpenCaptureScreen)
        app.screen.query_one("#path").value = str(empty)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert s.live is not None and s.live.path == empty.resolve()
        app.main.stop_live("test over")
        await _until(pilot, lambda: s.live is None)
    store.close()


WINDOWS_D = """1. \\Device\\NPF_{0A1B2C3D-1111-4E3B-9F1A-2C3D4E5F6A7B} (Local Area Connection* 9)
2. \\Device\\NPF_{6B4C2A7E-2222-4E3B-9F1A-2C3D4E5F6A7B} (WAN Miniport (IPv6))
3. \\Device\\NPF_{9F8E7D6C-3333-4E3B-9F1A-2C3D4E5F6A7B} (Wi-Fi)
4. \\Device\\NPF_{11223344-4444-4E3B-9F1A-2C3D4E5F6A7B} (Ethernet 2)
5. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)
6. etwdump (Event Tracing for Windows (ETW) reader)
"""


def test_windows_interface_names_are_friendly():
    ifaces = parse_interface_list(WINDOWS_D)
    assert [i.friendly for i in ifaces] == [
        "Local Area Connection* 9",
        "WAN Miniport (IPv6)",
        "Wi-Fi",
        "Ethernet 2",
        "Adapter for loopback traffic capture",
        "Event Tracing for Windows (ETW) reader",
    ]
    assert ifaces[2].name == "\\Device\\NPF_{9F8E7D6C-3333-4E3B-9F1A-2C3D4E5F6A7B}"
    assert parse_interface_list("1. eth0\n")[0].friendly == "eth0"


async def test_interface_picker_shows_full_names_and_returns_the_device(tmp_path):
    from trace_zero.ui.screens.dialogs import InterfaceScreen

    app, s, store = _app(tmp_path)
    chosen = []
    async with app.run_test(size=(100, 30)) as pilot:
        app.push_screen(InterfaceScreen("dumpcap", parse_interface_list(WINDOWS_D)), chosen.append)
        await pilot.pause()
        screen = app.screen
        # Wi-Fi and Ethernet are listed first, under hotkeys 1 and 2
        assert [i.friendly for i in screen.interfaces[:2]] == ["Wi-Fi", "Ethernet 2"]
        text = app.export_screenshot()
        for name in ("Wi-Fi", "Ethernet&#160;2", "WAN&#160;Miniport&#160;(IPv6)"):
            assert name in text, name
        await pilot.press("down")
        assert "Ethernet 2" in str(screen.query_one("#detail").render())
        await pilot.press("1")
        await pilot.pause()
    assert chosen == ["\\Device\\NPF_{9F8E7D6C-3333-4E3B-9F1A-2C3D4E5F6A7B}"]
    store.close()


# -- which adapter is connected ------------------------------------------------------------
def test_default_route_parsers():
    from trace_zero.live.route import parse_macos_route, parse_proc_net_route, parse_windows

    one = '{"Alias":"Wi-Fi","Guid":"{9f8e7d6c-3333-4e3b-9f1a-2c3d4e5f6a7b}","IPv4":["192.168.1.23"]}'
    routes = parse_windows(one)
    assert routes[0].name == "Wi-Fi" and routes[0].guid == "{9F8E7D6C-3333-4E3B-9F1A-2C3D4E5F6A7B}"
    assert routes[0].addresses == ("192.168.1.23",)
    two = '[{"Alias":"Ethernet 2","Guid":"11223344-4444-4e3b-9f1a-2c3d4e5f6a7b","IPv4":"10.0.0.5"},{"Alias":"Wi-Fi","Guid":"","IPv4":[]}]'
    assert [(r.name, r.guid, r.addresses) for r in parse_windows(two)] == [
        ("Ethernet 2", "{11223344-4444-4E3B-9F1A-2C3D4E5F6A7B}", ("10.0.0.5",)),
        ("Wi-Fi", "", ()),
    ]
    assert parse_windows("") == [] and parse_windows("not json") == []
    table = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
        "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        "tun0\t00000000\t00000000\t0000\t0\t0\t50\t00000000\t0\t0\t0\n"
    )
    assert parse_proc_net_route(table) == ["wlan0", "eth0"]  # lowest metric first; routes that are down ignored
    assert parse_macos_route("   route to: default\ndestination: default\n  interface: en0\n") == "en0"


def test_connected_adapter_is_matched_by_guid_or_name():
    from trace_zero.live.route import DefaultRoute, mark_connected

    ifaces = parse_interface_list(WINDOWS_D)
    marked = mark_connected(ifaces, [DefaultRoute("Wi-Fi", "{9F8E7D6C-3333-4E3B-9F1A-2C3D4E5F6A7B}", ("192.168.1.23",))])
    assert [i.friendly for i in marked if i.connected] == ["Wi-Fi"]
    assert next(i for i in marked if i.connected).addresses == ("192.168.1.23",)
    by_name = mark_connected(ifaces, [DefaultRoute("Ethernet 2")])
    assert [i.friendly for i in by_name if i.connected] == ["Ethernet 2"]
    linux = mark_connected(parse_interface_list(TCPDUMP_D), [DefaultRoute("eth0", "", ("10.1.2.3",))])
    assert [i.name for i in linux if i.connected] == ["eth0"]
    assert mark_connected(ifaces, []) == ifaces


async def test_picker_puts_the_connected_adapter_first_and_selected(tmp_path, monkeypatch):
    import trace_zero.ui.screens.main as main_mod
    from trace_zero.live.route import DefaultRoute
    from trace_zero.ui.screens.dialogs import ChoiceScreen, InterfaceScreen

    # Ethernet 2 is the connected one here, so it must beat Wi-Fi to the top.
    monkeypatch.setattr(main_mod, "find_tool", lambda configured=None: CaptureTool("dumpcap", "dumpcap"))
    monkeypatch.setattr(main_mod, "list_interfaces", lambda tool: parse_interface_list(WINDOWS_D))
    monkeypatch.setattr(main_mod, "detect_default_routes", lambda: [DefaultRoute("Ethernet 2", "{11223344-4444-4E3B-9F1A-2C3D4E5F6A7B}", ("10.0.0.5",))])
    chosen = []
    app, s, store = _app(tmp_path)
    async with app.run_test(size=(120, 30)) as pilot:
        main = app.main
        monkeypatch.setattr(main, "_ask_capture_filter", lambda tool, name, addresses=(): chosen.append((name, addresses)))
        await pilot.press("F")
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("c")
        await app.workers.wait_for_complete()
        await pilot.pause()
        screen = app.screen
        assert isinstance(screen, InterfaceScreen) and screen.found_connected
        assert screen.interfaces[0].friendly == "Ethernet 2"
        text = app.export_screenshot()
        assert "CONNECTED&#160;10.0.0.5" in text
        assert "this computer is 10.0.0.5" in str(screen.query_one("#detail").render())
        await pilot.press("enter")  # the pre-selected (connected) adapter
        await pilot.pause()
    assert chosen == [("\\Device\\NPF_{11223344-4444-4E3B-9F1A-2C3D4E5F6A7B}", ("10.0.0.5",))]
    store.close()


@pytest.mark.skipif(sys.platform not in ("win32", "linux"), reason="checked on the CI platforms")
def test_real_default_route_detection():
    """Runs the real lookup (PowerShell on Windows, /proc/net/route on Linux); CI machines have a default route."""
    from trace_zero.live.route import detect_default_routes

    routes = detect_default_routes()
    if not routes:
        # GitHub's runners are always online: an empty result there means the lookup is broken.
        assert not os.environ.get("GITHUB_ACTIONS"), f"default route detection returned nothing on CI: {_route_diagnostics()}"
        pytest.skip("this machine has no default route")
    assert routes[0].name
    assert all(addr.count(".") == 3 for addr in routes[0].addresses)
    if sys.platform == "win32" and os.environ.get("GITHUB_ACTIONS"):
        from trace_zero.live.route import windows_ipconfig, windows_powershell

        ps = windows_powershell()
        assert ps and ps[0].guid.startswith("{") and ps[0].addresses, f"PowerShell lookup: {ps} {_route_diagnostics()}"
        ipc = windows_ipconfig()
        assert ipc and ipc[0].addresses == ps[0].addresses[:1], f"ipconfig fallback: {ipc} vs {ps}"
        assert ipc[0].name.endswith(ps[0].name), (ipc, ps)  # the heading names the same adapter


def _route_diagnostics() -> str:
    """What the platform tools actually printed, to make a CI failure self-explanatory."""
    import subprocess

    from trace_zero.live import route

    if sys.platform != "win32":
        return ""
    proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", route._WINDOWS_SCRIPT], capture_output=True, text=True, timeout=30)
    return f"exit={proc.returncode} stdout={proc.stdout[:800]!r} stderr={proc.stderr[:800]!r} source={route._source_address()}"



IPCONFIG_EN = """
Windows IP Configuration


Ethernet adapter Ethernet 2:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : attlocal.net
   IPv4 Address. . . . . . . . . . . : 192.168.1.23(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.254
"""
IPCONFIG_DE = """
Windows-IP-Konfiguration

Drahtlos-LAN-Adapter WLAN:

   IPv4-Adresse  . . . . . . . . . . : 192.168.1.23
   Standardgateway . . . . . . . . . : 192.168.1.254
"""


def test_ipconfig_fallback_finds_the_adapter_by_address_in_any_language():
    from trace_zero.live.route import mark_connected, parse_ipconfig

    en = parse_ipconfig(IPCONFIG_EN, "192.168.1.23")
    assert [(r.name, r.addresses) for r in en] == [("Wireless LAN adapter Wi-Fi", ("192.168.1.23",))]
    assert parse_ipconfig(IPCONFIG_EN, "192.168.1.2") == []  # no partial-number matches
    assert parse_ipconfig(IPCONFIG_EN, None) == []
    marked = mark_connected(parse_interface_list(WINDOWS_D), en)
    assert [i.friendly for i in marked if i.connected] == ["Wi-Fi"]
    de = parse_ipconfig(IPCONFIG_DE, "192.168.1.23")
    assert de[0].name == "Drahtlos-LAN-Adapter WLAN"
    wlan = [Interface("\\Device\\NPF_{AA}", "(WLAN)")]
    assert mark_connected(wlan, de)[0].connected


def test_live_capture_knows_this_computer_until_another_file_is_opened(tmp_path, sample_pcap):
    from types import SimpleNamespace

    from trace_zero.analysis.identity import identify

    cfg, store, s = _session(tmp_path)
    path = tmp_path / "mine.pcap"
    path.write_bytes(sample_pcap.read_bytes())
    proc = SimpleNamespace(
        tool=CaptureTool("dumpcap", "dumpcap"), interface="eth0", bpf="", local_addresses=("10.20.0.12",), running=False, stop=lambda: 0
    )
    live = LiveCapture(path, cfg, proc)
    s.start_live(live)
    s.apply_live(live.refresh())
    assert identify("10.20.0.12", s.capture.index, s.local_addresses).role == "THIS COMPUTER"
    s.finish_live(load_capture(path, cfg))
    assert s.local_addresses == frozenset({"10.20.0.12"})  # still this computer's recording
    s.attach(load_capture(sample_pcap, cfg))
    assert s.local_addresses == frozenset()
    store.close()
