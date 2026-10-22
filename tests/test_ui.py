"""Drive the real TUI with keystrokes (Textual pilot, headless) and assert on state."""

from __future__ import annotations

import io

import pytest
from scapy.layers.inet import IP, TCP
from textual.widgets import Input, TextArea

from trace_zero.analysis.timeline import WindowMode
from trace_zero.config import Config
from trace_zero.session import Session
from trace_zero.storage import Store
from trace_zero.ui.app import TraceZeroApp
from trace_zero.ui.screens.dialogs import FilterScreen, HelpScreen, NoteScreen, OpenCaptureScreen, PromptScreen
from trace_zero.ui.widgets.table import VirtualTable

from .conftest import ETH, write_pcap

WIDE = (160, 48)


def make_app(tmp_path, capture=None, name="ui-test"):
    cfg = Config(db_path=tmp_path / "ui.db", export_dir=tmp_path / "exports")
    store = Store(cfg.db_path)
    session = Session(cfg, store, store.open_or_create(name))
    return TraceZeroApp(session, str(capture) if capture else None), session


async def wait_loaded(app, pilot, session, timeout=15.0):
    waited = 0.0
    while session.capture is None and waited < timeout:
        await pilot.pause(0.05)
        waited += 0.05
    await app.workers.wait_for_complete()
    await pilot.pause()
    assert session.capture is not None, "capture did not load"


def screen(app):
    return app.main


async def test_launch_loads_and_shows_workspace(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        assert main.center_view == "map"
        hosts = main.query_one("#hosts-table", VirtualTable)
        assert hosts.count == len(s.capture.index.hosts)
        assert main.query_one("#header").status[0] == "ok"
        assert main.focused.id == "hosts-table"


async def test_view_keys_switch_and_focus(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        for key, view, focus in [
            ("p", "packets", "view-packets"),
            ("f", "findings", "view-findings"),
            ("b", "journal", "view-journal"),
            ("n", "map", "peers-table"),
        ]:
            await pilot.press(key)
            assert main.center_view == view and main.focused.id == focus, key
        await pilot.press("h")
        assert main.focused.id == "hosts-table"
        await pilot.press("i")
        assert main.focused.id == "inspector-panel"
        await pilot.press("t")
        assert main.focused.id == "timeline"


async def test_q_goes_back_then_quits(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        await pilot.press("p")
        await pilot.press("f")
        await pilot.press("q")
        assert main.center_view == "packets"
        await pilot.press("q")
        assert main.center_view == "map"
        await pilot.press("q")
        await pilot.pause()
        assert not app.is_running


async def test_timeline_keys(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        tl = s.timeline
        await pilot.press("home")
        assert tl.cursor == tl.t0
        await pilot.press("right")
        assert tl.cursor == pytest.approx(tl.t0 + tl.span / 50)
        await pilot.press("left")
        assert tl.cursor == tl.t0
        await pilot.press("end")
        assert tl.cursor == tl.t1
        speed = tl.speed
        await pilot.press("plus")
        assert tl.speed > speed
        await pilot.press("minus")
        await pilot.press("minus")
        assert tl.speed < speed
        await pilot.press("w")
        assert tl.mode is WindowMode.SLIDING
        width = tl.width
        await pilot.press("right_square_bracket")
        assert tl.width > width
        await pilot.press("left_square_bracket")
        assert tl.width == width
        lo, hi = tl.window()
        stats = s.window_stats()
        assert stats.packets == sum(1 for p in s.capture.result.packets if lo <= p.ts <= hi)


async def test_replay_plays_and_pauses(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        tl = s.timeline
        await pilot.press("space")  # at end -> restarts from the beginning
        assert tl.playing and tl.cursor < tl.t1
        start = tl.cursor
        await pilot.pause(0.6)
        assert tl.cursor > start
        await pilot.press("space")
        assert not tl.playing
        frozen = tl.cursor
        await pilot.pause(0.3)
        assert tl.cursor == frozen


async def test_packet_and_event_stepping(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("home")
        seen = []
        for _ in range(4):
            await pilot.press("shift+right")
            seen.append(int(s.selection.ref))
        await pilot.press("shift+left")
        back = int(s.selection.ref)
        times = [s.capture.index.packet(n).ts for n in seen]
        assert times == sorted(times) and len(set(seen)) == 4
        assert back == seen[-2]
        assert s.timeline.cursor == s.capture.index.packet(back).ts
        main = screen(app)
        await pilot.press("home")
        await pilot.press("greater_than_sign")
        first = s.timeline.cursor
        assert first in main.sig_times and first > s.timeline.t0
        await pilot.press("greater_than_sign")
        assert s.timeline.cursor > first
        await pilot.press("less_than_sign")
        assert s.timeline.cursor == first


async def test_filter_dialog_apply_invalid_and_clear(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("slash")
        assert isinstance(app.screen, FilterScreen)
        app.screen.query_one(Input).value = "port:99999"
        await pilot.press("enter")
        assert isinstance(app.screen, FilterScreen)  # invalid expression keeps the dialog open
        app.screen.query_one(Input).value = "proto:dns"
        await pilot.press("enter")
        await pilot.pause()
        assert s.filter is not None and s.filter.text == "proto:dns"
        assert all(p.app == "DNS" for p in (s.view.packet_at(i) for i in range(len(s.view))))
        await pilot.press("escape")
        assert s.filter is None


async def test_finding_enter_shows_evidence(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        await pilot.press("f")
        await pilot.press("down")
        fid = s.selection.ref
        finding = s.capture.finding(fid)
        await pilot.press("enter")
        await pilot.pause()
        assert main.center_view == "packets"
        assert s.filter.frame_set == frozenset(finding.frames)
        table = main.query_one("#view-packets", VirtualTable)
        assert table.count == len(finding.frames)


async def test_bookmark_note_and_journal(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        await pilot.press("p")
        await pilot.press("up")
        sel = s.selection
        assert sel.kind == "packet"
        await pilot.press("m")
        assert s.is_bookmarked(sel)
        await pilot.press("a")
        assert isinstance(app.screen, NoteScreen)
        app.screen.query_one(TextArea).text = "retransmission storm starts here"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert [n.body for n in s.notes_for(sel)] == ["retransmission storm starts here"]
        await pilot.press("b")
        kinds = {r[1] for r in main.journal_rows}
        assert {"BOOKMARK", "NOTE", "LOG"} <= kinds
        await pilot.press("m")
        assert not s.is_bookmarked(sel)


async def test_raw_bytes_toggle(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        await pilot.press("p")
        await pilot.press("up")
        no = int(s.selection.ref)
        await pilot.press("x")
        await app.workers.wait_for_complete()
        await pilot.pause()
        raw = main.raw_cache[no]
        assert raw["data"] and len(raw["data"]) == s.capture.index.packet(no).caplen
        assert raw["layers"][0][0] == "Ethernet"
        from rich.console import Console

        from trace_zero.ui import inspect

        console = Console(width=44, record=True, file=io.StringIO())
        console.print(inspect.packet(s, s.capture.index.packet(no), raw, 8))
        text = console.export_text()
        assert "RAW BYTES" in text and "SCAPY DISSECTION" in text
        hex_rows = [line for line in text.splitlines() if line.strip().startswith("0000")]
        assert hex_rows and all(len(line) <= 44 for line in hex_rows)
        await pilot.press("x")
        assert main.show_raw is False


async def test_help_and_escape(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("question_mark")
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        assert not isinstance(app.screen, HelpScreen)
        await pilot.press("p")
        await pilot.press("up")
        assert s.selection is not None
        await pilot.press("escape")
        assert s.selection is None


async def test_open_dialog_validates_and_loads(tmp_path, sample_pcap, sample_pcapng):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("o")
        assert isinstance(app.screen, OpenCaptureScreen)
        app.screen.query_one("#path", Input).value = str(tmp_path / "missing.pcap")
        await pilot.press("enter")
        assert isinstance(app.screen, OpenCaptureScreen)
        assert "not found" in str(app.screen.query_one("#msg").render())
        app.screen.query_one("#path", Input).value = str(sample_pcapng)
        await pilot.press("enter")
        for _ in range(100):
            await pilot.pause(0.05)
            if s.capture.result.file.fmt == "pcapng":
                break
        assert s.capture.result.file.fmt == "pcapng"


async def test_bad_capture_reports_error_and_keeps_running(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_text("this is not a capture")
    app, s = make_app(tmp_path, bad)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause(0.3)
        assert s.capture is None
        assert screen(app).query_one("#header").status[0] == "error"
        for key in ("space", "right", "shift+right", "p", "f", "slash", "escape", "m", "x", "question_mark", "escape"):
            await pilot.press(key)
        assert app.is_running


async def test_empty_capture_is_handled(tmp_path):
    empty = write_pcap(tmp_path / "empty.pcap", [])
    app, s = make_app(tmp_path, empty)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        assert s.capture.result.packets == []
        for key in ("space", "right", "shift+right", "greater_than_sign", "home", "p", "f", "n", "w"):
            await pilot.press(key)
        assert app.is_running


async def test_cancel_import(tmp_path):
    frame = bytes(ETH() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="S"))
    big = write_pcap(tmp_path / "big.pcap", [(1000.0 + i * 0.001, frame) for i in range(300_000)])
    app, s = make_app(tmp_path)
    async with app.run_test(size=WIDE) as pilot:
        main = screen(app)
        main.start_load(str(big))
        await pilot.pause(0.2)
        await pilot.press("escape")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert s.capture is None
        assert main.loading is None


async def test_compact_layout_and_tabs(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=(100, 30)) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        hosts, center, insp = (main.query_one(i) for i in ("#hosts-panel", "#center-panel", "#inspector-panel"))
        assert main.compact and center.display and not hosts.display and not insp.display
        await pilot.press("h")
        assert hosts.display and not center.display
        await pilot.press("i")
        assert insp.display and not hosts.display
        await pilot.press("p")
        assert center.display and main.center_view == "packets"
        await pilot.press("q")
        assert insp.display  # back returns to the previous panel


async def test_too_small_terminal(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=(50, 14)) as pilot:
        await wait_loaded(app, pilot, s)
        assert screen(app).query_one("#too-small").display
        assert not screen(app).query_one("#body").display


async def test_sort_keys(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        await pilot.press("p")
        await pilot.press("s")
        assert main.packet_sort == ("no", False)
        await pilot.press("S")
        assert main.packet_sort == ("no", True)
        assert int(main.query_one("#view-packets", VirtualTable).key_fn(0)) == len(s.capture.result.packets)


async def test_export_rename_and_new_investigation(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("e")
        assert isinstance(app.screen, PromptScreen)
        await pilot.press("enter")
        await pilot.pause()
        exports = sorted("".join(p.suffixes) for p in (tmp_path / "exports").iterdir())
        assert exports == [".html", ".html.sha256", ".json", ".json.sha256"]
        await pilot.press("r")
        app.screen.query_one(Input).value = "Renamed case"
        await pilot.press("enter")
        assert s.investigation.name == "Renamed case"
        await pilot.press("ctrl+n")
        app.screen.query_one(Input).value = "Second case"
        await pilot.press("enter")
        assert s.investigation.name == "Second case"
        assert screen(app).query_one("#header").investigation == "Second case"


async def test_global_keys_do_not_leak_into_dialog_inputs(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        cursor = s.timeline.cursor
        await pilot.press("slash")
        for key in ("q", "space", "p", "left", "home", "right"):
            await pilot.press(key)
        assert isinstance(app.screen, FilterScreen) and app.is_running
        assert app.screen.query_one(Input).value == "q p"
        assert s.timeline.cursor == cursor and not s.timeline.playing
        await pilot.press("escape")
        assert not isinstance(app.screen, FilterScreen) and s.filter is None


async def test_markup_like_names_and_filters_are_inert(tmp_path, sample_pcap):
    """File names, filter text and capture-derived strings must render literally.

    Textual markup would otherwise rewrite them (``capture[bold red]x`` shows as
    ``capturex``), raise on ``[/x]``, or turn ``[@click=...]`` into an app action.
    """
    hostile = tmp_path / "capture[bold red][@click=app.quit]x.pcap"
    hostile.write_bytes(sample_pcap.read_bytes())
    app, s = make_app(tmp_path, hostile)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        header = screen(app).query_one("#header").render().plain
        assert "capture[bold red][@click=app.quit]x.pcap" in header
        await pilot.press("slash")
        app.screen.query_one(Input).value = "dns:[/x]"
        await pilot.press("enter")
        await pilot.pause()
        assert s.filter is not None and s.filter.text == "dns:[/x]"
        notes = list(app._notifications)
        assert notes and not any(n.markup for n in notes)
        assert any("dns:[/x]" in n.message for n in notes)
        await pilot.press("o")
        app.screen.query_one("#path", Input).value = str(tmp_path / "[bold]missing[1].pcap")
        await pilot.press("enter")
        await pilot.pause()
        msg = app.screen.query_one("#msg").render()
        assert "[bold]missing[1].pcap" in getattr(msg, "plain", str(msg))
        assert app.is_running


async def test_markup_in_investigation_name_is_inert(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap, name="Case [/x] [bold]")
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("b")
        await pilot.pause()
        assert app.is_running
        assert "Case [/x] [bold]" in screen(app).query_one("#header").render().plain


async def test_flows_view_follow_stream_and_packets(tmp_path, sample_pcap):
    from trace_zero.ui.screens.stream import FollowStreamScreen

    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        await pilot.press("c")
        assert main.center_view == "flows" and main.focused.id == "view-flows"
        table = main.query_one("#view-flows", VirtualTable)
        assert table.count == len(s.flows())
        # Pick an HTTP flow so the reassembled stream has decodable content.
        target = next(i for i, f in enumerate(main.flow_rows) if f.app == "HTTP" and f.state == "closed")
        table.move_to(target)
        await pilot.pause()
        assert s.selection.kind == "flow"
        flow = s.flow(s.selection.ref)
        await pilot.press("enter")
        assert isinstance(app.screen, FollowStreamScreen)
        await app.workers.wait_for_complete()
        await pilot.pause()
        stream = app.screen.stream
        assert stream is not None and stream.data("a").startswith(b"GET /status/index.html")
        assert any("HTTP/1.1 200 OK" in t for t, _ in stream.decoded)
        await pilot.press("x")  # hex view renders
        await pilot.press("p")
        await pilot.pause()
        assert main.center_view == "packets" and s.filter.frame_set == frozenset(flow.frames)
        await pilot.press("m")  # bookmark a packet of the flow, then the flow itself from flows view
        await pilot.press("escape")
        await pilot.press("c")
        await pilot.press("s")
        assert main.flow_sort == ("bytes", False)


async def test_export_packets_key(tmp_path, sample_pcap):
    from trace_zero.parsing.reader import read_capture

    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("slash")
        app.screen.query_one(Input).value = "proto:dns"
        await pilot.press("enter")
        await pilot.press("X")
        assert isinstance(app.screen, PromptScreen)
        target = tmp_path / "out" / "dns.pcapng"
        app.screen.query_one(Input).value = str(target)
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause()
        exported = read_capture(target).packets
        assert exported and all(p.app == "DNS" for p in exported)
        assert any(e.kind == "export" and "Wireshark filter: dns" in e.message for e in s.store.events(s.investigation.id))


async def test_triage_and_suppression_keys(tmp_path, sample_pcap):
    from trace_zero.ui.screens.dialogs import ChoiceScreen

    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        await pilot.press("f")
        await pilot.press("down")
        fid = s.selection.ref
        finding = s.capture.finding(fid)
        await pilot.press("T")
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("b")  # hotkey: benign
        assert isinstance(app.screen, PromptScreen)
        app.screen.query_one(Input).value = "scheduled backup"
        await pilot.press("enter")
        assert s.triage()[fid] == ("benign", "scheduled backup")
        total = main.query_one("#view-findings", VirtualTable).count
        await pilot.press("z")
        await pilot.press("a")  # suppress rule for any host
        app.screen.query_one(Input).value = "known noisy in this network"
        await pilot.press("enter")
        await pilot.pause()
        same_rule = sum(1 for f in s.capture.findings if f.rule == finding.rule)
        assert main.query_one("#view-findings", VirtualTable).count == total - same_rule
        assert all(f.rule != finding.rule for f in main.finding_rows)
        # Suppressed findings no longer mark the timeline.
        assert sorted(main.finding_times) == sorted(f.first_ts for f in s.capture.findings if f.rule != finding.rule)
        await pilot.press("Z")
        assert main.query_one("#view-findings", VirtualTable).count == total
        await pilot.press("b")
        kinds = {r[1] for r in main.journal_rows}
        assert "SUPPRESS" in kinds
        from trace_zero.export import build_report

        rep = build_report(s)
        exported = {f["id"]: f for f in rep["heuristic_findings"]["findings"]}
        assert exported[fid]["analyst_status"] == "benign" and exported[fid]["suppressed_by"]["reason"] == "known noisy in this network"


async def test_window_diff_and_marks(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        main = screen(app)
        tl = s.timeline
        await pilot.press("w")  # sliding window
        await pilot.press("home")
        for _ in range(4):
            await pilot.press("right")
        await pilot.press("d")
        assert main.center_view == "diff" and main.diff_base == tl.window()
        base = main.diff_base
        await pilot.press("end")
        await pilot.pause()
        table = main.query_one("#view-diff", VirtualTable)
        assert table.count > 0 and main._diff_cache[1].b == tl.window() and main._diff_cache[1].a == base
        # Enter on a NEW HOST row jumps to that host on the map.
        rows = main._diff_cache[1].rows
        target = next(i for i, r in enumerate(rows) if r.change == "NEW HOST")
        table.move_to(target)
        await pilot.press("enter")
        assert main.center_view == "map" and main.focus_host == rows[target].ref
        # Marks: add two, then jump between them.
        await pilot.press("home")
        await pilot.press("right")
        await pilot.press("k")
        app.screen.query_one(Input).value = "first contact"
        await pilot.press("enter")
        first = tl.cursor
        await pilot.press("right")
        await pilot.press("right")
        await pilot.press("k")
        await pilot.press("enter")  # default label
        second = tl.cursor
        assert [m.label for m in s.marks()][0] == "first contact" and len(s.marks()) == 2
        await pilot.press("home")
        await pilot.press("right_curly_bracket")
        assert tl.cursor == first
        await pilot.press("right_curly_bracket")
        assert tl.cursor == second
        await pilot.press("left_curly_bracket")
        assert tl.cursor == first
        assert second in main.mark_times
        await pilot.press("D")
        assert main.diff_base is None


async def test_filter_history_and_saved_filters(tmp_path, sample_pcap):
    app, s = make_app(tmp_path, sample_pcap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        for expr in ("proto:dns", "port:3389"):
            await pilot.press("slash")
            await pilot.pause()
            app.screen.query_one("#expr", Input).value = expr
            await pilot.press("enter")
            await app.workers.wait_for_complete()
            await pilot.pause()
        assert s.store.filter_history()[:2] == ["port:3389", "proto:dns"]
        # up/down walks the history, newest first, and returns to the draft
        await pilot.press("slash")
        await pilot.pause()
        expr = app.screen.query_one("#expr", Input)
        expr.value = "draft"
        await pilot.press("up")
        assert expr.value == "port:3389"
        await pilot.press("up")
        assert expr.value == "proto:dns"
        await pilot.press("down", "down")
        assert expr.value == "draft"
        # ctrl+s names and saves the current expression
        expr.value = "proto:tcp flags:S"
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert isinstance(app.screen, PromptScreen)
        app.screen.query_one(Input).value = "[b]syns"
        await pilot.press("enter")
        await pilot.pause()
        assert s.store.saved_filters() == [("[b]syns", "proto:tcp flags:S")]
        saved = app.screen.query_one("#saved", VirtualTable)
        assert saved.display and saved.count == 1
        await pilot.press("escape")
        await pilot.pause()
        # reopen: tab to the saved list, enter applies it
        await pilot.press("slash")
        await pilot.pause()
        app.screen.query_one("#saved", VirtualTable).focus()
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert isinstance(app.screen, type(app.main))
        assert s.filter is not None and s.filter.text == "proto:tcp flags:S"
        # delete removes a saved filter from the list and the database
        await pilot.press("slash")
        await pilot.pause()
        app.screen.query_one("#saved", VirtualTable).focus()
        await pilot.press("delete")
        await pilot.pause()
        assert s.store.saved_filters() == []
        assert not app.screen.query_one("#saved", VirtualTable).display


async def test_command_palette_runs_actions_and_saved_filters(tmp_path, sample_pcap):
    from textual.command import CommandPalette

    app, s = make_app(tmp_path, sample_pcap)
    s.store.save_filter("rdp", "port:3389")
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("ctrl+p")
        await pilot.pause()
        assert isinstance(app.screen, CommandPalette)
        await pilot.press(*"flows")
        await pilot.pause(0.5)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert app.main.center_view == "flows"
        await pilot.press("ctrl+p")
        await pilot.pause()
        await pilot.press(*"filter: rdp")
        await pilot.pause(0.5)
        await pilot.press("enter")
        await app.workers.wait_for_complete()
        await pilot.pause(0.3)
        assert s.filter is not None and s.filter.text == "port:3389"
        assert s.store.filter_history()[0] == "port:3389"


async def test_command_palette_shows_markup_like_filters_verbatim(tmp_path, sample_pcap):
    from textual.command import CommandPalette
    from textual.content import Content

    from trace_zero.ui.commands import WorkspaceCommands

    app, s = make_app(tmp_path, sample_pcap)
    s.store.save_filter("[red]x", "dns:[b]evil")
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("ctrl+p")
        await pilot.pause()
        assert isinstance(app.screen, CommandPalette)
        provider = WorkspaceCommands(app.screen)
        hits = [h async for h in provider.search("red")]
        hit = next(h for h in hits if h.text == "filter: [red]x")
        assert hit.match_display.plain == "filter: [red]x"
        assert Content.from_markup(hit.help).plain == "dns:[b]evil"


async def test_verify_key_reports_evidence_state(tmp_path, sample_pcap):
    import shutil

    cap = tmp_path / "ev.pcap"
    shutil.copy(sample_pcap, cap)
    app, s = make_app(tmp_path, cap)
    async with app.run_test(size=WIDE) as pilot:
        await wait_loaded(app, pilot, s)
        await pilot.press("V")
        await app.workers.wait_for_complete()
        await pilot.pause()
        events = [e for e in s.store.events(s.investigation.id) if e.kind == "verify"]
        assert len(events) == 1 and "MATCH sha256" in events[0].message
        cap.write_bytes(b"tampered")
        await pilot.press("V")
        await app.workers.wait_for_complete()
        await pilot.pause()
        events = [e for e in s.store.events(s.investigation.id) if e.kind == "verify"]
        assert "MISMATCH" in events[-1].message


async def test_cancel_releases_ui_at_once_and_ignores_late_callbacks(tmp_path, sample_pcap):
    """Escape must not depend on the worker thread noticing the cancellation in time."""
    from trace_zero.session import load_capture

    app, s = make_app(tmp_path)
    async with app.run_test(size=WIDE) as pilot:
        main = screen(app)
        main.start_load(str(sample_pcap))
        worker = main.loading
        await pilot.press("escape")
        assert main.loading is None and main.busy == ""
        # A result delivered late by the cancelled worker is ignored.
        main._on_loaded(load_capture(sample_pcap, s.config), worker)
        main._load_failed("late failure", worker)
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert s.capture is None and main.loading is None
        assert main.query_one("#header").status[0] != "error"
