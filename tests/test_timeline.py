from __future__ import annotations

from trace_zero.analysis.timeline import SPEEDS, WIDTHS, Timeline, WindowMode


def make() -> Timeline:
    return Timeline.for_span(1000.0, 1300.0)


def test_defaults():
    tl = make()
    assert tl.cursor == tl.t1 and not tl.playing and tl.mode is WindowMode.CUMULATIVE
    assert tl.window() == (1000.0, 1300.0)


def test_sliding_window_and_step():
    tl = make()
    tl.toggle_mode()
    assert tl.mode is WindowMode.SLIDING
    lo, hi = tl.window()
    assert hi == tl.cursor and hi - lo == tl.width
    before = tl.cursor
    tl.move(-1)
    assert tl.cursor == before - tl.width


def test_clamping():
    tl = make()
    tl.move(10_000)
    assert tl.cursor == tl.t1
    tl.move(-10_000)
    assert tl.cursor == tl.t0
    tl.change_speed(999)
    assert tl.speed == SPEEDS[-1]
    tl.change_width(-999)
    assert tl.width == WIDTHS[0]


def test_play_from_end_restarts_and_stops_at_end():
    tl = make()
    tl.toggle_play()
    assert tl.playing and tl.cursor == tl.t0
    tl.speed_idx = SPEEDS.index(100.0)
    tl.advance(1.0)
    assert tl.cursor == tl.t0 + 100.0
    tl.advance(10.0)
    assert tl.cursor == tl.t1 and not tl.playing


def test_advance_ignored_when_paused():
    tl = make()
    tl.jump_start()
    assert tl.advance(5.0) is False and tl.cursor == tl.t0


def test_deterministic_replay():
    """Same wall-clock deltas -> same cursor, regardless of how they are chunked."""
    a, b = make(), make()
    for tl in (a, b):
        tl.jump_start()
        tl.speed_idx = SPEEDS.index(10.0)
        tl.playing = True
    for _ in range(10):
        a.advance(0.1)
    b.advance(0.5)
    b.advance(0.5)
    assert abs(a.cursor - b.cursor) < 1e-9


def test_event_navigation():
    tl = make()
    tl.jump_start()
    times = [1010.0, 1050.0, 1200.0]
    assert tl.to_next(times) and tl.cursor == 1010.0
    assert tl.to_next(times) and tl.cursor == 1050.0
    assert tl.to_prev(times) and tl.cursor == 1010.0
    assert not tl.to_prev(times)
    tl.jump_end()
    assert not tl.to_next(times)


def test_zero_span_capture():
    tl = Timeline.for_span(5.0, 5.0)
    tl.move(3)
    assert tl.cursor == 5.0 and tl.step == 0.0
    tl.toggle_play()
    tl.advance(1.0)
    assert tl.cursor == 5.0
