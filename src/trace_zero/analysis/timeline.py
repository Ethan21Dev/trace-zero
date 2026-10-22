"""Network time machine: cursor, window and replay state.

The timeline is a pure state machine with no clock of its own. The UI feeds
it wall-clock deltas while replaying; the observed network state is a function
of (filter, cursor, window mode, window width) only, so the same position
always reproduces the same picture.

Window modes:
  CUMULATIVE  everything observed from the first packet up to the cursor
  SLIDING     only packets in [cursor - width, cursor]
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
from enum import Enum

# Replay speeds in capture-seconds per wall-clock second.
SPEEDS: tuple[float, ...] = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 1000.0, 5000.0)
WIDTHS: tuple[float, ...] = (0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 900.0, 1800.0, 3600.0, 21600.0, 86400.0)


class WindowMode(str, Enum):
    CUMULATIVE = "CUMULATIVE"
    SLIDING = "SLIDING"


@dataclass
class Timeline:
    t0: float
    t1: float
    cursor: float
    mode: WindowMode = WindowMode.CUMULATIVE
    width_idx: int = 0
    speed_idx: int = 5
    playing: bool = False

    @classmethod
    def for_span(cls, t0: float, t1: float) -> Timeline:
        span = max(0.0, t1 - t0)
        # Default width ~ 1/20 of the capture; default speed replays it in ~30 s.
        width_idx = min(range(len(WIDTHS)), key=lambda i: abs(WIDTHS[i] - span / 20)) if span else 0
        speed_target = span / 30 if span else 1.0
        speed_idx = min(range(len(SPEEDS)), key=lambda i: abs(SPEEDS[i] - speed_target))
        return cls(t0=t0, t1=t1, cursor=t1, width_idx=width_idx, speed_idx=speed_idx)

    # -- derived -----------------------------------------------------------
    @property
    def span(self) -> float:
        return max(0.0, self.t1 - self.t0)

    @property
    def width(self) -> float:
        return WIDTHS[self.width_idx]

    @property
    def speed(self) -> float:
        return SPEEDS[self.speed_idx]

    def window(self) -> tuple[float, float]:
        if self.mode is WindowMode.SLIDING:
            return (max(self.t0, self.cursor - self.width), self.cursor)
        return (self.t0, self.cursor)

    @property
    def step(self) -> float:
        if self.mode is WindowMode.SLIDING:
            return self.width
        return self.span / 50 if self.span else 0.0

    @property
    def at_end(self) -> bool:
        return self.cursor >= self.t1

    # -- mutation ----------------------------------------------------------
    def set_cursor(self, t: float) -> None:
        self.cursor = min(self.t1, max(self.t0, t))

    def move(self, steps: int) -> None:
        self.set_cursor(self.cursor + steps * self.step)

    def jump_start(self) -> None:
        self.cursor = self.t0

    def jump_end(self) -> None:
        self.cursor = self.t1

    def toggle_mode(self) -> None:
        self.mode = WindowMode.SLIDING if self.mode is WindowMode.CUMULATIVE else WindowMode.CUMULATIVE

    def change_width(self, delta: int) -> None:
        self.width_idx = min(len(WIDTHS) - 1, max(0, self.width_idx + delta))

    def change_speed(self, delta: int) -> None:
        self.speed_idx = min(len(SPEEDS) - 1, max(0, self.speed_idx + delta))

    def toggle_play(self) -> None:
        if self.playing:
            self.playing = False
            return
        if self.at_end:
            self.cursor = self.t0  # replay from the beginning
        self.playing = True

    def advance(self, wall_seconds: float) -> bool:
        """Advance replay by a wall-clock delta. Returns True if the cursor moved."""
        if not self.playing:
            return False
        before = self.cursor
        self.set_cursor(self.cursor + wall_seconds * self.speed)
        if self.at_end:
            self.playing = False
        return self.cursor != before

    def to_next(self, times: list[float]) -> bool:
        """Move to the first time in sorted ``times`` strictly after the cursor."""
        i = bisect_right(times, self.cursor)
        if i < len(times):
            self.set_cursor(times[i])
            return True
        return False

    def to_prev(self, times: list[float]) -> bool:
        i = bisect_left(times, self.cursor)
        if i > 0:
            self.set_cursor(times[i - 1])
            return True
        return False

    def fraction(self, t: float) -> float:
        return 0.0 if not self.span else (t - self.t0) / self.span
