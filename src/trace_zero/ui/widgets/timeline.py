"""Timeline panel: activity histogram, cursor, window and replay state."""

from __future__ import annotations

import math
from dataclasses import dataclass

from rich.text import Text
from textual.widget import Widget

from trace_zero.analysis.timeline import Timeline, WindowMode
from trace_zero.models import fmt_bytes, fmt_duration, fmt_rel, fmt_ts
from trace_zero.sanitize import clean
from trace_zero.ui import theme

BLOCKS = " ▁▂▃▄▅▆▇█"


@dataclass
class TimelineSnapshot:
    timeline: Timeline
    counts: list[int]
    finding_times: list[float]
    window_packets: int
    window_bytes: int
    event_label: str | None
    filtered: bool


class TimelinePanel(Widget, can_focus=True):
    DEFAULT_CSS = """
    TimelinePanel { height: 7; }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.snap: TimelineSnapshot | None = None

    @property
    def bar_width(self) -> int:
        return max(10, self.size.width - 2)

    def update_snapshot(self, snap: TimelineSnapshot | None) -> None:
        self.snap = snap
        self.refresh()

    def render(self) -> Text:
        width = max(10, self.size.width)
        height = max(1, self.size.height)
        snap = self.snap
        if snap is None:
            return Text("no capture loaded — press o to open a PCAP/PCAPNG file", style=theme.S_DIM)
        tl = snap.timeline
        counts = snap.counts
        bins = len(counts)
        hist_rows = max(1, min(3, height - 3))
        lo, hi = tl.window()

        def col_of(t: float) -> int:
            if not tl.span:
                return 0
            return min(bins - 1, max(0, int((t - tl.t0) / tl.span * bins)))

        cur_col = col_of(tl.cursor)
        lo_col, hi_col = col_of(lo), col_of(hi)
        peak = max(counts) if counts else 0
        levels = hist_rows * 8
        lines: list[Text] = []
        for row in range(hist_rows):
            t = Text(no_wrap=True, end="")
            for c, n in enumerate(counts):
                # Square-root scale keeps quiet periods visible next to a spike.
                lvl = 0 if not peak or not n else max(1, round(math.sqrt(n / peak) * levels))
                cell_lvl = min(8, max(0, lvl - (hist_rows - 1 - row) * 8))
                ch = BLOCKS[cell_lvl]
                if c == cur_col:
                    st = theme.S_CYAN_B
                elif lo_col <= c <= hi_col and c < cur_col:
                    st = theme.S_CYAN_DIM
                elif c > cur_col:
                    st = theme.S_FAINT
                else:
                    st = theme.S_DIM
                t.append(ch, st)
            lines.append(t)
        # Axis: window bracket, findings and cursor.
        axis = ["─"] * bins
        axis_style = [theme.S_FAINT] * bins
        for c in range(lo_col, hi_col + 1):
            axis[c] = "═" if tl.mode is WindowMode.SLIDING else "─"
            axis_style[c] = theme.S_CYAN_DIM
        for ft in snap.finding_times:
            c = col_of(ft)
            axis[c] = "◆"
            axis_style[c] = theme.S_AMBER
        axis[cur_col] = "▲"
        axis_style[cur_col] = theme.S_CYAN_B
        at = Text(no_wrap=True, end="")
        for ch, st in zip(axis, axis_style):
            at.append(ch, st)
        lines.append(at)
        # Labels.
        if height >= 4:
            left = fmt_ts(tl.t0)
            right = fmt_ts(tl.t1)
            mid = f"▲ {fmt_ts(tl.cursor, True)}  T{fmt_rel(tl.cursor - tl.t0)}"
            lt = Text(no_wrap=True, end="")
            lt.append(left, theme.S_DIM)
            gap = bins - len(left) - len(right) - len(mid)
            if gap >= 2:
                lpad = max(1, min(gap - 1, cur_col - len(left) - len(mid) // 2))
                lt.append(" " * lpad)
                lt.append(mid, theme.S_CYAN)
                lt.append(" " * (gap - lpad))
            else:
                lt.append(" " * max(1, bins - len(left) - len(right)))
            lt.append(right, theme.S_DIM)
            lines.append(lt)
        # Replay state.
        st = Text(no_wrap=True, overflow="ellipsis", end="")
        if tl.playing:
            st.append("▶ REPLAY ", theme.S_CYAN_B)
        else:
            st.append("❙❙ PAUSED ", theme.S_DIM)
        st.append(f"{tl.speed:g}x", theme.S_TEXT)
        st.append("  │  ", theme.S_FAINT)
        if tl.mode is WindowMode.SLIDING:
            st.append(f"SLIDING {fmt_duration(tl.width)}", theme.S_TEXT)
        else:
            st.append("CUMULATIVE", theme.S_TEXT)
        st.append("  │  ", theme.S_FAINT)
        st.append(f"{snap.window_packets:,} pkts  {fmt_bytes(snap.window_bytes)}", theme.S_TEXT)
        st.append(" observed in window" + (" (filtered)" if snap.filtered else ""), theme.S_DIM)
        if snap.event_label:
            st.append("  │  ", theme.S_FAINT)
            st.append("EVENT ", theme.S_AMBER)
            st.append(clean(snap.event_label, 160), theme.S_TEXT)
        lines.append(st)
        lines = lines[-height:] if len(lines) > height else lines
        return Text("\n", no_wrap=True).join(lines)
