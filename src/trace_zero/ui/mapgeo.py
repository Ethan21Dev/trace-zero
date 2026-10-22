"""Deterministic character-cell network map.

Nodes are placed on an ellipse in address order, so a host keeps its position
while the timeline moves; hosts simply appear when first observed. Edges are
drawn with Bresenham lines; arrowheads mark the observed direction of packets
(both ends when traffic was seen both ways).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from rich.style import Style
from rich.text import Text

from trace_zero.analysis.index import ip_sort_key
from trace_zero.ui import theme


@dataclass(frozen=True)
class MapNode:
    ip: str
    state: str  # active | dormant  (dormant = seen before the window, not inside it)
    selected: bool = False


@dataclass(frozen=True)
class MapEdge:
    a: str
    b: str
    a_to_b: bool
    b_to_a: bool
    recent: bool
    highlighted: bool


def _label(ip: str, limit: int) -> str:
    return ip if len(ip) <= limit else ip[: limit - 1] + "…"


def layout(ips: list[str], width: int, height: int, label_len: int) -> dict[str, tuple[int, int]]:
    ordered = sorted(ips, key=ip_sort_key)
    n = len(ordered)
    if n == 0 or width < 4 or height < 3:
        return {}
    cx, cy = (width - 1) / 2, (height - 1) / 2
    if n == 1:
        return {ordered[0]: (int(cx), int(cy))}
    rx = max(2.0, width / 2 - label_len - 3)
    ry = max(1.0, height / 2 - 1)
    pos = {}
    used: set[tuple[int, int]] = set()
    for i, ip in enumerate(ordered):
        # Half-step rotation: no node sits exactly at the top or bottom, so labels point outward.
        ang = -math.pi / 2 + 2 * math.pi * (i + 0.5) / n
        x = int(round(cx + rx * math.cos(ang)))
        y = int(round(cy + ry * math.sin(ang)))
        # Nudge collisions vertically so two nodes never share a cell.
        for dy in (0, 1, -1, 2, -2):
            cand = (x, min(height - 1, max(0, y + dy)))
            if cand not in used:
                break
        used.add(cand)
        pos[ip] = cand
    return pos


def _line_char(dx: int, dy: int) -> str:
    if dx == 0:
        return "│"
    slope = abs(dy * 2 / dx)  # terminal cells are roughly twice as tall as wide
    if slope < 0.45:
        return "─"
    if slope > 2.6:
        return "│"
    return "╲" if (dx > 0) == (dy > 0) else "╱"


def _arrow(dx: int, dy: int) -> str:
    if abs(dx) >= abs(dy) * 2:
        return "▸" if dx > 0 else "◂"
    return "▾" if dy > 0 else "▴"


def _place_label(x: int, y: int, length: int, width: int, cx: float, taken: set[tuple[int, int]]) -> int | None:
    right, left = x + 2, x - 1 - length
    for start in ([right, left] if x >= cx else [left, right]):
        if start < 0 or start + length > width:
            continue
        if any((start + i, y) in taken for i in range(-1, length + 1)):
            continue
        return start
    return None


def _bresenham(x0: int, y0: int, x1: int, y1: int) -> list[tuple[int, int]]:
    pts = []
    dx, dy = abs(x1 - x0), -abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx + dy
    x, y = x0, y0
    while True:
        pts.append((x, y))
        if x == x1 and y == y1:
            break
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x += sx
        if e2 <= dx:
            err += dx
            y += sy
    return pts


def render_map(width: int, height: int, nodes: list[MapNode], edges: list[MapEdge]) -> list[Text]:
    width = max(1, width)
    height = max(1, height)
    label_len = 15 if all(":" not in n.ip for n in nodes) else 22
    label_len = min(label_len, max(6, width // 3))
    pos = layout([n.ip for n in nodes], width, height, label_len)
    chars = [[" "] * width for _ in range(height)]
    styles: list[list[Style | None]] = [[None] * width for _ in range(height)]

    def put(x: int, y: int, ch: str, st: Style) -> None:
        if 0 <= x < width and 0 <= y < height:
            chars[y][x] = ch
            styles[y][x] = st

    # Non-highlighted edges first so highlighted ones end up on top.
    for edge in sorted(edges, key=lambda e: (e.highlighted, e.recent, ip_sort_key(e.a), ip_sort_key(e.b))):
        if edge.a not in pos or edge.b not in pos:
            continue
        (x0, y0), (x1, y1) = pos[edge.a], pos[edge.b]
        pts = _bresenham(x0, y0, x1, y1)
        if len(pts) < 3:
            continue
        st = theme.S_CYAN if edge.highlighted else (theme.S_DIM if edge.recent else theme.S_FAINT)
        # Selected links are solid; the rest are light dotted traces so the map stays legible.
        ch = _line_char(x1 - x0, y1 - y0) if edge.highlighted else "·"
        for x, y in pts[1:-1]:
            if edge.highlighted or chars[y][x] == " ":
                put(x, y, ch, st)
        if edge.a_to_b:
            put(*pts[-2], _arrow(x1 - x0, y1 - y0), st)
        if edge.b_to_a:
            put(*pts[1], _arrow(x0 - x1, y0 - y1), st)

    cx = (width - 1) / 2
    taken: set[tuple[int, int]] = {pos[n.ip] for n in nodes if n.ip in pos}
    # Selected node first so its label wins any contest for space.
    for node in sorted(nodes, key=lambda n: (not n.selected, ip_sort_key(n.ip))):
        if node.ip not in pos:
            continue
        x, y = pos[node.ip]
        if node.selected:
            marker, st, lst = "◉", theme.S_CYAN_B, theme.S_CYAN_B
        elif node.state == "active":
            marker, st, lst = "●", theme.S_TEXT, theme.S_TEXT
        else:
            marker, st, lst = "○", theme.S_FAINT, theme.S_FAINT
        put(x, y, marker, st)
        label = _label(node.ip, label_len)
        start = _place_label(x, y, len(label), width, cx, taken)
        if start is None:
            # No clean slot on either side: shorten the label to the free run on the right.
            free = 0
            while x + 2 + free < width and (x + 2 + free, y) not in taken:
                free += 1
            if free < 2:
                continue
            label = _label(node.ip, free - 1)
            start = x + 2
        for i, ch in enumerate(label):
            put(start + i, y, ch, lst)
            taken.add((start + i, y))

    lines = []
    for y in range(height):
        t = Text(no_wrap=True, end="")
        run_style: Style | None = None
        run = []
        for x in range(width):
            st = styles[y][x]
            if st != run_style and run:
                t.append("".join(run), run_style)
                run = []
            run_style = st
            run.append(chars[y][x])
        if run:
            t.append("".join(run), run_style)
        lines.append(t)
    return lines
