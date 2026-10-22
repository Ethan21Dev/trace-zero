"""Network map canvas."""

from __future__ import annotations

from rich.text import Text
from textual.widget import Widget

from trace_zero.ui import theme
from trace_zero.ui.mapgeo import MapEdge, MapNode, render_map


class MapCanvas(Widget):
    DEFAULT_CSS = """
    MapCanvas { height: 1fr; min-height: 5; }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.nodes: list[MapNode] = []
        self.edges: list[MapEdge] = []
        self.caption: Text | None = None

    def set_graph(self, nodes: list[MapNode], edges: list[MapEdge], caption: Text | None) -> None:
        self.nodes, self.edges, self.caption = nodes, edges, caption
        self.refresh()

    def render(self) -> Text:
        w, h = self.size.width, self.size.height
        if not self.nodes:
            return Text("no hosts observed up to the cursor", style=theme.S_DIM)
        body_h = h - 1 if self.caption is not None else h
        lines = render_map(w, max(1, body_h), self.nodes, self.edges)
        if self.caption is not None:
            cap = self.caption.copy()
            cap.truncate(w, overflow="ellipsis")
            lines = [cap] + lines
        return Text("\n", no_wrap=True).join(lines)
