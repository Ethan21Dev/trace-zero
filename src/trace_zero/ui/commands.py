"""Command palette (ctrl+p): every workspace action, saved filters and recent filters.

Entries are built from the workspace key bindings, so the palette never
drifts from the keyboard map. All text is shown as plain Text: saved filter
names and expressions are user data and must not be read as markup.
"""

from __future__ import annotations

from functools import partial

from rich.text import Text
from textual.command import CommandPalette, DiscoveryHit, Hit, Hits, Provider, SearchIcon
from textual.content import Content
from textual.markup import escape

from trace_zero.ui import theme


def _key_label(keys: str) -> str:
    first = keys.split(",")[0]
    return {
        "question_mark": "?",
        "slash": "/",
        "less_than_sign": "<",
        "greater_than_sign": ">",
        "plus": "+",
        "minus": "-",
        "left_square_bracket": "[",
        "right_square_bracket": "]",
        "left_curly_bracket": "{",
        "right_curly_bracket": "}",
        "space": "space",
    }.get(first, first)


class WorkspaceCommands(Provider):
    def _entries(self) -> list[tuple[str, str, object]]:
        """(title, help, callback) for everything the palette can run."""
        app = self.app
        main = app.main
        entries: list[tuple[str, str, object]] = []
        seen: set[str] = set()
        for binding in type(main).BINDINGS:
            if not binding.description or binding.action in seen or binding.action == "open_selected":
                continue
            seen.add(binding.action)
            entries.append((binding.description, f"key {_key_label(binding.key)}", partial(main.run_action, binding.action)))
        session = main.session
        if session.capture is not None:
            for name, expression in session.store.saved_filters():
                entries.append((f"filter: {name}", expression, partial(main.apply_filter_text, expression)))
            for expression in session.store.filter_history(limit=10):
                entries.append((f"recent filter: {expression}", "from filter history", partial(main.apply_filter_text, expression)))
        return entries

    async def discover(self) -> Hits:
        for title, help_text, callback in self._entries():
            yield DiscoveryHit(Text(title, style=theme.S_TEXT), callback, text=title, help=escape(help_text))

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for title, help_text, callback in self._entries():
            score = matcher.match(title)
            if score > 0:
                yield Hit(score, self._highlight(matcher, title), callback, text=title, help=escape(help_text))

    @staticmethod
    def _highlight(matcher, title: str) -> Content:
        # Matcher.highlight() parses its input as markup; saved filter names are user data.
        content = Content(title)
        _score, offsets = matcher.fuzzy_search.match(matcher.query, title)
        for offset in offsets:
            if not title[offset].isspace():
                content = content.stylize(matcher.match_style, offset, offset + 1)
        return content


class TracePalette(CommandPalette):
    """Textual's command palette with a plain prompt glyph (the default is an emoji)."""

    DEFAULT_CSS = """
    TracePalette SearchIcon { color: $accent; }
    """

    def on_mount(self) -> None:
        self.query_one(SearchIcon).icon = ">"
