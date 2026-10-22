"""Textual application shell."""

from __future__ import annotations

from textual.app import App
from textual.binding import Binding
from textual.notifications import SeverityLevel

from trace_zero import PRODUCT, TAGLINE
from trace_zero.session import Session
from trace_zero.ui.commands import WorkspaceCommands
from trace_zero.ui.screens.main import MainScreen
from trace_zero.ui.theme import TRACE_ZERO_THEME


class TraceZeroApp(App):
    CSS_PATH = "app.tcss"
    TITLE = PRODUCT
    SUB_TITLE = TAGLINE
    COMMANDS = {WorkspaceCommands}
    COMMAND_PALETTE_BINDING = "ctrl+p"
    BINDINGS = [Binding("ctrl+q", "quit", "quit", priority=True, show=False)]

    def __init__(self, session: Session, capture: str | list[str] | None = None) -> None:
        super().__init__()
        self.session = session
        self.initial_capture = capture
        self.register_theme(TRACE_ZERO_THEME)
        self.theme = TRACE_ZERO_THEME.name

    def notify(self, message: str, *, title: str = "", severity: SeverityLevel = "information", timeout: float | None = None, markup: bool = False) -> None:
        """Notifications default to plain text: messages can carry file names, filter text or
        values derived from captures, which must never be interpreted as markup."""
        super().notify(message, title=title, severity=severity, timeout=timeout, markup=markup)

    def get_default_screen(self) -> MainScreen:
        return MainScreen(self.session, self.initial_capture)

    @property
    def main(self) -> MainScreen:
        """The workspace screen (always at the bottom of the screen stack)."""
        return self.screen_stack[0]  # type: ignore[return-value]
