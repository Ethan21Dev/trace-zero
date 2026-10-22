"""Quiet, centralised scapy imports.

Scapy logs warnings to stderr, which would corrupt a full-screen TUI. All
scapy imports go through this module so its loggers are silenced and its
warnings can be collected into the import report instead.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager

_scapy_logger = logging.getLogger("scapy")
for _h in list(_scapy_logger.handlers):
    _scapy_logger.removeHandler(_h)
_scapy_logger.addHandler(logging.NullHandler())
_scapy_logger.propagate = False
_scapy_logger.setLevel(logging.WARNING)

from scapy.error import Scapy_Exception  # noqa: E402
from scapy.layers.dns import DNS  # noqa: E402
from scapy.packet import Packet, Raw  # noqa: E402
from scapy.utils import RawPcapNgReader, RawPcapReader  # noqa: E402

# Importing layers may have re-added handlers; strip them again.
for _name in ("scapy", "scapy.runtime", "scapy.loading", "scapy.interactive"):
    _lg = logging.getLogger(_name)
    for _h in list(_lg.handlers):
        if not isinstance(_h, logging.NullHandler):
            _lg.removeHandler(_h)
    _lg.propagate = _name != "scapy"

__all__ = [
    "DNS",
    "Packet",
    "Raw",
    "RawPcapNgReader",
    "RawPcapReader",
    "Scapy_Exception",
    "collect_warnings",
]


class _ListHandler(logging.Handler):
    def __init__(self, sink: list[str], limit: int) -> None:
        super().__init__(level=logging.WARNING)
        self.sink = sink
        self.limit = limit

    def emit(self, record: logging.LogRecord) -> None:
        if len(self.sink) >= self.limit:
            return
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - malformed log args must not break parsing
            msg = str(record.msg)
        if msg not in self.sink:
            self.sink.append(msg)


@contextmanager
def collect_warnings(sink: list[str], limit: int = 50) -> Iterator[None]:
    handler = _ListHandler(sink, limit)
    _scapy_logger.addHandler(handler)
    try:
        yield
    finally:
        _scapy_logger.removeHandler(handler)


def dissect_frame(data: bytes, linktype: int) -> Packet | None:
    """Full scapy dissection of one frame, used only for on-demand inspection."""
    from scapy.config import conf

    cls = conf.l2types.get(linktype)
    if cls is None:
        return None
    return cls(data)
