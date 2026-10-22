"""Neutralise untrusted strings taken from packet captures.

Capture contents are attacker-controllable. Anything derived from packet
bytes (DNS names, HTTP hosts, TLS SNI, ...) must pass through ``clean`` before
it reaches the terminal, so embedded control characters or terminal escape
sequences are displayed as inert text instead of being interpreted.
"""

from __future__ import annotations

_PRINTABLE_CACHE: dict[str, str] = {}


def _escape_char(ch: str) -> str:
    code = ord(ch)
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}"


def clean(value: object, max_len: int = 512) -> str:
    """Return a printable, single-line, length-bounded representation."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        text = bytes(value).decode("utf-8", errors="backslashreplace")
    else:
        text = str(value)
    cached = _PRINTABLE_CACHE.get(text)
    if cached is not None:
        return cached
    out = []
    for ch in text:
        code = ord(ch)
        # C0/C1 controls, DEL, and bidi/format overrides that can disguise text.
        if code < 0x20 or 0x7F <= code < 0xA0 or 0x200B <= code <= 0x200F or 0x202A <= code <= 0x202E or 0x2066 <= code <= 0x2069:
            out.append(_escape_char(ch))
        else:
            out.append(ch)
    result = "".join(out)
    if len(result) > max_len:
        result = result[: max_len - 1] + "…"
    if len(_PRINTABLE_CACHE) < 50_000:
        _PRINTABLE_CACHE[text] = result
    return result


def hexdump(data: bytes, width: int = 16) -> list[str]:
    """Classic offset / hex / ASCII dump. Non-printable bytes render as '.'."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{off:06x}  {hexpart:<{width * 3 - 1}}  {asc}")
    return lines
