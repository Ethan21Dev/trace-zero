"""Which network adapter does this computer use to reach the internet?

Used to pre-select the right interface for live capture. Everything here is a
local lookup of the operating system's own configuration - the routing
table - and never sends a packet:

* Windows: PowerShell ``Get-NetRoute`` for the default route, then that
  route's adapter (name, interface GUID) and IPv4 addresses. The GUID is the one
  in dumpcap's ``\\Device\\NPF_{GUID}`` names. If PowerShell is unavailable,
  ``ipconfig`` is read instead: the section holding this computer's source
  address names the adapter.
* Linux: ``/proc/net/route`` (the default route's device).
* macOS: ``route -n get default`` and ``ipconfig getifaddr``.

Detection is best effort: any failure returns an empty list and the picker
simply shows the adapters without a CONNECTED mark.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path

from trace_zero.live.tool import Interface

# Default IPv4 routes, best (lowest metric) first, with their adapter's name, GUID and addresses.
# Errors about unrelated virtual adapters are silenced; they must not hide the answer.
_WINDOWS_SCRIPT = (
    "$ErrorActionPreference = 'SilentlyContinue'; "
    "@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | "
    "ForEach-Object { $i = $_.InterfaceIndex; $a = Get-NetAdapter -InterfaceIndex $i; "
    "if ($a) { [pscustomobject]@{ Alias = $a.Name; Guid = [string]$a.InterfaceGuid; "
    "IPv4 = @(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 | ForEach-Object { $_.IPAddress }) } } }) "
    "| ConvertTo-Json -Compress"
)


@dataclass(frozen=True)
class DefaultRoute:
    """An adapter with a default route (the way out to the internet)."""

    name: str  # Windows: connection name ("Wi-Fi"); Linux/macOS: device ("wlan0", "en0")
    guid: str = ""  # Windows interface GUID, "{...}" upper case
    addresses: tuple[str, ...] = ()


def parse_windows(text: str) -> list[DefaultRoute]:
    try:
        data = json.loads(text) if text.strip() else []
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    out = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict) or not item.get("Alias"):
            continue
        guid = str(item.get("Guid") or "").strip().upper()
        if guid and not guid.startswith("{"):
            guid = "{" + guid + "}"
        ips = item.get("IPv4") or []
        if isinstance(ips, str):
            ips = [ips]
        out.append(DefaultRoute(str(item["Alias"]), guid, tuple(str(i) for i in ips if i)))
    return out


def parse_ipconfig(text: str, source_address: str | None) -> list[DefaultRoute]:
    """The ``ipconfig`` section that holds ``source_address``. Labels are localised, so only the
    unindented section heading and the address itself are used."""
    if not source_address:
        return []
    heading = None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            heading = line.rstrip()[:-1].strip()
        elif heading and re.search(r"(?<![\d.])" + re.escape(source_address) + r"(?![\d.])", line):
            return [DefaultRoute(heading, "", (source_address,))]
    return []


def parse_proc_net_route(text: str) -> list[str]:
    """Devices with a default route (destination 0.0.0.0, mask 0, route up), lowest metric first."""
    found: list[tuple[int, str]] = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 8:
            continue
        iface, dest, flags, metric, mask = cols[0], cols[1], cols[3], cols[6], cols[7]
        try:
            up = int(flags, 16) & 0x1
            if dest == "00000000" and mask == "00000000" and up:
                found.append((int(metric), iface))
        except ValueError:
            continue
    return [iface for _m, iface in sorted(found)]


def parse_macos_route(text: str) -> str | None:
    m = re.search(r"^\s*interface:\s*(\S+)", text, re.MULTILINE)
    return m.group(1) if m else None


def _run(cmd: list[str], timeout: float) -> str:
    kwargs: dict = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # no console flash
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, check=False, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    # Keep the output even with a non-zero exit: PowerShell sets one for errors about other adapters.
    return proc.stdout or ""


def windows_powershell(timeout: float = 8.0) -> list[DefaultRoute]:
    return parse_windows(_run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_SCRIPT], timeout))


def windows_ipconfig(timeout: float = 8.0) -> list[DefaultRoute]:
    return parse_ipconfig(_run(["ipconfig"], timeout), _source_address())


def _source_address() -> str | None:
    """The local IPv4 address used for the default route. A UDP connect sends no packet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # documentation address; nothing is transmitted
            return s.getsockname()[0]
    except OSError:
        return None


def detect_default_routes(timeout: float = 8.0) -> list[DefaultRoute]:
    """Adapters this computer uses to reach the internet. Never raises."""
    try:
        if sys.platform == "win32":
            return windows_powershell(timeout) or windows_ipconfig(timeout)
        if sys.platform == "darwin":
            dev = parse_macos_route(_run(["route", "-n", "get", "default"], timeout))
            if not dev:
                return []
            addr = _run(["ipconfig", "getifaddr", dev], timeout).strip()
            return [DefaultRoute(dev, "", (addr,) if addr else ())]
        devices = parse_proc_net_route(Path("/proc/net/route").read_text(encoding="ascii", errors="replace"))
        if not devices:
            return []
        addr = _source_address()
        return [DefaultRoute(devices[0], "", (addr,) if addr else ())] + [DefaultRoute(d) for d in devices[1:]]
    except Exception:  # noqa: BLE001 - a convenience; the picker works without it
        return []


def mark_connected(interfaces: list[Interface], routes: list[DefaultRoute]) -> list[Interface]:
    """Copy of ``interfaces`` with ``connected``/``addresses`` set on the adapters that carry a default route."""
    out = []
    for iface in interfaces:
        match = None
        for route in routes:
            if route.guid and route.guid in iface.name.upper():
                match = route
            elif route.name and (route.name == iface.name or route.name == iface.friendly):
                match = route
            elif route.name.endswith(" " + iface.friendly):  # ipconfig heading: "Wireless LAN adapter Wi-Fi"
                match = route
            if match:
                break
        out.append(replace(iface, connected=True, addresses=match.addresses) if match else iface)
    return out
