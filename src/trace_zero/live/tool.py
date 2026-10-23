"""Launch a packet-capture tool that writes the file TRACE//ZERO follows.

TRACE//ZERO never captures packets itself and never asks for elevated
privileges. Live capture is delegated to Wireshark's ``dumpcap`` (preferred)
or ``tcpdump``. Only that tool needs permission to capture - for example
membership of the ``wireshark`` group on Linux, or Npcap on Windows - and
TRACE//ZERO simply reads the file it writes.

The capture is passive and receive-only, and deliberately limited:

* promiscuous mode is always disabled (``-p``): only traffic to and from this
  machine plus broadcast/multicast is recorded. Monitoring other hosts'
  traffic (a mirror port, a tap) is outside what TRACE//ZERO starts; record
  that with your own authorised tooling and follow the file instead;
* the interface must be one the tool itself lists (``-D``);
* commands are argument lists, never shell strings;
* packet-count and file-size limits stop the tool with the configured limits.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_WINDOWS_DUMPCAP = (
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "dumpcap.exe",
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark" / "dumpcap.exe",
)
_LIST_LINE = re.compile(r"^\s*\d+\.\s*(\S+)(?:\s+(.*))?$")
_MAX_FILTER = 1000


class CaptureToolError(Exception):
    """The capture tool is missing, refused the request, or failed."""


@dataclass(frozen=True)
class CaptureTool:
    kind: str  # "dumpcap" or "tcpdump"
    path: str


@dataclass(frozen=True)
class Interface:
    name: str
    description: str
    connected: bool = False  # carries this computer's default route (see live.route)
    addresses: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.name}  {self.description}".strip()

    @property
    def friendly(self) -> str:
        """The human name: Windows lists '\\Device\\NPF_{GUID} (Wi-Fi)', so the part in parentheses."""
        desc = self.description.strip()
        if desc.startswith("(") and desc.endswith(")"):
            desc = desc[1:-1].strip()
        return desc or self.name


def find_tool(configured: str | os.PathLike[str] | None = None) -> CaptureTool | None:
    """dumpcap if available, else tcpdump. ``configured`` is an explicit path from the config."""
    if configured:
        path = Path(configured).expanduser()
        if not path.is_file():
            raise CaptureToolError(f"configured capture tool not found: {path}")
        kind = "tcpdump" if "tcpdump" in path.name.lower() else "dumpcap"
        return CaptureTool(kind, str(path))
    found = shutil.which("dumpcap")
    if found:
        return CaptureTool("dumpcap", found)
    if sys.platform == "win32":
        for candidate in _WINDOWS_DUMPCAP:
            if candidate.is_file():
                return CaptureTool("dumpcap", str(candidate))
    found = shutil.which("tcpdump")
    if found:
        return CaptureTool("tcpdump", found)
    return None


def _run(cmd: list[str], timeout: float = 15) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureToolError(f"cannot run {Path(cmd[0]).name}: {exc}") from exc


def parse_interface_list(text: str) -> list[Interface]:
    """Parse ``dumpcap -D`` / ``tcpdump -D`` output: ``1. eth0 (description)``."""
    out = []
    for line in text.splitlines():
        m = _LIST_LINE.match(line)
        if m:
            desc = (m.group(2) or "").strip()
            out.append(Interface(m.group(1), desc))
    return out


def list_interfaces(tool: CaptureTool) -> list[Interface]:
    proc = _run([tool.path, "-D"])
    interfaces = parse_interface_list(proc.stdout)
    if not interfaces:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        raise CaptureToolError(f"{tool.kind} listed no capture interfaces" + (f": {detail[-1]}" if detail else "") + "; " + permission_hint(tool))
    return interfaces


def permission_hint(tool: CaptureTool) -> str:
    if sys.platform == "win32":
        return "install Npcap (bundled with Wireshark) so dumpcap can capture"
    if tool.kind == "dumpcap":
        return "on Linux, allow non-root capture: sudo dpkg-reconfigure wireshark-common, then add yourself to the 'wireshark' group and log in again"
    return "tcpdump needs capture permission (for example CAP_NET_RAW); TRACE//ZERO itself never runs with elevated privileges"


def validate_filter(bpf: str) -> str:
    bpf = bpf.strip()
    if len(bpf) > _MAX_FILTER:
        raise CaptureToolError(f"capture filter is longer than {_MAX_FILTER} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in bpf):
        raise CaptureToolError("capture filter contains control characters")
    if bpf.startswith("-"):
        raise CaptureToolError("capture filter must not start with '-'")
    return bpf


def build_command(tool: CaptureTool, interface: str, out_path: Path, bpf: str = "", max_packets: int = 0, max_file_mb: int = 0) -> list[str]:
    """Argument list for a passive, non-promiscuous capture into ``out_path``."""
    bpf = validate_filter(bpf)
    if not interface or interface.startswith("-"):
        raise CaptureToolError("invalid interface name")
    if tool.kind == "dumpcap":
        cmd = [tool.path, "-i", interface, "-p", "-q", "-w", str(out_path)]
        if max_packets:
            cmd += ["-c", str(max_packets)]
        if max_file_mb:
            cmd += ["-a", f"filesize:{max_file_mb * 1024}"]
        if bpf:
            cmd += ["-f", bpf]
        return cmd
    # tcpdump: -U writes each packet as it arrives, so the file grows promptly; -n no lookups.
    cmd = [tool.path, "-i", interface, "-p", "-n", "-U", "-w", str(out_path)]
    if max_packets:
        cmd += ["-c", str(max_packets)]
    if bpf:
        cmd += [bpf]
    return cmd


class CaptureProcess:
    """A running capture tool. Its messages go to a log file next to TRACE//ZERO's own log."""

    def __init__(
        self,
        tool: CaptureTool,
        interface: str,
        out_path: Path,
        log_path: Path,
        bpf: str = "",
        max_packets: int = 0,
        max_file_mb: int = 0,
        local_addresses: tuple[str, ...] = (),
    ) -> None:
        self.tool = tool
        self.interface = interface
        # This computer's addresses on that interface (when known), to label it in the analysis.
        self.local_addresses = tuple(local_addresses)
        self.out_path = Path(out_path)
        self.log_path = Path(log_path)
        self.cmd = build_command(tool, interface, self.out_path, bpf, max_packets, max_file_mb)
        self.bpf = bpf
        self._proc: subprocess.Popen | None = None
        self._log = None

    def start(self, wait_for_file: float = 10.0) -> None:
        """Start the tool and wait until it has created the output file."""
        if self.out_path.exists():
            raise CaptureToolError(f"refusing to overwrite an existing file: {self.out_path}")
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = open(self.log_path, "ab")
        kwargs: dict = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # lets stop() send CTRL_BREAK
        try:
            self._proc = subprocess.Popen(self.cmd, stdin=subprocess.DEVNULL, stdout=self._log, stderr=self._log, **kwargs)
        except OSError as exc:
            self._log.close()
            raise CaptureToolError(f"cannot start {self.tool.kind}: {exc}") from exc
        deadline = time.monotonic() + wait_for_file
        while time.monotonic() < deadline:
            if self.out_path.exists():
                return
            if self._proc.poll() is not None:
                break
            time.sleep(0.05)
        code = self._proc.poll()
        tail = self.log_tail()
        self.stop()
        if code is not None:
            raise CaptureToolError(f"{self.tool.kind} exited with code {code}: {tail or 'no message'}; {permission_hint(self.tool)}")
        raise CaptureToolError(f"{self.tool.kind} did not create {self.out_path.name} within {wait_for_file:g}s: {tail or 'no message'}")

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def returncode(self) -> int | None:
        return None if self._proc is None else self._proc.poll()

    def log_tail(self, lines: int = 3) -> str:
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return " | ".join(line.strip() for line in text.strip().splitlines()[-lines:] if line.strip())

    def stop(self, timeout: float = 5.0) -> int | None:
        """Ask the tool to finish its file (SIGINT / CTRL_BREAK), then terminate if needed."""
        proc = self._proc
        if proc is not None and proc.poll() is None:
            try:
                if sys.platform == "win32":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    proc.send_signal(signal.SIGINT)
                proc.wait(timeout=timeout)
            except (OSError, subprocess.TimeoutExpired):
                proc.terminate()
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=timeout)
        if self._log is not None:
            self._log.close()
            self._log = None
        return None if proc is None else proc.returncode
