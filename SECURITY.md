# Security policy

TRACE//ZERO reads untrusted input by design: capture files, and the packets inside them, can come
from anywhere. Bugs that let a crafted capture crash the application, hang it, exhaust memory
beyond the configured limits, inject terminal escape sequences or markup, write outside the chosen
export location, or run code are security issues.

## Reporting a vulnerability

Please report it **privately** through GitHub:
**Security** tab of this repository -> **Report a vulnerability**
(https://github.com/Ethan21Dev/trace-zero/security/advisories/new).

Do not open a public issue for security problems.

Include the TRACE//ZERO version (`trace-zero --version`), your operating system, and the steps to
reproduce. If a capture file is needed, **build a minimal one** that triggers the problem (for
example with `scripts/generate_sample.py` or a few hand-made packets) instead of sending a
recording of a real network, which can contain private information.

You can expect an acknowledgement within a week. Fixes are released as a new version and credited
in the changelog unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Scope notes

- TRACE//ZERO never captures packets itself. Live capture runs Wireshark's `dumpcap` or `tcpdump`
  as a separate program, without a shell, non-promiscuous, on an interface taken from that tool's
  own list. Vulnerabilities in those tools should be reported to their projects.
- Optional reference files (IEEE `oui.csv`, MaxMind `.mmdb`) are parsed with bounds checks;
  malformed files are in scope.
