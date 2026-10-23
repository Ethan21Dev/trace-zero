# Changelog

All notable changes to TRACE//ZERO. Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-23

First public release.

TRACE//ZERO is a keyboard-driven terminal tool for looking at network traffic: open a
PCAP/PCAPNG capture, or record your own computer's traffic live, then explore it on a timeline,
a network map, connection and packet lists, and a plain-language inspector.

### Highlights

- **Live capture** - press `Shift+F` (or the start-screen button), pick the adapter marked
  **CONNECTED** and watch your computer's traffic arrive. Capture is passive and never promiscuous:
  only traffic to and from your own computer is recorded. Uses Wireshark's `dumpcap` (or
  `tcpdump`); TRACE//ZERO itself never needs administrator rights.
- **WHAT IS THIS** - select any address to see, in plain language, whether it is this computer,
  your router, a device on your network, an internet server or a discovery/broadcast address,
  the names seen for it and the services it provides. Nothing is looked up online.
- **Network time machine** - scrub, replay and step through a capture; hosts and links appear on
  the map as they were first seen; compare two moments with the window diff.
- **Flows and streams** - connection table and reassembled TCP streams with HTTP, TLS and DNS
  decoded; gaps and changed retransmissions are reported, not hidden.
- **Ten explainable heuristics** - failed connections, port fan-out, traffic and DNS spikes,
  periodic contacts, ARP conflicts, unsolicited DNS answers, heavy uploads, late new destinations
  and TLS-name/DNS mismatches; each with numbers, evidence frames and a confidence statement.
  Triage findings and suppress known-benign patterns with a reason.
- **Investigations** - notes, bookmarks, timeline marks, journal, JSON and HTML reports, PCAPNG
  export of exactly the packets shown, with an equivalent Wireshark filter.
- **Evidence integrity** - captures are opened read-only and hashed (SHA-256); re-verify any
  time; every export gets a `.sha256` file.
- **Standalone downloads** for Windows, macOS (Apple Silicon) and Linux - no Python needed.

### Since the 0.1 test releases

- Start screen buttons for opening a file and starting live capture; `Shift+F` shown everywhere.
- The file browser starts in your Downloads folder (never `C:\Windows\System32`), with quick
  jumps to Desktop, Documents, home, exports and every drive.
- The adapter picker shows full adapter names, lists Wi-Fi and Ethernet first, and marks and
  pre-selects the one connected to the internet.
- Live mode explains what to install when Wireshark is missing.

### Known limitations

- Executables are not code-signed: Windows SmartScreen and macOS Gatekeeper ask for confirmation.
- About 1.1 KB of memory per packet; captures above about a million packets need a raised limit.
- No HTTP/2, QUIC or IP fragment reassembly; TLS 1.3 certificates are encrypted and not shown.

[1.0.0]: https://github.com/Ethan21Dev/trace-zero/releases/tag/v1.0.0
