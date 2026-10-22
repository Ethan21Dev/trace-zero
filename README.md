# TRACE//ZERO

**EVERY PACKET LEAVES A TRACE.**

TRACE//ZERO is a keyboard-driven terminal instrument for offline network forensics.
Open a PCAP or PCAPNG capture, scrub through it with a deterministic time machine,
watch hosts and links appear on a network map as the cursor moves, inspect any frame
down to raw bytes, review transparent anomaly heuristics, and keep bookmarks, notes and
exports in a persistent investigation.

![TRACE//ZERO workspace: hosts, network map, inspector and timeline](docs/screenshots/01-workspace-map.svg)

<sub>Every screenshot in this repository is rendered from the running application by
`scripts/capture_screenshots.py` (Textual's own SVG export, real keystrokes, synthetic sample capture).</sub>

---

## What it is - and is not

* **Offline only.** It reads capture files you explicitly choose. There is no live capture,
  no administrator privilege, no special hardware, and no network access of any kind.
* **Evidence stays read-only.** Captures are opened read-only and hashed (SHA-256) at import.
* **Nothing leaves the machine.** No telemetry, no uploads, no external lookups. Exported
  HTML reports carry a Content-Security-Policy that blocks scripts and remote fetches.
* **No offensive features.** No scanning, exploitation, credential harvesting or interception.
* **Explainable, not oracular.** Heuristics flag *possible anomalies* with the rule, numbers,
  supporting frames and a confidence statement. They never claim malicious intent.

## Features (implemented and covered by tests)

| Area | What you get |
| --- | --- |
| Import | PCAP (µs and ns) and PCAPNG; Ethernet, 802.1Q/QinQ, Linux SLL/SLL2, BSD loopback, raw IPv4/IPv6. Background import with progress, `esc` to cancel. Malformed, truncated and empty files are reported, not fatal. |
| Decoding | Timestamps, MACs, VLAN, IPv4/IPv6 (incl. extension headers, fragments), TCP (flags, seq/ack, window), UDP, ICMP/ICMPv6, ARP, DNS/mDNS/LLMNR (via scapy, with sanity checks), HTTP request/status lines, TLS ClientHello SNI. Fields that are not present are left empty - never guessed. |
| Hosts | Per-window and whole-capture traffic, peers, MACs seen as source, TTLs, ports observed accepting TCP, ports initiated, DNS names **only** when an answer in the capture maps to the address. |
| Network map | Deterministic layout; hosts appear when first observed; arrowheads show observed packet direction; selected host's links highlighted; dormant hosts dimmed in sliding windows. |
| Packets | Virtualised list (a million rows cost the same as ten), sortable, filterable, chronological stepping, full decode, optional raw hex + full scapy dissection. |
| Time machine | Cursor, cumulative or sliding window, play/pause, 15 replay speeds, step by window, by packet, or by significant event; filter replay by host, protocol or time range. |
| Heuristics | Repeated failed connections, destination-port fan-out, traffic spikes, DNS query spikes, unusually frequent / periodic host pairs. Each with severity, hosts, timestamps, frames, rule, explanation and confidence. |
| Investigations | Create, rename, switch; bookmarks (packets, hosts, findings, links); analyst notes; activity journal; JSON and HTML export. Stored in SQLite. |
| Interface | Full-screen Textual TUI, keyboard only, contextual shortcut bar, help overlay, compact single-panel mode below 130 columns, guard screen below 60x16. |

## Install and launch

Requires Python 3.11+ (tested on 3.11, 3.12 and 3.13). Dependencies: Textual, Rich, Scapy.

### Linux

```bash
git clone https://github.com/<you>/trace-zero.git
cd trace-zero
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

trace-zero --generate-sample sample.pcapng --format pcapng   # synthetic, safe sample
trace-zero sample.pcapng
```

### Debian / Ubuntu on WSL

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/<you>/trace-zero.git && cd trace-zero
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
trace-zero --generate-sample sample.pcapng --format pcapng
trace-zero sample.pcapng
# Windows files are reachable under /mnt/c, e.g.:
trace-zero /mnt/c/Users/<you>/Downloads/capture.pcapng
```

Run it inside **Windows Terminal** (the WSL profile) for full colour and Unicode support.

### Windows (native, Windows Terminal + PowerShell)

```powershell
git clone https://github.com/<you>/trace-zero.git
cd trace-zero
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
trace-zero --generate-sample sample.pcapng --format pcapng
trace-zero sample.pcapng
```

No Npcap/WinPcap is needed: TRACE//ZERO only reads files. Use Windows Terminal rather than
the legacy console host. See [docs/SETUP.md](docs/SETUP.md) for fonts, sizes and details.

### Other ways to run

```bash
python -m trace_zero capture.pcap                  # without the console script
trace-zero capture.pcap -i "Case 2026-114"         # open or create a named investigation
trace-zero                                         # start empty, press o to open a file
```

## Using it

```
 HEADER    TRACE//ZERO | investigation | capture | import status
 HOSTS     |  CENTER: map / packets / findings / journal  |  INSPECTOR
 TIMELINE  activity histogram, cursor, window, findings markers, replay state
 STATUS    contextual keys | filter | selected range | app status
```

| Key | Action | Key | Action |
| --- | --- | --- | --- |
| `o` | open capture | `space` | play / pause replay |
| `/` | search / filter | `←` `→` | step cursor |
| `h` `n` `p` `f` `b` | hosts, map, packets, findings, journal | `⇧←` `⇧→` | previous / next packet |
| `t` `i` | timeline, inspector | `<` `>` | previous / next significant event |
| `enter` | open selected item | `home` `end` | start / end |
| `esc` | close / cancel / clear | `+` `-` | replay speed |
| `m` `a` | bookmark, note | `w` `[` `]` | window mode and width |
| `x` | raw bytes + scapy dissection | `s` `S` | sort / reverse |
| `e` | export JSON + HTML | `r` `ctrl+n` `l` | rename, new, list investigations |
| `?` | help | `q` | back, then quit |

Full reference: [docs/KEYBINDINGS.md](docs/KEYBINDINGS.md) (generated from the in-app keymap).

### Filter language

```
host:10.20.0.12 proto:tcp !port:445        # TCP to/from a host, excluding SMB
proto:dns|mdns dns:telemetry               # DNS questions containing "telemetry"
flags:S !flags:A dport:1-1024              # bare SYNs to low ports
t>200 t<205 len>1000                       # large frames in a 5-second slice
host:10.20.0.0/24 error                    # frames with decode issues from a subnet
```

The filter drives everything: packet list, hosts, map, histogram and replay.

### The network time machine

The cursor defines what has been **observed**: in `CUMULATIVE` mode everything from the
first packet up to the cursor, in `SLIDING` mode only the last *width* seconds. Hosts appear
on the map when first observed; links show how long before the cursor they were last seen.
These are historical observations from the capture - TRACE//ZERO never presents them as live
connection state.

Replay is deterministic: the displayed state is a pure function of capture, filter, cursor,
window mode and width. Playback merely moves the cursor.

![Sliding window replay](docs/screenshots/02-replay-sliding-window.svg)

### Possible anomalies

| Rule | Looks for |
| --- | --- |
| `TZ-R1` | Repeated **failed** TCP connection attempts (refused or unanswered SYNs) to one destination port |
| `TZ-R2` | One source initiating connections to many distinct destination ports in a short window |
| `TZ-R3` | Bytes per time bin far above the capture's own median (robust z-score) |
| `TZ-R4` | DNS query bursts relative to the source's own baseline (with NXDOMAIN and uniqueness context) |
| `TZ-R5` | Host pairs with far more separate contacts than others, or contacts at a very regular interval |

`enter` on a finding turns its supporting frames into the packet list and the timeline,
so the evidence can be replayed packet by packet. Details and thresholds:
[docs/HEURISTICS.md](docs/HEURISTICS.md).

![Finding evidence on the timeline](docs/screenshots/04-finding-evidence.svg)

### Investigations and exports

Investigations live in a SQLite database (`~/.local/share/trace-zero/investigations.db`,
`%LOCALAPPDATA%\trace-zero\` on Windows; override with `--db` or `TRACE_ZERO_HOME`).
They record the captures examined (path + SHA-256), bookmarks, analyst notes and a journal.

`e` writes a JSON summary and a self-contained HTML report. Both separate **observed
facts**, **heuristic findings** and **analyst interpretations** into distinct sections.

### Headless mode

```bash
trace-zero capture.pcapng --headless --json report.json --html report.html
```

Prints a summary (hashes, counts, findings) and writes the same exports as the TUI.

## Configuration

Optional. Copy [config.example.toml](config.example.toml) to `~/.config/trace-zero/config.toml`
(Linux/WSL) or `%APPDATA%\trace-zero\config.toml` (Windows), or pass `--config`. It sets
resource limits, heuristic thresholds and storage paths.

## Performance and capture-size limits

Measured in this repository's development container (4 vCPU x86-64, Python 3.13):

| Capture | Import | Peak RAM | Window query | Full UI refresh |
| --- | --- | --- | --- | --- |
| 2,608 packets (sample) | 0.1 s | ~70 MB (whole TUI process) | < 1 ms | ~3 ms (max 5 ms) |
| 260,800 packets / 110 MB | 11-12 s (~21-30k packets/s) | ~220 MB (import + analysis) | 0.5-4 ms | 11-18 ms |

* Default limits: files up to **1 GiB**, at most **1,000,000 packets** (the import stops and the
  capture is clearly marked `TRUNCATED`). Both are configurable.
* Memory is roughly **0.7 KB per packet**. Raw bytes are not kept in memory; they are re-read
  from the (unchanged, verified) file on demand.
* Import, filtering of large captures and raw-byte loading run in worker threads; the UI
  stays responsive. Sorting the packet list by a non-time column re-sorts the current window
  on each change, which costs ~80 ms per refresh at 260k packets.

## Known limitations

* Offline analysis only; no live capture by design.
* No TCP stream reassembly: HTTP and TLS details come from single segments; DNS over TCP is
  decoded only when the message fits one segment.
* IP fragments are flagged but not reassembled; non-first fragments carry no ports.
* Decoded application protocols are limited to DNS/mDNS/LLMNR, HTTP request/status lines
  and TLS ClientHello SNI. Everything else is shown at transport level, plus full scapy
  dissection on demand with `x`.
* 802.11, Bluetooth and other non-IP link types are imported with timing and length only.
* Gzip-compressed captures must be decompressed first.
* Heuristic thresholds are generic defaults; tune them for your environment.
* The map draws at most ~28 nodes (largest by traffic, plus the selected host); the rest are
  listed in the hosts panel and counted in the map caption.
* Captures above ~1M packets need a raised limit and proportionally more RAM.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q                          # unit, integration and keyboard-driven UI tests
python scripts/gen_keybindings.py --check    # docs/KEYBINDINGS.md in sync with the keymap
python scripts/capture_screenshots.py        # regenerate docs/screenshots/*.svg from the real app
python scripts/generate_sample.py s.pcapng   # synthetic sample (also: --scale, --truncate)
```

The test suite never touches the network: a fixture makes any scapy send/ARP call fail.
Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Troubleshooting: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## License

MIT - see [LICENSE](LICENSE).
