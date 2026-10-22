# Troubleshooting

## Import problems

| Message | Meaning and fix |
| --- | --- |
| `file is empty (0 bytes)` | The file has no content. Re-export the capture. |
| `not a PCAP or PCAPNG file (unrecognised header ...)` | Wrong file type (for example an ETL, snoop or text export). Convert it with `editcap -F pcapng in out.pcapng` from Wireshark. |
| `compressed (gzip) captures are not supported` | Decompress first: `gunzip capture.pcap.gz`. |
| `file is N MB; the configured limit is ...` | Raise `[limits] max_file_mb` in the config, or split the capture: `editcap -c 500000 big.pcap part.pcap`. |
| `path is not a regular file` | Devices, FIFOs and sockets are refused by design; save the capture to a file first. |
| `TRUNCATED - packet limit reached` | Import stopped at `[limits] max_packets`. Everything shown covers only the imported part. Raise the limit (about 1.1 KB of RAM per packet) or split the file. |
| `TRUNCATED - file ends mid-record` / `damaged capture` | The file was cut off or corrupted. All packets before the damage are available; the warning names the byte offset. |
| `capture file changed on disk since import` (raw bytes) | Raw bytes are re-read from disk, and the file's size or modification time no longer matches. Re-open the capture. |
| `... changed on disk since import; re-open it before exporting` | Packet export copies frames from the original file, which no longer matches what was imported. Re-open it (and consider why it changed). |
| `combined captures hold N packets; the limit is ...` | Merged captures count against `[limits] max_packets` together. |
| `packet(s) carry no timestamp (pcapng simple packet blocks)` | The capture uses SPBs, which have no timestamps. Those packets are ordered after the previous packet and flagged. |

Many frames shown in amber with `[...]` in the info column: those frames have decode issues
(truncated headers, invalid lengths, malformed DNS). Filter them with `error`.

## Finding files

* **The file browser starts somewhere odd** - it opens in the folder you used last, else the
  current folder if it contains captures, else Downloads, else your home folder. Starting the
  `.exe` by double-click or from a browser's download list used to land in `C:\Windows\System32`;
  that no longer happens.
* **Getting around** - type any file or folder path and press `enter` (quoted paths from
  Explorer's *Copy as path* work), `tab` to the *Places* list (Downloads, Desktop, Documents,
  home, exports, drives), and `backspace` in the folder tree to go up a level.

## Display problems

* **Boxes, question marks or misaligned lines** - the font lacks box-drawing or geometric glyphs.
  Use Cascadia Mono, JetBrains Mono, DejaVu Sans Mono or similar.
* **Washed-out or wrong colours** - enable 256-colour/true-colour: `export COLORTERM=truecolor`,
  and in tmux add `set -as terminal-features ",*:RGB"`.
* **"terminal too small"** - the workspace needs at least 60 x 16; three panels appear from
  130 columns. Enlarge the window or reduce the font size.
* **Garbled screen after a crash in another program** - run `reset`.

## Keyboard problems

* **Arrow keys do not move the timeline** - left/right always drive the timeline on the main
  screen; inside dialogs they edit text instead. Close the dialog with `esc`.
* **`shift+left` / `shift+right` do nothing** - some terminals or multiplexers intercept them.
  In tmux: `set -g xterm-keys on`. In Windows Terminal, remove custom bindings for those keys.
  Packet stepping is also reachable by selecting rows in the packet list.
* **`home` / `end` do not scroll the inspector** - they are reserved for timeline jumps; use
  `pgup` / `pgdn` in the inspector.
* **`ctrl+s` does not save a note** - some terminals use it for flow control (XOFF). Run
  `stty -ixon` before starting, or disable flow control in the terminal settings.

## Investigation database

* **`investigation database is unusable`** - the SQLite file is corrupt or not a database. Move it
  aside (`mv investigations.db investigations.db.bak`) and restart; a new database is created.
* **`database was created by a newer TRACE//ZERO version`** - upgrade, or point `--db` at a
  different file.
* Bookmarks and notes are tied to the capture's SHA-256. If a capture is modified (even
  re-saved), it is a different piece of evidence and starts without bookmarks.

## Chain of custody

* **`CHAIN OF CUSTODY` warning when opening a capture** - this path was imported before with a
  different SHA-256: the file changed (re-saved, truncated, replaced). Treat the two versions as
  different evidence. Both hashes are in the journal and the report.
* **`V` reports `MISMATCH`** - the file on disk differs from the bytes that were analysed.
  **`UNAVAILABLE`** - it was moved, deleted or is unreadable. `trace-zero -i NAME --verify` checks
  every capture of an investigation from the command line (exit code 3 on any problem).
* **Checking an export later** - `sha256sum -c report.json.sha256` (Linux/WSL) or
  `Get-FileHash report.json` (PowerShell) against the sidecar and the journal entry.

## Live mode

| Message | Meaning and fix |
| --- | --- |
| `no capture tool found` | Install Wireshark (`dumpcap`) or `tcpdump`, or set `[paths] capture_tool`. Following a file needs neither. |
| `dumpcap listed no capture interfaces ...` / `exited with code ...` | The tool may not capture: see SETUP.md, *Live capture permissions*. The tool's own messages are in `capture-tool.log` in the data directory. |
| `does not list interface 'X'` | Use a name from `trace-zero --list-interfaces`. |
| `file shrank ... following stopped` | The file was rotated, truncated or overwritten. Ring-buffer captures are not followed; capture into a single file. |
| `invalid PCAPNG block length ...` / `capture damaged` | The writer produced something that is not a valid capture. Following stops; packets read until then remain. |
| `LIVE waiting for packets` never changes | The writer buffers output. Use `tcpdump -U` (TRACE//ZERO does when it starts tcpdump), or check the capture filter. |
| Refreshes become slow | Each refresh re-analyses the whole capture; the interval grows with its size (about 10 s at 260k packets). Stop and restart into a new file for very long sessions. |

## Cache

* **Reopening is not faster** - the cache is keyed by content hash and limits; changing
  `[limits]` or upgrading TRACE//ZERO invalidates it. Hashing still reads the whole file.
* **Disk usage** - capped by `[limits] cache_max_mb` (least recently used entries go first);
  `trace-zero --clear-cache` empties it, `--no-cache` bypasses it for one run.
* A damaged cache entry fails its checksum and is silently re-parsed from the capture.

## Reference data

* **`reference data not loaded` at startup** (headless: `warning: reference data: ...`) - the OUI or MMDB file could not be read or is
  not the expected format. Re-download it; TRACE//ZERO runs without it.
* **No country/ASN for internal hosts** - by design: lookups only run for public and
  documentation-range addresses.

## Performance

* First import runs at roughly 17-30k packets/s (including detection and flows); progress is
  shown in the header and `esc` cancels. Reopening a cached capture is about 10x faster.
* Filtering large captures runs in the background (status `FILTERING`).
* Sorting the packet list by a non-time column re-sorts on every timeline change; return to time
  order (`s` until `sort:time`) while replaying very large windows.

## Logs

Unexpected errors are written to `trace-zero.log` in the data directory (see SETUP.md). The log
stays on the local machine; TRACE//ZERO never sends data anywhere.

## Still stuck?

Run the self-test: `python -m pytest -q`. Then try the synthetic sample
(`trace-zero --generate-sample s.pcap && trace-zero s.pcap`) to separate capture-specific
problems from environment problems.
