# Troubleshooting

## Import problems

| Message | Meaning and fix |
| --- | --- |
| `file is empty (0 bytes)` | The file has no content. Re-export the capture. |
| `not a PCAP or PCAPNG file (unrecognised header ...)` | Wrong file type (for example an ETL, snoop or text export). Convert it with `editcap -F pcapng in out.pcapng` from Wireshark. |
| `compressed (gzip) captures are not supported` | Decompress first: `gunzip capture.pcap.gz`. |
| `file is N MB; the configured limit is ...` | Raise `[limits] max_file_mb` in the config, or split the capture: `editcap -c 500000 big.pcap part.pcap`. |
| `path is not a regular file` | Devices, FIFOs and sockets are refused by design; save the capture to a file first. |
| `TRUNCATED - packet limit reached` | Import stopped at `[limits] max_packets`. Everything shown covers only the imported part. Raise the limit (about 0.7 KB of RAM per packet) or split the file. |
| `TRUNCATED - file ends mid-record` / `damaged capture` | The file was cut off or corrupted. All packets before the damage are available; the warning names the byte offset. |
| `capture file changed on disk since import` (raw bytes) | Raw bytes are re-read from disk, and the file's size or modification time no longer matches. Re-open the capture. |
| `packet(s) carry no timestamp (pcapng simple packet blocks)` | The capture uses SPBs, which have no timestamps. Those packets are ordered after the previous packet and flagged. |

Many frames shown in amber with `[...]` in the info column: those frames have decode issues
(truncated headers, invalid lengths, malformed DNS). Filter them with `error`.

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

## Performance

* Import runs at roughly 20-30k packets/s; progress is shown in the header and `esc` cancels.
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
