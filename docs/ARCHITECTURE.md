# Architecture

TRACE//ZERO is split into layers that only depend downwards. Everything below `ui/`
is plain Python with no terminal dependency, which is what lets the headless CLI and
most of the test suite run the exact same analysis code as the TUI.

```
cli.py ─────────────┐
ui/  (Textual)      │   presentation: screens, widgets, rendering helpers
  │                 │
session.py ◄────────┘   application state: capture, filter, view, timeline, selection
  │
  ├── analysis/          index, filters, timeline state machine, anomaly heuristics
  ├── storage/           SQLite: investigations, captures, bookmarks, notes, journal
  ├── export/            report model, JSON writer, HTML renderer
  └── parsing/           file validation, scapy framing, bounds-checked decoder
        │
models.py, sanitize.py, config.py   shared data types, untrusted-text handling, limits
```

## Source map

| Module | Responsibility |
| --- | --- |
| `parsing/reader.py` | Path validation (regular file, size limit, magic bytes), SHA-256, streaming import through scapy's `RawPcapReader` / `RawPcapNgReader`, progress + cancellation callbacks, damage detection, on-demand re-read of one frame. |
| `parsing/decoder.py` | Bounds-checked `struct` decoder for link, network and transport layers; scapy `DNS` for DNS payloads; strict HTTP and TLS-SNI extraction. Produces `PacketRecord`. |
| `parsing/scapy_bridge.py` | The only place scapy is imported; silences scapy's stderr logging (which would corrupt the TUI) and collects its warnings into the import report. |
| `models.py` | `PacketRecord` (slots dataclass), `DnsInfo`, `ParseResult`, formatting helpers. |
| `analysis/index.py` | `CaptureIndex` (time order, per-host metadata, first-observation events) and `CaptureView` (a filter applied to the index, with block aggregates). |
| `analysis/filters.py` | Filter language compiler -> predicate. |
| `analysis/timeline.py` | Pure timeline state machine: cursor, window mode/width, speed, replay. |
| `analysis/anomaly.py` | Five heuristics producing `Finding` objects. |
| `session.py` | `Session` (state shared by TUI and CLI) and `load_capture` (import + index + detect, worker-safe). |
| `storage/db.py` | SQLite schema and access. |
| `export/` | `build_report` (one model, three provenance sections), JSON + HTML writers, atomic writes. |
| `ui/app.py`, `ui/screens/main.py` | Application shell and the workspace screen: layout, bindings, refresh pipeline, workers. |
| `ui/widgets/table.py` | `VirtualTable`: Line-API table rendering only visible rows. |
| `ui/mapgeo.py` | Pure map renderer (layout, Bresenham edges, arrows, label placement). |
| `ui/inspect.py` | Inspector content for capture, host, packet, conversation, finding. |
| `ui/keymap.py` | Single source of truth for the help screen and `docs/KEYBINDINGS.md`. |

## Data flow

1. **Validate** - `validate_capture_path` resolves the path, refuses directories, devices,
   pipes and oversized files, and sniffs magic bytes (gzip is named explicitly).
2. **Import (worker thread)** - hash the file, then frame it with scapy's raw readers through
   `_GuardedFile`, a proxy that caps every single read at 64 MiB and records partial reads.
   This protects against hostile PCAPNG block lengths and detects files that end mid-record.
3. **Decode** - each frame becomes a `PacketRecord`. Scapy's full dissection runs at roughly
   6.5k packets/s; the custom decoder plus scapy DNS runs at ~21-30k packets/s, so bulk import
   uses the decoder and full scapy dissection is reserved for the single packet being inspected.
4. **Index** - `CaptureIndex` sorts by timestamp (stable, so file order breaks ties), builds
   per-host metadata and the list of first observations (new host, new link).
5. **Detect** - heuristics run once per import on the whole capture.
6. **Present** - the UI receives the finished `LoadedCapture` via `call_from_thread`.

## The time machine

`CaptureView` holds the filtered packet positions in time order plus parallel timestamp
array. Packets are grouped into blocks of 1,024 positions, and each block stores
pre-aggregated host and edge statistics. A window query:

1. finds `[i0, i1)` with two binary searches,
2. merges whole blocks inside the range,
3. scans only the partial blocks at both ends,
4. caches the result by `(i0, i1)` (LRU).

Cost is `O(log n + blocks + 2 x 1024)` instead of `O(window size)`. At 260k packets a
cumulative window takes ~4 ms and a sliding one ~0.5 ms.

The `Timeline` has no clock. During replay the UI timer feeds it wall-clock deltas; the
displayed state depends only on `(filter, cursor, mode, width)`, so the same position always
renders the same map, tables and inspector content.

Historical vs live: every visible statistic is "observed in window". Map links carry their
time since last packet relative to the cursor, and the map caption states that it shows
historical observations, not live state.

## Heuristics

See [HEURISTICS.md](HEURISTICS.md). Design rules: one transparent statistic per rule,
thresholds in configuration, supporting frames always attached, confidence phrased in terms
of what the capture can and cannot show, findings labelled as possible anomalies.

## Persistence

SQLite with WAL journaling. Tables: `investigations`, `captures` (path + SHA-256 + counts,
never contents), `bookmarks`, `notes`, `events` (activity journal), `meta` (schema version).
Bookmarks and notes are keyed by capture SHA-256, so they reattach when the same evidence is
reopened from a different path. All SQL is parameterised.

## Security model

* Inputs (capture files and everything inside them) are untrusted.
* Every string derived from packet bytes passes `sanitize.clean`, which escapes C0/C1 control
  characters and bidi overrides so terminal escape sequences in, for example, a DNS name are
  displayed inertly.
* Markup is never interpreted for dynamic text. Capture-derived values, file names, filter
  expressions and investigation names are rendered as `rich.text.Text` objects or with
  `markup=False` (notifications, dialog messages, border titles). Otherwise Textual markup would
  rewrite them (`capture[bold]x` displays as `capturex`), raise on `[/x]`, or turn
  `[@click=...]` into an application action. Regression tests cover all three cases.
* The HTML report escapes every value and ships a CSP of `default-src 'none'`.
* Packet payloads are never executed, evaluated or passed to a shell.
* No network code exists in the application; the test suite enforces this for scapy calls.
* Exports are written atomically and refuse to overwrite the capture file.
* Unexpected exceptions in workers are logged to a local file (`trace-zero.log` in the data
  directory) and reported in the UI; a bad frame or a failed render never terminates the app.

## Responsive layout

* `>= 130` columns: three panels (hosts, centre, inspector) plus timeline.
* `< 130` columns: one panel at a time with a tab strip (`h`, `n`, `p`, `f`, `b`, `i`).
* Timeline height adapts to terminal height (8, 6 or 4 rows).
* `< 60x16`: a guard screen replaces the workspace instead of overlapping panels.
