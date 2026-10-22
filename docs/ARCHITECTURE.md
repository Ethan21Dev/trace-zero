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
  ├── analysis/          index, filters, timeline, heuristics, flows, streams, diff, Wireshark filters
  ├── storage/           SQLite: investigations, captures, triage, marks, notes, filters, journal
  ├── export/            report model, JSON writer, HTML renderer
  ├── cache.py           SHA-256-keyed on-disk cache of parsed captures, indexes and findings
  ├── enrich.py          offline reference data: OUI vendors, MaxMind DB reader
  ├── custody.py         evidence re-verification, export digests
  └── parsing/           file validation, scapy framing, bounds-checked decoder, TLS, PCAPNG writer
        │
models.py, sanitize.py, config.py   shared data types, untrusted-text handling, limits
```

## Source map

| Module | Responsibility |
| --- | --- |
| `parsing/reader.py` | Path validation (regular file, size limit, magic bytes), SHA-256, streaming import through scapy's `RawPcapReader` / `RawPcapNgReader`, progress + cancellation callbacks, damage detection, on-demand re-read of one frame. |
| `parsing/decoder.py` | Bounds-checked `struct` decoder for link, network and transport layers, DHCP and the packet quoted inside ICMP errors; scapy `DNS` for DNS payloads; strict HTTP extraction. Produces `PacketRecord`. |
| `parsing/tls.py` | TLS record/handshake parser: ClientHello (SNI, ALPN, versions, JA3, JA4), ServerHello (JA3S), certificate chain via a minimal bounds-checked DER reader. |
| `parsing/writer.py` | PCAPNG writer: copies selected frames byte-for-byte from one or more source captures, nanosecond timestamps, provenance comment, atomic write. |
| `parsing/scapy_bridge.py` | The only place scapy is imported; silences scapy's stderr logging (which would corrupt the TUI) and collects its warnings into the import report. |
| `models.py` | `PacketRecord` (slots dataclass), `DnsInfo`, `ParseResult`, formatting helpers. |
| `analysis/index.py` | `CaptureIndex` (time order, per-host metadata, first-observation events) and `CaptureView` (a filter applied to the index, with block aggregates). |
| `analysis/filters.py` | Filter language compiler -> predicate. |
| `analysis/timeline.py` | Pure timeline state machine: cursor, window mode/width, speed, replay. |
| `analysis/anomaly.py` | Ten heuristics producing `Finding` objects. |
| `analysis/flows.py` | Flow table: 5-tuple conversations, state, proven initiator, per-direction counters. |
| `analysis/streams.py` | TCP reassembly (mod 2^32 sequence arithmetic; gaps, retransmissions, conflicting overlaps) and HTTP / TLS / DNS-over-TCP decoding of the result. |
| `analysis/diff.py` | Window diff: new/gone hosts, links and services, and rate changes between two windows. |
| `analysis/wireshark.py` | Translates the filter language into a Wireshark display filter, with notes where semantics differ. |
| `session.py` | `Session` (state shared by TUI and CLI), `load_capture` / `load_captures` (validate, hash, cache or parse, index, detect, build flows; multi-capture merge; worker-safe). |
| `cache.py` | On-disk cache: `marshal`-encoded chunks with a SHA-256 checksum, keyed by format version, Python version, capture hash and limits; LRU size cap. Never pickle. |
| `enrich.py` | OUI table (IEEE CSV or Wireshark `manuf`), bounds-checked pure-Python MMDB reader, `Enrichment` facade. |
| `custody.py` | Re-hashing evidence, `.sha256` sidecars for exports. |
| `storage/db.py` | SQLite schema and access. |
| `export/` | `build_report` (one model, three provenance sections), JSON + HTML writers, atomic writes. |
| `ui/app.py`, `ui/screens/main.py` | Application shell and the workspace screen: layout, bindings, refresh pipeline, workers. |
| `ui/widgets/table.py` | `VirtualTable`: Line-API table rendering only visible rows. |
| `ui/mapgeo.py` | Pure map renderer (layout, Bresenham edges, arrows, label placement). |
| `ui/inspect.py` | Inspector content for capture, host, packet, flow, conversation, finding. |
| `ui/screens/stream.py` | Follow-stream screen. |
| `ui/commands.py` | Command palette provider built from the workspace bindings, saved and recent filters. |
| `ui/keymap.py` | Single source of truth for the help screen and `docs/KEYBINDINGS.md`. |

## Data flow

1. **Validate** - `validate_capture_path` resolves the path, refuses directories, devices,
   pipes and oversized files, and sniffs magic bytes (gzip is named explicitly).
2. **Cache** - hash the file; if the cache holds this SHA-256 (with the same limits and format
   version), restore packets, index, findings and flows and skip steps 3-5. A cache entry is
   only trusted when its own checksum verifies.
3. **Import (worker thread)** - frame the file with scapy's raw readers through
   `_GuardedFile`, a proxy that caps every single read at 64 MiB and records partial reads.
   This protects against hostile PCAPNG block lengths and detects files that end mid-record.
4. **Decode** - each frame becomes a `PacketRecord`. Scapy's full dissection runs at roughly
   6.5k packets/s; the custom decoder plus scapy DNS runs at ~21-30k packets/s, so bulk import
   uses the decoder and full scapy dissection is reserved for the single packet being inspected.
5. **Index** - `CaptureIndex` sorts by timestamp (stable, so file order breaks ties), builds
   per-host metadata and the list of first observations (new host, new link).
6. **Detect** - heuristics run once per import on the whole capture; flows are built.
7. **Present** - the UI receives the finished `LoadedCapture` via `call_from_thread`. Callbacks
   from an import that was cancelled or replaced in the meantime are ignored.

Several captures load file by file (each cached separately) and are merged before indexing:
frames are renumbered consecutively, each source keeps its `FileInfo` for raw re-reads and
exports, and the combined identity is a SHA-256 over the sorted source hashes.

## The time machine

`CaptureView` holds the filtered packet positions in time order plus parallel timestamp
array. Packets are grouped into blocks of 1,024 positions, and each block stores
pre-aggregated host and edge statistics. A window query:

1. finds `[i0, i1)` with two binary searches,
2. merges whole blocks inside the range,
3. scans only the partial blocks at both ends,
4. caches the result by `(i0, i1)` (LRU).

Cost is `O(log n + blocks + 2 x 1024)` instead of `O(window size)`. At 263k packets a
window query takes at most ~2.4 ms.

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

SQLite with WAL journaling, schema version 2 (version 1 databases are migrated in place).
Tables: `investigations`, `captures` (path + SHA-256 + counts, never contents), `bookmarks`,
`notes`, `marks`, `finding_status`, `suppressions`, `saved_filters`, `filter_history`, `events`
(activity journal), `meta`. Bookmarks, notes, marks and triage are keyed by capture SHA-256, so
they reattach when the same evidence is reopened from a different path. All SQL is
parameterised. The connection belongs to the UI thread: workers hash, parse and write files,
and hand results back to the main thread for journaling.

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
* Exports are written atomically, refuse to overwrite a source capture, and get `.sha256`
  sidecars. The PCAPNG writer re-checks size and modification time of every source first.
* The cache never deserialises code: `marshal` of plain tuples only, behind a checksum.
* Offline reference files (OUI, MMDB) are parsed with bounds checks and depth limits; lookups
  never leave the machine. The only network-capable code is `scripts/fetch_oui.py`, run by hand.
* The command palette's fuzzy highlighter parses markup, so palette entries are highlighted
  by TRACE//ZERO itself and help text is escaped; saved filter names are user data.
* Unexpected exceptions in workers are logged to a local file (`trace-zero.log` in the data
  directory) and reported in the UI; a bad frame or a failed render never terminates the app.

## Responsive layout

* `>= 130` columns: three panels (hosts, centre, inspector) plus timeline.
* `< 130` columns: one panel at a time with a tab strip (`h`, `n`, `p`, `f`, `b`, `i`).
* Timeline height adapts to terminal height (8, 6 or 4 rows).
* `< 60x16`: a guard screen replaces the workspace instead of overlapping panels.
