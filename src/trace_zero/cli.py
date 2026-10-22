"""Command-line entry point.

    trace-zero [CAPTURE ...]                   interactive TUI
    trace-zero CAPTURE [CAPTURE ...] --headless [--json F] [--html F]
    trace-zero --generate-sample FILE [--format pcapng]
    trace-zero --follow FILE | --capture IFACE [--capture-filter BPF]   live mode
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import sys
from pathlib import Path

from trace_zero import PRODUCT, TAGLINE, __version__
from trace_zero.config import Config, ConfigError, default_data_dir, load_config


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trace-zero",
        description=f"{PRODUCT} - keyboard-driven network forensics for PCAP/PCAPNG captures. {TAGLINE}",
    )
    p.add_argument("capture", nargs="*", help="capture file(s) to open (.pcap / .pcapng); several are merged onto one timeline")
    p.add_argument("-i", "--investigation", help="investigation name to open or create")
    p.add_argument("--db", type=Path, help="investigation database path (overrides config)")
    p.add_argument("--config", type=Path, help="TOML configuration file")
    p.add_argument("--headless", action="store_true", help="analyse without the TUI and print a summary")
    p.add_argument("--json", type=Path, help="headless: write the JSON summary here")
    p.add_argument("--html", type=Path, help="headless: write the HTML report here")
    p.add_argument("--filter", metavar="EXPR", help="headless: filter expression (same syntax as / in the TUI)")
    p.add_argument("--pcap", type=Path, metavar="OUT", help="headless: export the (filtered) packets to PCAPNG")
    p.add_argument("--oui", type=Path, metavar="FILE", help="IEEE oui.csv or Wireshark manuf file for MAC vendor names")
    p.add_argument("--geoip", type=Path, action="append", default=[], metavar="FILE", help="MaxMind .mmdb database (repeatable: City/Country/ASN)")
    p.add_argument("--verify", action="store_true", help="re-hash every capture recorded in the investigation (-i) and exit 0 if all match, 3 if not")
    live = p.add_argument_group("live mode (the capture tool needs capture permission; TRACE//ZERO never does)")
    live.add_argument("--follow", type=Path, metavar="FILE", help="follow a capture file while another program writes it")
    live.add_argument("--capture", dest="capture_iface", metavar="IFACE", help="capture on IFACE with dumpcap/tcpdump (passive, not promiscuous) and follow it")
    live.add_argument("--capture-filter", default="", metavar="BPF", help="capture filter for --capture")
    live.add_argument("--capture-out", type=Path, metavar="FILE", help="file for --capture (default: a new file in the export folder)")
    live.add_argument("--list-interfaces", action="store_true", help="list interfaces the capture tool can use and exit")
    p.add_argument("--no-cache", action="store_true", help="parse from scratch; do not read or write the capture cache")
    p.add_argument("--clear-cache", action="store_true", help="delete all cached parsed captures and exit")
    p.add_argument("--generate-sample", type=Path, metavar="FILE", help="write the synthetic sample capture and exit")
    p.add_argument("--format", choices=("pcap", "pcapng"), default="pcap", help="format for --generate-sample")
    p.add_argument("--version", action="version", version=f"{PRODUCT} {__version__}")
    return p


def _setup_logging() -> None:
    """Errors go to a local log file only; nothing is ever sent anywhere."""
    try:
        directory = default_data_dir()
        directory.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.FileHandler(directory / "trace-zero.log", encoding="utf-8")
    except OSError:
        handler = logging.NullHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger = logging.getLogger("trace_zero")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def _headless(args: argparse.Namespace, cfg: Config) -> int:
    from trace_zero import custody
    from trace_zero.export import build_report, write_html, write_json
    from trace_zero.parsing import CaptureError
    from trace_zero.session import Session, load_captures
    from trace_zero.storage import StorageError, Store

    if not args.capture:
        print("error: --headless needs a capture file", file=sys.stderr)
        return 2
    try:
        store = Store(cfg.db_path)
        inv = store.open_or_create(args.investigation)
        loaded = load_captures(args.capture, cfg, use_cache=not args.no_cache)
    except (CaptureError, StorageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    session = Session(cfg, store, inv)
    for problem in session.enrichment_problems:
        print(f"warning: reference data: {problem}", file=sys.stderr)
    session.attach(loaded)
    if args.filter:
        from trace_zero.analysis.filters import FilterError

        try:
            flt = session.compile(args.filter)
        except FilterError as exc:
            print(f"error: invalid filter: {exc}", file=sys.stderr)
            return 2
        session.apply_view(flt, session.build_view(flt))
    r, idx = loaded.result, loaded.index
    print(f"{PRODUCT}  {TAGLINE}")
    print(f"investigation  {inv.name}")
    print(f"capture        {r.file.name}  ({r.file.fmt}, {r.file.size:,} bytes)")
    print(f"sha256         {r.file.sha256}" + ("  (combined)" if r.sources else ""))
    if r.sources:
        for info, offset, count in r.sources:
            print(f"  source       {info.name}  frames {offset + 1:,}-{offset + count:,}  sha256 {info.sha256}")
    print(f"packets        {len(r.packets):,}   hosts {len(idx.hosts):,}   load {r.elapsed_s:.2f}s" + ("  (from cache)" if r.cached else ""))
    if r.truncated:
        print(f"TRUNCATED      {r.stop_reason}")
    for w in r.warnings[:10]:
        print(f"warning        {w}")
    print(f"protocols      {', '.join(f'{k} {v}' for k, v in idx.proto_counts.most_common(8))}")
    print(f"possible anomalies (heuristic, not proof): {len(loaded.findings)}")
    for f in loaded.findings:
        print(f"  {f.severity:<6} {f.rule}  {f.title}  [confidence {f.confidence}, {f.frame_count} frames]")
    if args.filter:
        expr, notes = session.wireshark_filter()
        print(f"filter         {args.filter}  ->  {len(session.view):,} packets")
        print(f"wireshark      {expr}")
        for note in notes:
            print(f"               note: {note}")
    try:
        if args.pcap:
            count, _expr, _notes = session.export_packets(args.pcap)
            print(f"pcapng         {args.pcap}  ({count:,} packets)  sha256 {custody.read_digest(args.pcap)}")
        if args.json or args.html:
            report = build_report(session)
            if args.json:
                write_json(report, args.json)
                print(f"json           {args.json}  sha256 {session.record_export(args.json, 'JSON summary')}")
            if args.html:
                write_html(report, args.html)
                print(f"html           {args.html}  sha256 {session.record_export(args.html, 'HTML report')}")
    except (OSError, CaptureError) as exc:
        print(f"error: cannot write export: {exc}", file=sys.stderr)
        return 1
    store.close()
    return 0


def _verify(args: argparse.Namespace, cfg: Config) -> int:
    """Chain of custody: compare evidence files with the hashes recorded at import."""
    from trace_zero import custody
    from trace_zero.storage import StorageError, Store

    try:
        store = Store(cfg.db_path)
        inv = store.find_investigation(args.investigation) if args.investigation else (store.list_investigations() or [None])[0]
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if inv is None:
        print("error: no such investigation", file=sys.stderr)
        return 1
    evidence = [(c["filename"], c["path"], c["sha256"]) for c in store.captures(inv.id)]
    if not evidence:
        print(f"investigation '{inv.name}' has no recorded captures")
        return 0
    results = custody.verify(evidence)
    print(f"investigation  {inv.name}")
    for v in results:
        print(f"{v.verdict:<12} {v.path}")
        print(f"             recorded {v.expected}")
        if v.actual and not v.ok:
            print(f"             now      {v.actual}")
        if v.error:
            print(f"             {v.error}")
        store.log(inv.id, "verify", v.describe())
    store.close()
    bad = sum(not v.ok for v in results)
    print(f"{len(results) - bad} of {len(results)} evidence file(s) match")
    return 3 if bad else 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.generate_sample:
        from trace_zero.samples import generate_sample

        n = generate_sample(args.generate_sample, fmt=args.format)
        print(f"wrote {n} synthetic packets to {args.generate_sample}")
        return 0
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.db:
        cfg = dataclasses.replace(cfg, db_path=args.db)
    if args.oui or args.geoip:
        cfg = dataclasses.replace(cfg, oui_path=args.oui or cfg.oui_path, mmdb_paths=tuple(args.geoip) or cfg.mmdb_paths)
    if args.no_cache:
        cfg = dataclasses.replace(cfg, limits=dataclasses.replace(cfg.limits, cache_max_mb=0))
    if args.clear_cache:
        from trace_zero.cache import CaptureCache

        n = CaptureCache(cfg.cache_dir, 1).clear()
        print(f"removed {n} cache file(s) from {cfg.cache_dir}")
        return 0
    _setup_logging()
    if args.list_interfaces:
        return _list_interfaces(cfg)
    if args.verify:
        return _verify(args, cfg)
    if args.headless:
        return _headless(args, cfg)
    for capture in args.capture:
        if not Path(capture).expanduser().exists():
            print(f"error: capture not found: {capture}", file=sys.stderr)
            return 1
    if sum(bool(x) for x in (args.capture, args.follow, args.capture_iface)) > 1:
        print("error: use one of: capture file(s), --follow FILE, --capture IFACE", file=sys.stderr)
        return 2
    if args.follow and not args.follow.expanduser().is_file():
        print(f"error: file to follow not found: {args.follow}", file=sys.stderr)
        return 1

    from trace_zero.session import Session
    from trace_zero.storage import StorageError, Store
    from trace_zero.ui.app import TraceZeroApp

    try:
        store = Store(cfg.db_path)
        inv = store.open_or_create(args.investigation)
    except StorageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    live = None
    if args.follow:
        live = (str(args.follow.expanduser()), None)
    elif args.capture_iface:
        try:
            proc = _start_capture(args, cfg)
        except _CliError as exc:
            print(f"error: {exc}", file=sys.stderr)
            store.close()
            return 1
        live = (str(proc.out_path), proc)
    session = Session(cfg, store, inv)
    app = TraceZeroApp(session, args.capture or None, live)
    try:
        app.run()
    finally:
        if session.live is not None:
            session.live.stop_tool()  # never leave a capture tool running
        elif live is not None and live[1] is not None:
            live[1].stop()
        store.close()
    return 0


class _CliError(Exception):
    pass


def _list_interfaces(cfg: Config) -> int:
    from trace_zero.live import CaptureToolError, find_tool, list_interfaces

    try:
        tool = find_tool(cfg.capture_tool)
        if tool is None:
            print("error: no capture tool found; install Wireshark (dumpcap) or tcpdump", file=sys.stderr)
            return 1
        interfaces = list_interfaces(tool)
    except CaptureToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"capture tool   {tool.kind}  ({tool.path})")
    for i in interfaces:
        print(f"  {i.name:<24} {i.description}")
    return 0


def _start_capture(args: argparse.Namespace, cfg: Config):
    import time

    from trace_zero.config import default_data_dir
    from trace_zero.export.report import slug
    from trace_zero.live import CaptureProcess, CaptureToolError, find_tool, list_interfaces

    try:
        tool = find_tool(cfg.capture_tool)
        if tool is None:
            raise _CliError("no capture tool found; install Wireshark (dumpcap) or tcpdump")
        names = [i.name for i in list_interfaces(tool)]
        if args.capture_iface not in names:
            raise _CliError(f"{tool.kind} does not list interface '{args.capture_iface}' (available: {', '.join(names)})")
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        ext = "pcapng" if tool.kind == "dumpcap" else "pcap"
        out = (args.capture_out or Path(cfg.export_dir) / f"live-{slug(args.capture_iface)}-{stamp}.{ext}").expanduser()
        proc = CaptureProcess(
            tool, args.capture_iface, out, default_data_dir() / "capture-tool.log", args.capture_filter, cfg.limits.max_packets, cfg.limits.max_file_mb
        )
        proc.start()
    except CaptureToolError as exc:
        raise _CliError(str(exc)) from exc
    print(f"capturing on {args.capture_iface} with {tool.kind} into {out}")
    return proc


if __name__ == "__main__":
    raise SystemExit(main())
