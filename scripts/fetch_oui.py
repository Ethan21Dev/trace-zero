#!/usr/bin/env python3
"""Download the IEEE MAC vendor registry (oui.csv) for offline use.

This is the only TRACE//ZERO component that contacts the network, and it only
runs when you invoke it. It downloads the public IEEE MA-L registry and stores
it locally; TRACE//ZERO then reads the file offline (``--oui`` or
``[paths] oui`` in the config).

    python scripts/fetch_oui.py                 # -> <data dir>/oui.csv
    python scripts/fetch_oui.py -o ~/oui.csv

GeoIP / ASN databases are not fetched: MaxMind requires a free account and
licence key. Download GeoLite2-City / -Country / -ASN (.mmdb) from MaxMind
yourself and pass them with ``--geoip``.
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_zero.config import default_data_dir  # noqa: E402
from trace_zero.enrich import EnrichmentError, OuiTable  # noqa: E402

URL = "https://standards-oui.ieee.org/oui/oui.csv"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-o", "--output", type=Path, default=default_data_dir() / "oui.csv")
    args = p.parse_args()
    print(f"downloading {URL}")
    req = urllib.request.Request(URL, headers={"User-Agent": "trace-zero-fetch-oui"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URL
        data = resp.read(64 * 1024 * 1024)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_suffix(".tmp")
    tmp.write_bytes(data)
    try:
        table = OuiTable(tmp)
    except EnrichmentError as exc:
        tmp.unlink()
        print(f"error: downloaded file is not a usable registry: {exc}", file=sys.stderr)
        return 1
    tmp.replace(args.output)
    count = sum(len(v) for v in table.prefixes.values())
    print(f"wrote {args.output} ({count:,} prefixes). Use: trace-zero --oui {args.output} capture.pcapng")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
