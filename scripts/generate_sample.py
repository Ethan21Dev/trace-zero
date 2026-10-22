#!/usr/bin/env python3
"""Write the synthetic TRACE//ZERO sample capture.

Safe by construction: packets are built in memory and written to a file.
Nothing is transmitted. Addresses are RFC 1918 / RFC 5737 / RFC 3849
documentation ranges and names are RFC 2606 reserved names.

    python scripts/generate_sample.py samples/trace-zero-sample.pcapng --format pcapng
    python scripts/generate_sample.py big.pcap --scale 20      # more baseline traffic
    python scripts/generate_sample.py truncated.pcap --truncate 300   # damaged copy for testing
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_zero.samples import generate_sample  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("output", type=Path)
    p.add_argument("--format", choices=("pcap", "pcapng"), default=None, help="default: from the file extension")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--scale", type=int, default=1, help="repeat baseline traffic N times")
    p.add_argument("--truncate", type=int, metavar="BYTES", help="also chop BYTES off the end to simulate a damaged capture")
    args = p.parse_args()
    fmt = args.format or ("pcapng" if args.output.suffix.lower() == ".pcapng" else "pcap")
    n = generate_sample(args.output, fmt=fmt, seed=args.seed, scale=max(1, args.scale))
    if args.truncate:
        data = args.output.read_bytes()
        args.output.write_bytes(data[: max(0, len(data) - args.truncate)])
        print(f"wrote {n} packets to {args.output}, then removed the last {args.truncate} bytes")
    else:
        print(f"wrote {n} packets to {args.output} ({fmt})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
