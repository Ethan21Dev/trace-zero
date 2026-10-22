"""PyInstaller entry point for the standalone trace-zero binary."""

from trace_zero.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
