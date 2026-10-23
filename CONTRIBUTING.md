# Contributing to TRACE//ZERO

Thanks for helping. Bug reports, fixes, documentation and new decoders or heuristics are welcome.

## Privacy first

**Never attach or commit a capture of a real network.** Captures can contain names, addresses,
browsing history and credentials of people who never agreed to share them. Reproduce problems with
the synthetic sample (`trace-zero --generate-sample sample.pcapng --format pcapng`), with
`scripts/generate_sample.py`, or with a few packets built in a test (see `tests/conftest.py`).
`.gitignore` already excludes `*.pcap`, `*.pcapng` and investigation databases.

## Development setup

```bash
git clone https://github.com/Ethan21Dev/trace-zero.git
cd trace-zero
python -m venv .venv
. .venv/bin/activate            # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m pytest -q
```

Python 3.11, 3.12 and 3.13 on Linux and Windows are tested in CI.

## Before you open a pull request

- `python -m pytest -q` passes. Tests never touch the network: a fixture makes scapy send/ARP
  calls fail, and new tests must not need network access.
- New behaviour has a test; UI changes have a keyboard-driven test (see `tests/test_ui.py`).
- `python scripts/gen_keybindings.py --check` passes if you changed key bindings
  (run it without `--check` to regenerate `docs/KEYBINDINGS.md`).
- Screenshots in `docs/screenshots/` come from `python scripts/capture_screenshots.py`; regenerate
  them if you changed what they show.
- Text from captures is untrusted: render it with `rich.text.Text` or `markup=False`, and pass it
  through `sanitize.clean`.
- No new network access, telemetry or online lookups. Offline reference data only.
- No offensive features (scanning, exploitation, credential harvesting, interception).
- Keep the visual style: dark theme, cyan/green/amber/red accents, no emoji.

## Heuristics

A new rule needs: a single transparent statistic, thresholds in `config.py` and
`config.example.toml`, supporting frames, an explanation that lists benign causes, a confidence
statement, tests, and a section in `docs/HEURISTICS.md`.

## Releasing (maintainers)

1. Update `__version__` in `src/trace_zero/__init__.py` and add a section to `CHANGELOG.md`.
2. Push to `main` and wait for CI.
3. Tag and push: `git tag -a vX.Y.Z -m "TRACE//ZERO X.Y.Z" && git push origin vX.Y.Z`.
   The release workflow builds and tests the executables and publishes the release with the
   changelog section as its notes.
