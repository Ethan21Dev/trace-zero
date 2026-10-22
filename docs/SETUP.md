# Setup guide

TRACE//ZERO needs Python 3.11 or newer and a terminal with 256-colour or true-colour support and
a Unicode monospace font. It reads capture files, so no packet-capture driver, root or
administrator rights are required. Only optional live capture on an interface needs a capture
tool with capture permission (see *Live capture permissions* below).

Recommended terminal size: **160 x 45** or larger for the three-panel workspace. Between
60 x 16 and 130 columns the interface switches to one panel at a time with tabs.

## Standalone executable or PyPI

Tagged releases provide single-file executables (Linux x86-64, Windows x86-64, macOS arm64)
with a `SHA256SUMS` file, and the `trace-zero` package on PyPI (`pipx install trace-zero`).
Neither needs a source checkout. The sections below install from source.

## Linux

```bash
# Debian / Ubuntu
sudo apt install -y python3 python3-venv git
# Fedora
sudo dnf install -y python3 git

git clone https://github.com/Ethan21Dev/trace-zero.git
cd trace-zero
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
trace-zero --version
```

Terminals known to work well: GNOME Terminal, Konsole, Alacritty, kitty, WezTerm, foot.
Inside tmux, enable true colour: `set -g default-terminal "tmux-256color"` and
`set -as terminal-features ",*:RGB"`.

## Debian on WSL (Windows Subsystem for Linux)

1. In an elevated PowerShell: `wsl --install -d Debian`, then reboot if asked and create the user.
2. Open **Windows Terminal** and choose the *Debian* profile.
3. Inside Debian:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
git clone https://github.com/Ethan21Dev/trace-zero.git
cd trace-zero
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
trace-zero --generate-sample ~/sample.pcapng --format pcapng
trace-zero ~/sample.pcapng
```

Captures stored on the Windows side are under `/mnt/c/...`. Reading from `/mnt/c` is slower
than the Linux file system; copy large captures into the WSL home directory for faster import.
Debian 12 ships Python 3.11, which is supported.

## Windows (native)

1. Install Python 3.11+ from python.org (tick *Add python.exe to PATH*) or `winget install Python.Python.3.12`.
2. Install **Windows Terminal** (`winget install Microsoft.WindowsTerminal`) and use it instead of
   the legacy console host, which has limited colour and Unicode support.
3. In PowerShell inside Windows Terminal:

```powershell
git clone https://github.com/Ethan21Dev/trace-zero.git
cd trace-zero
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1      # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -e ".[dev]"
trace-zero --generate-sample sample.pcapng --format pcapng
trace-zero sample.pcapng
```

Npcap/WinPcap is **not** required for analysing files. If scapy prints a notice about a missing
libpcap provider during installation or import, it can be ignored: scapy is only used to read files.
Live capture on an interface needs Wireshark with Npcap (see *Live capture permissions*).

### Windows Terminal settings

* Font: *Cascadia Mono* (default) or any Nerd/monospace font with box-drawing glyphs.
* Settings -> Profiles -> Defaults -> Appearance: keep *Retro terminal effects* off.
* Settings -> Rendering: the default GPU renderer is fine.
* `shift+left` / `shift+right` are not bound by Windows Terminal by default; if you have custom
  bindings for them, remove them so TRACE//ZERO receives the keys.

## File locations

| Item | Linux / WSL | Windows |
| --- | --- | --- |
| Investigation database | `~/.local/share/trace-zero/investigations.db` | `%LOCALAPPDATA%\trace-zero\investigations.db` |
| Error log (local only) | `~/.local/share/trace-zero/trace-zero.log` | `%LOCALAPPDATA%\trace-zero\trace-zero.log` |
| Configuration | `~/.config/trace-zero/config.toml` | `%APPDATA%\trace-zero\config.toml` |
| Default export folder | `~/trace-zero-exports` | `%USERPROFILE%\trace-zero-exports` |
| Parsed-capture cache | `~/.local/share/trace-zero/cache/` | `%LOCALAPPDATA%\trace-zero\cache\` |
| MAC vendor list (optional) | `~/.local/share/trace-zero/oui.csv` | `%LOCALAPPDATA%\trace-zero\oui.csv` |

`TRACE_ZERO_HOME` overrides the data directory; `--db` and `--config` override individual files.

## Verifying an installation

```bash
python -m pytest -q
trace-zero --generate-sample /tmp/s.pcap && trace-zero /tmp/s.pcap --headless
```

The headless run should report 3,324 packets, 18 hosts and 12 possible anomalies.

## Live capture permissions

TRACE//ZERO itself never needs elevated rights. Live capture on an interface (`F`, `--capture`)
runs Wireshark's `dumpcap` or `tcpdump`, and **that tool** needs permission to capture:

* **Debian / Ubuntu**: `sudo apt install wireshark-common` (or `tshark`), answer *Yes* to letting
  non-superusers capture (or `sudo dpkg-reconfigure wireshark-common`), then
  `sudo usermod -aG wireshark $USER` and log in again. `dumpcap -D` should then list interfaces.
* **Fedora**: `sudo dnf install wireshark-cli`, then `sudo usermod -aG wireshark $USER`.
* **Windows**: install Wireshark with **Npcap**. `dumpcap.exe` is found in
  `C:\Program Files\Wireshark` automatically; `[paths] capture_tool` overrides the location.
* **WSL**: capture inside WSL sees only WSL's own virtual network. To analyse the Windows host's
  traffic, record it on Windows (Wireshark/dumpcap) into a file and follow that file from WSL
  under `/mnt/c/...` - or run TRACE//ZERO natively on Windows.
* **macOS**: Wireshark's *Install ChmodBPF* package grants capture access to your user.

Following a file (`--follow`) needs only read access to it. If you prefer not to grant capture
rights at all, start the capture tool however your organisation allows and follow its output.

## Optional reference data

* **MAC vendors.** `python scripts/fetch_oui.py` downloads the IEEE registry once into the data
  directory (the only network access in the project, and only when you run it). A Wireshark
  `manuf` file also works. Point TRACE//ZERO at it with `--oui` or `[paths] oui`.
* **GeoIP / ASN.** Download GeoLite2 City/Country/ASN `.mmdb` files from MaxMind (free account)
  and pass them with `--geoip` (repeatable) or `[paths] geoip`.

Problems loading either file are reported at startup and never stop the application.
