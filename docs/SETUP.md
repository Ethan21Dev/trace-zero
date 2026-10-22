# Setup guide

TRACE//ZERO needs Python 3.11 or newer and a terminal with 256-colour or true-colour support and
a Unicode monospace font. It reads capture files only, so no packet-capture driver, root or
administrator rights are required.

Recommended terminal size: **160 x 45** or larger for the three-panel workspace. Between
60 x 16 and 130 columns the interface switches to one panel at a time with tabs.

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

Npcap/WinPcap is **not** required. If scapy prints a notice about a missing libpcap provider
during installation or import, it can be ignored: only offline file reading is used.

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

`TRACE_ZERO_HOME` overrides the data directory; `--db` and `--config` override individual files.

## Verifying an installation

```bash
python -m pytest -q
trace-zero --generate-sample /tmp/s.pcap && trace-zero /tmp/s.pcap --headless
```

The headless run should report 2,608 packets, 14 hosts and six possible anomalies.
