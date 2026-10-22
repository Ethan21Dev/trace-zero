"""Keyboard reference. Shared by the help screen and docs/KEYBINDINGS.md."""

from __future__ import annotations

KEYMAP: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "GLOBAL",
        [
            ("?", "help (this screen)"),
            ("q", "back to previous view; quit at the top level"),
            ("ctrl+q", "quit immediately"),
            ("o", "open a PCAP / PCAPNG capture"),
            ("O", "add another capture to the timeline (multi-sensor)"),
            ("/", "search and filter packets (up/down history, ctrl+s save, tab saved filters)"),
            ("ctrl+p", "command palette: every action, saved and recent filters"),
            ("esc", "close dialog / cancel import / clear selection, then filter"),
            ("tab / shift+tab", "move focus between panels"),
        ],
    ),
    (
        "VIEWS",
        [
            ("h", "host explorer"),
            ("n", "network map (topology of the time window)"),
            ("c", "flows / connections; enter follows the reassembled stream"),
            ("p", "packet explorer"),
            ("f", "findings (possible anomalies)"),
            ("d", "window diff (see TIME MACHINE)"),
            ("b", "bookmarks, notes and activity journal"),
            ("t", "timeline"),
            ("i", "inspector for the selected item"),
        ],
    ),
    (
        "LISTS",
        [
            ("up / down", "move through rows"),
            ("pgup / pgdn", "page"),
            ("ctrl+home / ctrl+end", "first / last row"),
            ("enter", "open selected item"),
            ("s / S", "cycle sort column / reverse sort"),
        ],
    ),
    (
        "TIME MACHINE",
        [
            ("space", "play / pause replay"),
            ("left / right", "step the cursor: one window (SLIDING) or 1/50 of the capture"),
            ("shift+left / right", "previous / next packet, in chronological order"),
            ("< / >", "previous / next significant event (new host, new link, finding)"),
            ("home / end", "jump to beginning / end"),
            ("+ / -", "replay speed up / down"),
            ("w", "toggle CUMULATIVE / SLIDING window"),
            ("[ / ]", "narrow / widen the sliding window"),
            ("d", "window diff: current window becomes baseline A; B follows the cursor"),
            ("D", "clear the diff baseline"),
            ("k", "add a named mark at the cursor"),
            ("{ / }", "previous / next timeline mark"),
        ],
    ),
    (
        "INVESTIGATION",
        [
            ("m", "bookmark the selected host, packet, finding or conversation"),
            ("a", "add an analyst note to the selection (or to the investigation)"),
            ("x", "show / hide raw bytes and full scapy dissection of a packet"),
            ("T", "triage the selected finding: open / benign / escalated, with reason"),
            ("z / Z", "suppress findings like the selected one (reason required) / show suppressed"),
            ("delete", "delete the selected bookmark, note, mark or suppression (journal view)"),
            ("e", "export JSON summary + HTML report (each export gets a .sha256 sidecar)"),
            ("X", "export the packets shown (filter + window) to PCAPNG; Wireshark filter copied"),
            ("V", "verify evidence: re-hash the capture file(s) against the SHA-256 recorded at import"),
            ("r", "rename investigation"),
            ("ctrl+n", "new investigation"),
            ("l", "list / switch investigations"),
        ],
    ),
]

FILTER_HELP = [
    ("host:10.0.0.5", "source or destination (CIDR ok: host:10.0.0.0/24)"),
    ("src:  dst:", "directional address"),
    ("port:443  sport:  dport:", "port or range (port:1000-2000)"),
    ("proto:tcp|dns", "tcp udp icmp icmpv6 arp ipv4 ipv6 dns mdns llmnr http tls"),
    ("flags:S", "TCP flags present (S A F R P U E C)"),
    ("len>1000", "wire length (> < >= <= =)"),
    ("t>12.5  t<30", "seconds since first packet"),
    ("dns:example", "DNS question contains text"),
    ("mac:02:00:00:00:00:01", "Ethernet address"),
    ("no:100-200", "frame numbers"),
    ("error", "frames with decode issues"),
    ("!term", "negate a term; terms are ANDed"),
    ("word", "bare words search summary, addresses, protocol"),
]
