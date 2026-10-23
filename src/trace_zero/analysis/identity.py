"""Plain-language answers to "what is this address?".

Everything comes from the capture itself and from fixed knowledge about
address ranges and well-known ports; nothing is looked up online.

* Role: this computer (only when TRACE//ZERO recorded the capture here and
  knows the address), the router (the hardware address all internet traffic is
  sent to), a device on the local network, an internet server, or one of the
  special discovery/broadcast addresses, with what those are for.
* Names: announced by the device (DHCP), found in a DNS answer, or used when a
  TLS connection was opened to it - each labelled with how it is known.
* Services: TCP ports it accepted connections on and UDP services it answered.
"""

from __future__ import annotations

import ipaddress
import weakref
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from trace_zero.analysis.index import CaptureIndex, classify_ip

# Special addresses everyone on a local network sees. (address, short label, explanation)
WELL_KNOWN: dict[str, tuple[str, str]] = {
    "255.255.255.255": ("BROADCAST", "a message to every device on the local network - for example a device asking for an address (DHCP)"),
    "0.0.0.0": ("NO ADDRESS YET", "used by a device that has not been given an address yet, typically while asking for one (DHCP)"),
    "224.0.0.251": ("DEVICE DISCOVERY (mDNS)", "Bonjour / mDNS: devices announcing themselves and their names - phones, printers, TVs, Apple devices"),
    "ff02::fb": ("DEVICE DISCOVERY (mDNS)", "Bonjour / mDNS over IPv6: devices announcing themselves and their names"),
    "239.255.255.250": ("DEVICE DISCOVERY (SSDP)", "SSDP / UPnP: discovery of smart TVs, Chromecast, game consoles, media servers and routers"),
    "ff02::c": ("DEVICE DISCOVERY (SSDP)", "SSDP / UPnP over IPv6: discovery of smart TVs, media devices and routers"),
    "224.0.0.252": ("NAME LOOKUP (LLMNR)", "LLMNR: Windows asking the local network for a computer name"),
    "ff02::1:3": ("NAME LOOKUP (LLMNR)", "LLMNR over IPv6: Windows asking the local network for a computer name"),
    "224.0.0.22": ("MULTICAST MEMBERSHIP (IGMP)", "devices telling the router which multicast groups they want to receive"),
    "ff02::16": ("MULTICAST MEMBERSHIP (MLD)", "IPv6 devices telling the router which multicast groups they want to receive"),
    "224.0.0.1": ("ALL DEVICES", "every device on the local network"),
    "ff02::1": ("ALL DEVICES", "every IPv6 device on the local network"),
    "224.0.0.2": ("ALL ROUTERS", "every router on the local network"),
    "ff02::2": ("ALL ROUTERS", "every IPv6 router on the local network - devices asking how to reach the internet"),
    "ff02::1:2": ("ADDRESS REQUEST (DHCPv6)", "an IPv6 device asking for an address"),
}

TCP_SERVICES = {
    20: "file transfer (FTP data)", 21: "file transfer (FTP)", 22: "remote login (SSH)", 23: "remote login (Telnet, unencrypted)",
    25: "email sending (SMTP)", 53: "name lookups (DNS)", 80: "website (HTTP, unencrypted)", 110: "email (POP3)",
    139: "Windows networking (NetBIOS)", 143: "email (IMAP)", 443: "website or app service (HTTPS)", 445: "Windows file sharing (SMB)",
    465: "email sending (SMTPS)", 548: "Apple file sharing (AFP)", 554: "camera / video stream (RTSP)", 587: "email sending (SMTP)",
    631: "printer (IPP)", 853: "encrypted name lookups (DNS over TLS)", 993: "email (IMAPS)", 995: "email (POP3S)",
    1883: "smart-home messaging (MQTT)", 3306: "database (MySQL)", 3389: "remote desktop (RDP)", 5000: "AirPlay / web service",
    5432: "database (PostgreSQL)", 5900: "screen sharing (VNC)", 7000: "AirPlay", 8008: "Chromecast / media device",
    8009: "Chromecast", 8080: "website (alternate port)", 8443: "website (alternate HTTPS port)", 9100: "printer (raw printing)",
    62078: "iPhone / iPad sync",
}
UDP_SERVICES = {
    53: "name lookups (DNS)", 67: "hands out addresses (DHCP server)", 123: "clock time (NTP)", 137: "Windows name lookups (NetBIOS)",
    443: "web traffic (QUIC / HTTP/3)", 1900: "device discovery (SSDP / UPnP)", 3478: "video / voice calls (STUN)",
    5353: "device discovery (mDNS)", 5355: "name lookups (LLMNR)",
}

_RECORDER_SHARE = 0.6  # an address in this share of IP packets is very likely the recording computer


@dataclass
class CaptureFacts:
    """Per-capture facts needed to identify hosts, computed once in a single pass."""

    gateway_mac: str | None = None
    gateway_share: float = 0.0
    router_ips: set[str] = field(default_factory=set)
    udp_services: dict[str, Counter] = field(default_factory=dict)
    recorder: tuple[str, float] | None = None


@dataclass
class Identity:
    role: str
    explanation: str
    names: list[tuple[str, str]] = field(default_factory=list)  # (name, how it is known)
    services: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


_facts_cache: "weakref.WeakKeyDictionary[CaptureIndex, CaptureFacts]" = weakref.WeakKeyDictionary()


def _is_public(ip: str | None) -> bool:
    return ip is not None and classify_ip(ip) in ("public", "documentation range")


def capture_facts(index: CaptureIndex) -> CaptureFacts:
    cached = _facts_cache.get(index)
    if cached is not None:
        return cached
    to_internet: Counter = Counter()  # destination MACs of packets leaving for public addresses
    from_internet: Counter = Counter()  # source MACs of packets arriving from public addresses
    udp: dict[str, Counter] = defaultdict(Counter)
    involvement: Counter = Counter()
    ip_packets = 0
    scope_cache: dict[str, bool] = {}

    def public(ip):
        if ip is None:
            return False
        v = scope_cache.get(ip)
        if v is None:
            v = scope_cache[ip] = _is_public(ip)
        return v

    for p in index.packets:
        if p.src is None or p.dst is None or p.net not in ("IPv4", "IPv6"):
            continue
        ip_packets += 1
        involvement[p.src] += 1
        involvement[p.dst] += 1
        if p.eth_dst and public(p.dst) and not public(p.src):
            to_internet[p.eth_dst.lower()] += 1
        if p.eth_src and public(p.src) and not public(p.dst):
            from_internet[p.eth_src.lower()] += 1
        if p.transport == "UDP" and p.sport in UDP_SERVICES and (p.dport is None or p.dport >= 1024 or p.dport == p.sport):
            udp[p.src][UDP_SERVICES[p.sport]] += 1
    facts = CaptureFacts(udp_services=dict(udp))
    combined = to_internet + from_internet
    if combined:
        mac, n = combined.most_common(1)[0]
        facts.gateway_mac = mac
        facts.gateway_share = n / sum(combined.values())
        facts.router_ips = {ip for ip, meta in index.hosts.items() if mac in {m.lower() for m in meta.macs} and not _is_public(ip)}
    if ip_packets:
        for ip, n in involvement.most_common(3):
            scope = classify_ip(ip)
            if scope in ("private", "link-local") and n / ip_packets >= _RECORDER_SHARE:
                facts.recorder = (ip, n / ip_packets)
                break
    _facts_cache[index] = facts
    return facts


def _names(meta) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if meta is None:
        return out
    for name in list(meta.dhcp_names)[:2]:
        out.append((name, "announced by the device"))
    for name in list(meta.dns_names)[:3]:
        out.append((name, "DNS answer"))
    for name in list(meta.tls_names)[:3]:
        if name not in {n for n, _ in out}:
            out.append((name, "secure-connection name"))
    return out


def identify(ip: str, index: CaptureIndex, local_addresses: frozenset[str] | set[str] = frozenset()) -> Identity:
    meta = index.hosts.get(ip)
    facts = capture_facts(index)
    names = _names(meta)
    services: list[str] = []
    if meta is not None:
        for port, _n in meta.ports_accepting.most_common(8):
            services.append(f"{TCP_SERVICES.get(port, 'a service')} on TCP port {port}")
    for svc, n in facts.udp_services.get(ip, Counter()).most_common(4):
        services.append(f"{svc} - answered {n:,} time(s)")
    notes: list[str] = []
    scope = classify_ip(ip)
    key = ip.lower()

    if ip in local_addresses:
        ident = Identity("THIS COMPUTER", "the address of this computer on the adapter TRACE//ZERO recorded")
    elif ip in facts.router_ips:
        ident = Identity(
            "ROUTER",
            "your gateway to the internet: traffic to and from internet addresses goes through its hardware address",
        )
        notes.append(f"gateway hardware address {facts.gateway_mac} ({facts.gateway_share:.0%} of internet-bound frames)")
    elif key in WELL_KNOWN:
        role, text = WELL_KNOWN[key]
        ident = Identity(role, text)
    elif key.startswith("ff02::1:ff"):
        ident = Identity("NEIGHBOUR DISCOVERY", "IPv6 devices finding each other's hardware addresses (the IPv6 version of ARP)")
    elif scope == "multicast":
        ident = Identity("MULTICAST GROUP", "one message delivered to every device that joined this group; not a single device")
    elif scope == "loopback":
        ident = Identity("THIS COMPUTER (LOOPBACK)", "traffic that never leaves the recording computer")
    elif scope == "link-local":
        if ip.startswith("169.254."):
            ident = Identity("SELF-ASSIGNED ADDRESS", "a device that did not get an address from the router and picked its own")
        else:
            ident = Identity("LOCAL DEVICE (IPv6)", "a device's automatic IPv6 address, only usable on the local network")
    elif scope == "documentation range":
        ident = Identity(
            "EXAMPLE ADDRESS",
            "a range reserved for documentation and tests - not used on the real internet; typical of example or synthetic captures",
        )
    elif scope == "private":
        if ip.count(".") == 3 and ip.endswith(".255"):
            ident = Identity("LOCAL BROADCAST", "probably the broadcast address of the local network: a message to every device on it")
        else:
            ident = Identity("DEVICE ON YOUR NETWORK", "a computer, phone, printer, TV or other device on the local network")
    elif scope == "public":
        if _in(ip, "100.64.0.0/10"):
            ident = Identity("PROVIDER NETWORK", "an address inside your internet provider's network (carrier-grade NAT)")
        else:
            ident = Identity("INTERNET SERVER", "a computer on the internet - a website, an app's server, a CDN or a cloud service")
            if not names:
                notes.append("no name was seen for it in this capture; names appear when the DNS lookup or a secure connection is captured")
    else:
        ident = Identity(scope.upper(), "")

    if facts.recorder and facts.recorder[0] == ip and ident.role not in ("THIS COMPUTER", "ROUTER"):
        notes.insert(0, f"probably the computer that recorded this capture: it is in {facts.recorder[1]:.0%} of all packets")
    ident.names = names
    ident.services = services
    ident.notes = notes + ident.notes
    return ident


def _in(ip: str, net: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net)
    except ValueError:
        return False
