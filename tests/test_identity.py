"""'What is this address?' - roles, names and services from the capture alone."""

from __future__ import annotations

from scapy.layers.inet import IP, UDP

from trace_zero.analysis.identity import capture_facts, identify
from trace_zero.config import Config
from trace_zero.session import Session, load_capture
from trace_zero.storage import Store
from trace_zero.ui import inspect

from .conftest import ETH, write_pcap


def test_roles_names_and_services_on_the_sample(loaded_sample):
    idx = loaded_sample.index
    facts = capture_facts(idx)
    assert facts.router_ips == {"10.20.0.1"} and facts.gateway_share > 0.9
    router = identify("10.20.0.1", idx)
    assert router.role == "ROUTER" and "internet" in router.explanation
    dns = identify("10.20.0.53", idx)
    assert dns.role == "DEVICE ON YOUR NETWORK" and any("DNS" in s for s in dns.services)
    web = identify("203.0.113.10", idx)
    assert web.names[0] == ("www.example.com", "DNS answer")
    assert "website or app service (HTTPS) on TCP port 443" in web.services
    assert identify("224.0.0.251", idx).role == "DEVICE DISCOVERY (mDNS)"
    assert identify("255.255.255.255", idx).role == "BROADCAST"
    assert identify("0.0.0.0", idx).role == "NO ADDRESS YET"
    # names a device announced itself (DHCP) come first
    named = [ip for ip, m in idx.hosts.items() if m.dhcp_names]
    assert named and identify(named[0], idx).names[0][1] == "announced by the device"


def test_this_computer_needs_known_local_addresses(loaded_sample):
    idx = loaded_sample.index
    assert identify("10.20.0.12", idx).role == "DEVICE ON YOUR NETWORK"
    assert identify("10.20.0.12", idx, frozenset({"10.20.0.12"})).role == "THIS COMPUTER"


def test_recording_computer_is_suggested_not_asserted(tmp_path):
    frames = []
    for i in range(20):
        frames.append((1000.0 + i, bytes(ETH() / IP(src="192.168.1.23", dst=f"93.184.216.{i % 3 + 1}") / UDP(sport=50000 + i, dport=443) / b"q")))
        frames.append((1000.5 + i, bytes(ETH() / IP(src=f"93.184.216.{i % 3 + 1}", dst="192.168.1.23") / UDP(sport=443, dport=50000 + i) / b"r")))
    path = write_pcap(tmp_path / "pc.pcap", frames)
    lc = load_capture(path, Config(cache_dir=tmp_path / "cache"))
    me = identify("192.168.1.23", lc.index)
    assert me.role == "DEVICE ON YOUR NETWORK"
    assert me.notes[0].startswith("probably the computer that recorded this capture")
    server = identify("93.184.216.1", lc.index)
    assert server.role == "INTERNET SERVER"
    assert any("QUIC" in s for s in server.services)
    assert any("no name was seen" in n for n in server.notes)


def test_inspector_shows_what_is_this(tmp_path, sample_pcap):
    cfg = Config(db_path=tmp_path / "i.db", cache_dir=tmp_path / "cache")
    store = Store(cfg.db_path)
    s = Session(cfg, store, store.open_or_create("identity"))
    s.attach(load_capture(sample_pcap, cfg))
    from rich.console import Console

    def render(ip):
        console = Console(width=100, record=True)
        console.print(inspect.host(s, ip, s.window_stats()))
        return console.export_text()

    text = render("10.20.0.1")
    assert "WHAT IS THIS" in text and "ROUTER" in text
    assert "www.example.com" in render("203.0.113.10")
    # known local addresses (a live capture recorded here) label this computer; opening a file clears them
    s.local_addresses = frozenset({"10.20.0.12"})
    assert "THIS COMPUTER" in render("10.20.0.12")
    s.attach(load_capture(sample_pcap, cfg))
    assert "THIS COMPUTER" not in render("10.20.0.12")
    store.close()
