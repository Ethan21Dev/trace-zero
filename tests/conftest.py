from __future__ import annotations

import struct
from pathlib import Path

import pytest
from scapy.layers.l2 import Ether

from trace_zero.config import Config, Limits
from trace_zero.samples import generate_sample
from trace_zero.session import Session, load_capture
from trace_zero.storage import Store


def pytest_configure(config):
    """Keep tests away from the real data directory (database, cache, log)."""
    import os
    import tempfile

    os.environ["TRACE_ZERO_HOME"] = tempfile.mkdtemp(prefix="tz-test-home-")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly if anything under test tries to put a packet on a network."""
    import scapy.layers.l2
    import scapy.sendrecv

    def refuse(*args, **kwargs):
        raise AssertionError("network I/O attempted during tests")

    for name in ("send", "sendp", "sr", "sr1", "srp", "srp1", "sniff"):
        monkeypatch.setattr(scapy.sendrecv, name, refuse, raising=False)
    monkeypatch.setattr(scapy.layers.l2, "getmacbyip", refuse)


def ETH(**kw):
    """Ethernet header with explicit MACs.

    A bare scapy Ether() resolves the destination MAC itself, which can send
    real ARP requests and block on timeouts. Tests must never touch the network.
    """
    return Ether(src="02:00:00:00:00:aa", dst="02:00:00:00:00:bb", **kw)


def pcap_bytes(frames: list[tuple[float, bytes]], linktype: int = 1, nano: bool = False, wirelens: list[int] | None = None) -> bytes:
    """Build a little-endian classic pcap file from (timestamp, frame) pairs."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = [struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)]
    for i, (ts, data) in enumerate(frames):
        sec = int(ts)
        frac = round((ts - sec) * (1e9 if nano else 1e6))
        wl = wirelens[i] if wirelens else len(data)
        out.append(struct.pack("<IIII", sec, frac, len(data), wl))
        out.append(data)
    return b"".join(out)


def write_pcap(path: Path, frames: list[tuple[float, bytes]], **kw) -> Path:
    path.write_bytes(pcap_bytes(frames, **kw))
    return path


@pytest.fixture(scope="session")
def sample_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("samples")
    generate_sample(d / "sample.pcap", fmt="pcap")
    generate_sample(d / "sample.pcapng", fmt="pcapng")
    return d


@pytest.fixture(scope="session")
def sample_pcap(sample_dir) -> Path:
    return sample_dir / "sample.pcap"


@pytest.fixture(scope="session")
def sample_pcapng(sample_dir) -> Path:
    return sample_dir / "sample.pcapng"


@pytest.fixture(scope="session")
def loaded_sample(sample_pcap):
    return load_capture(sample_pcap, Config())


@pytest.fixture
def config(tmp_path) -> Config:
    return Config(limits=Limits(), db_path=tmp_path / "test.db", export_dir=tmp_path / "exports", cache_dir=tmp_path / "cache")


@pytest.fixture
def store(config):
    s = Store(config.db_path)
    yield s
    s.close()


@pytest.fixture
def session(config, store, loaded_sample) -> Session:
    sess = Session(config, store, store.create_investigation("test-investigation"))
    sess.attach(loaded_sample)
    return sess
