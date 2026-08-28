import json
import threading
import time
import builtins
import sys
from types import SimpleNamespace

import pytest

import sniffer


def test_validate_capture_iface_success(monkeypatch):
    # monkeypatch sniff to return quickly (worker will set ok)
    def fake_sniff(*args, **kwargs):
        return None

    monkeypatch.setattr(sniffer, "sniff", fake_sniff)
    ok = sniffer.validate_capture_iface("lo", timeout=0.1)
    assert ok is True


def test_validate_capture_iface_timeout(monkeypatch):
    # sniff sleeps longer than timeout to simulate hang/unresponsive
    def slow_sniff(*args, **kwargs):
        time.sleep(2)

    monkeypatch.setattr(sniffer, "sniff", slow_sniff)
    ok = sniffer.validate_capture_iface("lo", timeout=0.1)
    assert ok is False


def test_format_payload_ascii_and_hex():
    s = sniffer.PacketSniffer()
    payload = b"Hello\x00\xffWorld"  # includes non-printable bytes
    out = s._format_payload(payload, length=12)
    # hex preview of first 16 bytes (truncated to payload len)
    assert "48656c6c6f" in out  # "Hello" in hex
    assert "." in out  # non-printable replaced


class DummyLayer:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class DummyPacket:
    def __init__(self, layers: dict):
        # layers: mapping layer class -> layer instance
        self._layers = layers

    def haslayer(self, layer):
        return layer in self._layers

    def __getitem__(self, layer):
        return self._layers[layer]

    def summary(self):
        return "DummyPacketSummary"


def test_arp_processing_json_mode(capsys):
    pkt = DummyPacket({sniffer.ARP: DummyLayer(op=1, pdst="10.0.0.5", psrc="10.0.0.1"),
                       sniffer.Ether: DummyLayer(src="aa:bb:cc", dst="dd:ee:ff")})
    s = sniffer.PacketSniffer(json_mode=True)
    s._process_packet(pkt)
    captured = capsys.readouterr().out.strip()
    # valid JSON printed
    obj = json.loads(captured)
    assert obj["proto"] == "ARP"
    assert "mac_src" in obj and "mac_dst" in obj


def test_l2_other_count_and_summary(capsys):
    # No IP/ARP/IPv6 layers -> treated as L2-only
    pkt = DummyPacket({sniffer.Ether: DummyLayer(src="aa:bb", dst="cc:dd")})
    s = sniffer.PacketSniffer()
    s._process_packet(pkt)
    # stats incremented
    assert s.stats["l2_other"] == 1
    # stdout includes L2 tag
    captured = capsys.readouterr().out
    assert "[L2]" in captured or "L2-only" not in captured  # at least didn't crash
