#!/usr/bin/env python3
"""
sniffer.py - Hardened, responsive network packet sniffer using Scapy.

Updates in this version:
 - Professional ASCII banner with version info
 - Color-coded output for better readability
 - Responsive stop loop (sniff with short timeout loop)
 - IPv6 support (basic parsing + stats)
 - L2-only frame accounting via 'l2_other' stat (LLDP/STP/802.1Q etc.)
 - Preserves earlier features: ARP handling, safe threaded capture test, JSON/quiet modes, pcap cleanup

Note: helper function renamed to `validate_capture_iface` to avoid pytest automatic test collection.
"""

from __future__ import annotations

import atexit
import argparse
import datetime
import json
import logging
import os
import signal
import sys
import threading
import time
from typing import Dict, Optional

# Scapy imports
try:
    from scapy.all import (
        ARP,
        Ether,
        ICMP,
        IP,
        IPv6,
        PcapWriter,
        Raw,
        TCP,
        UDP,
        get_if_list,
        sniff,
    )
except ImportError:
    print("[!] Scapy library is required. Install: pip install scapy", file=sys.stderr)
    sys.exit(2)

logger = logging.getLogger("sniffer")

# Version info
__version__ = "1.0.0"
__author__ = "CodeAlpha Intern"
__tool_name__ = "GHOST-SNIFFER"

# ANSI Color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def is_running_as_root() -> bool:
    try:
        return os.name != "nt" and os.geteuid() == 0
    except Exception:
        return False

def recommend_setcap() -> str:
    return (
        "On Linux, prefer capabilities over running as root:\n"
        "  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)\n"
        "Warning: setcap persists until the binary is replaced. Re-run after Python updates or for virtualenvs."
    )

def print_banner(quiet: bool = False) -> None:
    """Print professional ASCII banner."""
    if quiet:
        return

    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════╗
║{Colors.GREEN}   ██████╗ ███████╗ ██████╗ ███████╗████████╗    ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ {Colors.CYAN}║
║{Colors.GREEN}  ██╔════╝ ██╔════╝██╔═══██╗██╔════╝╚══██╔══╝    ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗{Colors.CYYAN}║
║{Colors.GREEN}  ██║  ███╗█████╗  ██║   ██║███████╗   ██║       ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝{Colors.CYAN}║
║{Colors.GREEN}  ██║   ██║██╔══╝  ██║   ██║╚════██║   ██║       ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗{Colors.CYAN}║
║{Colors.GREEN}  ╚██████╔╝███████╗╚██████╔╝███████║   ██║       ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║{Colors.CYAN}║
║{Colors.GREEN}   ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝       ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝{Colors.CYAN}║
║                                                                          ║
║{Colors.BLUE}   Sniffysh -  Network Sniffer v{__version__} - Hardened Packet Analysis Tool{Colors.CYAN}      ║
║{Colors.WARNING}   [!] Educational Use Only - Authorized Testing Only{Colors.CYAN}                    ║
╚══════════════════════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)

class PacketSniffer:
    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        output_pcap: Optional[str] = None,
        packet_count: int = 0,
        show_payload: bool = True,
        quiet: bool = False,
        json_mode: bool = False,
        sniff_timeout: float = 1.0,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.output_pcap = output_pcap
        self.packet_count = packet_count
        self.show_payload = show_payload
        self.quiet = quiet
        self.json_mode = json_mode
        self.sniff_timeout = sniff_timeout

        self.pcap_writer: Optional[PcapWriter] = None
        if self.output_pcap:
            try:
                self.pcap_writer = PcapWriter(self.output_pcap, append=True, sync=True)
            except Exception as e:
                logger.exception("Failed to open PCAP writer: %s", e)
                print(f"{Colors.FAIL}[!] Failed to open PCAP file '{self.output_pcap}': {e}{Colors.ENDC}", file=sys.stderr)
                sys.exit(1)

        # Statistics: include 'arp', 'l2_other' and IPv6 counts via same tcp/udp/icmps
        self.stats: Dict[str, int] = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "arp": 0,
            "l2_other": 0,
            "other": 0,
        }
        self.start_time: Optional[datetime.datetime] = None

        self._stop_requested = False

        atexit.register(self._close_pcap)

        # Register signals only in main thread
        if threading.current_thread() is threading.main_thread():
            try:
                signal.signal(signal.SIGINT, self._handle_signal)
            except Exception:
                pass
            try:
                signal.signal(signal.SIGTERM, self._handle_signal)
            except Exception:
                pass

    def _close_pcap(self) -> None:
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
                logger.debug("PCAP writer closed")
            except Exception:
                logger.exception("Error closing PCAP writer")

    def _handle_signal(self, signum, frame) -> None:
        self._stop_requested = True
        if not self.quiet:
            print(f"\n{Colors.WARNING}[!] Signal received; stopping capture...{Colors.ENDC}")

    def _format_payload(self, raw_data: bytes, length: int = 64) -> str:
        truncated = raw_data[:length]
        ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in truncated)
        hex_preview = truncated[:16].hex()
        if len(raw_data) > length:
            return f"\n    └─ Payload ({len(raw_data)} bytes): {Colors.CYAN}{hex_preview}{Colors.ENDC} | {ascii_preview}..."
        return f"\n    └─ Payload ({len(raw_data)} bytes): {Colors.CYAN}{hex_preview}{Colors.ENDC} | {ascii_preview}"

    def _process_packet(self, packet) -> None:
        self.stats["total"] += 1

        if self.pcap_writer:
            try:
                self.pcap_writer.write(packet)
            except Exception:
                logger.exception("Failed to write packet to PCAP")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mac_src = packet[Ether].src if packet.haslayer(Ether) else "N/A"
        mac_dst = packet[Ether].dst if packet.haslayer(Ether) else "N/A"

        # ARP
        if packet.haslayer(ARP):
            self.stats["arp"] += 1
            arp_op = "Request" if getattr(packet[ARP], "op", 0) == 1 else "Reply"
            layer_info = f"{arp_op}: Who has {getattr(packet[ARP], 'pdst', '?')}? Tell {getattr(packet[ARP], 'psrc', '?')}"
            if self.json_mode:
                print(json.dumps({"ts": timestamp, "proto": "ARP", "layer4": layer_info, "mac_src": mac_src, "mac_dst": mac_dst}))
                return
            if not self.quiet:
                print(f"{Colors.WARNING}[{timestamp}] [ARP] {layer_info}{Colors.ENDC}")
                print(f"    └─ MAC: {mac_src} -> {mac_dst}")
            return

        # IPv4
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            ttl = getattr(packet[IP], "ttl", "N/A")
            protocol = "OTHER"
            layer4_info = ""

            if packet.haslayer(TCP):
                protocol = "TCP"
                self.stats["tcp"] += 1
                layer4_info = f"Ports: {Colors.GREEN}{packet[TCP].sport}{Colors.ENDC} -> {Colors.GREEN}{packet[TCP].dport}{Colors.ENDC} | Flags: [{Colors.WARNING}{packet[TCP].flags}{Colors.ENDC}]"
            elif packet.haslayer(UDP):
                protocol = "UDP"
                self.stats["udp"] += 1
                layer4_info = f"Ports: {Colors.GREEN}{packet[UDP].sport}{Colors.ENDC} -> {Colors.GREEN}{packet[UDP].dport}{Colors.ENDC}"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                self.stats["icmp"] += 1
                layer4_info = f"Type: {getattr(packet[ICMP], 'type', '?')} | Code: {getattr(packet[ICMP], 'code', '?')}"
            else:
                self.stats["other"] += 1

            if self.json_mode:
                obj = {"ts": timestamp, "proto": protocol, "src": ip_src, "dst": ip_dst, "ttl": ttl, "layer4": layer4_info, "mac_src": mac_src, "mac_dst": mac_dst}
                if self.show_payload and packet.haslayer(Raw):
                    truncated = packet[Raw].load[:16]
                    obj["payload_len"] = len(packet[Raw].load)
                    obj["payload_hex"] = truncated.hex()
                print(json.dumps(obj))
                return

            if not self.quiet:
                proto_color = Colors.GREEN if protocol == "TCP" else Colors.BLUE if protocol == "UDP" else Colors.WARNING
                print(f"{Colors.CYAN}[{timestamp}]{Colors.ENDC} [{proto_color}{protocol}{Colors.ENDC}] {Colors.BOLD}{ip_src}{Colors.ENDC} -> {Colors.BOLD}{ip_dst}{Colors.ENDC} | TTL: {ttl} | {layer4_info}")
                print(f"    └─ MAC: {mac_src} -> {mac_dst}")
                if self.show_payload and packet.haslayer(Raw):
                    try:
                        payload_bytes = packet[Raw].load
                        print(self._format_payload(payload_bytes))
                    except Exception:
                        logger.exception("Failed to extract payload")
            return

        # IPv6 (basic handling)
        if packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
            ip_dst = packet[IPv6].dst
            hlim = getattr(packet[IPv6], "hlim", "N/A")
            protocol = "OTHER"
            layer4_info = ""

            if packet.haslayer(TCP):
                protocol = "TCP"
                self.stats["tcp"] += 1
                layer4_info = f"Ports: {Colors.GREEN}{packet[TCP].sport}{Colors.ENDC} -> {Colors.GREEN}{packet[TCP].dport}{Colors.ENDC} | Flags: [{Colors.WARNING}{packet[TCP].flags}{Colors.ENDC}]"
            elif packet.haslayer(UDP):
                protocol = "UDP"
                self.stats["udp"] += 1
                layer4_info = f"Ports: {Colors.GREEN}{packet[UDP].sport}{Colors.ENDC} -> {Colors.GREEN}{packet[UDP].dport}{Colors.ENDC}"
            else:
                self.stats["other"] += 1

            if self.json_mode:
                obj = {"ts": timestamp, "proto": protocol, "src": ip_src, "dst": ip_dst, "ttl": hlim, "layer4": layer4_info, "mac_src": mac_src, "mac_dst": mac_dst}
                if self.show_payload and packet.haslayer(Raw):
                    truncated = packet[Raw].load[:16]
                    obj["payload_len"] = len(packet[Raw].load)
                    obj["payload_hex"] = truncated.hex()
                print(json.dumps(obj))
                return

            if not self.quiet:
                proto_color = Colors.GREEN if protocol == "TCP" else Colors.BLUE
                print(f"{Colors.CYAN}[{timestamp}]{Colors.ENDC} [{proto_color}{protocol}{Colors.ENDC}] {Colors.BOLD}{ip_src}{Colors.ENDC} -> {Colors.BOLD}{ip_dst}{Colors.ENDC} | HLim: {hlim} | {layer4_info}")
                print(f"    └─ MAC: {mac_src} -> {mac_dst}")
                if self.show_payload and packet.haslayer(Raw):
                    try:
                        payload_bytes = packet[Raw].load
                        print(self._format_payload(payload_bytes))
                    except Exception:
                        logger.exception("Failed to extract payload")
            return

        # L2-only or other frames (LLDP, STP, 802.1Q, etc.)
        self.stats["l2_other"] += 1
        if self.json_mode:
            print(json.dumps({"ts": timestamp, "proto": "L2", "summary": packet.summary(), "mac_src": mac_src, "mac_dst": mac_dst}))
            return
        if not self.quiet:
            print(f"{Colors.HEADER}[{timestamp}] [L2] {packet.summary()}{Colors.ENDC}")
            print(f"    └─ MAC: {mac_src} -> {mac_dst}")

    def _print_statistics(self) -> None:
        elapsed = (datetime.datetime.now() - self.start_time).total_seconds() if self.start_time else 0.0
        if self.json_mode:
            print(json.dumps({"stats": self.stats, "elapsed_s": elapsed}))
            return
        if not self.quiet:
            print("\n" + Colors.GREEN + "=" * 60 + Colors.ENDC)
            print(f"{Colors.BOLD}{Colors.HEADER}CAPTURE STATISTICS{Colors.ENDC}")
            print(Colors.GREEN + "=" * 60 + Colors.ENDC)
            print(f" {Colors.CYAN}Total Packets:{Colors.ENDC} {self.stats['total']}")
            print(f"   {Colors.GREEN}TCP:{Colors.ENDC}         {self.stats['tcp']}")
            print(f"   {Colors.BLUE}UDP:{Colors.ENDC}         {self.stats['udp']}")
            print(f"   {Colors.WARNING}ICMP:{Colors.ENDC}        {self.stats['icmp']}")
            print(f"   {Colors.FAIL}ARP:{Colors.ENDC}         {self.stats['arp']}")
            print(f"   {Colors.HEADER}L2-only:{Colors.ENDC}     {self.stats['l2_other']}")
            print(f"   {Colors.ENDC}Other IP:    {self.stats['other']}")
            print(f" {Colors.CYAN}Elapsed (s):{Colors.ENDC}  {elapsed:.2f}")
            print(Colors.GREEN + "=" * 60 + Colors.ENDC)

    def start(self) -> None:
        # Print banner first
        print_banner(self.quiet)

        if not self.quiet:
            print(f"{Colors.CYAN}[*] Target Interface :{Colors.ENDC} {self.interface or 'Default System Interface'}")
            print(f"{Colors.CYAN}[*] BPF Filter       :{Colors.ENDC} {self.bpf_filter or 'None (Capturing All)'}")
            print(f"{Colors.CYAN}[*] Output PCAP      :{Colors.ENDC} {self.output_pcap or 'None'}")
            print(f"{Colors.CYAN}[*] Capture Limit    :{Colors.ENDC} {self.packet_count or 'Unlimited'}")
            if not is_running_as_root():
                print(f"{Colors.WARNING}[!] Not running as root. Packet capture may fail.{Colors.ENDC}")
                print(f"    {Colors.WARNING}{recommend_setcap()}{Colors.ENDC}")
            print(Colors.GREEN + "=" * 70 + Colors.ENDC)
            print(f"{Colors.CYAN}[*] Press Ctrl+C to stop capture.{Colors.ENDC}\n")

        self.start_time = datetime.datetime.now()

        try:
            # Responsive sniff loop with short timeouts so stop requests are honored quickly
            while not self._stop_requested:
                # Check packet_count termination
                if self.packet_count > 0 and self.stats["total"] >= self.packet_count:
                    break

                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._process_packet,
                    store=False,
                    timeout=self.sniff_timeout,
                    count=0,
                )
                # small sleep to avoid tight-loop CPU spin if needed
                time.sleep(0)

        except PermissionError:
            print(f"\n{Colors.FAIL}[!] Error: Insufficient permissions to capture raw packets.{Colors.ENDC}", file=sys.stderr)
            self._close_pcap()
            sys.exit(3)
        except Exception as e:
            logger.exception("Unexpected capture error: %s", e)
            print(f"\n{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}", file=sys.stderr)
        finally:
            self._print_statistics()
            self._close_pcap()


def validate_capture_iface(iface: str, timeout: float = 1.0) -> bool:
    """Threaded sniff test with hard join limit to avoid hanging scapy variants."""
    result = {"ok": False}

    def worker():
        try:
            sniff(iface=iface, count=0, timeout=timeout, store=False)
            result["ok"] = True
        except Exception:
            logger.exception("Capture test failed for %s", iface)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout + 0.5)
    return result["ok"]


def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"{__tool_name__} v{__version__} - Hardened Network Packet Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  sudo python3 {sys.argv[0]} -i eth0 -c 100
  sudo python3 {sys.argv[0]} -i eth0 -f "tcp port 80" -w capture.pcap
  sudo python3 {sys.argv[0]} -i eth0 --json --quiet > traffic.json
  python3 {sys.argv[0]} --test-iface -i eth0
        """
    )
    p.add_argument("-i", "--interface", type=str, help="Interface to listen on (e.g. eth0)")
    p.add_argument("-f", "--filter", type=str, help="BPF filter (e.g. 'tcp port 80')")
    p.add_argument("-w", "--write", type=str, help="Write PCAP to file (append if exists)")
    p.add_argument("-c", "--count", type=int, default=0, help="Packet count (0 = unlimited)")
    p.add_argument("--no-payload", action="store_true", help="Disable payload printing")
    p.add_argument("--json", action="store_true", help="Output JSON objects (one per packet)")
    p.add_argument("--quiet", action="store_true", help="Minimal human output (opsec)")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    p.add_argument("--test-iface", action="store_true", help="Run a short capture test on the selected interface and exit")
    p.add_argument("--sniff-timeout", type=float, default=1.0)
