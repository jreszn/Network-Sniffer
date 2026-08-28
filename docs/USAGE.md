# 🛠️ CodeAlpha Network Sniffer — CLI Usage Guide

`sniffer.py` is a high-performance, hardened Python network traffic analyzer built with Scapy. It features non-blocking interface testing, kernel-level BPF filtering, multi-protocol analysis, and atomic PCAP logging.

---

## ⚡ Quick Start

```bash
# 1. Activate virtual environment
source venv/bin/activate

# 2. Basic live capture on eth0 (Stop after 10 packets)
sudo ./venv/bin/python3 sniffer.py -i eth0 -c 10

📖 Command Reference

____ Sniffysh Network Sniffer ____
  [ Multi-Protocol L2/L3/L4 Traffic Analyzer ]

usage: sniffer.py [-h] -i IFACE [-f BPF] [-w PCAP] [-c COUNT] [--json] [--quiet] [--no-payload] [--test-iface]

Options BreakdownFlagFull NameTypeDescriptionExample-i--interfaceSTRING[Required] Network interface to listen on.-i eth0 / -i wlan0-f--filterSTRINGBerkeley Packet Filter (BPF) syntax string.-f "tcp port 80"-w--writePATHSave captured packets to a Wireshark-compatible .pcap file.-w capture.pcap-c--countINTTotal packets to capture before exiting cleanly (0 = infinite).-c 100--json--json-modeFLAGFormat real-time packet stream as single-line JSON objects (SIEM ready).--json--quiet--quiet-modeFLAGSuppress packet stream display. Prints initial notice & final stats table.--quiet--no-payload--no-payloadFLAGOmit packet payload body printing (Privacy/OPSEC mode).--no-payload--test-iface--test-ifaceFLAGExecute a non-blocking 1-second capture probe to verify interface binding.--test-iface-h--helpFLAGDisplay formatted help menu and exit.-h

🎯 Common Execution Scenarios1. Web Traffic Inspection (HTTP/HTTPS)Capture 20 TCP packets on port 80 or 443 with payload details:

sudo ./venv/bin/python3 sniffer.py -i eth0 -f "tcp port 80 or tcp port 443" -c 20

2. SIEM Integration / Automated Logging (JSON)
Pipe live structured JSON output into jq for real-time field filtering:

sudo ./venv/bin/python3 sniffer.py -i eth0 --json -c 50 | jq '.ip.src'

3. Stealth/OPSEC Logging to PCAP
Silently record 1000 packets to a PCAP file without flooding standard output:

sudo ./venv/bin/python3 sniffer.py -i eth0 -w /tmp/stealth_capture.pcap -c 1000 --quiet

4. Low-Overhead ARP / Local Discovery Sniffing
Filter specifically for Address Resolution Protocol packets:

sudo ./venv/bin/python3 sniffer.py -i eth0 -f "arp" -c 10

5. Interface Capability Validation
Check if an interface binds properly before running scheduled jobs:

sudo ./venv/bin/python3 sniffer.py -i eth0 --test-iface

[+] Capture test OK on 'eth0'

🔒 Security & Exit Codes
Exit Code 0: Clean completion / SIGINT (Ctrl+C) received safely without PCAP corruption.

Exit Code 1: Invalid interface name or network adapter down.

Exit Code 3: Insufficient privileges (CAP_NET_RAW / root required).
