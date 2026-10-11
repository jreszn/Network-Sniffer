# Network Security Toolkit

Cybersecurity internship project combining network packet analysis with intrusion detection.

## Quick Start

```bash

# Task 1: Packet Sniffer
sudo python3 sniffer.py -i eth0 -c 100

# Task 4: NIDS Monitor
sudo python3 nids_monitor.py

Project Structure

├── sniffer.py              # Task 1: Network packet sniffer
├── check_env.py            # Environment validation
├── nids_monitor.py         # Task 4: Real-time NIDS alerts
├── nids_analyzer.py        # Task 4: Alert analysis
├── unified_security.py     # Combined Task 1+4 status
├── suricata-config/        # NIDS configuration files
│   ├── suricata-minimal.yaml
│   └── *.rules
├── tests/                  # pytest validation
├── docs/                   # Documentation
│   ├── USAGE.md
│   └── TASK4_NIDS.md
└── requirements.txt        # Python dependencies

Tasks Completed
TASK	DESCRIPTION	FILES
1	Basic Network Sniffer	sniffer.py, check_env.py
4	Network Intrusion Detection	nids_*.py, suricata-config/

Requirements
Python 3.8+
Scapy 2.7.0
Suricata 8.0.6

Installation

pip install -r requirements.txt

sudo apt install suricata

See docs/USAGE.md for detailed commands. 

