#!/usr/bin/env python3
"""
CodeAlpha Task 4: NIDS Alert Monitor
Real-time Suricata alert analysis with correlation
"""

import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, Any, Optional

EVE_LOG = "/var/log/suricata/eve.json"

# Severity colors
COLORS = {
    1: "\033[91m",  # Critical - Red
    2: "\033[93m",  # High - Yellow
    3: "\033[94m",  # Medium - Blue
    4: "\033[92m",  # Low - Green
}
RESET = "\033[0m"
BOLD = "\033[1m"

def follow_file(filename: str):
    """Generator that yields new lines from a file"""
    with open(filename, 'r') as f:
        f.seek(0, 2)  # Go to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line.strip()

def format_alert(event: Dict[str, Any]) -> str:
    """Format alert for display"""
    alert = event.get("alert", {})
    timestamp = event.get("timestamp", "N/A")[:19]
    signature = alert.get("signature", "Unknown")
    severity = alert.get("severity", 3)
    sid = alert.get("signature_id", 0)
    src_ip = event.get("src_ip", "N/A")
    dest_ip = event.get("dest_ip", "N/A")
    proto = event.get("proto", "N/A")
    
    color = COLORS.get(severity, "")
    
    return f"""
{color}{BOLD}[ALERT]{RESET} {color}{timestamp}{RESET}
       Signature: {signature} (SID: {sid})
       Severity:  {severity}
       Source:    {src_ip} -> {dest_ip} ({proto})
{'='*70}"""

def print_banner():
    print(f"""
{COLORS[3]}{'='*70}{RESET}
{BOLD}  CODEALPHA NIDS MONITOR - Task 4{RESET}
{COLORS[3]}{'='*70}{RESET}
[*] Monitoring: {EVE_LOG}
[*] Press Ctrl+C to stop
""")

def main():
    print_banner()
    
    if not os.path.exists(EVE_LOG):
        print(f"[!] Error: {EVE_LOG} not found")
        sys.exit(1)
    
    alert_count = 0
    
    try:
        for line in follow_file(EVE_LOG):
            try:
                event = json.loads(line)
                if event.get("event_type") != "alert":
                    continue
                
                alert_count += 1
                print(format_alert(event))
                
                # Summary every 10 alerts
                if alert_count % 10 == 0:
                    print(f"\n{'='*70}")
                    print(f"[i] Total alerts: {alert_count}")
                    print(f"{'='*70}\n")
                    
            except json.JSONDecodeError:
                continue
                
    except KeyboardInterrupt:
        print(f"\n{'='*70}")
        print(f"[+] Stopped. Total alerts processed: {alert_count}")
        print(f"{'='*70}")
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Warning: May need root to read eve.json")
    main()
