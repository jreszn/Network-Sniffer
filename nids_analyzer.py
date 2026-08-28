#!/usr/bin/env python3
"""
CodeAlpha Task 4: NIDS Alert Analyzer
Batch analysis and reporting of Suricata alerts
"""

import json
import sys
from collections import Counter
from datetime import datetime
from typing import Dict, List, Any

EVE_LOG = "/var/log/suricata/eve.json"

def load_alerts() -> List[Dict[str, Any]]:
    """Load all alerts from eve.json"""
    alerts = []
    try:
        with open(EVE_LOG, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        print(f"[!] Error: {EVE_LOG} not found")
        sys.exit(1)
    return alerts

def analyze(alerts: List[Dict]) -> Dict[str, Any]:
    """Analyze alert data"""
    stats = {
        "total": len(alerts),
        "by_severity": Counter(),
        "by_signature": Counter(),
        "by_source_ip": Counter(),
        "by_dest_ip": Counter(),
        "by_protocol": Counter(),
    }
    
    for alert in alerts:
        a = alert.get("alert", {})
        stats["by_severity"][a.get("severity", 3)] += 1
        stats["by_signature"][a.get("signature", "Unknown")] += 1
        stats["by_source_ip"][alert.get("src_ip", "Unknown")] += 1
        stats["by_dest_ip"][alert.get("dest_ip", "Unknown")] += 1
        stats["by_protocol"][alert.get("proto", "Unknown")] += 1
    
    return stats

def print_report(stats: Dict[str, Any]):
    """Print analysis report"""
    print("="*70)
    print("NIDS ALERT ANALYSIS REPORT")
    print("="*70)
    print(f"\nTotal Alerts: {stats['total']}")
    
    print(f"\n--- By Severity ---")
    for sev, count in sorted(stats["by_severity"].items()):
        label = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}.get(sev, "Unknown")
        print(f"  {label}: {count}")
    
    print(f"\n--- Top Signatures ---")
    for sig, count in stats["by_signature"].most_common(10):
        print(f"  {count}x: {sig[:50]}...")
    
    print(f"\n--- Top Source IPs ---")
    for ip, count in stats["by_source_ip"].most_common(5):
        print(f"  {count}x: {ip}")
    
    print(f"\n--- By Protocol ---")
    for proto, count in stats["by_protocol"].most_common():
        print(f"  {proto}: {count}")
    
    print("="*70)

def main():
    print("[*] Loading alerts from Suricata...")
    alerts = load_alerts()
    print(f"[+] Loaded {len(alerts)} alerts")
    
    if not alerts:
        print("[!] No alerts found")
        return
    
    stats = analyze(alerts)
    print_report(stats)

if __name__ == "__main__":
    main()
