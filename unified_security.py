#!/usr/bin/env python3
"""
CodeAlpha: Unified Security Platform
Integrates Task 1 (Network Sniffer) + Task 4 (NIDS)
"""

import subprocess
import json
from datetime import datetime

class UnifiedSecurity:
    def __init__(self):
        self.alerts = []
    
    def get_suricata_summary(self) -> dict:
        """Get summary of recent NIDS activity"""
        try:
            result = subprocess.run(
                ["sudo", "cat", "/var/log/suricata/eve.json"],
                capture_output=True, text=True, timeout=5
            )
            alerts = []
            for line in result.stdout.strip().split('\n'):
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append({
                            "time": event.get("timestamp"),
                            "signature": event.get("alert", {}).get("signature"),
                            "severity": event.get("alert", {}).get("severity"),
                            "src": event.get("src_ip"),
                            "dst": event.get("dest_ip"),
                        })
                except:
                    continue
            return {"status": "active", "alert_count": len(alerts), "recent": alerts[-5:]}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def print_status(self):
        """Print unified security status"""
        print("="*70)
        print("CODEALPHA UNIFIED SECURITY PLATFORM")
        print("="*70)
        print(f"Timestamp: {datetime.now().isoformat()}")
        print()
        
        # NIDS Status
        nids = self.get_suricata_summary()
        print("--- NIDS (Suricata) Status ---")
        print(f"Status: {nids.get('status')}")
        print(f"Total Alerts: {nids.get('alert_count', 0)}")
        
        if nids.get("recent"):
            print("\nRecent Alerts:")
            for alert in nids["recent"]:
                print(f"  [{alert.get('time', 'N/A')[:19]}] {alert.get('signature', 'N/A')[:40]}...")
        
        print()
        print("--- Packet Sniffer (Task 1) ---")
        print("Status: Available (run: sudo python3 sniffer.py -i eth0)")
        print()
        print("="*70)

def main():
    platform = UnifiedSecurity()
    platform.print_status()

if __name__ == "__main__":
    main()
