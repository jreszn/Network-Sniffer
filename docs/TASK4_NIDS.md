# Task 4: Network Intrusion Detection System - Technical Documentation

## Executive Summary
Deployed Suricata 8.0.6 NIDS with 52,224 detection rules, real-time Python monitoring, and integration with Task 1 packet sniffer.

## System Architecture

### Suricata Configuration
- **Mode**: IDS (passive monitoring)
- **Interface**: eth0 (AF_PACKET)
- **Rules**: Emerging Threats Open + Custom test rules
- **Output**: JSON (eve.json) + Text (fast.log)

### Detection Capabilities
| Category | Rule Count | Example Detections |
|----------|-----------|-------------------|
| Malware C2 | ~15,000 | Botnet callbacks, trojan traffic |
| Web Attacks | ~8,000 | SQLi, XSS, RCE attempts |
| Network Scans | ~2,000 | Nmap, masscan detection |
| Policy Violations | ~5,000 | P2P, tunneling, cryptomining |

### Python Integration
- **nids_monitor.py**: Real-time `tail -f` style alert display
- **nids_analyzer.py**: Batch statistics and reporting
- **unified_security.py**: Combined Task 1 + Task 4 status

## Deployment Commands

```bash
# 1. Validate configuration
sudo suricata -T -c suricata-config/suricata-minimal.yaml

# 2. Start NIDS
sudo suricata -c suricata-config/suricata-minimal.yaml -i eth0 -D

# 3. Monitor in real-time
sudo python3 nids_monitor.py

# 4. Generate report
sudo python3 nids_analyzer.py

Sample Output
Real-Time Alert

[ALERT] 2026-08-28T07:02:05
       Signature: TEST: ANY IP TRAFFIC (SID: 9000003)
       Severity:  3
       Source:    192.168.23.4 -> 255.255.255.255 (UDP)
Unified Status

--- NIDS (Suricata) Status ---
Status: active
Total Alerts: 80
Interview Talking Points
 Why Suricata over Snort?
Multi-threaded architecture, native JSON output, better performance on modern hardware.
 How do you handle false positives?
Thresholding, suppression rules, and tuning HOME_NET variables to reduce noise.
 Integration with SIEM?
EVE JSON format is directly ingestible by Splunk/ELK without parsing.
 Difference between IDS and IPS?
IDS monitors and alerts; IPS can drop packets. This deployment is IDS-only for safety. 

