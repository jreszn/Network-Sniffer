#!/usr/bin/env python3
"""
check_env.py - Hardened environment verification for CodeAlpha Network Sniffer

Improvements over the earlier version:
 - Verifies scapy presence and version robustly
 - Enumerates interfaces with multiple scapy fallbacks
 - Checks runtime prerequisites (tcpdump, libpcap integration)
 - Tests whether a brief sniff can be opened on a chosen interface
 - Cross-platform admin detection (POSIX/Windows)
 - --json outputs only machine-readable JSON (no human text)
 - --quiet suppresses human output (useful for opsec)
 - Recommends setcap with a persistence/update warning
Exit codes:
 0 = OK (dependencies present; interfaces found; capture test passed or not required)
 1 = Python version too old
 2 = Missing dependency (scapy)
 3 = No usable interfaces detected
 4 = Insufficient privileges for packet capture (when --require-root)
 5 = Capture test failed on chosen interface
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import shutil
import sys
import time
from typing import Dict, List, Optional, Tuple

try:
    from importlib import metadata as importlib_metadata  # type: ignore
except Exception:
    import importlib_metadata  # type: ignore

logger = logging.getLogger("check_env")


def is_running_as_admin() -> bool:
    """Return True if the current process has privileges needed for raw packet capture."""
    try:
        if os.name == "nt":
            import ctypes

            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_scapy_version() -> Optional[str]:
    """Try to obtain the installed Scapy version reliably."""
    try:
        return importlib_metadata.version("scapy")
    except Exception:
        try:
            import scapy  # type: ignore

            return getattr(scapy, "__version__", None)
        except Exception:
            return None


def list_interfaces_with_scapy() -> Tuple[List[Dict[str, str]], List[str]]:
    """Return (detailed_list, simple_names) using Scapy APIs when possible."""
    detailed: List[Dict[str, str]] = []
    simple: List[str] = []

    try:
        from scapy.arch import get_working_ifaces  # type: ignore

        ifaces = get_working_ifaces()
        for iface in ifaces:
            name = getattr(iface, "name", str(iface))
            ip = getattr(iface, "ip", "") or getattr(iface, "ip_addr", "")
            detailed.append({"name": str(name), "ip": str(ip) if ip else ""})
            simple.append(str(name))
        if simple:
            return detailed, simple
    except Exception:
        logger.debug("scapy.arch.get_working_ifaces() not available or failed", exc_info=True)

    try:
        from scapy.all import get_if_list  # type: ignore

        names = get_if_list()
        for n in names:
            simple.append(str(n))
            detailed.append({"name": str(n), "ip": ""})
    except Exception:
        logger.debug("scapy.all.get_if_list() not available or failed", exc_info=True)

    # Last resort: try conf.ifaces if available
    try:
        from scapy.all import conf  # type: ignore

        if hasattr(conf, "ifaces"):
            for k, v in conf.ifaces.items():
                name = getattr(v, "name", str(k))
                ip = getattr(v, "ip", "") or ""
                simple.append(str(name))
                detailed.append({"name": str(name), "ip": str(ip) if ip else ""})
    except Exception:
        logger.debug("scapy.conf.ifaces not available or failed", exc_info=True)

    return detailed, simple


def recommend_capability_fix() -> str:
    """Return a short string with recommended non-root approach for Linux and a persistence warning."""
    return (
        "On Linux you can allow packet capture without running as root. Example:\n"
        "  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)\n\n"
        "Warning: setcap persists on the binary until the file is replaced. If the Python\n"
        "binary is updated/reinstalled (or a virtualenv uses a different interpreter),\n"
        "you must re-run setcap. Applying setcap to system utilities like dumpcap/tcpdump\n"
        "is often safer than applying it to the system python binary."
    )


def check_capture_prerequisites() -> List[str]:
    """Verify external dependencies scapy may rely on."""
    issues: List[str] = []
    # tcpdump/dumpcap presence (used by scapy for certain operations)
    if shutil.which("tcpdump") is None and shutil.which("dumpcap") is None:
        issues.append("tcpdump/dumpcap not found in PATH — some scapy features limited")

    # libpcap bindings: do a light check by importing common arch modules.
    try:
        # This will raise if scapy isn't present or integrations are badly broken.
        import scapy.arch.common  # type: ignore
    except Exception as e:
        issues.append(f"libpcap integration may be broken: {e}")
    return issues


def test_packet_capture(iface: str, timeout: float = 1.0) -> bool:
    """
    Verify we can actually sniff (opens socket briefly).
    This is a best-effort test that attempts to create a sniff socket and returns quickly.
    """
    try:
        # Import here so the main script can check scapy presence first
        from scapy.all import sniff  # type: ignore

        # Use small timeout and count=0 to validate socket creation (no packets required)
        sniff(iface=iface, count=0, timeout=timeout)
        return True
    except Exception as e:
        logger.debug("Capture test failed", exc_info=True)
        return False


def verify_environment(
    require_root: bool = False,
    json_mode: bool = False,
    quiet: bool = False,
    iface_to_test: Optional[str] = None,
) -> int:
    """Verify environment and return exit codes suitable for automation."""
    result: Dict = {"python": None, "scapy": None, "interfaces": [], "usable": [], "prereq_issues": []}
    # Python version check
    min_major, min_minor = 3, 8
    py_major, py_minor = sys.version_info[:2]
    result["python"] = {"implementation": platform.python_implementation(), "version": sys.version.split()[0]}

    if (py_major, py_minor) < (min_major, min_minor):
        if json_mode:
            print(json.dumps({"exit_code": 1, "reason": f"Python {min_major}.{min_minor}+ required"}))
        elif not quiet:
            print(f"[!] Python {min_major}.{min_minor}+ is required. Found: {py_major}.{py_minor}", file=sys.stderr)
        return 1

    # Scapy presence & version
    scapy_ver = get_scapy_version()
    if not scapy_ver:
        if json_mode:
            print(json.dumps({"exit_code": 2, "reason": "Scapy not found"}))
        elif not quiet:
            print("[!] Scapy not found. Install: pip install scapy", file=sys.stderr)
        return 2
    result["scapy"] = {"version": scapy_ver}

    # List interfaces
    detailed, simple = list_interfaces_with_scapy()
    result["interfaces"] = detailed
    loopbacks = {"lo", "lo0", "loopback0", "Loopback Pseudo-Interface 1"}
    usable = [n for n in simple if n not in loopbacks]
    result["usable"] = usable

    prereqs = check_capture_prerequisites()
    result["prereq_issues"] = prereqs

    # Privilege detection
    has_admin = is_running_as_admin()
    result["has_admin"] = has_admin

    # If JSON mode, output only JSON
    if json_mode:
        # Optionally include more fields (prereqs, usable interfaces)
        result["exit_code"] = 0
        # If require_root is set and we don't have it, set non-zero exit
        if require_root and not has_admin:
            result["exit_code"] = 4
        print(json.dumps(result))
        return result["exit_code"]

    # Human-readable output unless quiet
    if not quiet:
        print("[*] Python:", result["python"]["implementation"], result["python"]["version"])
        print(f"[+] Scapy detected: {scapy_ver}")
        print(f"[+] Network interfaces detected: {len(simple)}")
        for entry in detailed:
            ip_info = f" - {entry['ip']}" if entry.get("ip") else ""
            print(f"    • {entry['name']}{ip_info}")
        print(f"[+] Usable interfaces (non-loopback): {usable}")
        if prereqs:
            print("[!] Runtime prerequisite issues detected:")
            for p in prereqs:
                print("    -", p)
        if has_admin:
            print("[✓] Process appears to have elevated privileges (can capture packets).")
        else:
            print("[!] Process does NOT have elevated privileges required for raw capture.")
            print("    Avoid running arbitrary scripts as root; consider the capability-based fix:")
            for ln in recommend_capability_fix().splitlines():
                print("    " + ln)

    if not usable:
        if not quiet:
            print("[!] No usable network interfaces found.", file=sys.stderr)
        return 3

    # If the caller requested a capture test, run it
    target_iface = iface_to_test or (usable[0] if usable else None)
    if target_iface:
        ok = test_packet_capture(target_iface)
        if not ok:
            if not quiet:
                print(f"[!] Capture test failed on interface: {target_iface}", file=sys.stderr)
            return 5
        else:
            if not quiet:
                print(f"[+] Capture test succeeded on interface: {target_iface}")

    if require_root and not has_admin:
        if not quiet:
            print("[!] Requirement: root/capture privileges not satisfied.", file=sys.stderr)
        return 4

    if not quiet:
        print("\n[+] Environment check complete. Good to go.")
    return 0


def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Hardened pre-flight environment check for network sniffer")
    p.add_argument("--require-root", action="store_true", help="Fail if not running with capture privileges")
    p.add_argument("--json", action="store_true", help="Output machine-readable JSON summary (no human text)")
    p.add_argument("--quiet", action="store_true", help="Suppress human-readable output (useful for opsec)")
    p.add_argument("--interface", type=str, help="Network interface to run a capture test on (defaults to first usable)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> None:
    parser = build_cli()
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    exit_code = verify_environment(
        require_root=args.require_root, json_mode=args.json, quiet=args.quiet, iface_to_test=args.interface
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
