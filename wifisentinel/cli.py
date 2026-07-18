"""
cli.py

Command-line entrypoint for WiFiSentinel.

Examples
--------
Scan for nearby networks:
    wifisentinel scan --interface wlan0 --duration 30

Full guided audit against one scoped target:
    wifisentinel audit --interface wlan0 --bssid AA:BB:CC:DD:EE:FF \\
        --channel 6 --wordlist wordlists/rockyou.txt

Every active command requires config/scope.yaml to exist and list the
target BSSID/ESSID, and requires the operator to type I CONFIRM.
"""

from __future__ import annotations

import argparse
import sys

from .core.authorization import Scope, confirm_authorization
from .core.capture import HandshakeCapture, PMKIDCapture
from .core.cracker import Cracker
from .core.interface import InterfaceManager
from .core.report import generate_report
from .core.scanner import Scanner
from .utils.logger import get_logger

log = get_logger("cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifisentinel",
        description="Wireless security auditing toolkit (aircrack-ng / hcxtools / hashcat orchestration).",
    )
    parser.add_argument("--scope", default="config/scope.yaml", help="Path to scope.yaml (default: config/scope.yaml)")
    parser.add_argument("--yes", action="store_true", help="Skip interactive confirmation (still requires scope.yaml).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Discover nearby access points")
    p_scan.add_argument("--interface", required=True)
    p_scan.add_argument("--duration", type=int, default=30)
    p_scan.add_argument("--channel", type=int, default=None)

    p_audit = sub.add_parser("audit", help="Run a full capture + crack workflow against one scoped target")
    p_audit.add_argument("--interface", required=True)
    p_audit.add_argument("--bssid", required=True)
    p_audit.add_argument("--essid", default="target")
    p_audit.add_argument("--channel", required=True)
    p_audit.add_argument("--method", choices=["handshake", "pmkid"], default="handshake")
    p_audit.add_argument("--wordlist", required=True)
    p_audit.add_argument("--engine", choices=["aircrack", "hashcat"], default="aircrack")
    p_audit.add_argument("--listen-seconds", type=int, default=45)
    p_audit.add_argument("--deauth-count", type=int, default=5)
    p_audit.add_argument("--report", default="reports/report.html")

    sub.add_parser("monitor-on", help="Enable monitor mode on an adapter").add_argument("--interface", required=True)
    sub.add_parser("monitor-off", help="Disable monitor mode on an adapter").add_argument("--interface", required=True)

    return parser


def cmd_scan(args, scope: Scope) -> None:
    confirm_authorization(scope, assume_yes=args.yes)
    scanner = Scanner(args.interface)
    aps = scanner.scan_for(seconds=args.duration, channel=args.channel)
    print(f"\n{'BSSID':<20}{'CH':<5}{'PRIVACY':<10}{'PWR':<6}ESSID")
    for ap in aps:
        in_scope = "*" if scope.permits(bssid=ap.bssid, essid=ap.essid) else " "
        print(f"{in_scope}{ap.bssid:<19}{ap.channel:<5}{ap.privacy:<10}{ap.power:<6}{ap.essid}")
    print("\n(* = matches your configured scope)")


def cmd_audit(args, scope: Scope) -> None:
    if not scope.permits(bssid=args.bssid, essid=args.essid):
        log.error(
            "Target BSSID %s / ESSID '%s' is NOT listed in %s. Refusing to proceed. "
            "Add it to allowed_bssids / allowed_essids only if you have written authorization.",
            args.bssid, args.essid, args.scope if hasattr(args, "scope") else "scope.yaml",
        )
        sys.exit(1)

    confirm_authorization(scope, assume_yes=args.yes)

    captures, cracks, aps = [], [], []

    if args.method == "handshake":
        hc = HandshakeCapture(args.interface)
        result = hc.capture(
            bssid=args.bssid, channel=args.channel, essid=args.essid,
            listen_seconds=args.listen_seconds, deauth_count=args.deauth_count,
        )
        captures.append({"target": args.bssid, "result": result})
        if result.success:
            cracker = Cracker()
            if args.engine == "aircrack":
                crack_result = cracker.crack_with_aircrack(result.file_path, args.bssid, args.wordlist)
            else:
                log.error("Handshake .cap files need conversion to hashcat's 22000 format first "
                          "(hcxpcapngtool). Use --method pmkid, or convert manually.")
                crack_result = None
            if crack_result:
                cracks.append({"target": args.bssid, "result": crack_result})
    else:
        pc = PMKIDCapture(args.interface)
        result = pc.capture(bssid=args.bssid, listen_seconds=args.listen_seconds)
        captures.append({"target": args.bssid, "result": result})
        if result.success:
            cracker = Cracker()
            crack_result = cracker.crack_with_hashcat(result.file_path, args.wordlist)
            cracks.append({"target": args.bssid, "result": crack_result})

    report_path = generate_report(
        output_path=args.report,
        client_name=scope.client_name,
        authorization_reference=scope.authorization_reference,
        access_points=aps,
        captures=captures,
        cracks=cracks,
    )
    print(f"\nReport written to: {report_path}")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    im = InterfaceManager()

    if args.command == "monitor-on":
        print(im.start_monitor_mode(args.interface))
        return
    if args.command == "monitor-off":
        im.stop_monitor_mode(args.interface)
        return

    try:
        scope = Scope.from_file(args.scope)
    except (FileNotFoundError, ValueError) as exc:
        log.error(str(exc))
        sys.exit(1)

    if args.command == "scan":
        cmd_scan(args, scope)
    elif args.command == "audit":
        cmd_audit(args, scope)


if __name__ == "__main__":
    main()
