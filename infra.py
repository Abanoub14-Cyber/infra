#!/usr/bin/env python3
"""INFRA — Infrastructure Intelligence Through Passive Observation.

Usage:
  sudo python3 infra.py capture [-i eth0] [-t 8] [--gateway]
  python3 infra.py replay <file.pcap>
  python3 infra.py analyze [--html]
  python3 infra.py status
  python3 infra.py diff <report1.json> <report2.json>
"""

import argparse
import json
import signal
import sys
import threading
from pathlib import Path

from infra import setup_logging
from infra.capture import CaptureEngine
from infra.db import InfraDB
from infra.intelligence import IntelligenceEngine
from infra.replay import PcapReplay
from infra.report import diff_reports, render_html, render_json

LOGO = "\033[96m" + r"""
   ██╗███╗   ██╗███████╗██████╗  █████╗
   ██║████╗  ██║██╔════╝██╔══██╗██╔══██╗
   ██║██╔██╗ ██║█████╗  ██████╔╝███████║
   ██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║
   ██║██║ ╚████║██║     ██║  ██║██║  ██║
   ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝
""" + "\033[0m   Infrastructure Intelligence — by Line-Out\n"


def cmd_capture(args, log) -> int:
    log.info("=" * 60)
    log.info("INFRA CAPTURE STARTING")
    log.info(f"Interface:    {args.interface or 'all'}")
    log.info(f"Gateway mode: {args.gateway}")
    log.info(f"Database:     {args.db}")
    log.info(f"Duration:     {args.hours or 'unlimited'}h")
    log.info("=" * 60)

    # Confirm authorization for gateway mode BEFORE doing anything
    if args.gateway:
        from infra.gateway import require_authorization
        if not require_authorization():
            return 2

    engine = CaptureEngine(
        db_path=args.db,
        interface=args.interface,
        gateway=args.gateway,
    )

    def handle_stop(signum, frame):
        print(f"\n  Stopping... ({engine.packets:,} packets captured)")
        engine.stop()
        # Don't sys.exit here — let main loop finish cleanup

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    if args.hours:
        timer = threading.Timer(args.hours * 3600, engine.stop)
        timer.daemon = True
        timer.start()
        print(f"  Auto-stop in {args.hours}h\n")

    try:
        engine.start(on_status=lambda m: print(m))
    except PermissionError:
        print(
            "\n  ❌ Permission denied. Run with: sudo python3 infra.py capture",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        engine.stop()

    print(f"\n  Database: {args.db}")
    print(f"  Log:      infra.log")
    print(f"  Next:     python3 infra.py analyze --db {args.db}")
    return 0


def cmd_replay(args, log) -> int:
    log.info("=" * 60)
    log.info("INFRA REPLAY MODE")
    log.info(f"PCAP:     {args.pcap}")
    log.info(f"Database: {args.db}")
    log.info("=" * 60)

    replay = PcapReplay(pcap_path=args.pcap, db_path=args.db)
    count = replay.replay()
    print(f"\n  Replayed {count:,} packets")
    print(f"  Database: {args.db}")
    print(f"  Next:     python3 infra.py analyze --db {args.db}")
    return 0 if count > 0 else 1


def cmd_analyze(args, log) -> int:
    log.info("=" * 60)
    log.info("INFRA ANALYSIS")
    log.info(f"Database: {args.db}")
    log.info("=" * 60)

    if not Path(args.db).exists():
        print(f"  ❌ Database not found: {args.db}", file=sys.stderr)
        return 1

    engine = IntelligenceEngine(args.db)
    report = engine.analyze()

    render_json(report, args.output)

    if args.html:
        html_path = args.output.replace(".json", ".html")
        if html_path == args.output:
            html_path = args.output + ".html"
        render_html(report, html_path)

    m = report["meta"]
    print(f"\n  Duration:      {m['hours']}h")
    print(f"  Flows:         {m['flows']:,}")
    print(f"  Devices:       {m['devices']}")
    print(f"  Data observed: {m['bytes'] / 1_000_000:.0f} MB")
    print(f"  SaaS apps:     {len(report['saas_inventory'])}")
    print(f"  Patterns:      {len(report['recurring_patterns'])}")
    print(f"  Dependencies:  {len(report['critical_dependencies'])}")
    print(f"  Anomalies:     {len(report['anomalies'])}")
    print(f"  JA4 apps:      {len(report['ja4_applications'])}")

    bh = report.get("business_hours", {})
    if bh:
        print(f"  Business hrs:  {bh.get('start', '?')} — "
              f"{bh.get('end', '?')} (peak {bh.get('peak', '?')})")
    topo = report.get("network_topology", {})
    if topo.get("vlans"):
        print(f"  VLANs:         {topo['vlans']}")
    if topo.get("switches"):
        print(f"  Switches:      {len(topo['switches'])} via LLDP")

    print(f"\n  Report (JSON): {args.output}")
    if args.html:
        print(f"  Report (HTML): {html_path}")
    print(f"  Log:           infra.log")
    return 0


def cmd_status(args, log) -> int:
    if not Path(args.db).exists():
        print(f"  ❌ No database found at {args.db}", file=sys.stderr)
        return 1
    db = InfraDB(args.db)
    first, last = db.time_range()
    hours = round((last - first) / 3600, 2) if first and last else 0
    print(f"  Database:  {args.db}")
    print(f"  Duration:  {hours}h")
    print(f"  Flows:     {db.count('flows'):,}")
    print(f"  Devices:   {db.count('devices')}")
    print(f"  Domains:   {db.count_distinct_sni()}")
    if first:
        from datetime import datetime
        print(f"  First pkt: {datetime.fromtimestamp(first).isoformat()}")
    if last:
        from datetime import datetime
        print(f"  Last pkt:  {datetime.fromtimestamp(last).isoformat()}")
    db.close()
    return 0


def cmd_diff(args, log) -> int:
    diff = diff_reports(args.report1, args.report2)
    print(json.dumps(diff, indent=2, default=str))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="INFRA — Infrastructure Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 infra.py capture -i eth0 -t 8\n"
            "  python3 infra.py replay sample.pcap\n"
            "  python3 infra.py analyze --html\n"
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=False)

    cap = sub.add_parser("capture", help="Start passive capture")
    cap.add_argument("-i", "--interface", help="Network interface (e.g. eth0)")
    cap.add_argument("-t", "--hours", type=float, help="Auto-stop after N hours")
    cap.add_argument("--gateway", action="store_true",
                     help="ARP gateway mode — REQUIRES WRITTEN AUTHORIZATION")
    cap.add_argument("--db", default="infra.db", help="Database file")

    rep = sub.add_parser("replay", help="Replay a PCAP file")
    rep.add_argument("pcap", help="Path to PCAP file (not PCAPNG)")
    rep.add_argument("--db", default="replay.db", help="Database file")

    ana = sub.add_parser("analyze", help="Generate report")
    ana.add_argument("--db", default="infra.db", help="Database file")
    ana.add_argument("-o", "--output", default="infra-report.json",
                     help="Output JSON path")
    ana.add_argument("--html", action="store_true",
                     help="Also render HTML report")

    sta = sub.add_parser("status", help="Show capture stats")
    sta.add_argument("--db", default="infra.db")

    dif = sub.add_parser("diff", help="Compare two reports")
    dif.add_argument("report1", help="First report (JSON)")
    dif.add_argument("report2", help="Second report (JSON)")

    args = parser.parse_args()
    print(LOGO)
    log = setup_logging()

    if args.cmd == "capture":
        return cmd_capture(args, log)
    elif args.cmd == "replay":
        return cmd_replay(args, log)
    elif args.cmd == "analyze":
        return cmd_analyze(args, log)
    elif args.cmd == "status":
        return cmd_status(args, log)
    elif args.cmd == "diff":
        return cmd_diff(args, log)
    else:
        parser.print_help()
        print("\n  Quick start:")
        print("    sudo python3 infra.py capture -i eth0 -t 8")
        print("    python3 infra.py analyze --html")
        return 0


if __name__ == "__main__":
    sys.exit(main())
