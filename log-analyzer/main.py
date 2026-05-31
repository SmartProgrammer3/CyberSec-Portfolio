import argparse
import sys

from analyzer.parser import parse_file
from analyzer.detector import detect
from analyzer.abuseipdb import enrich_alerts


# Entry point of the log analyzer.
# Parses the log file, runs the detection rules and prints the results to the terminal.
def main():
    args = _parse_args()

    print(f"\n[*] Reading log file: {args.log}")
    entries = parse_file(args.log)
    print(f"[*] Parsed {len(entries)} log entries")

    print(f"[*] Running detection rules...\n")
    alerts = detect(entries)

    if not alerts:
        print("[+] No attacks detected.")
        sys.exit(0)

    print(f"[!] {len(alerts)} attack(s) detected:\n")

    print(f"[*] Enriching IPs with AbuseIPDB...\n")
    reputation = enrich_alerts([alert.ip for alert in alerts])

    for alert in alerts:
        rep = reputation.get(alert.ip)
        print(f"  [{alert.severity.upper()}] {alert.attack_type}")
        print(f"  IP        : {alert.ip}")
        print(f"  Detail    : {alert.detail}")
        print(f"  Count     : {alert.count}")
        if rep:
            print(f"  AbuseScore: {rep.score}/100 | Country: {rep.country} | ISP: {rep.isp}")
            print(f"  Confirmed : {'YES' if rep.confirmed else 'NO'}")
        print()


def _parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Web server log analyzer — detects common attack patterns"
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to the log file to analyze (e.g. samples/access.log)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()