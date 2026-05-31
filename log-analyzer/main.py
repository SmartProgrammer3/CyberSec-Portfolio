import argparse
import sys
import time

from analyzer.parser import parse_file, parse_line
from analyzer.detector import detect
from analyzer.abuseipdb import enrich_alerts
from analyzer.reporter import generate
from notifier.telegram import send_alert, send_summary

# Entry point of the log analyzer.
# Supports two modes:
# - Batch mode (default): parses the entire log file, detects attacks, enriches IPs with AbuseIPDB and generates a PDF report.
# - Watch mode (--watch): monitors the log file in real time (detects attacks, enriches IPs with AbuseIPDB) and sends Telegram alerts for each detected attack.
def main():
    args = _parse_args()

    if args.watch:
        _watch_mode(args.log)
    else:
        _batch_mode(args.log)


def _batch_mode(log_path: str):
    print(f"\n[*] Reading log file: {log_path}")
    entries = parse_file(log_path)
    print(f"[*] Parsed {len(entries)} log entries")

    print(f"[*] Running detection rules...")
    alerts = detect(entries)

    if not alerts:
        print("[+] No attacks detected.")
        sys.exit(0)

    print(f"[!] {len(alerts)} attack(s) detected.")

    print(f"[*] Enriching IPs with AbuseIPDB...")
    reputation = enrich_alerts(alerts)

    print(f"[*] Generating and saving PDF report...")
    report_path = generate(alerts, log_path, len(entries), reputation)
    print(f"[+] Report saved to {report_path}")

    print(f"[*] Sending Telegram summary...")
    send_summary(alerts, len(entries), log_path, report_path)


def _watch_mode(log_path: str):
    print(f"\n[*] Watching log file: {log_path}")
    print(f"[*] Waiting for new entries... (Ctrl+C to stop)\n")
    
    with open(log_path, "r") as f:
        # Jump to end of file — ignore existing history
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            entry = parse_line(line.strip())
            if not entry:
                continue

            # Run detection on single entry wrapped in a list
            alerts = detect([entry])

            for alert in alerts:
                print(f"  [!] [{alert.severity.upper()}] {alert.attack_type} from {alert.ip}")
                send_alert(alert.attack_type, alert.ip, alert.severity, alert.detail)


# Parse command line arguments.
def _parse_args():
    parser = argparse.ArgumentParser(
        description="Web server log analyzer — detects common attack patterns"
    )
    
    parser.add_argument(
        "--log",
        required = True,
        help = "Path to the log file to analyze (e.g. samples/access.log)"
    )
    
    parser.add_argument(
        "--watch",
        action = "store_true",
        help = "Watch mode — monitor the log file in real time and send Telegram alerts"
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()