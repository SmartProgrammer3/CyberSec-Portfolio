import re

from collections import defaultdict
from datetime import timedelta

from analyzer.models import Alert, LogEntry

# Detect SQL Injection attempts.
#
# SQL Injection is an attack where malicious SQL code is inserted into a query through user input, allowing attackers to read, modify or destroy database data.
# It is listed in the OWASP Top 10 most critical web vulnerabilities.

def _detect_sql_injection(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    alerts.extend(_sqli_known_patterns(entries))
    alerts.extend(_sqli_encoded_payloads(entries))
    alerts.extend(_sqli_blind_probing(entries))
    alerts.extend(_sqli_error_based(entries))
    
    return alerts


# Known SQLi patterns in request path.
# Rule 1: Covers UNION-based, boolean-based, time-based and stacked queries.
# Example: /users?id=1' UNION SELECT username,password FROM users--
SQLI_PATTERN = re.compile(
    r"(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
    r"or\s+'1'\s*=\s*'1|sleep\s*\(|benchmark\s*\(|--\s*$|;--)",
    re.IGNORECASE
)

def _sqli_known_patterns(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if SQLI_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="SQL Injection",
                severity="Critical",
                detail=f"SQLi pattern detected in path: {entry.path[:80]}",
            ))

    return alerts


# Rule 2: URL-encoded SQLi payloads.
# Attackers encode payloads to bypass basic filters.
# Example: /search?q=%27%20OR%20%271%27%3D%271
SQLI_ENCODED_PATTERN = re.compile(
    r"(%27|%22|%3D|%3B|%2D%2D|%23|%2F%2A|union%20|select%20|insert%20|drop%20)",
    re.IGNORECASE
)

def _sqli_encoded_payloads(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if SQLI_ENCODED_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="SQL Injection",
                severity="Critical",
                detail=f"URL-encoded SQLi payload detected in path: {entry.path[:80]}",
            ))

    return alerts


# Rule 3: Blind SQLi probing.
# Same IP making 10+ requests to the same endpoint within 60 seconds.
# Example: /users?id=1, /users?id=2, /users?id=3 -> inferring data through response differences.
def _sqli_blind_probing(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    ip_endpoint_times = defaultdict(list)
    for entry in entries:
        if "?" in entry.path:
            base_path = entry.path.split("?")[0]
            ip_endpoint_times[(entry.ip, base_path)].append(entry.time)

    for (ip, endpoint), times in ip_endpoint_times.items():
        if ip in seen:
            continue
        times.sort()
        window = timedelta(seconds=60)
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= window]
            if len(window_hits) >= 10:
                seen.add(ip)
                alerts.append(Alert(
                    ip=ip,
                    attack_type="SQL Injection",
                    severity="Critical",
                    detail=f"Blind SQLi probing - {len(window_hits)} requests to {endpoint} in 60s",
                    count=len(window_hits)
                ))
                break

    return alerts


# Rule 4: Error-based SQLi.
# Server returns 500 after a request matching SQLi patterns.
# Example: /users?id=1' causes a database error and the server returns 500.
ERROR_STATUS = 500

def _sqli_error_based(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if entry.status == ERROR_STATUS and SQLI_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="SQL Injection",
                severity="Critical",
                detail=f"Error-based SQLi - server returned 500 after SQLi payload in path: {entry.path[:80]}",
            ))

    return alerts