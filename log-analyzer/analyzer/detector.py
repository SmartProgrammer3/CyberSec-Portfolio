import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from analyzer.parser import LogEntry

# SQL Injection patterns (a little help with - https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet).
# Covers UNION-based, boolean-based, time-based and stacked queries.
SQLI_PATTERN = re.compile(
    r"(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
    r"or\s+'1'\s*=\s*'1|sleep\s*\(|benchmark\s*\(|--\s*$|;--)",
    re.IGNORECASE
)

# Path traversal patterns.
# Sequences and direct sensitive file access.
TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/etc/shadow|/proc/self)",
    re.IGNORECASE
)

# Represents a detected attack.
# ip: IP address of the attacker (Answers Who?).
# attack_type: Type of attack (Brute Force, SQL Injection, PATH Traversal, Vulnerability Scanning) (Answers What?).
# severity: Severity level — Low, Medium, High or Critical (Answers How serious?).
# detail: Human-readable description of what was detected (Answers Why?).
# count: Number of occurrences that triggered the alert (Answers How many?).
@dataclass
class Alert:
    ip: str
    attack_type: str
    severity: str       
    detail: str
    count: int = 1
    
   
# Run all detection rules against a list of log entries.
# Returns a list of Alert objects, one per detected attack.
def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    alerts.extend(_detect_brute_force(entries))
    alerts.extend(_detect_sql_injection(entries))
    alerts.extend(_detect_path_traversal(entries))
    alerts.extend(_detect_vulnerability_scanning(entries))
    return alerts


# Detect brute force attacks.
# Rule: 10+ requests with status 401 or 403 from the same IP within 60 seconds.
# Severity: High. Because repeated failed authentication attempts indicate an automated attack trying to guess credentials. 
#                  If successful, gives the attacker full access to the compromised account.
def _detect_brute_force(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    # Group 401/403 timestamps by IP
    ip_events = defaultdict(list)
    for entry in entries:
        if entry.status in (401, 403):
            ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        window = timedelta(seconds=60)
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= window]
            if len(window_hits) >= 10:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Brute Force",
                    severity="High",
                    detail=f"{len(window_hits)} Failed auth attempts in 60s",
                    count=len(window_hits)
                ))
                break  

    return alerts


# Detect SQL Injection attempts.
# Rule: request path matches known SQLi patterns.
# Severity: Critical. Because a successful SQLi can expose or destroy the entire database.
def _detect_sql_injection(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set() 

    for entry in entries:
        if SQLI_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="SQL Injection",
                severity="Critical",
                detail=f"SQLi Pattern detected in path: {entry.path[:80]}",
            ))

    return alerts


# Detect path traversal attempts.
# Rule: request path contains ../ sequences or direct references to sensitive files.
# Severity: High. Because attacker may be attempting to read system files outside the web root.
def _detect_path_traversal(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set() 

    for entry in entries:
        if TRAVERSAL_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="Path Traversal",
                severity="High",
                detail=f"Traversal pattern detected in path: {entry.path[:80]}",
            ))

    return alerts


# Detect vulnerability scanning.
# Rule: 20+ requests returning 404 from the same IP within 60 seconds.
# Severity: medium. Because indicates automated probing for known vulnerabilities or exposed files.
def _detect_vulnerability_scanning(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    # Group 404 timestamps by IP
    ip_events = defaultdict(list)
    for entry in entries:
        if entry.status == 404:
            ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        window = timedelta(seconds=60)
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= window]
            if len(window_hits) >= 20:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Vulnerability Scan",
                    severity="Medium",
                    detail=f"{len(window_hits)} 404s in 60s",
                    count=len(window_hits)
                ))
                break  

    return alerts