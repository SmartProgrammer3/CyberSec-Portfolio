import re

from collections import defaultdict
from datetime import timedelta

from analyzer.models import Alert, LogEntry

# Detect Path Traversal attempts.
#
# Path Traversal is an attack where the attacker manipulates file path variables to access files and directories
# stored outside the web root folder. By using sequences like "../" the attacker can traverse the directory
# structure and reach sensitive system files such as /etc/passwd, /etc/shadow or configuration files
# containing database credentials.
# It is listed in the OWASP Top 10 most critical web vulnerabilities.

def _detect_path_traversal(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    alerts.extend(_traversal_sequences(entries))
    alerts.extend(_traversal_sensitive_files(entries))
    alerts.extend(_traversal_webshell(entries))
    alerts.extend(_traversal_repeated(entries))
    
    return alerts


# Rule 1: Directory traversal sequences.
# Detects ../ sequences and URL-encoded equivalents in request path.
# Example: /files/../../../etc/passwd - attacker traverses directories to reach system files.
TRAVERSAL_SEQUENCES_PATTERN = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f)",
    re.IGNORECASE
)

def _traversal_sequences(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if TRAVERSAL_SEQUENCES_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="Path Traversal",
                severity="High",
                detail=f"Directory traversal sequence detected in path: {entry.path[:80]}",
            ))

    return alerts


# Rule 2: Sensitive file access.
# Detects direct references to critical system files in request path.
# Attackers may access these files directly without using ../ sequences if the server is misconfigured or the file is accessible from the web root.
# Example: /etc/shadow - attacker attempts to read the system password file directly.
TRAVERSAL_SENSITIVE_PATTERN = re.compile(
    r"(/etc/passwd|/etc/shadow|/proc/self)",
    re.IGNORECASE
)

def _traversal_sensitive_files(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if TRAVERSAL_SENSITIVE_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="Path Traversal",
                severity="Critical",
                detail=f"Sensitive file access detected in path: {entry.path[:80]}",
            ))

    return alerts


# Rule 3: Web shell access.
# Detects attempts to access known web shell filenames in request path.
# A web shell is a malicious script uploaded to a server that gives the attacker remote control over the system - executing commands, reading files, exfiltrating data.
# Example: /uploads/shell.php - attacker uploaded a web shell and is trying to execute it.
WEBSHELL_PATTERN = re.compile(
    r"(shell\.php|cmd\.php|c99\.php|r57\.php|webshell\.php|\.asp|\.aspx|\.jsp)",
    re.IGNORECASE
)

def _traversal_webshell(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if WEBSHELL_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="Path Traversal",
                severity="Critical",
                detail=f"Web shell access detected in path: {entry.path[:80]}",
            ))

    return alerts


# Rule 4: Repeated traversal attempts.
# Detects same IP making 5+ traversal attempts within 60 seconds.
# Indicates automated scanning tools probing multiple paths to find accessible system files.
# Example: scanner trying /etc/passwd, /etc/shadow, /proc/self/environ in rapid succession.
def _traversal_repeated(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    ip_events = defaultdict(list)

    for entry in entries:
        if TRAVERSAL_SEQUENCES_PATTERN.search(entry.path) or TRAVERSAL_SENSITIVE_PATTERN.search(entry.path):
            ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        window = timedelta(seconds=60)
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= window]
            if len(window_hits) >= 5:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Path Traversal",
                    severity="High",
                    detail=f"{len(window_hits)} traversal attempts in 60s - automated scanning detected",
                    count=len(window_hits)
                ))
                break

    return alerts