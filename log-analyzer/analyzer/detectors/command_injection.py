import re

from analyzer.models import Alert, LogEntry

# Detect Command Injection attempts.
#
# Command Injection is an attack where the attacker injects operating system commands through web application parameters. 
# If the server passes these parameters directly to the system without validation, the commands execute with the web server's permissions.
# This gives the attacker full control over the server -> reading files, creating backdoors, deleting data or pivoting to internal systems.
# It is one of the most devastating web vulnerabilities and it is consistently ranked in the OWASP Top 10 most critical web vulnerabilities.
# Note: only GET-based Command Injection is detectable in Apache/Nginx access.log!
# POST-based payloads (more modern) are in the request body which is not logged by default.

def _detect_command_injection(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    alerts.extend(_cmd_known_patterns(entries))
    alerts.extend(_cmd_encoded_payloads(entries))
    
    return alerts


# Rule 1: Known command injection patterns in request path.
# Attacker appends a system command after a legitimate parameter.
# Example: /ping?host=192.168.1.1;whoami
KNOWN_CMD_INJECTIONS_PATTERNS = re.compile(
    r"(;whoami|;id|;ls|;cat|;pwd|;uname|;ifconfig|;netstat|;wget|;curl|"
    r"\|whoami|\|id|\|ls|\|cat|\|pwd|\|uname|"
    r"&&whoami|&&id|&&ls|&&cat|"
    r"`whoami`|`id`|`ls`|`cat`)",
    re.IGNORECASE
)

def _cmd_known_patterns(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if KNOWN_CMD_INJECTIONS_PATTERNS.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="Command Injection",
                severity="Critical",
                detail=f"Command injection pattern detected in path: {entry.path[:80]}",
            ))

    return alerts


# Rule 2: URL-encoded command injection payloads.
# Attackers encode payloads to bypass basic input filters.
# Example: %3Bwhoami instead of ;whoami, %7Cid instead of |id
KNOWN_CMD_INJECTIONS_ENCODED_PATTERN = re.compile(
    r"(%3Bwhoami|%3Bid|%3Bls|%3Bcat|%3Bpwd|%3Buname|"
    r"%7Cwhoami|%7Cid|%7Cls|%7Ccat|"
    r"%26%26whoami|%26%26id|%26%26ls)",
    re.IGNORECASE
)
def _cmd_encoded_payloads(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if KNOWN_CMD_INJECTIONS_ENCODED_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="Command Injection",
                severity="Critical",
                detail=f"URL-encoded command injection payload detected in path: {entry.path[:80]}",
            ))

    return alerts