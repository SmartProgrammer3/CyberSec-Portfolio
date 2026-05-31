import re

from analyzer.models import Alert, LogEntry

# Detect Cross-Site Scripting (XSS) attempts.
#
# XSS is an attack where malicious JavaScript code is injected into a web page.
# When another user visits the page, the code executes in their browser, not on the server.
# This allows attackers to steal session cookies, redirect users to phishing sites, capture keystrokes or modify page content.
# It is consistently ranked in the OWASP Top 10 most critical web vulnerabilities.
# Note: only GET-based XSS is detectable in Apache/Nginx access.log!
# POST-based XSS payloads (more modern) are in the request body which is not logged by default.

def _detect_xss(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    alerts.extend(_xss_known_patterns(entries))
    alerts.extend(_xss_encoded_payloads(entries))
    
    return alerts


# Rule 1: Known XSS patterns in request path.
# Attacker injects JavaScript to steal session cookies.
# Example: /search?q=<script>alert(document.cookie)</script>
XSS_PATTERN = re.compile(
    r"(<script|</script>|javascript:|onerror=|onload=|onclick=|alert\(|document\.cookie|<img\s+src=x)",
    re.IGNORECASE
)

def _xss_known_patterns(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if XSS_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="XSS",
                severity="High",
                detail=f"XSS pattern detected in path: {entry.path[:80]}",
            ))

    return alerts


# Rule 2: URL-encoded XSS payloads.
# Attackers encode payloads to bypass basic input filters.
# Example: /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
# Example: %3Cscript%3E instead of <script>
XSS_ENCODED_PATTERN = re.compile(
    r"(%3Cscript|%3C%2Fscript|%6Favascript|%6javascript|%3Cimg|onerror%3D|onload%3D)",
    re.IGNORECASE
)

def _xss_encoded_payloads(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if XSS_ENCODED_PATTERN.search(entry.path) and entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="XSS",
                severity="High",
                detail=f"URL-encoded XSS payload detected in path: {entry.path[:80]}",
            ))

    return alerts