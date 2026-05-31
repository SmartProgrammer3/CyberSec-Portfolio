from analyzer.models import Alert, LogEntry

# Detect HTTP Method Tampering attempts.
#
# HTTP Method Tampering is an attack where the attacker uses unexpected HTTP methods to probe or exploit web application endpoints. 
# Methods like TRACE, DELETE or PUT are rarely used in normal web traffic and their presence often indicates reconnaissance or an attempt to bypass access controls.
# Example: TRACE requests can be used to steal cookies via Cross-Site Tracing (XST).
# Note: PUT and DELETE on /api/ endpoints are excluded as they are legitimate REST API methods.

# HTTP methods that should never appear in normal web traffic.
HTTP_SUSPICIOUS_METHODS = {"DELETE", "PUT", "TRACE", "CONNECT", "PATCH"}

# Endpoints that legitimately accept PUT/DELETE (REST APIs) -> exclude from detection.
REST_API_PREFIXES = {"/api/"}

def _detect_http_method_tampering(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    seen = set()

    for entry in entries:
        if entry.method not in HTTP_SUSPICIOUS_METHODS:
            continue
        
        if any(entry.path.startswith(prefix) for prefix in REST_API_PREFIXES):
            continue
        
        if entry.ip not in seen:
            seen.add(entry.ip)
            alerts.append(Alert(
                ip=entry.ip,
                attack_type="HTTP Method Tampering",
                severity="Low",
                detail=f"Suspicious HTTP method {entry.method} used on path: {entry.path[:80]}",
            ))

    return alerts