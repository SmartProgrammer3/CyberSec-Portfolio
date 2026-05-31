from collections import defaultdict
from datetime import timedelta

from analyzer.models import Alert, LogEntry

# Detect brute force attacks.
#
# Brute force is an attack method where an automated tool repeatedly tries different credentials (username/password combinations) until it finds a valid one.
# It is one of the most common attacks against web applications, especially login endpoints.

def _detect_brute_force(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    alerts.extend(_brute_force_auth_failures(entries))
    alerts.extend(_brute_force_high_rate(entries))
    alerts.extend(_brute_force_login_hammering(entries))
    alerts.extend(_brute_force_distributed(entries))
    
    return alerts


# Rule 1: Repeated authentication failures.
# Detects 10+ requests returning status 401 or 403 from the same IP within 60 seconds.
# Example: Attacker tries 10 different passwords on /login in under a minute and the server returns 401 (Unauthorized) or 403 (Forbidden) on each attempt.
def _brute_force_auth_failures(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
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
                    detail=f"{len(window_hits)} failed auth attempts in 60s!",
                    count=len(window_hits)
                ))
                break

    return alerts


# Rule 2: High request rate regardless of status code.
# Detects 100+ requests from the same IP within 10 seconds.
# Example: Automated tool sending hundreds of requests per second to bypass rate limiting.
def _brute_force_high_rate(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    ip_events = defaultdict(list)
    for entry in entries:
        ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        window = timedelta(seconds=10)
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= window]
            if len(window_hits) >= 100:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Brute Force",
                    severity="High",
                    detail=f"{len(window_hits)} requests in 10s - Automated tooling detected!",
                    count=len(window_hits)
                ))
                break

    return alerts


# Rule 3: Login Endpoint hammering via POST requests.
# Detects 20+ POST requests to a known login endpoint from the same IP within 60 seconds.
# Example: Credential stuffing tool targeting /wp-login.php with leaked password lists.
LOGIN_ENDPOINTS_CONSIDERED = {"/login", "/admin", "/wp-login.php", "/signin", "/auth", "/api/login"}

def _brute_force_login_hammering(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    ip_events = defaultdict(list)
    for entry in entries:
        if entry.method == "POST" and any(entry.path.startswith(ep) for ep in LOGIN_ENDPOINTS_CONSIDERED):
            ip_events[entry.ip].append(entry.time)

    for ip, times in ip_events.items():
        times.sort()
        window = timedelta(seconds=60)
        for i, t in enumerate(times):
            window_hits = [x for x in times[i:] if x - t <= window]
            if len(window_hits) >= 20:
                alerts.append(Alert(
                    ip=ip,
                    attack_type="Brute Force",
                    severity="High",
                    detail=f"{len(window_hits)} POST requests to login endpoint in 60s!",
                    count=len(window_hits)
                ))
                break

    return alerts


# Rule 4: Distributed brute force.
# 10+ different IPs targeting the same login endpoint with 20+ total requests within 60 seconds.
# Example: Botnet with 50 different IPs all hitting /login within 60 seconds
#          each IP sends few requests (escapes per-IP rate limiting) but together reveal a coordinated attack.    
def _brute_force_distributed(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    # Group entries by endpoint
    seen_endpoints = set()
    endpoint_entries = defaultdict(list)
    for entry in entries:
        if entry.method == "POST" and any(entry.path.startswith(ep) for ep in LOGIN_ENDPOINTS_CONSIDERED):
            base = next(ep for ep in LOGIN_ENDPOINTS_CONSIDERED if entry.path.startswith(ep))
            endpoint_entries[base].append(entry)

    for endpoint, ep_entries in endpoint_entries.items():
        ep_entries.sort(key=lambda e: e.time)
        window = timedelta(seconds=60)

        for i, e in enumerate(ep_entries):
            window_entries = [x for x in ep_entries[i:] if x.time - e.time <= window]
            unique_ips = {x.ip for x in window_entries}

            if len(window_entries) >= 20 and len(unique_ips) >= 10:
                if endpoint not in seen_endpoints:
                    seen_endpoints.add(endpoint)
                    for ip in unique_ips:
                        alerts.append(Alert(
                            ip=ip,
                            attack_type="Brute Force",
                            severity="High",
                            detail=f"Distributed attack - part of {len(unique_ips)} IPs targeting {endpoint} in 60s",
                            count=len(window_entries)
                        ))
                break

    return alerts