import requests
import config

from analyzer.models import Alert

# Represents the reputation result for a given IP address, enriched from AbuseIPDB.
# ip: IP address that was checked.
# score: Abuse confidence score from 0 to 100 (higher = more malicious).
# country: Country code where the IP is registered (e.g. PT, RU, CN).
# isp: Internet Service Provider associated with the IP.
# confirmed: True if score is above the configured threshold in config.py (score >= ABUSEIPDB_MIN_SCORE).
# total_reports: Total number of times this IP has been reported by the community.
# last_reported: Timestamp of the most recent abuse report (or "N/A" if never reported).
class IPReputation:
    def __init__(self, ip: str, score: int, country: str, isp: str, confirmed: bool, total_reports: int, last_reported: str):
        self.ip = ip
        self.score = score
        self.country = country
        self.isp = isp
        self.confirmed = confirmed
        self.total_reports = total_reports
        self.last_reported = last_reported

    def __repr__(self):
        return (
            f"IPReputation(ip={self.ip}, score={self.score}, country={self.country}, "
            f"confirmed={self.confirmed}, total_reports={self.total_reports}, last_reported={self.last_reported})"
        )


# Query AbuseIPDB for the reputation of a given IP address.
# Returns an IPReputation object or None if the request fails.
def check_ip(ip: str) -> IPReputation | None:
    headers = {
        "Key": config.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
    }

    try:
        response = requests.get(config.ABUSEIPDB_URL, headers=headers, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()["data"]

        return IPReputation(
            ip=data["ipAddress"],
            score=data["abuseConfidenceScore"],
            country=data["countryCode"],
            isp=data["isp"],
            confirmed=data["abuseConfidenceScore"] >= config.ABUSEIPDB_MIN_SCORE,
            total_reports=data["totalReports"],
            last_reported=data["lastReportedAt"] or "N/A",
        )

    except requests.RequestException as e:
        print(f"  [!] AbuseIPDB request failed for {ip}: {e}")
        return None
    
    
# Check all unique IPs from a list of alerts against AbuseIPDB.
# Enriches each alert's detail if the IP is confirmed malicious.
# Returns a dict mapping each IP to its IPReputation result.
def enrich_alerts(alerts: list[Alert]) -> dict[str, IPReputation | None]:
    results = {}

    for alert in alerts:
        if alert.ip not in results:
            print(f"  [*] Checking {alert.ip}...")
            results[alert.ip] = check_ip(alert.ip)

        rep = results[alert.ip]
        
        # Enrich alert detail if IP is confirmed malicious by AbuseIPDB
        if rep and rep.confirmed:
            alert.detail += f" - AbuseIPDB confirmed malicious (score: {rep.score}/100, reports: {rep.total_reports}, last: {rep.last_reported})"

    return results