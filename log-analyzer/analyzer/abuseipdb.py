import requests
import config

# Represents the reputation result for a given IP.
# ip: IP address that was checked
# score: Abuse confidence score from 0 to 100 (higher = more malicious)
# country: Country code where the IP is registered (e.g. PT, RU, CN)
# isp: Internet Service Provider associated with the IP
# confirmed: True if score is above the configured threshold in config.py (confirmed = score >= 50)
class IPReputation:
    def __init__(self, ip: str, score: int, country: str, isp: str, confirmed: bool):
        self.ip = ip
        self.score = score
        self.country = country
        self.isp = isp
        self.confirmed = confirmed

    def __repr__(self):
        return (
            f"IPReputation(ip={self.ip}, score={self.score}, "
            f"country={self.country}, confirmed={self.confirmed})"
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
        )

    except requests.RequestException as e:
        print(f"  [!] AbuseIPDB request failed for {ip}: {e}")
        return None
    
    
# Check all unique IPs from a list of alerts against AbuseIPDB.
# Returns a dict mapping each IP to its IPReputation result.
def enrich_alerts(ips: list[str]) -> dict[str, IPReputation | None]:
    results = {}
    for ip in set(ips):
        print(f"  [*] Checking {ip}...")
        results[ip] = check_ip(ip)
    return results