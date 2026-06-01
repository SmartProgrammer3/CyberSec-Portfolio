"""
Check via "Have I Been Pwned API" if the password was pwned!

Have I Been Pwned (HIBP) is a service created by security researcher Troy Hunt that aggregates billions of passwords exposed in real-world data breaches.
Checking a password against this database is one of the most effective ways to determine whether it has been compromised.
Reference: https://haveibeenpwned.com/Passwords

Sending the full password to an external API would be a serious security risk.

HIBP solves this using a technique called k-anonymity (https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange):
    1. Hash the password locally using SHA-1.
        Example: "password" → "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        
    2. Send only the first 5 characters of the hash (the prefix) to the API.
       Example: "5BAA6"
       
    3. The API returns all hashes in its database that start with that prefix
       (typically several hundred entries), without knowing which one we are checking.
       
    4. Search the returned list locally for our hash suffix (remaining 35 characters).
       Example: suffix → "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    
    5. If the suffix is found, the password has been exposed in a breach.
       The response also includes how many times it appeared across all breaches.

Note: This means the full password or its complete hash never leaves the local machine.
    The API only ever sees a 5-character prefix, which could match hundreds of different hashes.
"""

import hashlib
import urllib.request
 
from checker.models import CheckResult

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
HASH_PREFIX_LENGTH = 5


# Hash the password using SHA-1 and return the result in uppercase hexadecimal.
def _hash_password(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
 
 
# Send the 5-character hash prefix to the HIBP API and return the raw response body.
def _query_hibp_api(prefix: str) -> str:
    url = HIBP_API_URL + prefix
    
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8")
    

# Search the API response for our hash suffix and return the breach count.
# Each line in the response has the format: SUFFIX:COUNT
# If the suffix is found, return the count as an integer.
# If not found, return 0 (the password has not appeared in any known breach).
def _find_suffix_in_response(suffix: str, response_body: str) -> int:
    for line in response_body.splitlines():
        parts = line.split(":")
 
        if len(parts) != 2:
            continue

        response_suffix, count = parts

        if response_suffix == suffix:
            return int(count)
 
    return 0


# Check whether the password has been exposed in a known data breach using the Have I Been Pwned Pwned Passwords API and k-anonymity.
#
# Decision logic:
#   1. Hash the password with SHA-1.
#   2. Split the hash into a 5-character prefix and a 35-character suffix.
#   3. Send the prefix to the HIBP API.
#   4. Search the response locally for the suffix.
#   5. If found, the password is compromised. Return failed CheckResult with breach count.
#   6. If not found, return passed CheckResult.
#   7. If the request fails, return passed CheckResult with a warning message.
def check_hibp(password: str) -> CheckResult:
    sha1_hash = _hash_password(password)
    prefix = sha1_hash[:HASH_PREFIX_LENGTH]
    suffix = sha1_hash[HASH_PREFIX_LENGTH:]
    
    try:
        response_body = _query_hibp_api(prefix)
    except Exception:
        return CheckResult(
            passed=True,
            name="HIBP",
            message="Have I Been Pwned check could not be completed due to a network error. This check was skipped.",
        )
        
    breach_count = _find_suffix_in_response(suffix, response_body)
    
    if breach_count > 0:
        return CheckResult(
            passed=False,
            name="HIBP",
            message=f"Password has been found in {breach_count:,} known data breach records.",
        )
        
    return CheckResult(
        passed=True,
        name="HIBP",
        message="Password was not found in any known data breach records.",
    )