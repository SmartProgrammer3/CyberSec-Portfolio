"""
Goal: Estimate Brute-Force Crack Time

Given a password's entropy H (in bits), the number of possible combinations an attacker must try in the worst case is:
    combinations = 2^H

In practice, an attacker on average finds the password after trying half of all possible combinations, so the expected number of guesses is:
    expected_guesses = 2^H / 2 = 2^(H-1)

Dividing by the attacker's guessing rate (passwords per second) gives the estimated time to crack:
    crack_time (seconds) = expected_guesses / guesses_per_second


GUESSING RATE REFERENCE:
The guessing rate depends on the attack scenario. We use three reference points
based on real-world benchmarks from Hashcat and academic literature:

    Online attack → 1,000 guesses/second
        Simulates a login form with rate limiting and network latency.
        Relevant for web applications without account lockout mechanisms.

    Offline slow hash → 10,000,000 guesses/second (10^7)
        Simulates a leaked database protected by bcrypt, scrypt, or Argon2.
        These algorithms are intentionally slow and memory-hard to resist offline attacks.

    Offline fast hash → 22,000,000,000 guesses/second (2.2 * 10^10)
        Simulates a leaked database using MD5 or SHA-1 (unsalted).
        Based on a measured benchmark of an NVIDIA RTX 3090 running Hashcat against MD5.
        This represents the worst-case scenario for the user.

References:
    Hashcat official benchmarks: https://hashcat.net/hashcat/
    Academic benchmark (RTX 3090, MD5, Hashcat): https://his.diva-portal.org/smash/get/diva2:1981580/FULLTEXT01.pdf
"""

from checker.models import CheckResult

# Guessing rates in passwords per second for each attack scenario.
GUESSES_PER_SECOND_ONLINE = 1_000
GUESSES_PER_SECOND_OFFLINE_SLOW = 10_000_000
GUESSES_PER_SECOND_OFFLINE_FAST = 22_000_000_000
 
# Time unit boundaries in seconds.
SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3_600
SECONDS_PER_DAY = 86_400
SECONDS_PER_6_MONTHS = 15_768_000  
SECONDS_PER_YEAR = 31_536_000


# Convert a number of seconds into a human-readable string.
# Returns the most appropriate unit for the given duration.
def _format_time(seconds: float) -> str:
    if seconds < 1:
        return "less than a second"
    elif seconds < SECONDS_PER_MINUTE:
        return f"{int(seconds)} second{'s' if seconds >= 2 else ''}"
    elif seconds < SECONDS_PER_HOUR:
        minutes = seconds / SECONDS_PER_MINUTE
        return f"{int(minutes)} minute{'s' if minutes >= 2 else ''}"
    elif seconds < SECONDS_PER_DAY:
        hours = seconds / SECONDS_PER_HOUR
        return f"{int(hours)} hour{'s' if hours >= 2 else ''}"
    elif seconds < SECONDS_PER_YEAR:
        days = seconds / SECONDS_PER_DAY
        return f"{int(days)} day{'s' if days >= 2 else ''}"
    elif seconds < SECONDS_PER_YEAR * 1_000:
        years = seconds / SECONDS_PER_YEAR
        return f"{int(years):,} year{'s' if years >= 2 else ''}"
    else:
        return "centuries"


# Estimate the expected crack time in seconds for a given entropy and guessing rate.
# Uses 2^(H-1) as the expected number of guesses (average case, not worst case).
# Returns 0.0 if entropy is zero or negative.
def _estimate_crack_time(entropy: float, guesses_per_second: int) -> float:
    if entropy <= 0:
        return 0.0
 
    expected_guesses = 2 ** (entropy - 1)
    
    return expected_guesses / guesses_per_second


# Estimate brute-force crack times for three attack scenarios and return a CheckResult.
# Receives the entropy value calculated by check_entropy() in entropy.py.
# The check passes if the password would take more than 6 months to crack in the worst-case scenario (offline fast hash attack at 22 billion guesses/second).
# Many organizations enforce password rotation every 90 to 180 days.
def check_crack_time(entropy: float) -> list[CheckResult]:
    online = _estimate_crack_time(entropy, GUESSES_PER_SECOND_ONLINE)
    offline_slow = _estimate_crack_time(entropy, GUESSES_PER_SECOND_OFFLINE_SLOW)
    offline_fast = _estimate_crack_time(entropy, GUESSES_PER_SECOND_OFFLINE_FAST)
 
    passed = offline_fast >= SECONDS_PER_6_MONTHS  
 
    return [
        CheckResult(
            passed=passed,
            name="Crack time (online)",
            message=f"Estimated crack time under an online attack (1,000 guesses/second, rate-limited): {_format_time(online)}.",
        ),
        CheckResult(
            passed=passed,
            name="Crack time (offline slow hash)",
            message=f"Estimated crack time against a slow hash (bcrypt/Argon2 at 10,000,000 guesses/second): {_format_time(offline_slow)}.",
        ),
        CheckResult(
            passed=passed,
            name="Crack time (offline fast hash)",
            message=f"Estimated crack time against a fast hash (MD5/SHA-1 on NVIDIA RTX 3090 at 22,000,000,000 guesses/second): {_format_time(offline_fast)}.",
        ),
    ]