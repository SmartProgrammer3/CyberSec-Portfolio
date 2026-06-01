"""
What is password entropy?
Password entropy is measured in bits and tells how unpredictable a password is against brute force attacks.

The formula is: H = L * log2(N)

Where:
    H = entropy in bits.
    L = length of the password (number of characters).
    N = size of the character pool the password draws from.
    
Example:
    Password "abc" 
    Length of the password -> L = 3
    Uses only lowercase letters → N = 26
    H = 3 * log2(26) = 14.1 bits
    
The higher the entropy, the more guesses an attacker needs on average to crack the password.
Each additional bit of entropy doubles the number of possible combinations.

Industry reference:
    < 28 bits → Very weak
    28 - 35 bits → Weak
    36 - 59 bits → Reasonable
    60 - 127 bits → Strong
    >= 128 bits → Very strong
"""

import math
 
from checker.models import CheckResult

# Character pool sizes used to determine N in the entropy formula.
CHARACTER_POOL_LOWERCASE = 26 # a-z
CHARACTER_POOL_UPPERCASE = 26 # A-Z
CHARACTER_POOL_DIGITS = 10 # 0-9
CHARACTER_POOL_SPECIAL = 32 # (ASCII defines 96 printable chars -> 96 - (26 + 26 + 10) = 32) !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~

# Entropy thresholds in bits.
ENTROPY_VERY_WEAK = 28
ENTROPY_WEAK = 36
ENTROPY_REASONABLE = 60
ENTROPY_STRONG = 128


# Determine the size of the character pool (N) based on which character classes are present in the password.
# This function inspects the password and adds the size of each character class detected.
# A larger pool means more possible combinations per character position, and therefore higher entropy.
def _calculate_password_pool_size(password: str) -> int:
    pool = 0
    
    if any(c.islower() for c in password):
        pool += CHARACTER_POOL_LOWERCASE
 
    if any(c.isupper() for c in password):
        pool += CHARACTER_POOL_UPPERCASE
 
    if any(c.isdigit() for c in password):
        pool += CHARACTER_POOL_DIGITS
 
    if any(not c.isalnum() for c in password):
        pool += CHARACTER_POOL_SPECIAL
        
    return pool


# Calculate the theoretical entropy of the password in bits using the formula (H = L * log2(N)).
def _calculate_password_entropy(password: str) -> float:
    if not password:
        return 0.0
    
    pool = _calculate_password_pool_size(password)
 
    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


# Map an entropy value in bits to a human-readable strength label, based on widely used industry thresholds.
def _get_entropy_label(entropy: float) -> str:
    if entropy < ENTROPY_VERY_WEAK:
        return "Very weak"
    
    elif entropy < ENTROPY_WEAK:
        return "Weak"
    
    elif entropy < ENTROPY_REASONABLE:
        return "Reasonable"
    
    elif entropy < ENTROPY_STRONG:
        return "Strong"
    
    return "Very strong"


# Calculate the entropy of the password and return a CheckResult indicating whether it meets the minimum acceptable threshold.
def check_entropy(password: str) -> tuple[CheckResult, float]:
    entropy = _calculate_password_entropy(password)
    label = _get_entropy_label(entropy)
    passed = entropy >= ENTROPY_VERY_WEAK # Minimum acceptable!!
    
    if passed:
        return CheckResult(
            passed=True,
            name="Entropy",
            message=f"Password entropy is {entropy:.2f} bits ({label}).",
        ), entropy
        
    return CheckResult(
        passed=False,
        name="Entropy",
        message=f"Password entropy is {entropy:.2f} bits ({label}), which is below the minimum acceptable threshold of {ENTROPY_VERY_WEAK} bits.",
    ), entropy