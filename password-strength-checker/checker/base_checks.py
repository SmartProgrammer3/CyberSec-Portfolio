import re

from checker.models import CheckResult


PASSWORD_MIN_LENGTH = 8 # Minimum length for a password to be considered acceptable.
PASSWORD_IDEAL_LENGTH = 12 # Ideal length for a strong password.

# https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
COMMON_WEAK_PASSWORDS = [
    "password", "admin", "login", "football", "iloveyou", 
    "baseball", "lovely", "master", "mustang"
]

# Common keyboard walk patterns.
COMMON_KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdf", "asdfghjkl", "zxcv", "zxcvbnm",
    "1234", "12345", "123456", "1234567", "12345678",
]

# Common character substitutions used in weak passwords.
COMMON_SUBSTITUTIONS = {
    "@": "a", "4": "a", "3": "e", "1": "i", "0": "o",
    "5": "s", "7": "t", "$": "s", "!": "i",
}

# Check if the password meets the length requirement.
def check_length(password: str) -> CheckResult:
    if len(password) >= PASSWORD_IDEAL_LENGTH:
        return CheckResult(
            passed=True,
            name="Length", 
            message=f"Password length is {len(password)} characters, which meets the strong password threshold.",
        )
    
    elif len(password) >= PASSWORD_MIN_LENGTH:
        return CheckResult(
            passed=True, 
            name="Length", 
            message=f"Password length is {len(password)} characters. Acceptable, but a minimum of {PASSWORD_IDEAL_LENGTH} is recommended.",
        )
    
    return CheckResult(
        passed=False, 
        name="Length", 
        message=f"Password length is {len(password)} characters, which is below the minimum required length of {PASSWORD_MIN_LENGTH}.",
    )


# Check if the password contains uppercase letters.
def check_uppercase(password: str) -> CheckResult:
    if any(c.isupper() for c in password):
        return CheckResult(
            passed=True, 
            name="Uppercase", 
            message="Password contains at least one uppercase letter.",
        )
    
    return CheckResult(
        passed=False, 
        name="Uppercase", 
        message="Password does not contain any uppercase letters.",
    )


# Check if the password contains lowercase letters.
def check_lowercase(password: str) -> CheckResult:
    if any(c.islower() for c in password):
        return CheckResult(
            passed=True, 
            name="Lowercase", 
            message="Password contains at least one lowercase letter.",
        )
    
    return CheckResult(
        passed=False, 
        name="Lowercase", 
        message="Password does not contain any lowercase letters.",
    )


# Check if the password contains digits.
def check_digits(password: str) -> CheckResult:
    if any(c.isdigit() for c in password):
        return CheckResult(
            passed=True, 
            name="Digits", 
            message="Password contains at least one digit.",
        )
    
    return CheckResult(
        passed=False, 
        name="Digits", 
        message="Password does not contain any digits.",
    )


# Check if the password contains special characters.
def check_special(password: str) -> CheckResult:
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return CheckResult(
            passed=True, 
            name="Special chars", 
            message="Password contains at least one special character.",
        )
    
    return CheckResult(
        passed=False, 
        name="Special chars", 
        message="Password does not contain any special characters.",
    )


# Check if the password contains common weak substitutions.
# Many users replace letters with visually similar symbols to "strengthen" a weak base word.
#       Example: "P@ssw0rd" → @ replaces a, 0 replaces o → "password" after normalization.
# This check normalizes the password by applying COMMON_SUBSTITUTIONS, then tests the result against known weak words and keyboard walk patterns.
#
# Decision logic:
#   1. Lowercase the password.
#   2. Replace every known symbol with its letter equivalent.
#   3. Check if the normalized result contains any keyboard walk (e.g. "qwerty").
#      → Detects cases like "Qw3rty!" which normalizes to "qwerty".
#   4. Check if the normalized result contains any common weak word (e.g. "password").
#      → Uses substring match (not equality) to catch "myP@ssw0rd2024" → "mypassword2024".
def check_substitutions(password: str) -> CheckResult:
    normalizedPassword = password.lower()
    
    for symbol, letter in COMMON_SUBSTITUTIONS.items():
        normalizedPassword = normalizedPassword.replace(symbol, letter)
        
    for walk in COMMON_KEYBOARD_WALKS:
        if walk in normalizedPassword:
            return CheckResult(
                passed=False,
                name="Weak substitutions",
                message="Password contains a keyboard walk pattern that remains predictable despite the use of character substitutions.",
            )
            
    for word in COMMON_WEAK_PASSWORDS:
        if word in normalizedPassword:
            return CheckResult(
                passed=False,
                name="Weak substitutions",
                message=f"Password is based on a commonly known word disguised with character substitutions: '{word}'.",
            )

    return CheckResult(
        passed=True, 
        name="Weak substitutions", 
        message="Password does not contain any common substitution patterns.",
    )
 
 
# Check if the password contains 3 or more consecutive repeated characters.
# Example: "aaaa", "1111", "!!!!" (repeated characters contribute zero entropy).
# Uses a back-reference regex: (.) captures any char, \1{2,} matches it 2+ more times.
def check_repeated(password: str) -> CheckResult:
    if re.search(r"(.)\1{2,}", password):
        return CheckResult(
            passed=False, 
            name="Repeated chars", 
            message="Password contains 3 or more consecutive repeated characters, which significantly reduces its strength.",
        )
    
    return CheckResult(
        passed=True, 
        name="Repeated chars", 
        message="Password does not contain any repeated character sequences.")


# Check if the password contains sequential character patterns. Alphabetic or numeric runs are easily guessable.
# Example: "abc", "xyz", "123", "987"
#
# Decision logic:
#   For every 3-character window, compare the ASCII values of consecutive characters.
#   Ascending sequence:  b - a == 1 and c - b == 1  (e.g. a=97, b=98, c=99)
#   Descending sequence: a - b == 1 and b - c == 1  (e.g. c=99, b=98, a=97)
def check_sequential(password: str) -> CheckResult:
    for i in range(len(password) - 2):
        a, b, c = ord(password[i]), ord(password[i + 1]), ord(password[i + 2])
        
        if (b - a == 1 and c - b == 1) or (a - b == 1 and b - c == 1):
            return CheckResult(
                passed=False,
                name="Sequential pattern",
                message=f"Password contains a sequential character pattern '{password[i:i + 3]}', which is easily guessable.",
            )
            
    return CheckResult(
        passed=True, 
        name="Sequential pattern", 
        message="Password does not contain any sequential patterns.",
    )


# Check if the password contains year or date patterns.
# Years (19xx or 20xx) and date fragments (DDMM format) are commonly appended to weak base words to meet length requirements. They add very little real entropy.
#
# Decision logic:
#   1. Year pattern: matches 4-digit strings starting with 19 or 20 (e.g. 1990, 2024).
#   2. Date pattern: matches DDMM format — day 01–31 followed by month 01–12 (e.g. 0101, 3112).
#      Uses \b (word boundary) to avoid matching arbitrary digit substrings.
def check_dates(password: str) -> CheckResult:
    if re.search(r"(19|20)\d{2}", password):
        return CheckResult(
            passed=False,
            name="Year pattern",
            message="Password contains a year pattern (e.g. 1990, 2024), which is a commonly used and predictable addition.",
        )
        
    if re.search(r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\b", password):
        return CheckResult(
            passed=False,
            name="Date pattern",
            message="Password contains a date pattern (e.g. 0101, 3112), which is a commonly used and predictable addition.",
        )
        
    return CheckResult(
        passed=True, 
        name="Date pattern", 
        message="Password does not contain any date or year patterns.",
    )
        
        
# Run all basic checks against the password.
# Returns a list of CheckResult objects in evaluation order.
def check(password: str) -> list[CheckResult]:
    return [
        check_length(password),
        check_uppercase(password),
        check_lowercase(password),
        check_digits(password),
        check_special(password),
        check_substitutions(password),
        check_repeated(password),
        check_sequential(password),
        check_dates(password),
    ]