import re

from checker.models import CheckResult

# Minimum length for a password to be considered acceptable.
PASSWORD_MIN_LENGTH = 8

# Ideal length for a strong password.
PASSWORD_IDEAL_LENGTH = 12

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
        return CheckResult(passed=True, name="Length", message=f"Password length {len(password)} - strong!")
    
    elif len(password) >= PASSWORD_MIN_LENGTH:
        return CheckResult(passed=True, name="Length", message=f"Password length {len(password)} - acceptable, but ideal is {IDEAL_LENGTH}+!")
    
    return CheckResult(passed=False, name="Length", message=f"Weak password length {len(password)} - minimum is {PASSWORD_MIN_LENGTH}.")

# Check if the password contains uppercase letters.
def check_uppercase(password: str) -> CheckResult:
    if any(c.isupper() for c in password):
        return CheckResult(passed=True, name="Uppercase", message="Password contains uppercase letters!")
    
    return CheckResult(passed=False, name="Uppercase", message="Password doesn`t contain uppercase letters.")

# Check if the password contains lowercase letters.
def check_lowercase(password: str) -> CheckResult:
    if any(c.islower() for c in password):
        return CheckResult(passed=True, name="Lowercase", message="Password contains lowercase letters!")
    
    return CheckResult(passed=False, name="Lowercase", message="Password doesn`t contain lowercase letters.")

# Check if the password contains digits.
def check_digits(password: str) -> CheckResult:
    if any(c.isdigit() for c in password):
        return CheckResult(passed=True, name="Digits", message="Password contains digits!")
    
    return CheckResult(passed=False, name="Digits", message="Password doesn`t contain digits.")

# Check if the password contains special characters.
def check_special(password: str) -> CheckResult:
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return CheckResult(passed=True, name="Special chars", message="Password contains special characters!")
    
    return CheckResult(passed=False, name="Special chars", message="Password doesn`t contain special characters.")
