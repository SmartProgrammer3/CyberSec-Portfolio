from dataclasses import dataclass

# Represents the result of a single password check.
#  passed: True if the check passed, False if it failed (Answers Did it pass?).
#  name: Name of the check performed (Answers What was checked?).
#  message: Human-readable description of the result (Answers Why?).
@dataclass
class CheckResult:
    passed: bool
    name: str
    message: str