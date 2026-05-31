from dataclasses import dataclass
from datetime import datetime

# Represents a single parsed log line from Apache/Nginx Combined Log Format.
# ip: IP address of the client that made the request.
# time: Timestamp of the request.
# method: HTTP method used (GET, POST, PUT, DELETE, etc). 
# path: Requested URL path including query string.
# status: HTTP response status code returned by the server.
# bytes: Size of the response body in bytes.
@dataclass
class LogEntry:
    ip: str
    time: datetime
    method: str
    path: str
    status: int
    bytes: int


# Represents a detected attack.
# ip: IP address of the attacker (Answers Who?).
# attack_type: Type of attack (Brute Force, SQL Injection, PATH Traversal, Vulnerability Scanning) (Answers What?).
# severity: Severity level — Low, Medium, High or Critical (Answers How serious?).
# detail: Human-readable description of what was detected (Answers Why?).
# count: Number of occurrences that triggered the alert (Answers How many?).
@dataclass
class Alert:
    ip: str
    attack_type: str
    severity: str       
    detail: str
    count: int = 1