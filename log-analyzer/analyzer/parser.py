import re

from datetime import datetime
from analyzer.models import LogEntry

# Map the Combined Log Format.
COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
)
    
# Takes a line of text and returns a LogEntry or None if the line does not match the pattern.
def parse_line(line: str) -> LogEntry | None:
    match = COMBINED_LOG_PATTERN.match(line)
    if not match:
        return None

    return LogEntry(
        ip=match.group("ip"),
        time=datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z"),
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        bytes=int(match.group("bytes")) if match.group("bytes") != "-" else 0,
    )
    
# It reads the file line by line, calls `parse_line` on each line, and stores the valid results in a list. 
def parse_file(path: str) -> list[LogEntry]:
    entries = []
    with open(path, "r") as f:
        for line in f:
            entry = parse_line(line.strip())
            if entry:
                entries.append(entry)
    return entries