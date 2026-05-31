from analyzer.models import Alert, LogEntry

from analyzer.detectors.brute_force import _detect_brute_force
from analyzer.detectors.sql_injection import _detect_sql_injection
from analyzer.detectors.path_traversal import _detect_path_traversal
from analyzer.detectors.vulnerability_scan import _detect_vulnerability_scanning
from analyzer.detectors.xss import _detect_xss
from analyzer.detectors.command_injection import _detect_command_injection
from analyzer.detectors.http_method_tampering import _detect_http_method_tampering

# Run all detection rules against a list of log entries.
# Returns a list of Alert objects, one per detected attack.
def detect(entries: list[LogEntry]) -> list[Alert]:
    alerts = []
    
    alerts.extend(_detect_brute_force(entries))
    alerts.extend(_detect_sql_injection(entries))
    alerts.extend(_detect_path_traversal(entries))
    alerts.extend(_detect_vulnerability_scanning(entries))
    alerts.extend(_detect_xss(entries))
    alerts.extend(_detect_command_injection(entries))
    alerts.extend(_detect_http_method_tampering(entries))
    
    return alerts