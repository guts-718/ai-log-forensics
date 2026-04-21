from .rules import (
    detect_burst_activity,
    detect_exfiltration_pattern,
    detect_multiple_ips
)

def run_detection(logs):
    alerts = []

    alerts.extend(detect_burst_activity(logs))
    alerts.extend(detect_exfiltration_pattern(logs))
    alerts.extend(detect_multiple_ips(logs))

    return alerts