from collections import defaultdict

from .rules import (
    detect_burst_activity,
    detect_exfiltration_pattern,
    detect_multiple_ips
)


def run_detection(logs):
    """
    Run rule-based detection PER USER.
    Returns alerts with user context attached.
    """

    alerts = []

    if not logs:
        return alerts

    # =========================
    # Group logs by user
    # =========================
    user_groups = defaultdict(list)

    for log in logs:
        user = log.get("user", "unknown")
        user_groups[user].append(log)

    # =========================
    # Run rules per user
    # =========================
    for user, user_logs in user_groups.items():

        # sort logs by time for sequence rules
        user_logs = sorted(user_logs, key=lambda x: x.get("timestamp", ""))

        user_alerts = []

        # ===== Rule executions =====
        user_alerts.extend(detect_burst_activity(user_logs))
        user_alerts.extend(detect_exfiltration_pattern(user_logs))
        user_alerts.extend(detect_multiple_ips(user_logs))

        # ===== Attach user =====
        for alert in user_alerts:
            alert["user"] = user

        alerts.extend(user_alerts)

    return alerts