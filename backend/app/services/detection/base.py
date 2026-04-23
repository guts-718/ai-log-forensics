from collections import defaultdict

from .rules import (
    detect_burst_activity,
    detect_exfiltration_pattern,
    detect_multiple_ips
)


def run_detection(logs):
    """
    Run detection rules per user.
    Ensures every alert has a 'user' field.
    """

    alerts = []

    # =========================
    # Group logs by user
    # =========================
    user_groups = defaultdict(list)

    for log in logs:
        user = log.get("user", "unknown")
        user_groups[user].append(log)

    # =========================
    # Run detection per user
    # =========================
    for user, user_logs in user_groups.items():

        user_alerts = []

        # Apply rules
        user_alerts.extend(detect_burst_activity(user_logs))
        user_alerts.extend(detect_exfiltration_pattern(user_logs))
        user_alerts.extend(detect_multiple_ips(user_logs))

        # Attach user to each alert
        for alert in user_alerts:
            alert["user"] = user

        alerts.extend(user_alerts)

    return alerts