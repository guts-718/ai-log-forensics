def correlate_events(user_logs, base_alerts):
    """
    Combine system + network signals into higher-level alerts
    """

    events = [l.get("event_type") for l in user_logs]
    sources = [l.get("source") for l in user_logs]

    correlated_alerts = []

    # ===== 1. Cross-source Data Exfiltration =====
    if (
        "system" in sources
        and "network" in sources
        and "usb" in events
        and events.count("file_access") >= 2
    ):
        correlated_alerts.append({
            "type": "cross_source_exfiltration",
            "details": "file access + usb + network activity spike",
        })

    # ===== 2. Suspicious Login + Network Spike =====
    if (
        "login" in events
        and "network" in sources
    ):
        correlated_alerts.append({
            "type": "login_followed_by_network_activity",
            "details": "login followed by unusual network activity"
        })

    # ===== 3. Brute Force + Lateral Movement =====
    if (
        events.count("login_failed") >= 3
        and "network" in sources
    ):
        correlated_alerts.append({
            "type": "brute_force_with_possible_lateral_movement",
            "details": "multiple failed logins + network activity"
        })

    return correlated_alerts