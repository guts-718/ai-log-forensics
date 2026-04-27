def correlate_events(user_logs, base_alerts):
    """
    Correlate multi-source + multi-step behaviors into higher-level alerts
    """

    correlated_alerts = []

    if not user_logs:
        return correlated_alerts

    # =========================
    # Prepare context
    # =========================
    logs = sorted(user_logs, key=lambda x: x.get("timestamp", ""))

    events = [l.get("event_type") for l in logs]
    sources = [l.get("source") for l in logs]

    has_system = "system" in sources
    has_network = "network" in sources

    # =========================
    # 1. Cross-source exfiltration
    # =========================
    if (
        has_system
        and has_network
        and "usb" in events
        and events.count("file_access") >= 2
    ):
        correlated_alerts.append({
            "type": "cross_source_exfiltration",
            "details": "file access + usb + network activity spike",
            "timestamp": logs[-1].get("timestamp")
        })

    # =========================
    # 2. Login → Network spike
    # =========================
    if (
        "login" in events
        and has_network
    ):
        correlated_alerts.append({
            "type": "login_followed_by_network_activity",
            "details": "login followed by unusual network behavior",
            "timestamp": logs[-1].get("timestamp")
        })

    # =========================
    # 3. Brute force + movement
    # =========================
    if (
        events.count("login_failed") >= 3
        and has_network
    ):
        correlated_alerts.append({
            "type": "brute_force_with_lateral_movement",
            "details": "multiple failed logins + network activity",
            "timestamp": logs[-1].get("timestamp")
        })

    # =========================
    # 4. Burst + sensitive activity
    # =========================
    if (
        any(a.get("type") == "burst_activity" for a in base_alerts)
        and "file_access" in events
    ):
        correlated_alerts.append({
            "type": "burst_followed_by_sensitive_activity",
            "details": "high activity followed by file access",
            "timestamp": logs[-1].get("timestamp")
        })

    # =========================
    # 5. Repeated USB usage
    # =========================
    if events.count("usb") > 1:
        correlated_alerts.append({
            "type": "repeated_usb_activity",
            "details": "multiple USB connections detected",
            "timestamp": logs[-1].get("timestamp")
        })

    return correlated_alerts