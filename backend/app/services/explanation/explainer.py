def generate_reasoning(features, logs):
    reasons = []

    events = [l.get("event_type") for l in logs]

    # ===== Access patterns =====
    if events.count("file_access") >= 2:
        reasons.append("Multiple sensitive file accesses detected")

    if events.count("file_access") > 4:
        reasons.append("High volume of file access indicates possible data staging")

    # ===== USB =====
    if "usb" in events:
        reasons.append("USB device activity detected (possible external data transfer)")

    if events.count("usb") > 1:
        reasons.append("Repeated USB connections observed")

    # ===== Login anomalies =====
    if events.count("login_failed") >= 3:
        reasons.append("Multiple failed login attempts detected")

    if "login" in events and "login_failed" in events:
        reasons.append("Combination of successful and failed logins detected")

    # ===== Sequence-based =====
    if "login" in events and "file_access" in events and "usb" in events:
        reasons.append("Sequence login → file access → USB suggests data exfiltration")

    # ===== Network / IP behavior =====
    if features.get("unique_ip_count", 0) > 2:
        reasons.append("Multiple IP addresses used for same user")

    # ===== Activity burst =====
    if features.get("event_count", 0) > 5:
        reasons.append("High activity in short duration detected")

    # ===== Generic fallback =====
    if not reasons:
        reasons.append("Unusual activity pattern detected")

    return reasons