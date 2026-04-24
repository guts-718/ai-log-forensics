def compute_risk_score(logs, features, alert):

    score = 0
    reasons = []

    events = [l.get("event_type") for l in logs]

    # ===== SYSTEM SIGNALS =====
    if "usb" in events:
        score += 2
        reasons.append("USB activity")

    if events.count("file_access") >= 2:
        score += 2
        reasons.append("Multiple file accesses")

    if events.count("login_failed") >= 3:
        score += 3
        reasons.append("Brute force pattern")

    # ===== NETWORK SIGNALS =====
    if features:
        if features.get("Flow Bytes/s", 0) > 10000:
            score += 3
            reasons.append("High network traffic")

        if features.get("packet_size_variation", 0) > 5:
            score += 2
            reasons.append("Unusual packet variation")

    # ===== ALERT TYPE BOOST =====
    if alert["type"] == "possible_exfiltration":
        score += 3

    if alert["type"] == "burst_activity":
        score += 1

    return score, reasons


def get_risk_level(score):
    if score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"