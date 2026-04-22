# rule based explainer
def generate_reasoning(features):
    reasons = []

    if features.get("flow_packets_per_sec", 0) > 1000:
        reasons.append("High packet rate detected")

    if features.get("file_access_count", 0) > 5:
        reasons.append("Multiple file accesses observed")

    if features.get("usb_events", 0) > 0:
        reasons.append("USB device activity detected")

    if features.get("failed_logins", 0) > 3:
        reasons.append("Multiple failed login attempts")

    return reasons