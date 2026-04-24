def classify_event(logs, features):
    events = [l.get("event_type") for l in logs]
    events_str = " ".join(events)

    if any(a.get("type") == "cross_source_exfiltration" for a in logs):
        return "Advanced Data Exfiltration"
    
    # ===== 1. Data Exfiltration =====
    if "usb" in events and events.count("file_access") >= 2:
        return "Data Exfiltration"

    if "file_access" in events and "transfer" in events_str:
        return "Data Exfiltration"

    # ===== 2. Brute Force =====
    if events.count("login_failed") >= 3:
        return "Brute Force Attack"

    # ===== 3. Suspicious Login =====
    if "login" in events and "login_failed" in events:
        return "Suspicious Login Activity"

    # ===== 4. Insider Threat =====
    if "login" in events and "file_access" in events and "usb" in events:
        return "Insider Threat"

    # ===== 5. Lateral Movement =====
    if features.get("unique_ip_count", 0) > 3:
        return "Lateral Movement"

    # ===== 6. Data Staging =====
    if events.count("file_access") > 3:
        return "Data Staging"

    # ===== 7. Credential Abuse =====
    if "login" in events and features.get("unique_ip_count", 0) > 2:
        return "Credential Abuse"

    # ===== 8. Reconnaissance =====
    if features.get("event_count", 0) > 10:
        return "Reconnaissance Activity"

    # ===== 9. Suspicious USB Usage =====
    if events.count("usb") > 1:
        return "Suspicious Peripheral Activity"

    # ===== 10. Anomalous Behavior =====
    if len(set(events)) > 3:
        return "Anomalous Behavior"

    return "Normal"