def classify_event(logs, features):
    events = [l.get("event_type") for l in logs]
    sources = [l.get("source") for l in logs]
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
        return "Authentication - Brute Force"
    
    if "usb" in events and events.count("file_access") >= 2:
        return "Data Exfiltration"


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
        return "Authentication - Suspicious Login"

    # ===== 8. Reconnaissance =====
    if features.get("event_count", 0) > 10:
        return "Reconnaissance Activity"

    # ===== 9. Suspicious USB Usage =====
    if events.count("usb") > 1:
        return "Device - Suspicious USB Usage"
    
    if "network" in sources and features:
        if features.get("Flow Bytes/s", 0) > 10000:
            return "Network - Traffic Spike"


    # ===== 10. Anomalous Behavior =====
    if len(set(events)) > 3:
        return "Anomalous Behavior"
    
    if len(events) > 6:
        return "Behavior - Anomalous Activity"

    return "Normal"