# hopefully i want to replae this with ml classifier
def classify_event(logs, features):
    # simple heuristic classification

    if features.get("flow_packets_per_sec", 0) > 1000:
        return "DoS Attack"

    if features.get("file_access_count", 0) > 5 and features.get("usb_events", 0) > 0:
        return "Data Exfiltration"

    if features.get("failed_logins", 0) > 3:
        return "Brute Force Attack"

    return "Unknown"