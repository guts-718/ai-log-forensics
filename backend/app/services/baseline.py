from collections import defaultdict


def build_user_baselines(logs):
    print("logs received inside the build_user_baselines: ", logs)
    """
    Build baseline per user from historical logs
    """

    baselines = defaultdict(lambda: {
        "event_counts": defaultdict(int),
        "total_events": 0,
        "usb_usage": 0,
        "ip_set": set(),
    })

    for log in logs:
        user = log.get("user", "unknown")
        event = log.get("event_type")
        source = log.get("source")

        b = baselines[user]

        b["event_counts"][event] += 1
        b["total_events"] += 1

        if event == "usb":
            b["usb_usage"] += 1

        if source == "network":
            ip = log.get("metadata", {}).get("src_ip")
            if ip:
                b["ip_set"].add(ip)
    
    print("baselines: ", baselines)
    return baselines



def detect_user_anomaly(user_logs, baseline):

    anomalies = []
    events = [l.get("event_type") for l in user_logs]

    # ===== 1. First-time USB usage =====
    if "usb" in events and baseline["usb_usage"] == 0:
        anomalies.append("First-time USB usage")

    # ===== 2. Sudden spike =====
    if len(user_logs) > baseline["total_events"] * 0.5:
        anomalies.append("Unusual spike in activity")

    # ===== 3. New IP usage =====
    new_ips = set()
    for l in user_logs:
        if l.get("source") == "network":
            ip = l.get("metadata", {}).get("src_ip")
            if ip and ip not in baseline["ip_set"]:
                new_ips.add(ip)

    if new_ips:
        anomalies.append("Access from new IP address")

    # ===== 4. New event type =====
    for e in events:
        if e not in baseline["event_counts"]:
            anomalies.append(f"New behavior: {e}")
            break

    return anomalies