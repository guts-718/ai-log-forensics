from collections import defaultdict

def extract_features(logs):
    user_features = defaultdict(lambda: {
        "event_count": 0,
        "file_access_count": 0,
        "login_count": 0,
        "unique_ips": set()
    })

    for log in logs:
        user = log.get("user", "unknown")

        user_features[user]["event_count"] += 1

        if log.get("event_type") == "file_access":
            user_features[user]["file_access_count"] += 1

        if log.get("event_type") == "login":
            user_features[user]["login_count"] += 1

        ip = log.get("source_ip")
        if ip:
            user_features[user]["unique_ips"].add(ip)

    final_features = []

    for user, f in user_features.items():
        final_features.append({
            "user": user,
            "event_count": f["event_count"],
            "file_access_count": f["file_access_count"],
            "login_count": f["login_count"],
            "unique_ip_count": len(f["unique_ips"]),
            "file_access_ratio": f["file_access_count"] / max(f["event_count"], 1)
        })

    return final_features