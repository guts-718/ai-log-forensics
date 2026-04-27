from datetime import datetime

def format_event(log):
    # if log["event_type"] == "login":
    #     return "login"
    #     return f"User logged in from {log.get('ip')}"
    # if log["event_type"] == "file_access":

    #     return f"Accessed file {log.get('file')}"
    # if log["event_type"] == "usb":
    #     return "USB device connected"

    return log["event_type"]

def build_timeline(logs):
    # filter invalid timestamps
    valid_logs = [l for l in logs if l.get("timestamp")]

    # sort logs
    sorted_logs = sorted(
        valid_logs,
        key=lambda x: datetime.strptime(x["timestamp"], "%Y-%m-%d %H:%M:%S")
    )

    timeline = []

    for log in sorted_logs:
        timeline.append({
            "time": log["timestamp"],
            "event":format_event(log),
            "user": log["user"],
            "ip": log.get("ip"),
            "file": log.get("file"),
            "action": log.get("action")
        })

    return timeline


def build_user_timelines(logs):
    user_map = {}

    for log in logs:
        user = log.get("user", "unknown")

        if user not in user_map:
            user_map[user] = []

        user_map[user].append(log)

    timelines = {}

    for user, user_logs in user_map.items():
        timelines[user] = build_timeline(user_logs)

    return timelines

def build_timeline_summary(events):
    seen = set()
    summary = []

    for e in events:
        key = (e["time"], e["event"])
        if key not in seen:
            seen.add(key)
            summary.append(f"{e['time']} → {e['event']}")

    return summary