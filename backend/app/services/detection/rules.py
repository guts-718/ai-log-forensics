from datetime import datetime, timedelta

def detect_burst_activity(logs):
    alerts = []

    print("\n\nSample log:", logs[0])
    print("\n\nKeys:", logs[0].keys())

    logs = [l for l in logs if l.get("time")]
    logs.sort(key=lambda x: x["time"])

    for i in range(len(logs)):
        count = 1
        t1 = datetime.strptime(logs[i]["time"], "%Y-%m-%d %H:%M:%S")

        for j in range(i+1, len(logs)):
            t2 = datetime.strptime(logs[j]["time"], "%Y-%m-%d %H:%M:%S")

            if (t2 - t1) <= timedelta(minutes=2):
                count += 1
            else:
                break

        if count >= 3:
            alerts.append({
                "type": "burst_activity",
                "details": f"{count} events in 2 minutes",
                "timestamp": logs[i]["time"]
            })

    return alerts


def detect_exfiltration_pattern(logs):
    alerts = []
    print(f"logs inside the detect_exfiltration_pattern: ", logs)

    state = {"login": False, "file": False}

    for log in logs:
        et = log.get("event")

        if et == "login":
            state["login"] = True

        elif et == "file_access" and state["login"]:
            state["file"] = True

        elif et in ["usb", "network_flow"] and state["file"]:
            alerts.append({
                "type": "possible_exfiltration",
                "details": "login → file → transfer",
                "timestamp": log.get("timestamp")
            })
            state = {"login": False, "file": False}

    return alerts



def detect_multiple_ips(logs):
    alerts = []

    user_ips = {}

    for log in logs:
        user = log.get("user")
        ip = log.get("source_ip")

        if not user or not ip:
            continue

        user_ips.setdefault(user, set()).add(ip)

    for user, ips in user_ips.items():
        if len(ips) >= 3:
            alerts.append({
                "type": "multiple_ip_usage",
                "user": user,
                "details": f"{len(ips)} IPs used"
            })

    return alerts