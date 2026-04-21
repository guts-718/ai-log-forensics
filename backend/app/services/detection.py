from collections import defaultdict

def detect_anomalies(logs):
    alerts = []

    user_events = defaultdict(list)

    for log in logs:
        user = log.get("user", "unknown")
        user_events[user].append(log)

    for user, events in user_events.items():

        login_failures = 0
        file_access_count = 0

        for e in events:
            if e.get("event_type") == "login" and e.get("status") == "failed":
                login_failures += 1

            if e.get("event_type") == "file_access":
                file_access_count += 1

        # Rule 1: Too many failed logins
        if login_failures >= 3:
            alerts.append({
                "user": user,
                "type": "brute_force_suspected",
                "details": f"{login_failures} failed login attempts"
            })

        # Rule 2: Unusual file access spike
        if file_access_count >= 5:
            alerts.append({
                "user": user,
                "type": "high_file_access",
                "details": f"{file_access_count} file accesses"
            })

    return alerts

def detect_suspicious_sequences(logs):
    alerts = []

    for i in range(len(logs) - 2):
        e1 = logs[i]
        e2 = logs[i + 1]
        e3 = logs[i + 2]

        if (
            e1["event_type"] == "login" and
            e2["event_type"] == "file_access" and
            e3["event_type"] == "usb"
        ):
            alerts.append({
                "type": "possible_data_exfiltration",
                "details": "login → file access → USB sequence detected",
                "timestamp": e3["timestamp"]
            })

    return alerts



from datetime import datetime, timedelta

def detect_burst_activity(logs):
    alerts = []

    logs = sorted(logs, key=lambda x: x["timestamp"])

    for i in range(len(logs)):
        count = 1
        t1 = datetime.strptime(logs[i]["timestamp"], "%Y-%m-%d %H:%M:%S")

        for j in range(i+1, len(logs)):
            t2 = datetime.strptime(logs[j]["timestamp"], "%Y-%m-%d %H:%M:%S")

            if (t2 - t1) <= timedelta(minutes=2):
                count += 1
            else:
                break

        if count >= 5:
            alerts.append({
                "type": "burst_activity",
                "details": f"{count} events within 2 minutes",
                "timestamp": logs[i]["timestamp"]
            })

    return alerts

def detect_exfiltration_pattern(logs):
    alerts = []

    state = {
        "login": False,
        "file_access": False
    }

    for log in logs:
        if log["event_type"] == "login":
            state["login"] = True

        elif log["event_type"] == "file_access" and state["login"]:
            state["file_access"] = True

        elif log["event_type"] in ["usb", "network_flow"] and state["file_access"]:
            alerts.append({
                "type": "possible_exfiltration",
                "details": "login → file access → transfer pattern"
            })
            state = {"login": False, "file_access": False}

    return alerts


def detect_multiple_ips(logs):
    alerts = []

    user_ips = {}

    for log in logs:
        user = log.get("user")
        ip = log.get("source_ip")

        if not user or not ip:
            continue

        if user not in user_ips:
            user_ips[user] = set()

        user_ips[user].add(ip)

    for user, ips in user_ips.items():
        if len(ips) >= 3:
            alerts.append({
                "user": user,
                "type": "multiple_ips",
                "details": f"{len(ips)} different IPs used"
            })

    return alerts


def run_detection(logs):
    alerts = []

    alerts.extend(detect_anomalies(logs))
    alerts.extend(detect_suspicious_sequences(logs))
    alerts.extend(detect_burst_activity(logs))
    alerts.extend(detect_exfiltration_pattern(logs))
    alerts.extend(detect_multiple_ips(logs))

    return alerts