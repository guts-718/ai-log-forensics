from collections import defaultdict

EVENT_MAP = {
    "login": 1,
    "login_failed": 2,
    "file_access": 3,
    "usb": 4,
    "network": 5
}

def encode_event(event):

    if event == "login":
        return 0

    if event == "file_access":
        return 1

    if event == "usb":
        return 2

    if event == "login_failed":
        return 3

    return 0


def build_sequences(logs, window_size=5):
    """
    Convert logs → sliding window sequences
    """

    user_groups = defaultdict(list)

    for log in logs:
        user = log.get("user", "unknown")
        user_groups[user].append(log)

    sequences = []

    for user, user_logs in user_groups.items():
        # sort by time
        user_logs = sorted(user_logs, key=lambda x: x.get("timestamp", ""))

        encoded = [encode_event(l.get("event_type")) for l in user_logs]

        # sliding window
        for i in range(len(encoded) - window_size + 1):
            seq = encoded[i:i+window_size]
            sequences.append(seq)

    return sequences