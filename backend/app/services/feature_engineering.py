# | Source       | Use              |
# | ------------ | ---------------- |
# | system logs  | rule-based + LLM |
# | network logs | ML + features    |


from collections import defaultdict

import numpy as np

def extract_network_features(logs):
    """
    Convert logs → CICIDS-like feature vector
    """

    if not logs:
        return None

    # Example aggregation (approximation)
    durations = []
    packet_lengths = []
    bytes_list = []

    for log in logs:
        if log.get("flow_duration"):
            durations.append(log["flow_duration"])

        if log.get("packet_length"):
            packet_lengths.append(log["packet_length"])

        if log.get("bytes"):
            bytes_list.append(log["bytes"])

    # fallback safe values
    def safe_mean(arr):
        return np.mean(arr) if arr else 0

    def safe_std(arr):
        return np.std(arr) if arr else 0

    features = {
        "Flow Duration": sum(durations),
        "Total Fwd Packet": len(logs),
        "Total Bwd packets": 0,  # placeholder
        "Total Length of Fwd Packet": sum(bytes_list),
        "Total Length of Bwd Packet": 0,

        "Flow Bytes/s": safe_mean(bytes_list),
        "Flow Packets/s": len(logs),

        "Fwd Packets/s": len(logs),
        "Bwd Packets/s": 0,

        "Packet Length Mean": safe_mean(packet_lengths),
        "Packet Length Std": safe_std(packet_lengths),
        "Packet Length Max": max(packet_lengths) if packet_lengths else 0,
        "Packet Length Min": min(packet_lengths) if packet_lengths else 0,

        "Flow IAT Mean": 0,
        "Flow IAT Std": 0,
        "Active Mean": 0,
        "Idle Mean": 0,

        "SYN Flag Count": 0,
        "RST Flag Count": 0,
        "ACK Flag Count": 0,
    }

    # Derived features (same as training)
    features["packet_size_variation"] = features["Packet Length Std"] / (features["Packet Length Mean"] + 1)
    features["activity_ratio"] = features["Active Mean"] / (features["Idle Mean"] + 1)
    features["bytes_per_packet"] = features["Flow Bytes/s"] / (features["Flow Packets/s"] + 1)
    features["packet_rate_ratio"] = features["Fwd Packets/s"] / (features["Bwd Packets/s"] + 1)
    features["flow_intensity"] = features["Flow Bytes/s"] * features["Flow Packets/s"]
    features["forward_backward_ratio"] = features["Total Fwd Packet"] / (features["Total Bwd packets"] + 1)

    return features


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