def normalize(parsed):
    return {
        "timestamp": parsed.get("timestamp"),
        "event_type": parsed.get("event_type"),
        "user": parsed.get("user") or "unknown",
        "device": parsed.get("device", "unknown"),
        "ip": parsed.get("ip"),
        "file": parsed.get("file"),
        "action": parsed.get("action"),
        "raw_log": parsed
    }