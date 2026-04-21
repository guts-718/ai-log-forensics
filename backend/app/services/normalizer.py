def normalize(parsed):
    return {
        "timestamp": parsed.get("timestamp"),
        "event_type": parsed.get("event_type"),
        "action": parsed.get("action"),

        "user": parsed.get("user") or "unknown",
        "device": parsed.get("device"),
        "session_id": parsed.get("session_id"),

        "source_ip": parsed.get("ip"),
        "destination_ip": parsed.get("destination_ip"),

        "file_name": parsed.get("file"),
        "file_path": parsed.get("file_path"),

        "process_name": parsed.get("process_name"),
        "parent_process": parsed.get("parent_process"),

        "status": parsed.get("status"),

        "raw_log": parsed
    }