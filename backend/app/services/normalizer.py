def detect_source(parsed):

    if "Flow Duration" in parsed:
        return "network"

    if parsed.get("event"):
        return "system"

    return "unknown"


def normalize_log(parsed):
    event_type = normalize_event(parsed.get("event") or parsed.get("event_type"))
    source = detect_source(parsed)
    base = {
        "timestamp": parsed.get("time") or parsed.get("timestamp"),
        "event_type": event_type,
        "user": parsed.get("user", "unknown"),
        "source": source,
        "metadata": {},
        "alert": {
            "type": event_type,
        }
       }
     # ===== SYSTEM LOG =====
    if source == "system":
        base["metadata"] = {
            "file_name": parsed.get("file"),
            "status": parsed.get("status"),
            "ip": parsed.get("ip")
        }

    # ===== NETWORK LOG =====
    elif source == "network":
        base["metadata"] = {
            "flow_duration": parsed.get("Flow Duration"),
            "bytes": parsed.get("Flow Bytes/s"),
            "packets": parsed.get("Flow Packets/s"),
            "src_ip": parsed.get("Src IP"),
            "dst_ip": parsed.get("Dst IP"),
        }

    return base


def normalize_event(event):
    if not event:
        return "unknown"

    mapping = {
        "login": "login",
        "login_failed": "login_failed",
        "file_access": "file_access",
        "usb": "usb",
        "usb_connected": "usb",
    }

    return mapping.get(event, event)


def normalize_status(status):
    if not status:
        return None

    mapping = {
        "success": "success",
        "failed": "failed",
        "fail": "failed"
    }

    return mapping.get(status, status)