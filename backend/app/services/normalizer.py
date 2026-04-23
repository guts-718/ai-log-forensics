def normalize_log(parsed):
    event_type = normalize_event(parsed.get("event") or parsed.get("event_type"))

    return {
        "timestamp": parsed.get("time") or parsed.get("timestamp"),
        "event_type": event_type,
        "user": parsed.get("user", "unknown"),
        "source_ip": parsed.get("ip") or parsed.get("source_ip"),
        "file_name": parsed.get("file") or parsed.get("file_name"),
        "status": normalize_status(parsed.get("status")),

        # 👇 optional structured field
        "alert": {
            "type": event_type,
        }
    }


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