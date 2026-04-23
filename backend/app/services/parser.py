import json
import re
def parse_log(raw):
    """
    Supports both:
    - dict input (preferred)
    - raw string (fallback)
    """

    # ✅ Case 1: Already structured JSON
    if isinstance(raw, dict):
        return raw

    # ❌ Case 2: string logs (optional fallback)
    log = {
        "timestamp": None,
        "event_type": None,
        "user": None,
        "source_ip": None,
        "file_name": None,
        "status": None
    }

    parts = raw.split()

    for part in parts:
        if "user=" in part:
            log["user"] = part.split("=")[1]

        elif "ip=" in part:
            log["source_ip"] = part.split("=")[1]

        elif "file=" in part:
            log["file_name"] = part.split("=")[1]

        elif "status=" in part:
            log["status"] = part.split("=")[1]

        elif part in ["login", "login_failed", "file_access", "usb"]:
            log["event_type"] = part

    # crude timestamp (first 2 parts)
    try:
        log["timestamp"] = " ".join(parts[:2])
    except:
        pass

    return log