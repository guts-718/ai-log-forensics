import json
import re

def parse_log(line: str):
    try:
        return json.loads(line)
    except:
        return {
            "timestamp": extract_timestamp(line),
            "event_type": detect_event(line),
            "raw": line
        }

def extract_timestamp(line):
    match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
    return match.group(0) if match else None

def detect_event(line):
    if "login" in line.lower():
        return "login"
    if "usb" in line.lower():
        return "usb"
    if "file" in line.lower():
        return "file_access"
    return "unknown"