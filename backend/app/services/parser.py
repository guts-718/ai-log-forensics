import json
import re

def parse_log(line: str):
    try:
        return json.loads(line)
    except:
        return {
            "timestamp": extract_timestamp(line),
            "event_type": detect_event(line),
            "user": extract_field(line, "user"),
            "ip": extract_field(line, "ip"),
            "file": extract_file(line),
            "action": extract_action(line),
            "raw": line
        }


def extract_timestamp(line):
    match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
    return match.group(0) if match else None


def extract_field(line, field):
    match = re.search(rf"{field}=([^\s]+)", line)
    return match.group(1) if match else None


def extract_file(line):
    match = re.search(r"file\s+([^\s]+)", line)
    return match.group(1) if match else None


def extract_action(line):
    if "login" in line.lower():
        return "login"
    if "accessed" in line.lower():
        return "access"
    if "connected" in line.lower():
        return "connect"
    return None


def detect_event(line):
    l = line.lower()

    if "login" in l:
        return "login"
    if "usb" in l:
        return "usb"
    if "file" in l:
        return "file_access"

    return "unknown"