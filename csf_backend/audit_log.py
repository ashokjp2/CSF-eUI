import os
import json
from datetime import datetime

AUDIT_FILE = "/opt/csfv2/audit.log"
MAX_ENTRIES = 500


def log_event(event_type, username="", ip="", detail=""):
    entry = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "user": username,
        "ip": ip,
        "detail": detail,
    }
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def get_events(limit=100, event_type=""):
    events = []
    try:
        with open(AUDIT_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if event_type and entry.get("type") != event_type:
                        continue
                    events.append(entry)
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass

    events.reverse()
    return events[:limit]


def clear_old(keep=MAX_ENTRIES):
    try:
        with open(AUDIT_FILE) as f:
            lines = f.readlines()
        if len(lines) > keep:
            with open(AUDIT_FILE, "w") as f:
                f.writelines(lines[-keep:])
    except OSError:
        pass
