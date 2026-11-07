import os
import json
import time
from datetime import datetime

HISTORY_FILE = "/var/lib/csfv2/login_history.json"


def _load():
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return []


def _save(entries):
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(entries[-500:], f)


def record_login(username, ip, success=True):
    entries = _load()
    entries.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": int(time.time()),
        "username": username,
        "ip": ip,
        "success": success,
    })
    _save(entries)


def record_failed_login(username, ip):
    record_login(username, ip, success=False)


def get_history(limit=100):
    entries = _load()
    return list(reversed(entries[-limit:]))


def get_stats():
    entries = _load()
    total = len(entries)
    successful = sum(1 for e in entries if e.get("success"))
    failed = total - successful

    ip_counts = {}
    failed_ips = {}
    for e in entries:
        ip = e.get("ip", "")
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        if not e.get("success"):
            failed_ips[ip] = failed_ips.get(ip, 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    top_failed = sorted(failed_ips.items(), key=lambda x: -x[1])[:10]

    return {
        "total": total,
        "successful": successful,
        "failed": failed,
        "unique_ips": len(ip_counts),
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "top_failed_ips": [{"ip": ip, "count": c} for ip, c in top_failed],
    }
