import os
import re
import subprocess
from collections import defaultdict


LOG_FILES = {
    "lfd": "/var/log/lfd.log",
    "auth": "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "kern": "/var/log/kern.log",
    "iptables": "/var/log/messages",
}


def _tail(path, lines=200):
    if not os.path.isfile(path):
        return []
    try:
        r = subprocess.run(
            ["tail", "-n", str(lines), path],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip().split("\n") if r.stdout.strip() else []
    except Exception:
        return []


def _classify_lfd_line(line):
    low = line.lower()
    if "*blocked*" in low or "temporary block" in low or "perm block" in low:
        return "block"
    if "login" in low or "ssh" in low or "authentication" in low:
        return "login"
    if "process" in low or "suspicious" in low or "tracking" in low:
        return "process"
    if "started" in low or "stopped" in low or "restarting" in low:
        return "service"
    return "other"


def _parse_ip(line):
    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    return m.group(1) if m else None


def get_log(logname, lines=200, search="", category="all"):
    path = LOG_FILES.get(logname)
    if not path:
        return {"error": f"Unknown log: {logname}", "entries": []}

    raw_lines = _tail(path, lines * 2 if search or category != "all" else lines)
    entries = []
    for line in raw_lines:
        if not line.strip():
            continue
        cat = _classify_lfd_line(line) if logname == "lfd" else "other"
        ip = _parse_ip(line)

        if search and search.lower() not in line.lower():
            continue
        if category != "all" and cat != category:
            continue

        severity = "info"
        low = line.lower()
        if "block" in low or "denied" in low or "failed" in low or "error" in low:
            severity = "danger"
        elif "warning" in low or "warn" in low:
            severity = "warning"
        elif "allow" in low or "success" in low or "started" in low:
            severity = "success"

        entries.append({
            "text": line,
            "category": cat,
            "severity": severity,
            "ip": ip,
        })

    entries = entries[-lines:]

    stats = defaultdict(int)
    for e in entries:
        stats[e["category"]] += 1

    return {
        "logname": logname,
        "path": path,
        "entries": entries,
        "stats": dict(stats),
        "total": len(entries),
    }


def get_available_logs():
    return {k: v for k, v in LOG_FILES.items() if os.path.isfile(v)}
