import os
import re
from datetime import datetime, timedelta
from collections import defaultdict


LOG_FILES = {
    "lfd": "/var/log/lfd.log",
    "auth": "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "kern": "/var/log/kern.log",
    "messages": "/var/log/messages",
}

ACTION_PATTERNS = {
    "block": [
        r"Blocked in iptables",
        r"temporary block",
        r"Temp.Block",
        r"\bBLOCK\b",
        r"\bdrop\b",
        r"\bDROP\b",
        r"SYN flood",
    ],
    "login_fail": [
        r"Failed password",
        r"authentication failure",
        r"Invalid user",
        r"failed login",
        r"FAILED LOGIN",
    ],
    "login_ok": [
        r"Accepted password",
        r"Accepted publickey",
        r"session opened",
    ],
    "allow": [
        r"csf\.allow",
        r"ALLOW\b",
        r"unblocked",
    ],
}

SEVERITY_MAP = {
    "block": "danger",
    "login_fail": "warning",
    "login_ok": "success",
    "allow": "info",
}


def _read_tail(path, max_lines=2000):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, max_lines * 300)
            f.seek(max(0, size - chunk))
            data = f.read().decode("utf-8", errors="replace")
            lines = data.splitlines()
            return lines[-max_lines:]
    except OSError:
        return []


def _classify(line):
    for action, patterns in ACTION_PATTERNS.items():
        for p in patterns:
            if re.search(p, line, re.IGNORECASE):
                return action
    return "other"


def _extract_ips(line):
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)


def search_logs(query="", log_name="", action_type="", time_range="24h", max_results=500):
    results = []
    hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720, "all": 0}.get(time_range, 24)

    cutoff = None
    if hours > 0:
        cutoff = datetime.now() - timedelta(hours=hours)

    logs_to_search = {log_name: LOG_FILES[log_name]} if log_name and log_name in LOG_FILES else LOG_FILES

    for name, path in logs_to_search.items():
        if not os.path.isfile(path):
            continue
        lines = _read_tail(path, 5000)
        for line in lines:
            action = _classify(line)
            if action_type and action != action_type:
                continue
            if query and query.lower() not in line.lower():
                continue

            ips = _extract_ips(line)
            severity = SEVERITY_MAP.get(action, "default")

            # Highlight matches
            highlighted = line
            if query:
                highlighted = re.sub(
                    re.escape(query),
                    lambda m: f'<mark>{m.group()}</mark>',
                    line,
                    flags=re.IGNORECASE,
                )

            results.append({
                "line": highlighted,
                "raw": line,
                "log": name,
                "action": action,
                "severity": severity,
                "ips": ips,
            })

            if len(results) >= max_results:
                break

    results.reverse()
    return results


def get_timeline_data(hours=24):
    """Get block/allow/login events grouped by hour for timeline chart."""
    buckets = defaultdict(lambda: {"blocks": 0, "logins": 0, "alerts": 0})

    now = datetime.now()
    cutoff = now - timedelta(hours=hours)

    for name, path in LOG_FILES.items():
        if not os.path.isfile(path):
            continue
        lines = _read_tail(path, 10000)
        for line in lines:
            action = _classify(line)
            if action == "other":
                continue

            # Try to extract timestamp — common syslog format: "Mon DD HH:MM:SS"
            ts_match = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
            if ts_match:
                try:
                    ts_str = ts_match.group(1)
                    ts = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
                    if ts > now:
                        ts = ts.replace(year=now.year - 1)
                except ValueError:
                    continue
            else:
                continue

            if ts < cutoff:
                continue

            bucket_key = ts.strftime("%Y-%m-%d %H:00")

            if action == "block":
                buckets[bucket_key]["blocks"] += 1
            elif action in ("login_fail", "login_ok"):
                buckets[bucket_key]["logins"] += 1
            elif action == "allow":
                buckets[bucket_key]["alerts"] += 1

    # Fill in empty hours
    timeline = []
    for i in range(hours):
        t = cutoff + timedelta(hours=i)
        key = t.strftime("%Y-%m-%d %H:00")
        label = t.strftime("%H:%M")
        if hours > 48:
            label = t.strftime("%m/%d %H:%M")
        data = buckets.get(key, {"blocks": 0, "logins": 0, "alerts": 0})
        timeline.append({
            "label": label,
            "blocks": data["blocks"],
            "logins": data["logins"],
            "alerts": data["alerts"],
        })

    # Summary stats
    total_blocks = sum(b["blocks"] for b in timeline)
    total_logins = sum(b["logins"] for b in timeline)
    total_alerts = sum(b["alerts"] for b in timeline)
    peak_hour = max(timeline, key=lambda x: x["blocks"]) if timeline else None

    return {
        "timeline": timeline,
        "summary": {
            "total_blocks": total_blocks,
            "total_logins": total_logins,
            "total_alerts": total_alerts,
            "peak_hour": peak_hour["label"] if peak_hour else "N/A",
            "peak_blocks": peak_hour["blocks"] if peak_hour else 0,
        },
        "hours": hours,
    }
