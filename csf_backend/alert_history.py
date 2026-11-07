import os
import re
from datetime import datetime, timedelta


def get_alerts(hours=24, limit=200):
    alerts = []
    now = datetime.now()
    cutoff = now - timedelta(hours=hours)

    path = "/var/log/lfd.log"
    if not os.path.isfile(path):
        return {"alerts": [], "summary": {}}

    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, 500000)
            f.seek(max(0, size - chunk))
            data = f.read().decode("utf-8", errors="replace")
            lines = data.splitlines()
    except OSError:
        return {"alerts": [], "summary": {}}

    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue

        # Classify
        severity = "info"
        category = "other"
        icon = "info-sign"

        if "Blocked" in line or "BLOCK" in line or "block" in line:
            severity = "danger"
            category = "block"
            icon = "ban-circle"
        elif "Failed" in line or "failure" in line:
            severity = "warning"
            category = "login_fail"
            icon = "lock"
        elif "Accepted" in line or "success" in line.lower():
            severity = "success"
            category = "login_ok"
            icon = "ok-sign"
        elif "SYN" in line or "flood" in line.lower():
            severity = "danger"
            category = "flood"
            icon = "flash"
        elif "distributed" in line.lower():
            severity = "danger"
            category = "distributed"
            icon = "warning-sign"
        elif "attacks" in line.lower():
            severity = "warning"
            category = "attack"
            icon = "exclamation-sign"
        elif "restarted" in line.lower() or "start" in line.lower():
            severity = "info"
            category = "service"
            icon = "refresh"

        # Extract IP
        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
        ip = ips[0] if ips else ""

        # Extract country
        country = ""
        cm = re.search(r'\(([A-Z]{2})/', line)
        if cm:
            country = cm.group(1)

        alerts.append({
            "line": line,
            "severity": severity,
            "category": category,
            "icon": icon,
            "ip": ip,
            "country": country,
        })

        if len(alerts) >= limit:
            break

    # Summary
    from collections import Counter
    cat_counts = Counter(a["category"] for a in alerts)

    return {
        "alerts": alerts,
        "summary": {
            "total": len(alerts),
            "blocks": cat_counts.get("block", 0),
            "login_fails": cat_counts.get("login_fail", 0),
            "floods": cat_counts.get("flood", 0),
            "services": cat_counts.get("service", 0),
        },
    }
