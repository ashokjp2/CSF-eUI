import os
import re


LFD_LOG = "/var/log/lfd.log"


def get_lfd_blocks(limit=200):
    """Parse LFD log for block events and alerts."""
    entries = []
    block_pat = re.compile(
        r'(\w+ +\d+ [\d:]+) \S+ lfd\[\d+\]: '
        r'(?:\((\w+)\) )?'
        r'(.+?)'
        r'\*Blocked in csf\*'
        r'(?: \[(.+?)\])?',
        re.IGNORECASE,
    )
    alert_pat = re.compile(
        r'(\w+ +\d+ [\d:]+) \S+ lfd\[\d+\]: \*(.+?)\* (.+)',
    )
    ip_re = re.compile(r'(\d+\.\d+\.\d+\.\d+)')

    if not os.path.isfile(LFD_LOG):
        return []
    try:
        with open(LFD_LOG) as f:
            lines = f.readlines()
    except OSError:
        return []

    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue

        m = block_pat.search(line)
        if m:
            detail = m.group(3).strip()
            ip_match = ip_re.search(detail)
            entries.append({
                "time": m.group(1),
                "type": "block",
                "ip": ip_match.group(1) if ip_match else "",
                "reason": m.group(4) or m.group(2) or detail[:60],
                "detail": detail[:120],
            })
        else:
            m2 = alert_pat.match(line)
            if m2:
                alert_type = m2.group(2)
                if alert_type in ("WARNING", "Error", "User Processing", "PT_FORKBOMB", "Excessive Processes"):
                    continue
                entries.append({
                    "time": m2.group(1),
                    "type": alert_type,
                    "detail": m2.group(3)[:120],
                })

        if len(entries) >= limit:
            break
    return entries


def get_block_timeline(hours=24):
    """Real LFD blocks ('*Blocked in csf*' lines) bucketed per hour for the last `hours`,
    plus the total for the preceding window. Only lfd.log counts — not SSH failures."""
    from datetime import datetime, timedelta
    now = datetime.now()
    cutoff = now - timedelta(hours=hours)
    prev_cutoff = now - timedelta(hours=hours * 2)
    buckets = [0] * hours
    total = prev_total = 0
    last_ip = None
    ts_re = re.compile(r'^(\w{3}) +(\d+) (\d{2}):(\d{2}):(\d{2})')
    ip_re = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
    months = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
    if os.path.isfile(LFD_LOG):
        try:
            with open(LFD_LOG, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 4_000_000))
                lines = f.read().decode("utf-8", "replace").splitlines()
        except OSError:
            lines = []
        for line in lines:
            if "Blocked in csf" not in line and "Blocked temporarily" not in line:
                continue
            m = ts_re.match(line)
            if not m or m.group(1) not in months:
                continue
            try:
                ts = datetime(now.year, months[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
            except ValueError:
                continue
            if ts > now + timedelta(hours=1):
                ts = ts.replace(year=now.year - 1)
            if ts >= cutoff:
                idx = hours - 1 - int((now - ts).total_seconds() // 3600)
                if 0 <= idx < hours:
                    buckets[idx] += 1
                    total += 1
                    ipm = ip_re.search(line)
                    last_ip = ipm.group(1) if ipm else last_ip
            elif ts >= prev_cutoff:
                prev_total += 1
    hourly = []
    for i in range(hours):
        slot = now - timedelta(hours=hours - 1 - i)
        hourly.append({"hour": slot.strftime("%H:00"), "count": buckets[i]})
    return {"hourly": hourly, "total": total, "prev_total": prev_total, "hours": hours, "last_ip": last_ip}


def get_lfd_stats():
    """Summary stats from LFD log."""
    blocks = get_lfd_blocks(500)
    block_count = sum(1 for b in blocks if b["type"] == "block")
    alert_count = len(blocks) - block_count

    ip_counts = {}
    reason_counts = {}
    for b in blocks:
        if b["type"] == "block":
            ip = b.get("ip", "")
            reason = b.get("reason", "")
            if ip:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            if reason:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: -x[1])[:10]
    top_reasons = sorted(reason_counts.items(), key=lambda x: -x[1])[:10]

    return {
        "total_blocks": block_count,
        "total_alerts": alert_count,
        "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        "top_reasons": [{"reason": r, "count": c} for r, c in top_reasons],
    }
