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
