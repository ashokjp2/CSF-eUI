"""Weekly digest: blocks by country/reason, open-port changes, config changes, cert and update status."""
import json
import os
import socket
import time
from collections import Counter

STATE = "/var/lib/csfv2/digest_state.json"


def _load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(s):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        with open(STATE, "w") as f:
            json.dump(s, f)
    except OSError:
        pass


def compose(days=7):
    from csf_backend import lfd_blocks, explain, config_history, port_defaults, csf_wrapper as csf, ssl_manager, updater, ip_utils
    now = time.time()
    since = now - days * 86400
    tl = lfd_blocks.get_block_timeline(days * 24)
    blocks = [b for b in lfd_blocks.get_lfd_blocks(5000) if b.get("type") == "block"]
    reasons = Counter(explain.explain(b.get("reason") or b.get("detail") or "")[1] for b in blocks)
    ips = Counter(b["ip"] for b in blocks if b.get("ip"))
    countries = Counter()
    try:
        geo = ip_utils.geolocate_batch([ip for ip, _ in ips.most_common(40)]) or {}
        for ip, n in ips.most_common(40):
            cc = (geo.get(ip) or {}).get("country_code", "")
            if cc and cc != "XX":
                countries[cc] += n
    except Exception:
        pass
    state = _load_state()
    try:
        open_ports = sorted({str(p) for _, p in port_defaults._get_listening_ports() if str(p).isdigit()}, key=int)
    except Exception:
        open_ports = []
    prev_ports = state.get("open_ports", [])
    new_ports = [p for p in open_ports if p not in prev_ports]
    gone_ports = [p for p in prev_ports if p not in open_ports]
    changes = [h for h in config_history.recent(200) if h.get("ts", 0) >= since]
    n_changes = sum(len(h.get("changes", [])) for h in changes)
    try:
        cert = (ssl_manager.get_ssl_status().get("current_cert") or {}).get("expiry", "unknown")
    except Exception:
        cert = "unknown"
    try:
        vi = updater.get_version_info()
        upd = f"update available: v{vi.get('latest')}" if vi.get("update_available") else f"up to date (v{vi.get('current')})"
    except Exception:
        upd = "unknown"
    conf = csf.load_csf_conf()

    lines = [f"Weekly firewall digest — {socket.gethostname()}",
             f"{tl['total']} LFD blocks in the last {days} days ({tl['prev_total']} the week before)"]
    if reasons:
        lines.append("Why: " + "; ".join(f"{r} ×{n}" for r, n in reasons.most_common(4)))
    if countries:
        lines.append("Top countries: " + ", ".join(f"{c} {n}" for c, n in countries.most_common(5)))
    if ips:
        lines.append("Most persistent: " + ", ".join(f"{ip} ({n})" for ip, n in ips.most_common(3)))
    lines.append(f"Open ports: {', '.join(open_ports) or 'none detected'}" + (f" — NEW since last digest: {', '.join(new_ports)}" if new_ports else "") + (f" — closed: {', '.join(gone_ports)}" if gone_ports else ""))
    lines.append(f"Config changes: {n_changes} setting(s) in {len(changes)} save(s)")
    lines.append(f"TESTING mode: {'ON — nothing is really blocked!' if conf.get('TESTING') == '1' else 'off'}")
    lines.append(f"HTTPS certificate expires: {cert}")
    lines.append(f"CSF-eUI: {upd}")
    state["open_ports"] = open_ports
    state["last_sent"] = int(now)
    _save_state(state)
    return "\n".join(lines)


def send():
    from csf_backend import notifications, email_alerts
    body = compose()
    res = notifications.event("weekly_digest", "Weekly firewall digest", body, "info")
    try:
        to = email_alerts.get_admin_email()
        if to:
            email_alerts.send_verification_email(to, "[CSF-eUI] Weekly firewall digest", body)
            res = dict(res or {}, email="ok")
    except Exception as e:
        res = dict(res or {}, email=str(e)[:100])
    return {"success": True, "sent": res, "body": body}


def due(conf):
    """True when the configured weekday/hour has arrived and nothing was sent in the last 6 days."""
    d = conf.get("digest") or {}
    if not d.get("enabled"):
        return False
    lt = time.localtime()
    if lt.tm_wday != int(d.get("weekday", 0)) or lt.tm_hour != int(d.get("hour", 8)):
        return False
    return time.time() - _load_state().get("last_sent", 0) > 6 * 86400
