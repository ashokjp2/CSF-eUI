"""'Why is this IP blocked?' — one report per IP: CSF status, LFD history, logs, GeoIP, audit trail."""
import ipaddress
import json
import os
import re
import subprocess
import time

from csf_backend import csf_wrapper as csf
from csf_backend import ip_lookup, lfd_blocks, audit_log

LFD_LOG = "/var/log/lfd.log"
LOGIN_LOG = "/var/log/csfv2.log"
AUTH_LOGS = ("/var/log/auth.log", "/var/log/secure")


def valid_ip(ip):
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False


def _grep(path, ip, limit):
    """Last `limit` lines in `path` containing the IP, newest first (tail-limited for speed)."""
    if not os.path.isfile(path):
        return []
    try:
        out = subprocess.run(["grep", "-F", ip, path], capture_output=True, text=True, timeout=10).stdout
    except (subprocess.SubprocessError, OSError):
        return []
    lines = [l for l in out.splitlines() if l.strip()]
    return list(reversed(lines[-limit:]))


def _csf_status(ip):
    """Parse `csf -g IP` into a status dict."""
    r = csf.search_ip(ip)
    out = (r.get("stdout") or "") + (r.get("stderr") or "")
    s = {"raw": out.strip(), "deny": None, "allow": None, "temp": None, "ignore": False, "iptables": []}
    for line in out.splitlines():
        l = line.strip()
        if not l:
            continue
        if l.startswith("csf.deny:"):
            s["deny"] = l.split(":", 1)[1].strip()
        elif l.startswith("csf.allow:"):
            s["allow"] = l.split(":", 1)[1].strip()
        elif l.startswith("csf.ignore:"):
            s["ignore"] = True
        elif "Temporary" in l and ("DENY" in l.upper() or "ALLOW" in l.upper()):
            s["temp"] = l
        elif re.match(r"^(Chain|num|\d+\s)", l) or "DROP" in l or "ACCEPT" in l:
            s["iptables"].append(l)
    if s["deny"] is None and "No matches found" not in out and "csf.deny" in out:
        s["deny"] = ""
    if s["deny"]:
        s["state"] = "blocked"
    elif s["temp"] and "DENY" in s["temp"].upper():
        s["state"] = "temp_blocked"
    elif s["allow"] or (s["temp"] and "ALLOW" in s["temp"].upper()):
        s["state"] = "allowed"
    elif s["ignore"]:
        s["state"] = "ignored"
    else:
        s["state"] = "clear"
    return s


def build(ip):
    ip = ip.strip()
    if not valid_ip(ip):
        return {"error": "Invalid IP address"}
    status = _csf_status(ip)

    # LFD block history for this IP
    history = [b for b in lfd_blocks.get_lfd_blocks(1500) if b.get("ip") == ip]
    lfd_lines = _grep(LFD_LOG, ip, 40)
    auth_lines = []
    for p in AUTH_LOGS:
        auth_lines += _grep(p, ip, 20)
    ui_lines = _grep(LOGIN_LOG, ip, 20)

    # Audit trail: UI actions that mention the IP
    audit = [e for e in audit_log.get_events(500) if ip in (e.get("detail") or "") or e.get("ip") == ip][:20]

    # Geo / WHOIS / reputation from the existing lookup (best effort)
    geo = {}
    try:
        info = ip_lookup.lookup_ip(ip)
        for sec in info.get("sections", []):
            geo[sec.get("title", "")] = sec.get("items", [])
    except Exception as e:
        geo = {"Lookup": [{"key": "Error", "value": str(e)}]}

    from csf_backend import explain, suggestions
    reasons = {}
    for b in history:
        reasons[b.get("reason") or "unknown"] = reasons.get(b.get("reason") or "unknown", 0) + 1
        b["why"] = explain.explain(b.get("reason") or b.get("detail") or "")[1]
    try:
        net = suggestions.for_ip(ip)
    except Exception:
        net = None
    top_reason = max(reasons.items(), key=lambda kv: kv[1])[0] if reasons else None

    # Plain-English summary
    if status["state"] == "blocked":
        summary = "Permanently blocked in csf.deny"
        if status["deny"]:
            summary += f" — {status['deny']}"
    elif status["state"] == "temp_blocked":
        summary = "Temporarily blocked by LFD" + (f" — {top_reason}" if top_reason else "")
    elif status["state"] == "allowed":
        summary = "Allowed (whitelisted)" + (f" — {status['allow']}" if status["allow"] else "")
    elif status["state"] == "ignored":
        summary = "In csf.ignore — LFD will never block this IP"
    else:
        summary = "Not blocked right now" + (f" — blocked {len(history)} time(s) before, last reason: {top_reason}" if history else "")

    return {
        "ip": ip,
        "status": status,
        "summary": summary,
        "history": history[:30],
        "history_count": len(history),
        "top_reason": top_reason,
        "top_reason_why": explain.explain(top_reason or "")[1] if top_reason else "",
        "reasons": sorted(reasons.items(), key=lambda kv: -kv[1]),
        "net": net,
        "lfd_lines": lfd_lines,
        "auth_lines": auth_lines[:20],
        "ui_lines": ui_lines,
        "audit": audit,
        "geo": geo,
        "generated": int(time.time()),
    }
