"""Scheduled allow/deny rules: applied at a start time, removed at an end time."""
import json
import os
import secrets
import time

PATH = "/etc/csfv2/scheduled_rules.json"


def _load():
    try:
        with open(PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"rules": []}


def _save(d):
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    tmp = PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, PATH)


def list_rules():
    rules = _load()["rules"]
    now = int(time.time())
    for r in rules:
        if r.get("removed"):
            r["state"] = "expired"
        elif r.get("applied"):
            r["state"] = "active"
        elif r["start"] > now:
            r["state"] = "scheduled"
        else:
            r["state"] = "pending"
    return sorted(rules, key=lambda r: (r.get("removed", False), r["start"]))


def add(kind, ip, start, end, ports="", comment="", user=""):
    if kind not in ("allow", "deny"):
        return False, "Type must be allow or deny"
    try:
        start, end = int(start), int(end)
    except (TypeError, ValueError):
        return False, "Bad start/end time"
    if end <= start:
        return False, "End must be after start"
    d = _load()
    r = {"id": secrets.token_hex(4), "kind": kind, "ip": ip.strip(), "ports": (ports or "").strip(), "comment": comment.strip()[:80],
         "start": start, "end": end, "created_by": user, "applied": False, "removed": False}
    d["rules"].append(r)
    _save(d)
    return True, r["id"]


def extend(rule_id, new_end):
    d = _load()
    for r in d["rules"]:
        if r["id"] == rule_id and not r.get("removed"):
            r["end"] = int(new_end)
            _save(d)
            return True
    return False


def expire_now(rule_id):
    d = _load()
    for r in d["rules"]:
        if r["id"] == rule_id and not r.get("removed"):
            r["end"] = int(time.time()) - 1
            _save(d)
            tick()
            return True
    return False


def delete(rule_id):
    d = _load()
    before = len(d["rules"])
    keep = []
    for r in d["rules"]:
        if r["id"] == rule_id:
            if r.get("applied") and not r.get("removed"):
                _remove(r)
            continue
        keep.append(r)
    d["rules"] = keep
    _save(d)
    return len(keep) < before


def _entry(r):
    if r.get("ports"):
        return f"tcp|in|d={r['ports']}|s={r['ip']}"
    return r["ip"]


def _apply(r):
    from csf_backend import csf_wrapper as csf
    comment = f"scheduled until {time.strftime('%Y-%m-%d %H:%M', time.localtime(r['end']))} {r.get('comment', '')}".strip()
    fn = csf.allow_ip if r["kind"] == "allow" else csf.deny_ip
    return fn(_entry(r), comment)


def _remove(r):
    from csf_backend import csf_wrapper as csf
    fn = csf.remove_allow if r["kind"] == "allow" else csf.remove_deny
    return fn(_entry(r))


def tick():
    """Apply due rules and remove expired ones. Called by the background watcher."""
    d = _load()
    now = int(time.time())
    changed = False
    for r in d["rules"]:
        if r.get("removed"):
            continue
        if not r.get("applied") and r["start"] <= now < r["end"]:
            res = _apply(r)
            r["applied"] = bool(res.get("success"))
            r["apply_error"] = "" if r["applied"] else (res.get("stderr") or res.get("error") or "")[:200]
            changed = True
        elif r["end"] <= now:
            if r.get("applied"):
                _remove(r)
            r["removed"] = True
            changed = True
    if changed:
        _save(d)
    return changed
