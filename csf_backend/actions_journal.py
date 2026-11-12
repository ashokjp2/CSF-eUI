"""Journal of recent UI actions with an inverse, so the last few can be undone from the bell panel."""
import json
import os
import secrets
import time

PATH = "/var/lib/csfv2/actions.jsonl"
KEEP = 50


def record(kind, label, undo, user=""):
    """kind: short id; label: human text; undo: {"action": name, ...params} or None if not undoable."""
    entry = {"id": secrets.token_hex(4), "ts": int(time.time()), "kind": kind, "label": label, "undo": undo, "user": user, "undone": False}
    try:
        os.makedirs(os.path.dirname(PATH), exist_ok=True)
        with open(PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
        if os.path.getsize(PATH) > 100_000:
            _rewrite(_all()[-KEEP:])
    except OSError:
        pass
    return entry["id"]


def _all():
    try:
        with open(PATH) as f:
            return [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return []


def _rewrite(entries):
    tmp = PATH + ".tmp"
    with open(tmp, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    os.replace(tmp, PATH)


def recent(limit=10):
    return list(reversed(_all()[-limit:]))


def undo(entry_id):
    """Apply the inverse of a journaled action. Returns a result dict."""
    from csf_backend import csf_wrapper as csf, docker_manager
    entries = _all()
    target = next((e for e in entries if e["id"] == entry_id), None)
    if not target:
        return {"success": False, "error": "Action not found"}
    if target.get("undone"):
        return {"success": False, "error": "Already undone"}
    u = target.get("undo") or {}
    a = u.get("action")
    if a == "remove_allow":
        r = csf.remove_allow(u["ip"])
    elif a == "remove_deny":
        r = csf.remove_deny(u["ip"])
    elif a == "deny":
        r = csf.deny_ip(u["ip"], u.get("comment", "re-blocked by undo"))
    elif a == "allow":
        r = csf.allow_ip(u["ip"], u.get("comment", "re-allowed by undo"))
    elif a == "remove_temp":
        r = csf.remove_temp_deny(u["ip"]) if u.get("type") == "deny" else csf.remove_temp_allow(u["ip"])
    elif a == "unrestrict_port":
        r = docker_manager.set_port_restriction(int(u["port"]), u.get("proto", "tcp"), False)
    elif a == "restrict_port":
        r = docker_manager.set_port_restriction(int(u["port"]), u.get("proto", "tcp"), True)
    elif a == "set_conf":
        r = csf.save_csf_conf({u["key"]: u["value"]})
    elif a == "remove_ignore":
        r = _remove_line("/etc/csf/csf.ignore", u["ip"])
    else:
        return {"success": False, "error": "This action cannot be undone automatically"}
    ok = bool(r.get("success", False))
    if ok:
        target["undone"] = True
        try:
            _rewrite(entries)
        except OSError:
            pass
    return {"success": ok, "error": "" if ok else (r.get("stderr") or r.get("error") or "Undo failed")[:200], "label": target["label"]}


def _remove_line(path, needle):
    try:
        with open(path) as f:
            lines = f.readlines()
        with open(path, "w") as f:
            f.writelines(l for l in lines if l.strip().split("#")[0].strip() != needle)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}
