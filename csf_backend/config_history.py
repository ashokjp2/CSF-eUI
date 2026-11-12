"""Diff of pending csf.conf changes and a history of what was saved, by whom, with old values."""
import json
import os
import time

from csf_backend import csf_wrapper as csf

HISTORY_PATH = "/var/lib/csfv2/config_history.jsonl"
KEEP = 200


def diff(changes):
    """Compare submitted {KEY: value} against the current csf.conf. Returns [{key, old, new}]."""
    current = csf.load_csf_conf()
    out = []
    for key, new in changes.items():
        old = current.get(key)
        if old is None or str(old) != str(new):
            out.append({"key": key, "old": "" if old is None else str(old), "new": str(new)})
    return out


def record(changes, user=""):
    if not changes:
        return
    try:
        os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
        with open(HISTORY_PATH, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "user": user, "changes": changes}) + "\n")
        if os.path.getsize(HISTORY_PATH) > 300_000:
            with open(HISTORY_PATH) as f:
                lines = f.readlines()[-KEEP:]
            with open(HISTORY_PATH, "w") as f:
                f.writelines(lines)
    except OSError:
        pass


def recent(limit=40):
    try:
        with open(HISTORY_PATH) as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
            e["when"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("ts", 0)))
            out.append(e)
        except ValueError:
            pass
    return out
