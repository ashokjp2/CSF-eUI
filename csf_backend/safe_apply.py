"""Safe apply: restart the firewall with an automatic rollback unless the admin confirms.

Flow
  1. The first config-changing request after a confirmed state takes a *baseline* backup of
     /etc/csf (known-good files) — see snapshot_baseline().
  2. "Apply safely" restarts csf+lfd and arms a detached watchdog process with a deadline.
  3. If the admin does not confirm in time (locked out, UI unreachable), the watchdog restores
     the baseline backup and restarts csf+lfd, then records the rollback for the UI to show.
  4. Confirming clears the state; the next change starts a new baseline.

The watchdog is a separate process (python -m csf_backend.safe_apply --watch) started with its
own session, so it survives gunicorn restarts and does not depend on the web app being reachable.
"""
import json
import os
import subprocess
import sys
import time

STATE_PATH = "/var/lib/csfv2/safe_apply.json"
APP_LOG = "/var/log/csfv2.log"
DEFAULT_SECONDS = 90
MAX_SECONDS = 600

# POST paths that modify firewall configuration (prefix match)
CHANGE_PATHS = (
    "/config/save", "/qconfig/", "/files/", "/lfd/", "/api/csf-file/", "/api/csfpost/save",
    "/api/csfpost/edit", "/api/csfpost/import", "/api/csfpost/restore",
    "/rules/build", "/api/rules/apply", "/api/country/", "/api/ip-lists/", "/api/port-defaults/apply",
    "/api/ports/add-port", "/api/services/add-ports", "/api/wizard/apply", "/api/health/quick-fix",
    "/templates/",
)


def _log(msg):
    try:
        with open(APP_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] safe-apply: {msg}\n")
    except OSError:
        pass


def _load():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_PATH)


def is_change_path(path):
    return any(path.startswith(p) for p in CHANGE_PATHS)


def snapshot_baseline():
    """Take a known-good backup before the first change since the last confirm. Idempotent."""
    state = _load()
    if state.get("baseline") or state.get("armed"):
        return state
    from csf_backend import config_backup
    res = config_backup.create_backup("baseline")
    if not res.get("success"):
        _log(f"baseline backup failed: {res.get('error')}")
        return state
    state = {"baseline": res["filename"], "baseline_at": int(time.time())}
    _save(state)
    _log(f"baseline taken: {res['filename']}")
    return state


def status():
    """State for the UI bar."""
    s = _load()
    now = time.time()
    out = {"pending": bool(s.get("baseline")) and not s.get("armed"),
           "armed": bool(s.get("armed")),
           "remaining": max(0, int(s.get("deadline", 0) - now)) if s.get("armed") else 0,
           "seconds": s.get("seconds", DEFAULT_SECONDS),
           "rolled_back": s.get("rolled_back"),
           "baseline_at": s.get("baseline_at")}
    if s.get("armed") and out["remaining"] == 0 and now - s.get("deadline", 0) > 30 and not s.get("rolled_back"):
        out["armed"] = False  # watchdog should have acted; avoid a stuck bar
    return out


def arm(seconds=DEFAULT_SECONDS):
    """Restart csf+lfd now and start the rollback watchdog. Returns a result dict."""
    from csf_backend import csf_wrapper as csf
    seconds = max(30, min(MAX_SECONDS, int(seconds or DEFAULT_SECONDS)))
    state = _load()
    if state.get("armed"):
        return {"success": False, "error": "A safe apply is already waiting for confirmation"}
    if not state.get("baseline"):
        state = snapshot_baseline()
        if not state.get("baseline"):
            return {"success": False, "error": "Could not take a baseline backup"}
    token = os.urandom(8).hex()
    state.update({"armed": True, "token": token, "deadline": int(time.time()) + seconds,
                  "seconds": seconds, "rolled_back": None})
    state.pop("rolled_back", None)
    _save(state)
    result = csf.restart_both()
    try:
        subprocess.Popen(
            [sys.executable, "-m", "csf_backend.safe_apply", "--watch", token],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True,
        )
    except Exception as e:
        state["armed"] = False
        _save(state)
        return {"success": False, "error": f"Restarted, but the rollback watchdog could not start: {e}"}
    _log(f"armed for {seconds}s (baseline {state['baseline']})")
    return {"success": bool(result.get("success", True)), "seconds": seconds, "restart": result}


def confirm():
    """Admin confirmed access still works: drop the baseline and stop the watchdog."""
    state = _load()
    if not state.get("armed") and not state.get("baseline"):
        return {"success": True, "message": "Nothing to confirm"}
    _save({"confirmed_at": int(time.time())})
    _log("confirmed by admin")
    return {"success": True}


def dismiss_rollback():
    state = _load()
    state.pop("rolled_back", None)
    _save(state)
    return {"success": True}


def clear_baseline():
    """Called after an ordinary (unsafe) restart: the running config is now whatever was applied."""
    state = _load()
    if state.get("armed"):
        return
    state.pop("baseline", None)
    state.pop("baseline_at", None)
    _save(state)


def _watch(token):
    state = _load()
    if state.get("token") != token or not state.get("armed"):
        return
    deadline = state.get("deadline", 0)
    while time.time() < deadline:
        time.sleep(2)
        state = _load()
        if state.get("token") != token or not state.get("armed"):
            return  # confirmed or superseded
    # Deadline passed without confirmation: roll back
    from csf_backend import config_backup, csf_wrapper as csf
    res = config_backup.restore_backup(state["baseline"])
    restart = csf.restart_both() if res.get("success") else {"success": False}
    msg = (f"No confirmation within {state.get('seconds')}s — restored {state['baseline']} and restarted csf+lfd"
           if res.get("success") else f"Rollback FAILED: {res.get('error')}")
    _log(msg)
    _save({"rolled_back": {"at": int(time.time()), "message": msg, "success": bool(res.get("success") and restart.get("success", True))}})
    try:
        from csf_backend import notifications
        notifications.event("safe_apply", "Firewall change rolled back", msg)
    except Exception:
        pass


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--watch":
        _watch(sys.argv[2])
