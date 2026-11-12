"""Push notifications: Telegram, Slack, Discord and generic webhooks.

Config lives in /etc/csfv2/notify.json. A background watcher (one per host, guarded by a
file lock so only one gunicorn worker runs it) tails lfd.log for new blocks and checks
LFD health, app updates and certificate expiry. Uses only the standard library.
"""
try:
    import fcntl
except ImportError:  # non-Linux dev machines: the watcher simply does not start
    fcntl = None
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.request
import urllib.error

CONF_PATH = "/etc/csfv2/notify.json"
STATE_PATH = "/var/lib/csfv2/notify_state.json"
LOCK_PATH = "/var/lib/csfv2/notify.lock"
LFD_LOG = "/var/log/lfd.log"
APP_LOG = "/var/log/csfv2.log"

CHANNELS = ("telegram", "slack", "discord", "webhook")
EVENTS = {
    "lfd_block":        "IP blocked by LFD (batched, at most one message per minute)",
    "lfd_down":         "LFD stopped running",
    "firewall_down":    "Firewall disabled or stopped",
    "update_available": "A new CSF-eUI version is available",
    "cert_expiry":      "HTTPS certificate expires within 14 days",
    "ui_login":         "Successful UI sign-in",
    "ui_login_failed":  "Failed UI sign-in attempt",
    "safe_apply":       "Safe-apply rolled back a change",
    "weekly_digest":    "Weekly digest (blocks, changes, open ports, certificate, updates)",
}
DEFAULT_CONF = {
    "channels": {
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        "slack":    {"enabled": False, "webhook_url": ""},
        "discord":  {"enabled": False, "webhook_url": ""},
        "webhook":  {"enabled": False, "url": "", "secret": ""},
    },
    "events": {k: (k in ("lfd_down", "firewall_down", "update_available", "cert_expiry", "safe_apply", "weekly_digest")) for k in EVENTS},
    "min_interval": 60,
    "digest": {"enabled": False, "weekday": 0, "hour": 8},
}

_lock = threading.Lock()
_watcher_started = False


# ---------- config ----------

def load_config():
    conf = json.loads(json.dumps(DEFAULT_CONF))
    try:
        with open(CONF_PATH) as f:
            saved = json.load(f)
        for ch, vals in (saved.get("channels") or {}).items():
            if ch in conf["channels"]:
                conf["channels"][ch].update(vals)
        for ev, on in (saved.get("events") or {}).items():
            if ev in conf["events"]:
                conf["events"][ev] = bool(on)
        conf["min_interval"] = int(saved.get("min_interval", conf["min_interval"]))
        conf["digest"].update({k: v for k, v in (saved.get("digest") or {}).items() if k in conf["digest"]})
    except (OSError, ValueError):
        pass
    return conf


def save_config(data):
    conf = load_config()
    for ch, vals in (data.get("channels") or {}).items():
        if ch in conf["channels"] and isinstance(vals, dict):
            for k in conf["channels"][ch]:
                if k in vals:
                    v = vals[k]
                    conf["channels"][ch][k] = bool(v) if k == "enabled" else str(v).strip()
    for ev in conf["events"]:
        if ev in (data.get("events") or {}):
            conf["events"][ev] = bool(data["events"][ev])
    try:
        conf["min_interval"] = max(10, int(data.get("min_interval", conf["min_interval"])))
    except (TypeError, ValueError):
        pass
    dg = data.get("digest") or {}
    if dg:
        conf["digest"]["enabled"] = bool(dg.get("enabled"))
        try:
            conf["digest"]["weekday"] = max(0, min(6, int(dg.get("weekday", conf["digest"]["weekday"]))))
            conf["digest"]["hour"] = max(0, min(23, int(dg.get("hour", conf["digest"]["hour"]))))
        except (TypeError, ValueError):
            pass
    os.makedirs(os.path.dirname(CONF_PATH), exist_ok=True)
    with open(CONF_PATH, "w") as f:
        json.dump(conf, f, indent=2)
    os.chmod(CONF_PATH, 0o600)
    return conf


def public_config():
    """Config for the UI: secrets are masked, only their presence is shown."""
    conf = load_config()
    for ch in conf["channels"].values():
        for k in ("bot_token", "webhook_url", "url", "secret"):
            if k in ch:
                ch[k + "_set"] = bool(ch[k])
                if k != "url":
                    ch[k] = ""
    conf["event_labels"] = EVENTS
    return conf


# ---------- state ----------

def _load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_PATH)
    except OSError:
        pass


def _log(msg):
    try:
        with open(APP_LOG, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] notify: {msg}\n")
    except OSError:
        pass


# ---------- sending ----------

def _post(url, body, headers=None, timeout=10):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "CSF-eUI-notify")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.status, r.read(500).decode("utf-8", "replace")


def _send_channel(name, ch, title, body, level):
    host = socket.gethostname()
    text = f"{title}\n{body}\n— {host}"
    if name == "telegram":
        url = f"https://api.telegram.org/bot{ch['bot_token']}/sendMessage"
        return _post(url, {"chat_id": ch["chat_id"], "text": f"*{title}*\n{body}\n_{host}_", "parse_mode": "Markdown"})
    if name == "slack":
        emoji = {"danger": ":rotating_light:", "warning": ":warning:", "info": ":information_source:", "success": ":white_check_mark:"}.get(level, "")
        return _post(ch["webhook_url"], {"text": f"{emoji} *{title}*\n{body}\n_{host}_"})
    if name == "discord":
        colour = {"danger": 0xDC2626, "warning": 0xD97706, "info": 0x4F7CFF, "success": 0x16A34A}.get(level, 0x6B7280)
        return _post(ch["webhook_url"], {"embeds": [{"title": title, "description": body[:4000], "color": colour, "footer": {"text": host}}]})
    if name == "webhook":
        payload = {"title": title, "body": body, "level": level, "host": host, "time": int(time.time())}
        raw = json.dumps(payload).encode()
        headers = {}
        if ch.get("secret"):
            headers["X-CSFv2-Signature"] = "sha256=" + hmac.new(ch["secret"].encode(), raw, hashlib.sha256).hexdigest()
        return _post(ch["url"], raw, headers)
    raise ValueError("unknown channel")


def _channel_ready(name, ch):
    if not ch.get("enabled"):
        return False
    if name == "telegram":
        return bool(ch.get("bot_token") and ch.get("chat_id"))
    if name in ("slack", "discord"):
        return bool(ch.get("webhook_url"))
    return bool(ch.get("url"))


def send(title, body, level="info", conf=None):
    """Send to every enabled channel. Returns {channel: 'ok'|error}."""
    conf = conf or load_config()
    results = {}
    for name in CHANNELS:
        ch = conf["channels"][name]
        if not _channel_ready(name, ch):
            continue
        try:
            status, _ = _send_channel(name, ch, title, body, level)
            results[name] = "ok" if status < 300 else f"HTTP {status}"
        except urllib.error.HTTPError as e:
            results[name] = f"HTTP {e.code}"
        except Exception as e:  # network errors must never break the caller
            results[name] = str(e)[:120]
    if results:
        _log(f"{title}: {results}")
    return results


def test_channel(name, overrides=None):
    conf = load_config()
    if name not in CHANNELS:
        return {"success": False, "error": "Unknown channel"}
    ch = dict(conf["channels"][name])
    for k, v in (overrides or {}).items():
        if k in ch and v not in ("", None):
            ch[k] = v
    ch["enabled"] = True
    if not _channel_ready(name, ch):
        return {"success": False, "error": "Channel is missing its token or URL"}
    try:
        status, text = _send_channel(name, ch, "CSF-eUI test notification", "If you can read this, notifications work.", "success")
        if status < 300:
            return {"success": True}
        return {"success": False, "error": f"HTTP {status}: {text[:200]}"}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code}: {e.read(300).decode('utf-8', 'replace')}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


EVENTS_PATH = "/var/lib/csfv2/notify_events.jsonl"
EVENTS_KEEP = 300
_LEVELS = {"lfd_block": "warning", "lfd_down": "danger", "firewall_down": "danger",
           "ui_login_failed": "warning", "safe_apply": "danger", "cert_expiry": "warning"}


def record(kind, title, body, level=None):
    """Append an event to the in-app notification centre (always, whatever the push settings)."""
    try:
        os.makedirs(os.path.dirname(EVENTS_PATH), exist_ok=True)
        with open(EVENTS_PATH, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "kind": kind, "title": title,
                                "body": (body or "")[:600], "level": level or _LEVELS.get(kind, "info")}) + "\n")
        if os.path.getsize(EVENTS_PATH) > 200_000:
            with open(EVENTS_PATH) as f:
                lines = f.readlines()[-EVENTS_KEEP:]
            with open(EVENTS_PATH, "w") as f:
                f.writelines(lines)
    except OSError:
        pass


def recent_events(limit=50):
    try:
        with open(EVENTS_PATH) as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def event(kind, title, body, level=None, conf=None):
    """Record an event in the notification centre and push it if that event is enabled.
    Safe to call from request handlers; never raises."""
    level = level or _LEVELS.get(kind, "info")
    record(kind, title, body, level)
    try:
        conf = conf or load_config()
        if not conf["events"].get(kind):
            return {}
        if not any(_channel_ready(n, conf["channels"][n]) for n in CHANNELS):
            return {}
        return send(title, body, level, conf)
    except Exception as e:
        _log(f"event {kind} failed: {e}")
        return {}


# ---------- background watcher ----------

_BLOCK_RE = re.compile(r"\*(?:Blocked|Block)[^*]*\*|Blocked in csf|Blocked temporarily", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_CC_RE = re.compile(r"\(([A-Z]{2})/")


def _tail_new_lines(state):
    """Return lines appended to lfd.log since the last check (handles rotation)."""
    try:
        st = os.stat(LFD_LOG)
    except OSError:
        return []
    pos = state.get("lfd_pos", 0)
    inode = state.get("lfd_inode")
    if inode != st.st_ino or pos > st.st_size:
        pos = st.st_size if inode is None else 0   # first run: start at end; rotation: start at 0
    lines = []
    try:
        with open(LFD_LOG, "rb") as f:
            f.seek(pos)
            chunk = f.read(512 * 1024)
            pos += len(chunk)
            lines = chunk.decode("utf-8", "replace").splitlines()
    except OSError:
        pass
    state["lfd_pos"], state["lfd_inode"] = pos, st.st_ino
    return lines


def _check_blocks(conf, state):
    lines = _tail_new_lines(state)
    blocks = []
    for line in lines:
        if _BLOCK_RE.search(line):
            ip = _IP_RE.search(line)
            cc = _CC_RE.search(line)
            reason = re.sub(r"^.*?lfd\[\d+\]:\s*", "", line)
            reason = re.sub(r"\*[^*]*\*", "", reason).replace("  ", " ").strip(" -")
            blocks.append(f"{ip.group(1) if ip else '?'}{' (' + cc.group(1) + ')' if cc else ''} — {reason[:110]}")
    if not blocks:
        return
    pending = state.setdefault("pending_blocks", []) + blocks
    state["pending_blocks"] = pending[-50:]
    last = state.get("last_block_sent", 0)
    if time.time() - last < conf.get("min_interval", 60):
        return
    pend = state.pop("pending_blocks")
    body = "\n".join(pend[:10])
    if len(pend) > 10:
        body += f"\n…and {len(pend) - 10} more"
    event("lfd_block", f"{len(pend)} IP{'s' if len(pend) != 1 else ''} blocked", body, "warning", conf)
    state["last_block_sent"] = time.time()


def _check_services(conf, state):
    from csf_backend import csf_wrapper as csf
    now = time.time()
    if now - state.get("last_service_check", 0) < 120:
        return
    state["last_service_check"] = now
    lfd = csf.lfd_status()
    lfd_running = lfd.get("success") and "active (running)" in lfd.get("stdout", "")
    enabled = csf.is_enabled()
    prev = state.get("services", {})
    if prev.get("lfd", True) and not lfd_running:
        event("lfd_down", "LFD is down", "Login failure detection is not running. Automatic blocking is off until it restarts.", "danger", conf)
    if prev.get("csf", True) and not enabled:
        event("firewall_down", "Firewall disabled", "CSF reports the firewall is disabled. No rules are active.", "danger", conf)
    state["services"] = {"lfd": bool(lfd_running), "csf": bool(enabled)}


def _check_updates(conf, state):
    now = time.time()
    if now - state.get("last_update_check", 0) < 6 * 3600:
        return
    state["last_update_check"] = now
    try:
        from csf_backend import updater
        info = updater.get_version_info()
        latest = info.get("latest")
        if info.get("update_available") and latest and state.get("notified_version") != latest:
            event("update_available", "CSF-eUI update available", f"Version {latest} is available (you have {info.get('current')}). Open System → Updates to install.", "info", conf)
            state["notified_version"] = latest
    except Exception as e:
        _log(f"update check failed: {e}")


def _check_cert(conf, state):
    now = time.time()
    if now - state.get("last_cert_check", 0) < 24 * 3600:
        return
    state["last_cert_check"] = now
    try:
        from csf_backend import ssl_manager
        status = ssl_manager.get_ssl_status()
        expiry = (status.get("current_cert") or {}).get("expiry", "")
        if not expiry:
            return
        from email.utils import parsedate_to_datetime
        try:
            exp_ts = parsedate_to_datetime(expiry).timestamp()
        except Exception:
            exp_ts = time.mktime(time.strptime(expiry.strip(), "%b %d %H:%M:%S %Y GMT"))
        days = int((exp_ts - now) // 86400)
        if days <= 14 and state.get("cert_notified_for") != expiry:
            event("cert_expiry", "HTTPS certificate expiring", f"The CSF-eUI certificate expires in {days} day{'s' if days != 1 else ''} ({expiry}).", "warning", conf)
            state["cert_notified_for"] = expiry
    except Exception as e:
        _log(f"cert check failed: {e}")


def _watch_loop():
    try:
        os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
        lock_fd = open(LOCK_PATH, "w")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        return  # another worker already runs the watcher
    _log("watcher started")
    while True:
        try:
            conf = load_config()
            state = _load_state()
            _check_blocks(conf, state)
            _check_services(conf, state)
            _check_updates(conf, state)
            _check_cert(conf, state)
            _save_state(state)
            try:
                from csf_backend import scheduled_rules, digest
                scheduled_rules.tick()
                if digest.due(conf):
                    digest.send()
            except Exception as e:
                _log(f"scheduled/digest error: {e}")
        except Exception as e:
            _log(f"watcher error: {e}")
        time.sleep(30)


def start_watcher():
    """Start the background watcher thread once per process (Linux only)."""
    global _watcher_started
    with _lock:
        if _watcher_started or fcntl is None:
            return
        _watcher_started = True
    t = threading.Thread(target=_watch_loop, name="csfv2-notify", daemon=True)
    t.start()
