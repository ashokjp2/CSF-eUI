"""Multi-server view: a registry of other CSF-eUI servers reached through their token API.

Each remote server needs an API token (Settings → API tokens on that server). Status is
fetched in parallel; allow/deny/unblock actions fan out to the selected servers.
"""
import json
import os
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

REGISTRY_PATH = "/etc/csfv2/servers.json"
TIMEOUT = 8
ACTIONS = {"allow": "allow", "deny": "deny", "unblock": "unblock", "temp-deny": "temp-deny"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a server's bearer token to a redirect destination.
        return None


def _load():
    try:
        with open(REGISTRY_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"servers": []}


def _save(data):
    os.makedirs(os.path.dirname(REGISTRY_PATH), exist_ok=True)
    with open(REGISTRY_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(REGISTRY_PATH, 0o600)


def list_servers(mask=True):
    out = []
    for s in _load()["servers"]:
        s = dict(s)
        if mask:
            s["token"] = ""
            s["has_token"] = True
        out.append(s)
    return out


def add_server(name, url, token, verify_tls=True):
    url = (url or "").strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        return False, "URL must start with http:// or https://"
    if not token or not token.startswith("csf_"):
        return False, "Paste an API token from the remote server (Settings → API tokens)"
    data = _load()
    sid = secrets.token_hex(4)
    data["servers"].append({"id": sid, "name": (name or url)[:60], "url": url, "token": token.strip(),
                            "verify_tls": bool(verify_tls), "added": int(time.time())})
    _save(data)
    return True, sid


def update_server(sid, **fields):
    data = _load()
    for s in data["servers"]:
        if s["id"] == sid:
            for k, v in fields.items():
                if k in ("name", "url", "verify_tls") or (k == "token" and v):
                    s[k] = v
            _save(data)
            return True
    return False


def remove_server(sid):
    data = _load()
    before = len(data["servers"])
    data["servers"] = [s for s in data["servers"] if s["id"] != sid]
    _save(data)
    return len(data["servers"]) < before


def _get_server(sid):
    for s in _load()["servers"]:
        if s["id"] == sid:
            return s
    return None


def _request(server, path, body=None):
    url = server["url"].rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("Authorization", "Bearer " + server.get("token", ""))
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "CSF-eUI-multiserver")
    ctx = ssl.create_default_context()
    if not server.get("verify_tls", True):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    t0 = time.time()
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        with opener.open(req, timeout=TIMEOUT) as r:
            payload = json.loads(r.read().decode("utf-8", "replace") or "{}")
            return {"ok": True, "data": payload, "ms": int((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read().decode("utf-8", "replace")).get("error", "")
        except Exception:
            msg = ""
        return {"ok": False, "error": f"HTTP {e.code}" + (f": {msg}" if msg else ""), "ms": int((time.time() - t0) * 1000)}
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError, ValueError) as e:
        return {"ok": False, "error": str(getattr(e, "reason", e))[:160], "ms": int((time.time() - t0) * 1000)}


def fetch_status(server):
    r = _request(server, "/api/v1/status")
    out = {"id": server["id"], "name": server["name"], "url": server["url"], "ok": r["ok"], "ms": r.get("ms")}
    if r["ok"]:
        out.update(r["data"])
    else:
        out["error"] = r.get("error")
    return out


def all_status():
    servers = _load()["servers"]
    if not servers:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(servers))) as ex:
        return list(ex.map(fetch_status, servers))


def test_server(sid):
    s = _get_server(sid)
    if not s:
        return {"ok": False, "error": "Unknown server"}
    return fetch_status(s)


def fan_out(action, ip, server_ids, comment="", seconds=3600, ports="*"):
    """Run an IP action on several remote servers in parallel. Returns one result per server."""
    if action not in ACTIONS:
        return [{"error": "Invalid action"}]
    body = {"ip": ip, "comment": comment or "pushed from multi-server view"}
    if action == "temp-deny":
        body.update({"seconds": int(seconds), "ports": ports or "*"})
    targets = [s for s in _load()["servers"] if s["id"] in server_ids]

    def one(s):
        r = _request(s, "/api/v1/" + ACTIONS[action], body)
        d = r.get("data") or {}
        return {"id": s["id"], "name": s["name"], "ok": r["ok"] and bool(d.get("success", True)),
                "error": r.get("error") or ("" if d.get("success", True) else (d.get("output") or "failed")), "ms": r.get("ms")}

    if not targets:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as ex:
        return list(ex.map(one, targets))
