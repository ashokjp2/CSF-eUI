"""Off-server copies of configuration backups: SFTP (scp), WebDAV/HTTP PUT, or rclone when installed."""
import json
import os
import shutil
import subprocess
import time

CONF = "/etc/csfv2/remote_backup.json"
DEFAULT = {"enabled": False, "method": "sftp", "sftp": {"host": "", "port": 22, "user": "", "key": "/root/.ssh/id_ed25519", "path": "/backups/csf"},
           "webdav": {"url": "", "user": "", "password": ""}, "rclone": {"remote": ""}, "keep": 14}


def load():
    c = json.loads(json.dumps(DEFAULT))
    try:
        with open(CONF) as f:
            saved = json.load(f)
        for k, v in saved.items():
            if isinstance(v, dict) and isinstance(c.get(k), dict):
                c[k].update(v)
            elif k in c:
                c[k] = v
    except (OSError, ValueError):
        pass
    return c


def save(data):
    c = load()
    for k in ("enabled", "method", "keep"):
        if k in data:
            c[k] = data[k]
    for sec in ("sftp", "webdav", "rclone"):
        for k, v in (data.get(sec) or {}).items():
            if k in c[sec] and not (k == "password" and v == ""):
                c[sec][k] = v
    c["keep"] = max(1, int(c.get("keep") or 14))
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    with open(CONF, "w") as f:
        json.dump(c, f, indent=2)
    os.chmod(CONF, 0o600)
    return c


def public():
    c = load()
    c["webdav"]["password_set"] = bool(c["webdav"]["password"])
    c["webdav"]["password"] = ""
    c["rclone_available"] = bool(shutil.which("rclone"))
    return c


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, (r.stderr or r.stdout).strip()[-400:]
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)


def upload(local_path):
    c = load()
    name = os.path.basename(local_path)
    m = c["method"]
    if m == "sftp":
        s = c["sftp"]
        if not (s["host"] and s["user"]):
            return {"success": False, "error": "SFTP host/user not set"}
        base = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-P", str(s["port"]), "-i", s["key"]]
        ok, out = _run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-p", str(s["port"]), "-i", s["key"],
                        f"{s['user']}@{s['host']}", f"mkdir -p '{s['path']}'"])
        if ok:
            ok, out = _run(["scp"] + base + [local_path, f"{s['user']}@{s['host']}:{s['path']}/{name}"])
        if ok:
            _run(["ssh", "-o", "BatchMode=yes", "-p", str(s["port"]), "-i", s["key"], f"{s['user']}@{s['host']}",
                  f"cd '{s['path']}' && ls -1t csf_backup_*.tar.gz 2>/dev/null | tail -n +{int(c['keep']) + 1} | xargs -r rm -f"])
        return {"success": ok, "error": "" if ok else out, "target": f"sftp://{s['host']}{s['path']}/{name}"}
    if m == "webdav":
        w = c["webdav"]
        if not w["url"]:
            return {"success": False, "error": "WebDAV URL not set"}
        url = w["url"].rstrip("/") + "/" + name
        cmd = ["curl", "-sS", "-f", "-T", local_path, url]
        if w["user"]:
            cmd += ["-u", f"{w['user']}:{w['password']}"]
        ok, out = _run(cmd)
        return {"success": ok, "error": "" if ok else out, "target": url}
    if m == "rclone":
        r = c["rclone"]
        if not shutil.which("rclone"):
            return {"success": False, "error": "rclone is not installed on this server"}
        if not r["remote"]:
            return {"success": False, "error": "rclone remote not set (e.g. s3:bucket/csf)"}
        ok, out = _run(["rclone", "copyto", local_path, r["remote"].rstrip("/") + "/" + name])
        if ok:
            _run(["rclone", "delete", "--min-age", f"{int(c['keep']) * 7}d", r["remote"]])
        return {"success": ok, "error": "" if ok else out, "target": r["remote"] + "/" + name}
    return {"success": False, "error": "Unknown method"}


def maybe_upload(result):
    """Called after a local backup is created; uploads if enabled. Never raises."""
    try:
        if load().get("enabled") and result.get("success"):
            r = upload(result["path"])
            result["remote"] = r
    except Exception as e:
        result["remote"] = {"success": False, "error": str(e)}
    return result


def test():
    c = load()
    tmp = "/tmp/csf_backup_test.tar.gz"
    try:
        import tarfile
        with tarfile.open(tmp, "w:gz") as t:
            pass
    except Exception as e:
        return {"success": False, "error": str(e)}
    r = upload(tmp)
    r["method"] = c["method"]
    return r
