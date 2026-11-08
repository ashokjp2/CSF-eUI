import os
import json
import subprocess
import time
from datetime import datetime

GITHUB_REPO = "ashokjp2/CSF-eUI"
INSTALL_DIR = "/opt/csfv2"
VERSION_FILE = os.path.join(INSTALL_DIR, "VERSION")
CACHE_FILE = "/tmp/csfv2_version_cache.json"
CACHE_TTL = 12 * 3600


def get_current_version():
    try:
        with open(VERSION_FILE) as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def _fetch_latest_version():
    try:
        import urllib.request
        url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/VERSION"
        req = urllib.request.Request(url, headers={"User-Agent": "CSF-eUI-updater/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode().strip()
    except Exception:
        pass
    try:
        import urllib.request, json as _json
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "CSF-eUI-updater/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = _json.loads(r.read())
            tag = data.get("tag_name", "").lstrip("v")
            return tag if tag else None
    except Exception:
        pass
    return None


def _version_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)


def get_version_info(force=False):
    current = get_current_version()
    cache = {}
    try:
        with open(CACHE_FILE) as f:
            cache = json.load(f)
    except Exception:
        pass

    age = time.time() - cache.get("checked_at", 0)
    if force or age > CACHE_TTL:
        latest = _fetch_latest_version()
        cache = {"checked_at": time.time(), "latest": latest}
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump(cache, f)
        except Exception:
            pass

    latest = cache.get("latest")
    update_available = bool(
        latest and latest != "unknown"
        and _version_tuple(latest) > _version_tuple(current)
    )
    checked_at = cache.get("checked_at", 0)
    return {
        "current": current,
        "latest": latest or "unknown",
        "update_available": update_available,
        "last_checked": datetime.fromtimestamp(checked_at).strftime("%Y-%m-%d %H:%M")
        if checked_at else "Never",
    }


def run_update_stream(force=False):
    """Generator yielding SSE lines for a live update log."""

    def _sse(msg):
        # Escape any bare newlines inside the data value
        for line in msg.rstrip("\n").splitlines():
            yield f"data: {line}\n"
        yield "\n"

    yield from _sse("=== CSF-eUI Update Started ===")
    yield from _sse(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    yield from _sse("")

    # Check latest version first
    yield from _sse("Checking GitHub for latest version...")
    latest = _fetch_latest_version()
    current = get_current_version()
    yield from _sse(f"Installed : {current}")
    yield from _sse(f"Available : {latest or '(could not reach GitHub)'}")
    yield from _sse("")

    if not latest and not force:
        yield from _sse("ERROR: Could not reach GitHub. Check network connectivity.")
        yield "data: __DONE_ERROR__\n\n"
        return

    if not force and latest and _version_tuple(latest) <= _version_tuple(current):
        yield from _sse("Already up to date — nothing to do.")
        yield "data: __DONE_OK__\n\n"
        return

    if force:
        yield from _sse("Force re-install: pulling latest commits from GitHub...")
    else:
        yield from _sse(f"Updating {current} → {latest} ...")
    yield from _sse("")

    # git pull
    yield from _sse("Running: git pull origin main")
    proc = subprocess.Popen(
        ["git", "pull", "origin", "main"],
        cwd=INSTALL_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for line in proc.stdout:
        yield from _sse(line.rstrip())
    rc = proc.wait()

    if rc != 0:
        yield from _sse(f"ERROR: git pull failed (exit {rc}). Update aborted.")
        yield "data: __DONE_ERROR__\n\n"
        return

    # pip install
    pip_bin = os.path.join(INSTALL_DIR, "venv/bin/pip")
    req_file = os.path.join(INSTALL_DIR, "requirements.txt")
    if os.path.exists(pip_bin) and os.path.exists(req_file):
        yield from _sse("")
        yield from _sse("Installing Python dependencies...")
        proc = subprocess.Popen(
            [pip_bin, "install", "-r", req_file],
            cwd=INSTALL_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            yield from _sse(line.rstrip())
        proc.wait()

    # Invalidate version cache
    try:
        os.unlink(CACHE_FILE)
    except Exception:
        pass

    # Restart service
    yield from _sse("")
    yield from _sse("Restarting CSF-eUI service...")
    proc = subprocess.Popen(
        ["systemctl", "restart", "csfv2"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for line in proc.stdout:
        yield from _sse(line.rstrip())
    rc = proc.wait()

    if rc == 0:
        yield from _sse("")
        yield from _sse("=== Update complete! Service restarted. ===")
        yield from _sse("Refresh this page in a few seconds.")
        yield "data: __DONE_OK__\n\n"
    else:
        yield from _sse(f"Service restart failed (exit {rc}).")
        yield from _sse("Run manually: systemctl restart csfv2")
        yield "data: __DONE_ERROR__\n\n"
