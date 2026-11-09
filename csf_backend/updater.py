import os
import json
import shutil
import subprocess
import tempfile
import time
from datetime import datetime

GITHUB_REPO = "ashokjp2/CSF-eUI"
INSTALL_DIR = "/opt/csfv2"
VERSION_FILE = os.path.join(INSTALL_DIR, "VERSION")
CACHE_FILE = "/tmp/csfv2_version_cache.json"
_DEFAULT_CACHE_TTL = 12 * 3600


def _get_cache_ttl():
    try:
        from csf_backend import auto_update as _au
        hours = _au.load().get("check_interval_hours", 12)
        return max(1, int(hours)) * 3600
    except Exception:
        return _DEFAULT_CACHE_TTL


def get_current_version():
    try:
        with open(VERSION_FILE) as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def _fetch_latest_version():
    import urllib.request, json as _json, base64
    # GitHub CDN caches raw.githubusercontent.com and ignores no-cache headers.
    # The Contents API bypasses the CDN and always returns the live file.
    _headers = {
        "User-Agent": "CSF-eUI-updater/1.0",
        "Accept": "application/vnd.github+json",
    }
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/VERSION"
        req = urllib.request.Request(url, headers=_headers)
        with urllib.request.urlopen(req, timeout=10) as r:
            data = _json.loads(r.read())
            content = base64.b64decode(data["content"]).decode().strip()
            return content if content else None
    except Exception:
        pass
    # Fallback: raw URL (may be stale due to CDN)
    try:
        url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/VERSION"
        req = urllib.request.Request(url, headers=_headers)
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode().strip()
    except Exception:
        pass
    return None


def _version_tuple(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0,)


def _invalidate_cache():
    try:
        os.unlink(CACHE_FILE)
    except Exception:
        pass


def _quarantine_conflicting_untracked_files():
    """Move only untracked files that the incoming release will track.

    ``git reset --hard`` does not remove untracked files.  That matters after a
    quick SCP deployment of a file that is introduced by the next release:
    ``git pull`` refuses to overwrite it.  Keep unrelated server-local files
    untouched and only move explicit path conflicts with ``origin/main`` into a
    temporary backup directory.
    """
    fetch = subprocess.run(
        ["git", "fetch", "origin", "main"],
        cwd=INSTALL_DIR,
        capture_output=True,
        text=True,
    )
    if fetch.returncode != 0:
        detail = (fetch.stderr or fetch.stdout or "fetch failed").strip()
        return [], None, f"Could not inspect incoming files: {detail}"

    remote_result = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "FETCH_HEAD"],
        cwd=INSTALL_DIR,
        capture_output=True,
        text=True,
    )
    untracked_result = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=INSTALL_DIR,
        capture_output=True,
        text=True,
    )
    if remote_result.returncode != 0 or untracked_result.returncode != 0:
        return [], None, "Could not inspect local/remote file lists"

    remote_files = set(remote_result.stdout.splitlines())
    untracked_files = set(untracked_result.stdout.splitlines())
    conflicts = sorted(remote_files & untracked_files)
    install_root = os.path.abspath(INSTALL_DIR)
    backup_root = tempfile.mkdtemp(prefix="csfv2-update-conflicts-") if conflicts else None
    moved = []

    for relative_path in conflicts:
        target = os.path.abspath(os.path.join(INSTALL_DIR, relative_path))
        if os.path.commonpath([install_root, target]) != install_root:
            continue
        try:
            if os.path.islink(target) or os.path.isfile(target):
                backup_target = os.path.join(backup_root, relative_path)
                os.makedirs(os.path.dirname(backup_target), exist_ok=True)
                shutil.move(target, backup_target)
                moved.append(relative_path)
            elif os.path.isdir(target):
                # A directory can also block a tracked file path.  Move only
                # that explicit conflict, preserving it in the backup.
                backup_target = os.path.join(backup_root, relative_path)
                os.makedirs(os.path.dirname(backup_target), exist_ok=True)
                shutil.move(target, backup_target)
                moved.append(relative_path)
        except OSError:
            # Leave failures for git pull to report with the exact path.
            continue

    return moved, backup_root, None


def get_version_info(force=False):
    current = get_current_version()
    cache = {}
    try:
        with open(CACHE_FILE) as f:
            cache = json.load(f)
    except Exception:
        pass

    # If the installed version is newer than what the cache thinks is "latest",
    # the app was updated out-of-band (e.g. manual git pull) — cache is stale.
    cached_latest = cache.get("latest")
    if cached_latest and _version_tuple(current) > _version_tuple(cached_latest):
        force = True

    age = time.time() - cache.get("checked_at", 0)
    cache_ttl = _get_cache_ttl()
    if force or age > cache_ttl:
        if force:
            _invalidate_cache()
            cache = {}
        latest = _fetch_latest_version()
        if latest:
            cache = {"checked_at": time.time(), "latest": latest}
            try:
                with open(CACHE_FILE, "w") as f:
                    json.dump(cache, f)
            except Exception:
                pass
        else:
            cache["checked_at"] = time.time()

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

    # Discard tracked edits, then quarantine only untracked paths that conflict
    # with files in the incoming release.  reset --hard alone does not do this.
    yield from _sse("Running: git reset --hard HEAD")
    subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=INSTALL_DIR,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    yield from _sse("Checking for untracked files that conflict with the update")
    moved, backup_root, cleanup_error = _quarantine_conflicting_untracked_files()
    if moved:
        yield from _sse(
            "Moved conflicting files to backup "
            + backup_root
            + ": "
            + ", ".join(moved)
        )
    if cleanup_error:
        yield from _sse("Warning: " + cleanup_error)

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
