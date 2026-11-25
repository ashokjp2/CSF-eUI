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
CACHE_FILE = "/var/cache/csfv2/version.json"
_DEFAULT_CACHE_TTL = 12 * 3600

UPDATE_SERVICE_UNIT = "/etc/systemd/system/csfv2-update-check.service"
UPDATE_TIMER_UNIT = "/etc/systemd/system/csfv2-update-check.timer"

_UPDATE_SERVICE_CONTENT = """[Unit]
Description=CSF-eUI version check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/csfv2/venv/bin/python3 /opt/csfv2/csf_backend/_version_check_runner.py
"""

_UPDATE_TIMER_CONTENT = """[Unit]
Description=CSF-eUI update check every 12 hours

[Timer]
Unit=csfv2-update-check.service
OnBootSec=5min
OnUnitActiveSec=12h
Persistent=true

[Install]
WantedBy=timers.target
"""


DOCKER_GUARD_SCRIPT = "/usr/local/sbin/csfv2-docker-chain-guard"
DOCKER_GUARD_SERVICE_UNIT = "/etc/systemd/system/csfv2-docker-chain-guard.service"
DOCKER_GUARD_TIMER_UNIT = "/etc/systemd/system/csfv2-docker-chain-guard.timer"

# Runs every 30 seconds, so the healthy path must stay a single iptables call.
# The Docker CLI is only consulted once the chain is actually missing, and a
# cooldown stops a persistent problem from turning into a Docker restart loop.
_DOCKER_GUARD_SCRIPT_CONTENT = r"""#!/bin/bash
# Managed by CSFv2 (rewritten on every update). Restores Docker's firewall
# chains when something outside CSFv2 flushes iptables (e.g. csf -r from a shell).
set -u

chain_ok() { iptables -w 5 -t filter -S DOCKER-FORWARD >/dev/null 2>&1; }

chain_ok && exit 0
systemctl is-active --quiet docker || exit 0

# Only Docker 28+ with the iptables backend owns a DOCKER-FORWARD chain.
VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
MAJOR="${VERSION%%.*}"
case "$MAJOR" in ''|*[!0-9]*) exit 0 ;; esac
[ "$MAJOR" -ge 28 ] || exit 0
BACKEND="$(docker info --format '{{with .FirewallBackend}}{{.Driver}}{{end}}' 2>/dev/null || true)"
case "$BACKEND" in *nftables*) exit 0 ;; esac

# CSF may be mid-reload; give its csfpost hook time to finish first.
sleep 10
chain_ok && exit 0

STAMP=/run/csfv2-docker-chain-guard.last
NOW="$(date +%s)"
LAST="$(cat "$STAMP" 2>/dev/null || echo 0)"
case "$LAST" in ''|*[!0-9]*) LAST=0 ;; esac
[ $((NOW - LAST)) -ge 600 ] || exit 0
echo "$NOW" > "$STAMP"

logger -t csfv2-docker-chain-guard "DOCKER-FORWARD missing; restarting Docker to restore its chains"
systemctl restart docker || true

for _ in $(seq 1 20); do
    chain_ok && exit 0
    sleep 1
done

logger -t csfv2-docker-chain-guard "Docker restarted but DOCKER-FORWARD is still missing"
exit 1
"""

_DOCKER_GUARD_SERVICE_CONTENT = """[Unit]
Description=CSFv2 Docker firewall chain guard
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/csfv2-docker-chain-guard
TimeoutStartSec=180
# Hide the per-run Starting/Finished lines; guard notices still reach the journal.
LogLevelMax=notice
"""

_DOCKER_GUARD_TIMER_CONTENT = """[Unit]
Description=Check Docker firewall chains every 30 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
Unit=csfv2-docker-chain-guard.service

[Install]
WantedBy=timers.target
"""


def _write_if_changed(path, content, mode):
    """Atomically write ``content`` to ``path``; return True when it changed."""
    try:
        with open(path) as f:
            if f.read() == content:
                return False
    except FileNotFoundError:
        pass
    fd, temp_path = tempfile.mkstemp(prefix=".csfv2-", dir=os.path.dirname(path), text=True)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return True


def _repair_docker_chain_guard():
    """Install or upgrade the Docker chain guard script and its timer.

    v1.2.74 shipped a guard whose ``docker info`` template was invalid, so it
    exited before checking anything while still costing a Docker CLI call every
    30 seconds. Rewrite it on every update/startup; safe to re-run.
    """
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return ["WARNING: systemctl is unavailable; skipped Docker chain guard repair."]
    if not (os.path.exists(DOCKER_GUARD_SCRIPT) or shutil.which("docker")):
        return ["Docker not installed; Docker chain guard not needed."]

    try:
        changed = _write_if_changed(DOCKER_GUARD_SCRIPT, _DOCKER_GUARD_SCRIPT_CONTENT, 0o755)
        units_changed = False
        for path, content in ((DOCKER_GUARD_SERVICE_UNIT, _DOCKER_GUARD_SERVICE_CONTENT),
                              (DOCKER_GUARD_TIMER_UNIT, _DOCKER_GUARD_TIMER_CONTENT)):
            units_changed = _write_if_changed(path, content, 0o644) or units_changed
        if units_changed:
            subprocess.run([systemctl, "daemon-reload"], capture_output=True, text=True, timeout=15)
        subprocess.run([systemctl, "enable", "--now", "csfv2-docker-chain-guard.timer"],
                       capture_output=True, text=True, timeout=15)
        active = subprocess.run([systemctl, "is-active", "--quiet", "csfv2-docker-chain-guard.timer"],
                                capture_output=True, text=True, timeout=15)
        if active.returncode != 0:
            return ["WARNING: Docker chain guard timer is not active."]
        if changed or units_changed:
            return ["Docker chain guard updated and timer is active."]
        return ["Docker chain guard verified active."]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"WARNING: Docker chain guard repair failed: {exc}"]


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


def _repair_update_timer():
    """Repair legacy timer units after an application update."""
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return ["WARNING: systemctl is unavailable; skipped update timer repair."]

    desired = {
        UPDATE_SERVICE_UNIT: _UPDATE_SERVICE_CONTENT,
        UPDATE_TIMER_UNIT: _UPDATE_TIMER_CONTENT,
    }
    changed = []
    backup_stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")

    try:
        for path, content in desired.items():
            try:
                with open(path) as f:
                    current = f.read()
            except FileNotFoundError:
                current = None

            if current == content:
                continue

            if os.path.exists(path):
                shutil.copy2(path, f"{path}.bak-{backup_stamp}")

            fd, temp_path = tempfile.mkstemp(
                prefix=".csfv2-update-unit-",
                dir=os.path.dirname(path),
                text=True,
            )
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(content)
                os.chmod(temp_path, 0o644)
                os.replace(temp_path, path)
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            changed.append(path)

        if changed:
            reload_result = subprocess.run(
                [systemctl, "daemon-reload"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if reload_result.returncode != 0:
                detail = (reload_result.stderr or reload_result.stdout).strip()
                return [f"WARNING: update timer reload failed: {detail}"]

        active_result = subprocess.run(
            [systemctl, "is-active", "--quiet", "csfv2-update-check.timer"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if active_result.returncode == 0 and not changed:
            return ["Update-check timer verified active."]

        start_result = subprocess.run(
            [systemctl, "enable", "--now", "csfv2-update-check.timer"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        active_result = subprocess.run(
            [systemctl, "is-active", "--quiet", "csfv2-update-check.timer"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if active_result.returncode != 0:
            detail = (start_result.stderr or start_result.stdout).strip()
            return [
                "WARNING: update timer is still inactive."
                + (f" {detail}" if detail else "")
            ]

        if changed:
            return ["Update-check systemd units repaired and timer is active."]
        return ["Update-check timer verified active."]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"WARNING: update timer repair failed: {exc}"]


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
                os.makedirs(os.path.dirname(CACHE_FILE), mode=0o700, exist_ok=True)
                with tempfile.NamedTemporaryFile(mode="w", dir=os.path.dirname(CACHE_FILE), delete=False) as f:
                    temporary = f.name
                    json.dump(cache, f)
                os.replace(temporary, CACHE_FILE)
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

    # Fetch, then hard-reset to origin/main.  Unlike ``git pull`` this keeps
    # working if the GitHub history is ever rewritten (force-pushed), because it
    # never tries to merge diverged histories.  Local edits were discarded above.
    yield from _sse("Running: git fetch origin main")
    rc = 1
    for cmd in (["git", "fetch", "origin", "main"],
                ["git", "reset", "--hard", "FETCH_HEAD"]):
        if cmd[1] == "reset":
            yield from _sse("Running: git reset --hard origin/main")
        proc = subprocess.Popen(
            cmd,
            cwd=INSTALL_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            yield from _sse(line.rstrip())
        rc = proc.wait()
        if rc != 0:
            break

    if rc != 0:
        yield from _sse(f"ERROR: git fetch/reset failed (exit {rc}). Update aborted.")
        yield "data: __DONE_ERROR__\n\n"
        return

    yield from _sse("")
    yield from _sse("Checking the update-check systemd timer...")
    for timer_message in _repair_update_timer():
        yield from _sse(timer_message)
    for guard_message in _repair_docker_chain_guard():
        yield from _sse(guard_message)

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
    # Run the restart in a separate transient systemd unit. Restarting the
    # current service directly terminates this updater process with SIGTERM
    # when systemd stops csfv2, which makes a successful update look failed.
    proc = subprocess.Popen(
        ["systemd-run", "--quiet", "--no-block",
         f"--unit=csfv2-update-restart-{os.getpid()}",
         "systemctl", "restart", "csfv2"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    for line in proc.stdout:
        yield from _sse(line.rstrip())
    rc = proc.wait()

    if rc == 0:
        yield from _sse("")
        yield from _sse("=== Update complete! Restart scheduled. ===")
        yield from _sse("Refresh this page in a few seconds.")
        yield "data: __DONE_OK__\n\n"
    else:
        yield from _sse(f"Service restart scheduling failed (exit {rc}).")
        yield from _sse("Run manually: systemctl restart csfv2")
        yield "data: __DONE_ERROR__\n\n"
