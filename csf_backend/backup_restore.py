import os
import subprocess
import tarfile
import time
from datetime import datetime

CSF_DIR = "/etc/csf"
BACKUP_DIR = "/var/lib/csfv2/backups"

BACKUP_FILES = [
    "csf.conf", "csf.allow", "csf.deny", "csf.ignore",
    "csf.blocklists", "csf.dyndns", "csf.rignore",
    "csf.pignore", "csf.fignore", "csf.signore",
    "csf.smtpauth", "csf.rblconf", "csf.dirwatch",
    "csf.logfiles", "csf.syslogfiles",
]


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "", "Command failed"


def list_backups():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backups = []
    for f in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if f.endswith(".tar.gz"):
            path = os.path.join(BACKUP_DIR, f)
            stat = os.stat(path)
            backups.append({
                "filename": f,
                "path": path,
                "size": stat.st_size,
                "size_human": _human_size(stat.st_size),
                "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
    return backups


def create_backup(label=""):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"csf_backup_{ts}"
    if label:
        safe = "".join(c for c in label if c.isalnum() or c in "-_")[:30]
        name = f"csf_backup_{ts}_{safe}"
    tarpath = os.path.join(BACKUP_DIR, f"{name}.tar.gz")

    try:
        with tarfile.open(tarpath, "w:gz") as tar:
            for fname in BACKUP_FILES:
                fpath = os.path.join(CSF_DIR, fname)
                if os.path.isfile(fpath):
                    tar.add(fpath, arcname=fname)
    except OSError as e:
        return {"success": False, "error": str(e)}

    return {
        "success": True,
        "message": f"Backup created: {name}.tar.gz",
        "filename": f"{name}.tar.gz",
    }


def restore_backup(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.isfile(path):
        return {"success": False, "error": "Backup file not found"}
    if not filename.endswith(".tar.gz"):
        return {"success": False, "error": "Invalid backup file"}

    # Create a pre-restore backup first
    create_backup(label="pre-restore")

    try:
        with tarfile.open(path, "r:gz") as tar:
            members = tar.getnames()
            for m in members:
                if m.startswith("/") or ".." in m:
                    return {"success": False, "error": "Invalid path in backup archive"}
            tar.extractall(CSF_DIR)
    except (OSError, tarfile.TarError) as e:
        return {"success": False, "error": str(e)}

    code, _, err = _run(["csf", "-r"], timeout=60)
    if code != 0:
        return {"success": False, "error": f"Config restored but CSF restart failed: {err}"}

    return {"success": True, "message": "Backup restored and CSF restarted."}


def delete_backup(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.isfile(path):
        return {"success": False, "error": "Backup not found"}
    os.unlink(path)
    return {"success": True, "message": "Backup deleted"}


def download_path(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if os.path.isfile(path):
        return path
    return None


def _human_size(b):
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"
