import os
import subprocess
import tarfile
import time
from datetime import datetime

from werkzeug.utils import secure_filename

CSF_DIR = "/etc/csf"
BACKUP_DIR = "/var/lib/csfv2/backups"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024

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


def _backup_path(filename):
    """Return a safe path for a stored backup filename, or None."""
    if not filename or filename != os.path.basename(filename) or not filename.endswith(".tar.gz"):
        return None
    return os.path.join(BACKUP_DIR, filename)


def _validate_archive(path):
    """Validate that an archive contains only regular, expected CSF files."""
    try:
        with tarfile.open(path, "r:gz") as tar:
            members = tar.getmembers()
            if not members:
                return False, "Backup archive is empty"

            seen = set()
            for member in members:
                if member.name not in BACKUP_FILES:
                    return False, f"Unexpected file in backup: {member.name}"
                if member.name in seen:
                    return False, f"Duplicate file in backup: {member.name}"
                if not member.isfile():
                    return False, f"Backup contains a non-regular file: {member.name}"
                seen.add(member.name)
    except (OSError, tarfile.TarError) as e:
        return False, f"Invalid backup archive: {e}"
    return True, ""


def upload_backup(file_storage):
    """Validate and save an uploaded CSF backup archive for later restore."""
    if not file_storage or not getattr(file_storage, "filename", ""):
        return {"success": False, "error": "Select a backup file to upload"}

    original_name = secure_filename(file_storage.filename)
    if not original_name or not original_name.endswith(".tar.gz"):
        return {"success": False, "error": "Backup must be a .tar.gz file"}

    os.makedirs(BACKUP_DIR, exist_ok=True)
    label = original_name[:-7]
    label = "".join(c for c in label if c.isalnum() or c in "-_")[:30] or "backup"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"csf_backup_{timestamp}_uploaded_{label}.tar.gz"
    path = os.path.join(BACKUP_DIR, filename)
    suffix = 2
    while os.path.exists(path):
        filename = f"csf_backup_{timestamp}_uploaded_{label}_{suffix}.tar.gz"
        path = os.path.join(BACKUP_DIR, filename)
        suffix += 1

    try:
        file_storage.save(path)
        if os.path.getsize(path) > MAX_UPLOAD_BYTES:
            os.unlink(path)
            return {"success": False, "error": "Backup file is too large (maximum 50 MB)"}

        valid, error = _validate_archive(path)
        if not valid:
            os.unlink(path)
            return {"success": False, "error": error}
    except OSError as e:
        if os.path.exists(path):
            os.unlink(path)
        return {"success": False, "error": str(e)}

    return {
        "success": True,
        "filename": filename,
        "message": f"Backup uploaded: {filename}. Use Restore to apply it.",
    }


def restore_backup(filename):
    path = _backup_path(filename)
    if not path or not os.path.isfile(path):
        return {"success": False, "error": "Backup file not found"}

    valid, error = _validate_archive(path)
    if not valid:
        return {"success": False, "error": error}

    # Create a pre-restore backup first
    safety_backup = create_backup(label="pre-restore")
    if not safety_backup["success"]:
        return {"success": False, "error": f"Failed to create safety backup: {safety_backup['error']}"}

    try:
        with tarfile.open(path, "r:gz") as tar:
            tar.extractall(CSF_DIR)
    except (OSError, tarfile.TarError) as e:
        return {"success": False, "error": str(e)}

    code, _, err = _run(["csf", "-r"], timeout=60)
    if code != 0:
        return {"success": False, "error": f"Config restored but CSF restart failed: {err}"}

    return {"success": True, "message": "Backup restored and CSF restarted."}


def delete_backup(filename):
    path = _backup_path(filename)
    if not path or not os.path.isfile(path):
        return {"success": False, "error": "Backup not found"}
    os.unlink(path)
    return {"success": True, "message": "Backup deleted"}


def download_path(filename):
    path = _backup_path(filename)
    if path and os.path.isfile(path):
        return path
    return None


def _human_size(b):
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"
