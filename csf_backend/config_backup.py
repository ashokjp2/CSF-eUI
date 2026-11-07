import os
import shutil
import tarfile
import time
from pathlib import Path

CSF_DIR = "/etc/csf"
BACKUP_DIR = "/opt/csfv2/backups"
MAX_BACKUPS = 10

CSF_FILES = [
    "csf.conf", "csf.allow", "csf.deny", "csf.ignore",
    "csf.pignore", "csf.fignore", "csf.rignore", "csf.signore",
    "csf.dyndns", "csf.blocklists", "csf.dirwatch",
    "csf.syslogusers", "csf.logfiles", "csf.smtpauth",
    "csf.rblconf",
]


def _ensure_dir():
    os.makedirs(BACKUP_DIR, exist_ok=True)


def create_backup(label=""):
    _ensure_dir()
    ts = time.strftime("%Y%m%d_%H%M%S")
    name = f"csf_backup_{ts}"
    if label:
        safe_label = "".join(c for c in label if c.isalnum() or c in "-_")[:30]
        name = f"csf_backup_{ts}_{safe_label}"
    tar_path = os.path.join(BACKUP_DIR, name + ".tar.gz")

    try:
        with tarfile.open(tar_path, "w:gz") as tar:
            for fn in CSF_FILES:
                full = os.path.join(CSF_DIR, fn)
                if os.path.isfile(full):
                    tar.add(full, arcname=fn)
        size = os.path.getsize(tar_path)
        _cleanup_old()
        return {
            "success": True,
            "filename": name + ".tar.gz",
            "path": tar_path,
            "size": size,
            "files": [fn for fn in CSF_FILES if os.path.isfile(os.path.join(CSF_DIR, fn))],
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def list_backups():
    _ensure_dir()
    backups = []
    for fn in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if fn.startswith("csf_backup_") and fn.endswith(".tar.gz"):
            full = os.path.join(BACKUP_DIR, fn)
            stat = os.stat(full)
            parts = fn.replace("csf_backup_", "").replace(".tar.gz", "")
            ts_str = parts[:15]
            label = parts[16:] if len(parts) > 16 else ""
            try:
                created = time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.strptime(ts_str, "%Y%m%d_%H%M%S"),
                )
            except ValueError:
                created = "Unknown"

            try:
                with tarfile.open(full, "r:gz") as tar:
                    file_count = len(tar.getnames())
            except Exception:
                file_count = 0

            backups.append({
                "filename": fn,
                "created": created,
                "size": stat.st_size,
                "size_human": _human_size(stat.st_size),
                "label": label.replace("_", " "),
                "files": file_count,
            })
    return backups


def restore_backup(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.isfile(path):
        return {"success": False, "error": "Backup file not found"}
    if ".." in filename or "/" in filename:
        return {"success": False, "error": "Invalid filename"}

    auto = create_backup(label="pre-restore")
    if not auto["success"]:
        return {"success": False, "error": f"Failed to create safety backup: {auto['error']}"}

    try:
        with tarfile.open(path, "r:gz") as tar:
            names = tar.getnames()
            for name in names:
                if name not in CSF_FILES:
                    return {"success": False, "error": f"Unexpected file in backup: {name}"}
            tar.extractall(path=CSF_DIR)
        return {
            "success": True,
            "restored": names,
            "safety_backup": auto["filename"],
            "message": f"Restored {len(names)} files. A safety backup was created: {auto['filename']}. Restart CSF to apply.",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def delete_backup(filename):
    path = os.path.join(BACKUP_DIR, filename)
    if not os.path.isfile(path):
        return {"success": False, "error": "File not found"}
    if ".." in filename or "/" in filename:
        return {"success": False, "error": "Invalid filename"}
    try:
        os.unlink(path)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _cleanup_old():
    backups = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.startswith("csf_backup_")],
        reverse=True,
    )
    for fn in backups[MAX_BACKUPS:]:
        try:
            os.unlink(os.path.join(BACKUP_DIR, fn))
        except OSError:
            pass


def _human_size(n):
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"
