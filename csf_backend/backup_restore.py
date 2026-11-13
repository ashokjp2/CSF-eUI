import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime

from werkzeug.utils import secure_filename

CSF_DIR = "/etc/csf"
BACKUP_DIR = "/var/lib/csfv2/backups"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
SSL_ARCHIVE_FILES = ("ssl/certificate.pem", "ssl/private-key.pem", "ssl/paths.json")
SSL_ALLOWED_ROOTS = ("/etc/csfv2/ssl", "/etc/letsencrypt/live")

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
            ssl_included = False
            try:
                with tarfile.open(path, "r:gz") as tar:
                    ssl_included = set(SSL_ARCHIVE_FILES).issubset({member.name for member in tar.getmembers()})
            except (OSError, tarfile.TarError):
                pass
            backups.append({
                "filename": f,
                "path": path,
                "size": stat.st_size,
                "size_human": _human_size(stat.st_size),
                "created": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "ssl_included": ssl_included,
            })
    return backups


def create_backup(label=""):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"csf_backup_{ts}"
    if label:
        safe = "".join(c for c in label if c.isalnum() or c in "-_")[:30]
        name = f"csf_backup_{ts}_{safe}"
    tarpath = os.path.join(BACKUP_DIR, f"{name}.tar.gz")

    ssl_paths = _active_ssl_paths()
    try:
        with tarfile.open(tarpath, "w:gz") as tar:
            for fname in BACKUP_FILES:
                fpath = os.path.join(CSF_DIR, fname)
                if os.path.isfile(fpath):
                    tar.add(fpath, arcname=fname)
            if ssl_paths:
                _add_file_bytes(tar, "ssl/certificate.pem", ssl_paths["cert_path"])
                _add_file_bytes(tar, "ssl/private-key.pem", ssl_paths["key_path"])
                _add_bytes(tar, "ssl/paths.json", json.dumps(ssl_paths, sort_keys=True).encode("utf-8"))
        os.chmod(tarpath, 0o600)
    except OSError as e:
        if os.path.exists(tarpath):
            os.unlink(tarpath)
        return {"success": False, "error": str(e)}

    message = f"Backup created: {name}.tar.gz"
    if ssl_paths:
        message += " Active SSL certificate and key included."
    return {
        "success": True,
        "message": message,
        "filename": f"{name}.tar.gz",
        "ssl_included": bool(ssl_paths),
    }


def _is_allowed_ssl_path(path):
    """Allow certificate paths only in the app's managed certificate locations."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return False
    normalized = os.path.abspath(path)
    return any(os.path.commonpath([normalized, root]) == root for root in SSL_ALLOWED_ROOTS)


def _active_ssl_paths():
    """Return the active certificate/key paths when both are safely managed."""
    try:
        from csf_backend import ssl_manager

        current = (ssl_manager.get_ssl_status() or {}).get("current_cert") or {}
        cert_path = current.get("cert_path")
        key_path = current.get("key_path")
        if (
            _is_allowed_ssl_path(cert_path)
            and _is_allowed_ssl_path(key_path)
            and os.path.isfile(cert_path)
            and os.path.isfile(key_path)
        ):
            return {"cert_path": cert_path, "key_path": key_path}
    except (OSError, ImportError):
        pass
    return None


def _add_bytes(tar, archive_name, data, mode=0o600):
    info = tarfile.TarInfo(archive_name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(data))


def _add_file_bytes(tar, archive_name, path):
    with open(path, "rb") as source:
        _add_bytes(tar, archive_name, source.read(), 0o600 if "private" in archive_name else 0o644)


def _backup_path(filename):
    """Return a safe path for a stored backup filename, or None."""
    if not filename or filename != os.path.basename(filename) or not filename.endswith(".tar.gz"):
        return None
    return os.path.join(BACKUP_DIR, filename)


def _validate_archive(path):
    """Validate that an archive contains only regular, expected CSF files."""
    try:
        with tarfile.open(path, "r:gz") as tar:
            allowed_files = set(BACKUP_FILES) | set(SSL_ARCHIVE_FILES)
            seen = set()
            total_size = 0
            for member in tar:
                total_size += member.size
                if total_size > MAX_UPLOAD_BYTES:
                    return False, "Uncompressed backup exceeds 50 MB"
                if member.name not in allowed_files:
                    return False, f"Unexpected file in backup: {member.name}"
                if member.name in seen:
                    return False, f"Duplicate file in backup: {member.name}"
                if not member.isfile():
                    return False, f"Backup contains a non-regular file: {member.name}"
                seen.add(member.name)
            if not seen:
                return False, "Backup archive is empty"
            ssl_members = set(SSL_ARCHIVE_FILES) & seen
            if ssl_members and ssl_members != set(SSL_ARCHIVE_FILES):
                return False, "SSL backup is incomplete"
            if ssl_members:
                metadata = tar.extractfile("ssl/paths.json")
                try:
                    paths = json.load(metadata)
                except (TypeError, ValueError):
                    return False, "Invalid SSL path metadata in backup"
                if not isinstance(paths, dict) or not (
                    _is_allowed_ssl_path(paths.get("cert_path"))
                    and _is_allowed_ssl_path(paths.get("key_path"))
                ):
                    return False, "SSL paths in backup are not allowed"
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
    os.chmod(BACKUP_DIR, 0o700)
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

    os.chmod(path, 0o600)
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

    ssl_members = set()
    try:
        with tarfile.open(path, "r:gz") as tar:
            members = tar.getmembers()
            config_members = [member for member in members if member.name in BACKUP_FILES]
            for member in config_members:
                target = os.path.join(CSF_DIR, member.name)
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(dir=CSF_DIR, delete=False) as destination:
                        temporary = destination.name
                        os.chmod(temporary, 0o600)
                        with tar.extractfile(member) as source:
                            shutil.copyfileobj(source, destination)
                    os.replace(temporary, target)
                finally:
                    if temporary and os.path.exists(temporary):
                        os.unlink(temporary)

            ssl_members = set(SSL_ARCHIVE_FILES) & {member.name for member in members}
            if ssl_members:
                metadata = tar.extractfile("ssl/paths.json")
                ssl_paths = json.load(metadata)
                _restore_ssl_file(tar, "ssl/certificate.pem", ssl_paths["cert_path"], 0o644)
                _restore_ssl_file(tar, "ssl/private-key.pem", ssl_paths["key_path"], 0o600)
    except (OSError, tarfile.TarError) as e:
        return {"success": False, "error": str(e)}
    except (KeyError, TypeError, ValueError) as e:
        return {"success": False, "error": f"Invalid SSL metadata: {e}"}

    code, _, err = _run(["csf", "-r"], timeout=60)
    if code != 0:
        return {"success": False, "error": f"Config restored but CSF restart failed: {err}"}

    message = "Backup restored and CSF restarted."
    if ssl_members:
        message += " SSL certificate and key restored; restart CSFv2 to apply the SSL changes."
    return {"success": True, "message": message, "ssl_restored": bool(ssl_members)}


def _restore_ssl_file(tar, archive_name, target_path, mode):
    if not _is_allowed_ssl_path(target_path):
        raise ValueError(f"SSL path is not allowed: {target_path}")
    source = tar.extractfile(archive_name)
    if source is None:
        raise ValueError(f"Missing SSL file: {archive_name}")
    os.makedirs(os.path.dirname(target_path), exist_ok=True)

    # Preserve certbot's live symlinks by writing through them instead of replacing them.
    if os.path.islink(target_path):
        with open(target_path, "wb") as destination:
            shutil.copyfileobj(source, destination)
        return

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=os.path.dirname(target_path), prefix=".csfv2-restore-", delete=False
        ) as destination:
            temp_path = destination.name
            shutil.copyfileobj(source, destination)
        os.chmod(temp_path, mode)
        os.replace(temp_path, target_path)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


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
