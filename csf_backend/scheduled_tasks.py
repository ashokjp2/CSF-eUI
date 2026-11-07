import os
import subprocess
import tempfile


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "", "Command failed"


def get_all_cron_jobs():
    """Get cron jobs from all sources with unique IDs for edit/delete."""
    jobs = []
    idx = 0

    # Root crontab
    code, out, _ = _run(["crontab", "-l"])
    if code == 0:
        line_idx = 0
        for line in out.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 5)
            if len(parts) >= 6:
                jobs.append({
                    "id": idx,
                    "schedule": " ".join(parts[:5]),
                    "command": parts[5],
                    "source": "root crontab",
                    "source_type": "crontab",
                    "line_idx": line_idx,
                    "raw": stripped,
                    "editable": True,
                })
                idx += 1
            line_idx += 1

    # /etc/crontab (has user field after schedule)
    _parse_file_jobs("/etc/crontab", "/etc/crontab", jobs, idx, has_user=True)
    idx = len(jobs)

    # /etc/cron.d/*
    cron_d = "/etc/cron.d"
    if os.path.isdir(cron_d):
        for fname in sorted(os.listdir(cron_d)):
            fpath = os.path.join(cron_d, fname)
            if not os.path.isfile(fpath) or fname.startswith("."):
                continue
            _parse_file_jobs(fpath, "cron.d/" + fname, jobs, len(jobs), has_user=True)

    # Periodic directories
    for period in ["hourly", "daily", "weekly", "monthly"]:
        d = "/etc/cron." + period
        if os.path.isdir(d):
            sched_map = {"hourly": "0 * * * *", "daily": "0 0 * * *", "weekly": "0 0 * * 0", "monthly": "0 0 1 * *"}
            for fname in sorted(os.listdir(d)):
                fpath = os.path.join(d, fname)
                if os.path.isfile(fpath) and not fname.startswith("."):
                    jobs.append({
                        "id": len(jobs),
                        "schedule": sched_map[period],
                        "command": fpath,
                        "source": "cron." + period,
                        "source_type": "periodic",
                        "file_path": fpath,
                        "raw": "",
                        "editable": False,
                    })

    return jobs


def _parse_file_jobs(filepath, source, jobs, start_idx, has_user=False):
    """Parse cron jobs from a file like /etc/crontab or /etc/cron.d/*."""
    try:
        with open(filepath) as f:
            lines = f.readlines()
    except OSError:
        return

    line_num = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            line_num += 1
            continue
        # Skip env variable assignments
        if "=" in stripped and not stripped[0].isdigit() and stripped[0] != "*" and stripped[0] != "@":
            line_num += 1
            continue
        if has_user:
            parts = stripped.split(None, 6)
            if len(parts) >= 7:
                jobs.append({
                    "id": len(jobs),
                    "schedule": " ".join(parts[:5]),
                    "command": parts[5] + " " + parts[6],
                    "source": source,
                    "source_type": "file",
                    "file_path": filepath,
                    "line_num": line_num,
                    "raw": stripped,
                    "editable": True,
                })
        else:
            parts = stripped.split(None, 5)
            if len(parts) >= 6:
                jobs.append({
                    "id": len(jobs),
                    "schedule": " ".join(parts[:5]),
                    "command": parts[5],
                    "source": source,
                    "source_type": "file",
                    "file_path": filepath,
                    "line_num": line_num,
                    "raw": stripped,
                    "editable": True,
                })
        line_num += 1


def add_cron_job(schedule, command):
    """Add a cron entry to root's crontab."""
    if not schedule or not command:
        return {"success": False, "error": "Schedule and command are required"}
    code, existing, _ = _run(["crontab", "-l"])
    current = existing if code == 0 else ""
    new_line = f"{schedule} {command}"
    if new_line in current:
        return {"success": False, "error": "This cron job already exists"}
    new_cron = (current + "\n" if current else "") + new_line + "\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cron", delete=False) as f:
        f.write(new_cron)
        tmp = f.name
    code, _, err = _run(["crontab", tmp])
    os.unlink(tmp)
    if code != 0:
        return {"success": False, "error": err}
    return {"success": True, "message": "Cron job added"}


def delete_cron_job(job):
    """Delete a cron job by its metadata."""
    source_type = job.get("source_type")
    raw = job.get("raw", "")

    if source_type == "crontab":
        return _delete_from_crontab(raw)
    elif source_type == "file":
        return _delete_from_file(job.get("file_path", ""), raw)
    elif source_type == "periodic":
        fpath = job.get("file_path", "")
        if os.path.isfile(fpath):
            try:
                os.unlink(fpath)
                return {"success": True, "message": f"Removed {fpath}"}
            except OSError as e:
                return {"success": False, "error": str(e)}
    return {"success": False, "error": "Unknown job type"}


def _delete_from_crontab(raw_line):
    code, out, _ = _run(["crontab", "-l"])
    if code != 0:
        return {"success": False, "error": "No crontab found"}
    new_lines = [l for l in out.splitlines() if l.strip() != raw_line]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cron", delete=False) as f:
        f.write("\n".join(new_lines) + "\n")
        tmp = f.name
    code, _, err = _run(["crontab", tmp])
    os.unlink(tmp)
    if code != 0:
        return {"success": False, "error": err}
    return {"success": True, "message": "Cron job removed"}


def _delete_from_file(filepath, raw_line):
    if not filepath or not os.path.isfile(filepath):
        return {"success": False, "error": "File not found"}
    try:
        with open(filepath) as f:
            lines = f.readlines()
        new_lines = [l for l in lines if l.strip() != raw_line]
        with open(filepath, "w") as f:
            f.writelines(new_lines)
        return {"success": True, "message": f"Removed from {filepath}"}
    except OSError as e:
        return {"success": False, "error": str(e)}


def edit_cron_job(job, new_schedule, new_command):
    """Edit a cron job — replace old line with new one."""
    source_type = job.get("source_type")
    old_raw = job.get("raw", "")

    if source_type == "file":
        has_user = job.get("source") in ("/etc/crontab",) or job.get("source", "").startswith("cron.d/")
        if has_user:
            # Extract user from old raw line
            old_parts = old_raw.split(None, 6)
            user = old_parts[5] if len(old_parts) >= 7 else "root"
            new_raw = f"{new_schedule} {user} {new_command}"
        else:
            new_raw = f"{new_schedule} {new_command}"
        return _replace_in_file(job.get("file_path", ""), old_raw, new_raw)
    elif source_type == "crontab":
        new_raw = f"{new_schedule} {new_command}"
        return _replace_in_crontab(old_raw, new_raw)
    return {"success": False, "error": "Cannot edit this job type"}


def _replace_in_crontab(old_raw, new_raw):
    code, out, _ = _run(["crontab", "-l"])
    if code != 0:
        return {"success": False, "error": "No crontab found"}
    new_lines = []
    found = False
    for l in out.splitlines():
        if l.strip() == old_raw and not found:
            new_lines.append(new_raw)
            found = True
        else:
            new_lines.append(l)
    if not found:
        return {"success": False, "error": "Original job not found"}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cron", delete=False) as f:
        f.write("\n".join(new_lines) + "\n")
        tmp = f.name
    code, _, err = _run(["crontab", tmp])
    os.unlink(tmp)
    if code != 0:
        return {"success": False, "error": err}
    return {"success": True, "message": "Cron job updated"}


def _replace_in_file(filepath, old_raw, new_raw):
    if not filepath or not os.path.isfile(filepath):
        return {"success": False, "error": "File not found"}
    try:
        with open(filepath) as f:
            lines = f.readlines()
        new_lines = []
        found = False
        for l in lines:
            if l.strip() == old_raw and not found:
                new_lines.append(new_raw + "\n")
                found = True
            else:
                new_lines.append(l)
        if not found:
            return {"success": False, "error": "Original job not found in file"}
        with open(filepath, "w") as f:
            f.writelines(new_lines)
        return {"success": True, "message": f"Updated in {filepath}"}
    except OSError as e:
        return {"success": False, "error": str(e)}


# Keep old function name for compatibility
def remove_cron_job(job_id):
    """Remove by index — kept for backward compat but prefer delete_cron_job."""
    return _delete_from_crontab_by_idx(job_id)


def _delete_from_crontab_by_idx(job_id):
    code, out, _ = _run(["crontab", "-l"])
    if code != 0:
        return {"success": False, "error": "No crontab found"}
    lines = out.splitlines()
    real_idx = 0
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        if real_idx == job_id:
            real_idx += 1
            continue
        new_lines.append(line)
        real_idx += 1
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cron", delete=False) as f:
        f.write("\n".join(new_lines) + "\n")
        tmp = f.name
    code, _, err = _run(["crontab", tmp])
    os.unlink(tmp)
    if code != 0:
        return {"success": False, "error": err}
    return {"success": True, "message": "Cron job removed"}


PRESETS = [
    {"name": "Restart CSF daily at 3 AM", "schedule": "0 3 * * *", "command": "csf -r"},
    {"name": "Restart CSF weekly (Sunday)", "schedule": "0 3 * * 0", "command": "csf -r"},
    {"name": "Restart LFD daily at 4 AM", "schedule": "0 4 * * *", "command": "systemctl restart lfd"},
    {"name": "Flush temp blocks daily", "schedule": "0 0 * * *", "command": "csf -tf"},
    {"name": "Update CSF daily at 5 AM", "schedule": "0 5 * * *", "command": "csf -u"},
    {"name": "Backup CSF config weekly", "schedule": "0 2 * * 0", "command": "tar czf /var/lib/csfv2/backups/csf_auto_$(date +\\%Y\\%m\\%d).tar.gz -C /etc/csf ."},
]
