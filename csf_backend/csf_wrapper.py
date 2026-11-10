import subprocess
import shlex
import os
import re
import time
from pathlib import Path

CSF_BIN = "/usr/sbin/csf"
LFD_RESTART_FLAG = "/var/lib/csf/lfd.restart"
CSF_CONF = "/etc/csf/csf.conf"
CSF_ALLOW = "/etc/csf/csf.allow"
CSF_DENY = "/etc/csf/csf.deny"
CSF_IGNORE = "/etc/csf/csf.ignore"
CSF_TEMPBAN = "/var/lib/csf/csf.tempban"
CSF_TEMPALLOW = "/var/lib/csf/csf.tempallow"
CSF_REDIRECT = "/etc/csf/csf.redirect"
CSF_SMTPAUTH = "/etc/csf/csf.smtpauth"
CSF_BLOCKLISTS = "/etc/csf/csf.blocklists"
CSF_DIRWATCH = "/etc/csf/csf.dirwatch"
CSF_DYNDNS = "/etc/csf/csf.dyndns"
CSF_SYSLOGUSERS = "/etc/csf/csf.syslogusers"
CSF_LOGFILES = "/etc/csf/csf.logfiles"
CSF_CLOUDFLARE = "/etc/csf/csf.cloudflare"
CSF_RBLCONF = "/etc/csf/csf.rblconf"
CSF_SIPS = "/etc/csf/csf.sips"
CSF_SYSLOGS = "/etc/csf/csf.syslogs"
CSF_RESELLERS = "/etc/csf/csf.resellers"
CSF_PROFILES_DIR = "/usr/local/csf/profiles"
CSF_BACKUP_DIR = "/var/lib/csf/backup"
CSF_TPL_DIR = "/usr/local/csf/tpl"
CSF_VERSION_FILE = "/etc/csf/version.txt"
CSF_DISABLE_FILE = "/etc/csf/csf.disable"
CSFTEST_BIN = "/usr/local/csf/bin/csftest.pl"
IPTABLES_LOG = "/var/lib/csf/stats/iptables_log"
LFD_LOG = "/var/log/lfd.log"


def run_csf(args, timeout=60):
    cmd = [CSF_BIN] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": "Command timed out", "returncode": -1}
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": f"CSF not found at {CSF_BIN}", "returncode": -1}


def run_command(cmd, timeout=30):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": "Command timed out", "returncode": -1}
    except FileNotFoundError:
        return {"success": False, "stdout": "", "stderr": f"Command not found: {cmd[0]}", "returncode": -1}


# Service lifecycle
def csf_start():
    return _apply_csf_with_docker_recovery()

def csf_stop():
    return run_csf(["-f"])

def csf_restart():
    return _apply_csf_with_docker_recovery()


def _apply_csf_with_docker_recovery():
    """Reload CSF while preserving Docker's version-specific firewall chains."""
    from csf_backend import service_integration

    docker_state = service_integration.get_docker_firewall_state()
    hook_result = service_integration.ensure_docker_forwarding_rules()
    result = run_csf(["-sf"], timeout=300)
    if not result["success"]:
        return result

    # CSF executes csfpost.sh during -sf. Run it once more so a newly upgraded
    # hook is applied on the same request, then recover Docker-owned chains if
    # CSF flushed them.
    service_integration._run(["/etc/csf/csfpost.sh"])
    docker_result = service_integration.restore_docker_firewall_chains(docker_state)
    warnings = []
    if not hook_result.get("success"):
        warnings.append(f"Docker forwarding hook: {hook_result.get('message', 'failed')}")
    if not docker_result.get("success"):
        warnings.append(docker_result.get("message", "Docker firewall recovery failed."))
    if warnings:
        result["success"] = False
        result["stderr"] = (result.get("stderr", "") + "\n" + "\n".join(warnings)).strip()
    elif docker_result.get("changed"):
        result["stdout"] = (result.get("stdout", "") + "\n" + docker_result["message"]).strip()
    return result

def csf_restart_q():
    return run_csf(["-q"], timeout=300)

def csf_enable():
    return run_csf(["-e"])

def csf_disable():
    return run_csf(["-x"])

def lfd_start():
    return run_command(["systemctl", "start", "lfd"])

def lfd_stop():
    return run_command(["systemctl", "stop", "lfd"])

def lfd_restart():
    Path(LFD_RESTART_FLAG).touch()
    return {"success": True, "stdout": "LFD restart scheduled", "stderr": "", "returncode": 0}

def lfd_status():
    return run_command(["systemctl", "status", "lfd"])

def restart_both():
    csf_result = csf_restart()
    lfd_result = lfd_restart()
    return {
        "success": csf_result["success"] and lfd_result["success"],
        "stdout": csf_result["stdout"] + "\n" + lfd_result["stdout"],
        "stderr": csf_result["stderr"] + "\n" + lfd_result["stderr"],
        "returncode": csf_result["returncode"],
    }


# IP management
def allow_ip(ip, comment=""):
    args = ["-a", ip]
    if comment:
        args.append(comment)
    return run_csf(args)

def deny_ip(ip, comment=""):
    args = ["-d", ip]
    if comment:
        args.append(comment)
    return run_csf(args)

def remove_allow(ip):
    return run_csf(["-ar", ip])

def remove_deny(ip):
    return run_csf(["-dr", ip])

def unblock_ip(ip):
    r1 = run_csf(["-dr", ip])
    r2 = run_csf(["-trd", ip])
    return {
        "success": r1["success"] or r2["success"],
        "stdout": r1["stdout"] + "\n" + r2["stdout"],
        "stderr": r1["stderr"] + "\n" + r2["stderr"],
        "returncode": 0 if r1["success"] or r2["success"] else 1,
    }

def flush_deny():
    """Remove all permanent entries from csf.deny."""
    return run_csf(["-df"])

def search_ip(ip):
    return run_csf(["-g", ip])

def flush_all_blocks():
    r1 = run_csf(["-df"])
    r2 = run_csf(["-tf"])
    return {
        "success": r1["success"] and r2["success"],
        "stdout": r1["stdout"] + "\n" + r2["stdout"],
        "stderr": r1["stderr"] + "\n" + r2["stderr"],
        "returncode": 0,
    }


# Temporary blocks
def temp_deny(ip, timeout_secs, ports="*", comment=""):
    args = ["-td", ip, str(timeout_secs), "-p", ports]
    if comment:
        args.append(comment)
    return run_csf(args)

def temp_allow(ip, timeout_secs, ports="*", comment=""):
    args = ["-ta", ip, str(timeout_secs), "-p", ports]
    if comment:
        args.append(comment)
    return run_csf(args)

def remove_temp_deny(ip):
    return run_csf(["-trd", ip])

def remove_temp_allow(ip):
    return run_csf(["-tra", ip])

def flush_temp():
    return run_csf(["-tf"])

def temp_to_perm(ip):
    run_csf(["-tr", ip])
    return run_csf(["-d", ip])

def get_temp_list():
    entries = []
    for filepath, entry_type in [(CSF_TEMPBAN, "DENY"), (CSF_TEMPALLOW, "ALLOW")]:
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) >= 6:
                        exp_time = int(parts[0])
                        remaining = max(0, exp_time - int(time.time()))
                        entries.append({
                            "type": entry_type,
                            "expires": exp_time,
                            "ip": parts[1],
                            "port": parts[2],
                            "direction": parts[3],
                            "timeout": parts[4],
                            "comment": parts[5] if len(parts) > 5 else "",
                            "remaining": remaining,
                            "remaining_str": format_duration(remaining),
                        })
        except (OSError, ValueError):
            pass
    return entries


def format_duration(secs):
    if secs <= 0:
        return "Expired"
    days = secs // 86400
    hours = (secs % 86400) // 3600
    mins = (secs % 3600) // 60
    s = secs % 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    if s:
        parts.append(f"{s}s")
    return " ".join(parts) or "0s"


# Ignore
def add_ignore(ip):
    with open(CSF_IGNORE, "a") as f:
        f.write(f"\n{ip}\n")
    return lfd_restart()


# Status and info
def get_status():
    return run_csf(["-l"])

def get_status6():
    return run_csf(["-l6"])

def get_version():
    try:
        return Path(CSF_VERSION_FILE).read_text().strip()
    except OSError:
        return "Unknown"

def is_enabled():
    return not os.path.exists(CSF_DISABLE_FILE)

def is_testing():
    conf = load_csf_conf()
    return conf.get("TESTING", "0") == "1"

def get_listening_ports():
    return run_csf(["-p"])

def run_csf_test():
    return run_command(["perl", CSFTEST_BIN])


# Config management
def load_csf_conf():
    config = {}
    if not os.path.exists(CSF_CONF):
        return config
    with open(CSF_CONF) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^(\w+)\s*=\s*"(.*)"', line)
            if match:
                config[match.group(1)] = match.group(2)
    return config


def load_csf_conf_full():
    sections = []
    current_section = {"name": "General", "settings": [], "lines": []}
    if not os.path.exists(CSF_CONF):
        return sections
    with open(CSF_CONF) as f:
        for line_num, line in enumerate(f, 1):
            raw = line.rstrip("\n")
            stripped = raw.strip()
            section_match = re.match(r'^#\s*SECTION:\s*(.*)$', stripped)
            if section_match:
                if current_section["settings"] or current_section["lines"]:
                    sections.append(current_section)
                section_name = section_match.group(1).strip()
                current_section = {"name": section_name, "settings": [], "lines": []}
                continue
            match = re.match(r'^(\w+)\s*=\s*"(.*)"', stripped)
            if match:
                key, val = match.group(1), match.group(2)
                current_section["settings"].append({
                    "key": key,
                    "value": val,
                    "line_num": line_num,
                })
            current_section["lines"].append({"num": line_num, "text": raw})
    if current_section["settings"] or current_section["lines"]:
        sections.append(current_section)
    return sections


def save_csf_conf(changes):
    if not os.path.exists(CSF_CONF):
        return {"success": False, "error": "csf.conf not found"}
    with open(CSF_CONF) as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        match = re.match(r'^(\w+)\s*=\s*"(.*)"', stripped)
        if match:
            key = match.group(1)
            if key in changes:
                lines[i] = f'{key} = "{changes[key]}"\n'
    with open(CSF_CONF, "w") as f:
        f.writelines(lines)
    return {"success": True}


# File management
def read_file(filepath):
    try:
        return Path(filepath).read_text()
    except OSError as e:
        return f"Error reading file: {e}"

def save_file(filepath, content):
    try:
        Path(filepath).write_text(content)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}


# Profiles
def list_profiles():
    profiles = []
    if os.path.isdir(CSF_PROFILES_DIR):
        for f in sorted(os.listdir(CSF_PROFILES_DIR)):
            fp = os.path.join(CSF_PROFILES_DIR, f)
            if os.path.isfile(fp):
                profiles.append({"name": f, "path": fp})
    return profiles

def list_backups():
    backups = []
    if os.path.isdir(CSF_BACKUP_DIR):
        for f in sorted(os.listdir(CSF_BACKUP_DIR), reverse=True):
            fp = os.path.join(CSF_BACKUP_DIR, f)
            if os.path.isfile(fp):
                backups.append({"name": f, "path": fp})
    return backups

def apply_profile(name):
    safe_name = re.sub(r'\W', '_', name)
    return run_csf(["--profile", "apply", safe_name])

def create_backup(name):
    safe_name = re.sub(r'\W', '_', name)
    timestamp = int(time.time())
    backup_name = f"{timestamp}_{safe_name}"
    import shutil
    dest = os.path.join(CSF_BACKUP_DIR, backup_name)
    os.makedirs(CSF_BACKUP_DIR, exist_ok=True)
    shutil.copy2(CSF_CONF, dest)
    return {"success": True, "name": backup_name}


# Log tail
def get_log_files():
    logs = []
    if os.path.exists(CSF_SYSLOGS):
        with open(CSF_SYSLOGS) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("Include"):
                    inc_path = line.split(None, 1)[1] if " " in line else ""
                    if inc_path and os.path.exists(inc_path):
                        with open(inc_path) as incf:
                            for incline in incf:
                                incline = incline.strip()
                                if incline and not incline.startswith("#"):
                                    logs.append(incline)
                else:
                    logs.append(line)
    defaults = ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages", LFD_LOG]
    for d in defaults:
        if d not in logs:
            logs.append(d)
    return [l for l in logs if os.path.isfile(l)]

def tail_log(logfile, lines=50):
    if not os.path.exists(logfile):
        return f"Log file not found: {logfile}"
    result = run_command(["tail", "-n", str(lines), logfile])
    return result["stdout"] if result["success"] else result["stderr"]

def grep_log(logfile, pattern, case_insensitive=False, extended=False):
    if not os.path.exists(logfile):
        return f"Log file not found: {logfile}"
    cmd = ["grep"]
    if case_insensitive:
        cmd.append("-i")
    if extended:
        cmd.append("-E")
    cmd.extend(["--", pattern, logfile])
    result = run_command(cmd, timeout=30)
    return result["stdout"] if result["success"] else result["stderr"]


# Cluster
def cluster_ping():
    return run_csf(["-cp"])

def cluster_allow(ip, comment=""):
    args = ["-ca", ip]
    if comment:
        args.append(comment)
    return run_csf(args)

def cluster_deny(ip, comment=""):
    args = ["-cd", ip]
    if comment:
        args.append(comment)
    return run_csf(args)

def cluster_remove_deny(ip):
    return run_csf(["-cr", ip])

def cluster_remove_allow(ip):
    return run_csf(["-car", ip])

def cluster_grep(ip):
    return run_csf(["-cg", ip])

def cluster_restart():
    return run_csf(["--crestart"])


# Server check
def server_check(verbose=False):
    args = ["-c"]
    if verbose:
        args.append("-v")
    return run_csf(args, timeout=120)


# iptables log
def get_iptables_log(limit=100):
    if not os.path.exists(IPTABLES_LOG):
        return []
    entries = []
    try:
        with open(IPTABLES_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(line)
    except OSError:
        pass
    entries.reverse()
    return entries[:limit]


# Templates
def list_templates():
    templates = []
    if os.path.isdir(CSF_TPL_DIR):
        for f in sorted(os.listdir(CSF_TPL_DIR)):
            if f.endswith(".txt"):
                templates.append(f)
    return templates
