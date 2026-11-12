import os
import re
import subprocess

from csf_backend import security_check


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception:
        return -1, "", ""


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _get_csf_val(key):
    raw = _read("/etc/csf/csf.conf")
    for line in raw.splitlines():
        m = re.match(r'^' + re.escape(key) + r'\s*=\s*"?(.*?)"?\s*$', line.strip())
        if m and not line.strip().startswith("#"):
            return m.group(1)
    return ""


def _get_sshd_val(key):
    raw = _read("/etc/ssh/sshd_config")
    val = ""
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == key.lower():
            val = parts[1]
    inc_dir = "/etc/ssh/sshd_config.d"
    if os.path.isdir(inc_dir):
        for fn in sorted(os.listdir(inc_dir)):
            if fn.endswith(".conf"):
                for line in _read(os.path.join(inc_dir, fn)).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2 and parts[0].lower() == key.lower():
                        val = parts[1]
    return val


def get_wizard_state(username=None, passkey_problem=""):
    """Get current state of all wizard steps."""
    steps = []

    # Step 0: protect this UI with a second sign-in step (passkey preferred)
    if username:
        from csf_backend import auth
        twofa = auth.second_factor_status(username)
        if twofa["passkeys"] and twofa["totp"]:
            current = "passkey + authenticator app"
        elif twofa["passkeys"]:
            current = f"{twofa['passkeys']} passkey(s)"
        elif twofa["totp"]:
            current = "authenticator app"
        else:
            current = "password only"
        steps.append({
            "id": "ui_passkey",
            "title": "Protect this UI with a passkey",
            "description": "This UI controls the firewall. Add a second sign-in step so a leaked password alone is not enough.",
            "status": "done" if twofa["enabled"] else "todo",
            "current": current,
            "recommended": "a passkey (Windows Hello, Touch ID, your phone or a security key)",
            "risk": "high",
            "category": "ui",
            "passkey_problem": passkey_problem,
            "help": ("A passkey never leaves your device and cannot be phished. It is tied to the address you register it on, "
                     "so open the UI by its domain name over a trusted HTTPS certificate. "
                     "An authenticator app (TOTP) works anywhere, including by IP, and can be set up on the Settings page."),
        })

    # Step 1: SSH Port
    ssh_status = security_check.get_ssh_port_status()
    ssh_port = ssh_status["configured_port"] or _get_sshd_val("Port") or "22"
    listening_ports = ssh_status["listening_ports"]
    ssh_runtime_mismatch = bool(
        listening_ports and str(ssh_port) not in listening_ports
    )
    ssh_current = str(ssh_port)
    if ssh_runtime_mismatch:
        ssh_current = f"configured: {ssh_port}; listening: {', '.join(listening_ports)}"
    steps.append({
        "id": "ssh_port",
        "title": "Change SSH Port",
        "description": "Move SSH away from the default port 22 to reduce automated attacks.",
        "status": "done" if ssh_port != "22" and not ssh_runtime_mismatch else "todo",
        "current": ssh_current,
        "recommended": "858 (or another unused port)",
        "risk": "high",
        "category": "ssh",
        "setting": "Port",
        "input_type": "number",
        "input_placeholder": "e.g. 858",
        "help": (
            "Port 22 is scanned by bots constantly. CSF-EUI updates both sshd and "
            "systemd ssh.socket when socket activation is enabled. Make sure you have "
            "an active SSH session and keep the new port allowed in TCP_IN."
        ),
    })

    # Step 2: SSH Root Login
    root_login = _get_sshd_val("PermitRootLogin") or "yes"
    steps.append({
        "id": "ssh_root",
        "title": "Restrict Root SSH Login",
        "description": "Disable password-based root login. Use SSH keys instead.",
        "status": "done" if root_login.lower() in ("no", "prohibit-password", "without-password") else "todo",
        "current": root_login,
        "recommended": "prohibit-password (key-only) or no",
        "risk": "high",
        "category": "ssh",
        "help": "If PermitRootLogin is 'yes', anyone who guesses the root password gets full server access. Set it to 'prohibit-password' to allow only SSH key login.",
    })

    # Step 3: SSH Password Auth
    pwd_auth = _get_sshd_val("PasswordAuthentication") or "yes"
    steps.append({
        "id": "ssh_password",
        "title": "Disable Password Authentication",
        "description": "Use SSH keys only. Eliminates password brute-force entirely.",
        "status": "done" if pwd_auth.lower() == "no" else "todo",
        "current": pwd_auth,
        "recommended": "no (after setting up SSH keys)",
        "risk": "medium",
        "category": "ssh",
        "help": "Make sure you have a working SSH key before disabling this, or you'll lock yourself out!",
    })

    # Step 4: CSF Testing Mode
    testing = _get_csf_val("TESTING")
    steps.append({
        "id": "csf_testing",
        "title": "Disable CSF Testing Mode",
        "description": "Testing mode clears firewall rules every 5 minutes. Turn it off once access is confirmed.",
        "status": "done" if testing == "0" else "todo",
        "current": f"TESTING = {testing}",
        "recommended": "0 (disabled)",
        "risk": "high",
        "category": "csf",
        "setting": "TESTING",
        "help": "While TESTING=1, your firewall rules are reset every 5 minutes. This is a safety net — once you're sure you can still SSH in, set TESTING=0.",
    })

    # Step 5: Brute-Force Protection
    lf_sshd = _get_csf_val("LF_SSHD")
    steps.append({
        "id": "csf_bruteforce",
        "title": "Enable SSH Brute-Force Protection",
        "description": "Automatically block IPs after failed SSH login attempts.",
        "status": "done" if lf_sshd and lf_sshd != "0" else "todo",
        "current": f"LF_SSHD = {lf_sshd}",
        "recommended": "5 (block after 5 failures)",
        "risk": "high",
        "category": "csf",
        "setting": "LF_SSHD",
        "help": "This is one of CSF's most important features. It blocks IPs that fail SSH login too many times.",
    })

    # Step 6: Port Scan Detection
    ps_limit = _get_csf_val("PS_LIMIT")
    steps.append({
        "id": "csf_portscan",
        "title": "Enable Port Scan Detection",
        "description": "Detect and block IPs that probe multiple ports looking for vulnerabilities.",
        "status": "done" if ps_limit and ps_limit != "0" else "todo",
        "current": f"PS_LIMIT = {ps_limit}",
        "recommended": "10",
        "risk": "medium",
        "category": "csf",
        "setting": "PS_LIMIT",
        "help": "Attackers scan for open ports before attacking. This detects and blocks them automatically.",
    })

    # Step 7: Connection Tracking
    ct_limit = _get_csf_val("CT_LIMIT")
    steps.append({
        "id": "csf_conntrack",
        "title": "Enable Connection Tracking",
        "description": "Block IPs with too many simultaneous connections (DDoS protection).",
        "status": "done" if ct_limit and ct_limit != "0" else "todo",
        "current": f"CT_LIMIT = {ct_limit}",
        "recommended": "300",
        "risk": "medium",
        "category": "csf",
        "setting": "CT_LIMIT",
        "help": "Limits how many connections a single IP can have open at once. Helps against DDoS and flooding attacks.",
    })

    # Step 8: Alert Email
    lf_alert = _get_csf_val("LF_ALERT_TO")
    steps.append({
        "id": "csf_alerts",
        "title": "Set Up Block Alerts",
        "description": "Get email notifications when IPs are blocked.",
        "status": "done" if lf_alert else "todo",
        "current": lf_alert or "(not set)",
        "recommended": "your-email@domain.com",
        "risk": "low",
        "category": "csf",
        "setting": "LF_ALERT_TO",
        "help": "Stay informed about attacks on your server. You'll get an email each time an IP is blocked.",
    })

    # Step 9: Docker Mode
    code, _, _ = _run(["docker", "info", "--format", "{{.ID}}"])
    has_docker = code == 0
    docker_mode = _get_csf_val("DOCKER")
    if has_docker:
        steps.append({
            "id": "csf_docker",
            "title": "Enable Docker Mode",
            "description": "Docker is installed. CSF must run in Docker mode to avoid breaking container networking.",
            "status": "done" if docker_mode == "1" else "todo",
            "current": f"DOCKER = {docker_mode}",
            "recommended": "1 (enabled)",
            "risk": "high",
            "category": "csf",
            "setting": "DOCKER",
            "help": "Without DOCKER=1, CSF's iptables rules will break Docker container networking. Enable this immediately if you use Docker.",
        })

    # Step 10: IPv6
    has_ipv6 = os.path.exists("/proc/net/if_inet6")
    ipv6_conf = _get_csf_val("IPV6")
    if has_ipv6:
        steps.append({
            "id": "csf_ipv6",
            "title": "Enable IPv6 Firewall",
            "description": "Your server has IPv6. Firewall it to prevent unfiltered IPv6 access.",
            "status": "done" if ipv6_conf == "1" else "todo",
            "current": f"IPV6 = {ipv6_conf}",
            "recommended": "1",
            "risk": "medium",
            "category": "csf",
            "setting": "IPV6",
            "help": "Without IPv6 firewalling, all IPv6 traffic bypasses your firewall rules entirely.",
        })

    # Step 11: Permanent Block
    lf_permblock = _get_csf_val("LF_PERMBLOCK")
    steps.append({
        "id": "csf_permblock",
        "title": "Enable Permanent Block for Repeat Offenders",
        "description": "Automatically permanently block IPs that keep getting temporarily blocked.",
        "status": "done" if lf_permblock and lf_permblock != "0" else "todo",
        "current": f"LF_PERMBLOCK = {lf_permblock}",
        "recommended": "1 (enabled)",
        "risk": "low",
        "category": "csf",
        "setting": "LF_PERMBLOCK",
        "help": "Without this, persistent attackers keep getting temporary blocks that expire, and they come right back.",
    })

    # Step 12: Restrict Syslog
    restrict = _get_csf_val("RESTRICT_SYSLOG")
    steps.append({
        "id": "csf_syslog",
        "title": "Restrict Syslog Access",
        "description": "Prevent log spoofing attacks that could bypass LFD detection.",
        "status": "done" if restrict and restrict != "0" else "todo",
        "current": f"RESTRICT_SYSLOG = {restrict}",
        "recommended": "3 (strict)",
        "risk": "low",
        "category": "csf",
        "setting": "RESTRICT_SYSLOG",
        "help": "Attackers could spoof syslog entries to trick LFD. Setting this to 3 prevents that.",
    })

    done = sum(1 for s in steps if s["status"] == "done")
    total = len(steps)
    progress = int((done / total) * 100) if total else 0

    return {
        "steps": steps,
        "done": done,
        "total": total,
        "progress": progress,
    }
