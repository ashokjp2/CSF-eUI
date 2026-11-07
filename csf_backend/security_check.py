import os
import re
import subprocess


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _get_sshd_config():
    raw = _read("/etc/ssh/sshd_config")
    conf = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            conf[parts[0].lower()] = parts[1]
    inc_dir = "/etc/ssh/sshd_config.d"
    if os.path.isdir(inc_dir):
        for fn in sorted(os.listdir(inc_dir)):
            if fn.endswith(".conf"):
                for line in _read(os.path.join(inc_dir, fn)).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        conf[parts[0].lower()] = parts[1]
    return conf


def _get_csf_conf():
    raw = _read("/etc/csf/csf.conf")
    conf = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^(\w+)\s*=\s*"?(.*?)"?\s*$', line)
        if m:
            conf[m.group(1)] = m.group(2)
    return conf


SSHD_SAFE_SETTINGS = {
    "port", "permitrootlogin", "passwordauthentication",
    "x11forwarding", "maxauthtries", "usedns", "clientaliveinterval",
    "clientalivecountmax", "logingracetime", "maxsessions",
}


def update_sshd_setting(key, value):
    key_lower = key.lower()
    if key_lower not in SSHD_SAFE_SETTINGS:
        return {"success": False, "error": f"Setting '{key}' is not allowed"}

    if key_lower == "port":
        try:
            p = int(value)
            if p < 1 or p > 65535 or p in (80, 443, 8080, 8750):
                return {"success": False, "error": f"Port {p} is invalid or reserved"}
        except ValueError:
            return {"success": False, "error": "Port must be a number"}

    sshd_conf = "/etc/ssh/sshd_config"
    try:
        with open(sshd_conf) as f:
            lines = f.readlines()
    except OSError as e:
        return {"success": False, "error": str(e)}

    found = False
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if not found:
            if stripped and not stripped.startswith("#"):
                parts = stripped.split(None, 1)
                if parts and parts[0].lower() == key_lower:
                    new_lines.append(f"{parts[0]} {value}\n")
                    found = True
                    continue
            elif stripped.startswith("#"):
                parts = stripped.lstrip("#").strip().split(None, 1)
                if parts and parts[0].lower() == key_lower:
                    new_lines.append(f"{parts[0]} {value}\n")
                    found = True
                    continue
        else:
            if stripped and not stripped.startswith("#"):
                parts = stripped.split(None, 1)
                if parts and parts[0].lower() == key_lower:
                    continue
        new_lines.append(line)

    if not found:
        new_lines.append(f"{key} {value}\n")

    try:
        with open(sshd_conf, "w") as f:
            f.writelines(new_lines)
    except OSError as e:
        return {"success": False, "error": str(e)}

    # Also check sshd_config.d for overrides
    inc_dir = "/etc/ssh/sshd_config.d"
    if os.path.isdir(inc_dir):
        for fn in os.listdir(inc_dir):
            if fn.endswith(".conf"):
                fp = os.path.join(inc_dir, fn)
                try:
                    with open(fp) as f:
                        clines = f.readlines()
                    changed = False
                    out = []
                    for cl in clines:
                        cs = cl.strip()
                        if cs and not cs.startswith("#"):
                            cp = cs.split(None, 1)
                            if cp and cp[0].lower() == key_lower:
                                out.append(f"# {cs}  # overridden by CSFv2\n")
                                changed = True
                                continue
                        out.append(cl)
                    if changed:
                        with open(fp, "w") as f:
                            f.writelines(out)
                except OSError:
                    pass

    # For port changes, add new port to CSF TCP_IN and update systemd socket
    if key_lower == "port":
        try:
            csf_conf_path = "/etc/csf/csf.conf"
            with open(csf_conf_path) as f:
                csf_lines = f.readlines()
            for i, cl in enumerate(csf_lines):
                m = re.match(r'^(TCP_IN\s*=\s*")(.*?)(".*)', cl)
                if m:
                    ports = [p.strip() for p in m.group(2).split(",")]
                    if value not in ports:
                        ports.append(value)
                    csf_lines[i] = m.group(1) + ",".join(ports) + m.group(3) + "\n"
                    break
            with open(csf_conf_path, "w") as f:
                f.writelines(csf_lines)
            subprocess.run(["csf", "-r"], capture_output=True, text=True, timeout=30)
        except Exception:
            pass
        socket_override = "/etc/systemd/system/ssh.socket.d/port.conf"
        socket_unit = None
        for name in ["ssh.socket", "sshd.socket"]:
            chk = subprocess.run(["systemctl", "is-active", name],
                                 capture_output=True, text=True, timeout=5)
            if chk.stdout.strip() == "active":
                socket_unit = name
                break
        if socket_unit:
            os.makedirs(os.path.dirname(socket_override), exist_ok=True)
            with open(socket_override, "w") as f:
                f.write(f"[Socket]\nListenStream=\nListenStream=0.0.0.0:{value}\nListenStream=[::]:{value}\n")
            subprocess.run(["systemctl", "daemon-reload"],
                           capture_output=True, text=True, timeout=10)
            subprocess.run(["systemctl", "restart", socket_unit],
                           capture_output=True, text=True, timeout=10)

    # Validate config before restarting
    check = subprocess.run(["sshd", "-t"], capture_output=True, text=True, timeout=5)
    if check.returncode != 0:
        return {"success": False, "error": f"Config validation failed: {check.stderr.strip()}. Change was written but sshd NOT restarted."}

    # Restart sshd
    svc = "ssh" if os.path.exists("/lib/systemd/system/ssh.service") else "sshd"
    restart = subprocess.run(["systemctl", "restart", svc], capture_output=True, text=True, timeout=10)
    if restart.returncode != 0:
        return {"success": False, "error": f"sshd restart failed: {restart.stderr.strip()}"}

    msg = f"{key} set to {value}. sshd restarted."
    if key_lower == "port":
        msg += f" SSH is now on port {value}. Update your SSH client connection."
    return {"success": True, "message": msg}


def run_full_check():
    checks = []
    sshd = _get_sshd_config()
    csf = _get_csf_conf()

    # --- SSH Hardening ---
    checks.append({"category": "SSH Hardening", "items": []})
    cat = checks[-1]["items"]

    port = sshd.get("port", "22")
    if port == "22":
        cat.append({
            "status": "warn",
            "title": "SSH running on default port 22",
            "detail": "Attackers scan port 22 constantly. Change to a non-standard port (e.g. 2222, 8022) in /etc/ssh/sshd_config.",
            "setting": "Port",
            "current": port,
            "recommended": "Non-standard (e.g. 2222)",
        })
    else:
        cat.append({
            "status": "pass",
            "title": f"SSH on non-standard port {port}",
            "detail": "Good. Reduces automated attack noise.",
            "current": port,
        })

    root_login = sshd.get("permitrootlogin", "yes").lower()
    if root_login in ("yes", "without-password", "prohibit-password"):
        if root_login == "yes":
            cat.append({
                "status": "fail",
                "title": "Root login with password is allowed",
                "detail": "Attackers can brute-force the root password directly. Set PermitRootLogin to 'no' or 'prohibit-password' (key-only).",
                "setting": "PermitRootLogin",
                "current": root_login,
                "recommended": "no (or prohibit-password for key-only)",
            })
        else:
            cat.append({
                "status": "pass",
                "title": "Root login restricted to SSH keys only",
                "detail": "Password-based root login is disabled. Good.",
                "current": root_login,
            })
    else:
        cat.append({
            "status": "pass",
            "title": "Root login is disabled",
            "current": root_login,
        })

    pwd_auth = sshd.get("passwordauthentication", "yes").lower()
    if pwd_auth == "yes":
        cat.append({
            "status": "warn",
            "title": "Password authentication is enabled",
            "detail": "SSH key authentication is more secure. Consider disabling password auth after setting up SSH keys.",
            "setting": "PasswordAuthentication",
            "current": "yes",
            "recommended": "no (use SSH keys instead)",
        })
    else:
        cat.append({
            "status": "pass",
            "title": "Password authentication is disabled (key-only)",
            "current": "no",
        })

    x11 = sshd.get("x11forwarding", "no").lower()
    if x11 == "yes":
        cat.append({
            "status": "warn",
            "title": "X11 forwarding is enabled",
            "detail": "Not needed on servers. Disable it to reduce attack surface.",
            "setting": "X11Forwarding",
            "current": "yes",
            "recommended": "no",
        })

    max_auth = sshd.get("maxauthtries", "6")
    try:
        if int(max_auth) > 4:
            cat.append({
                "status": "warn",
                "title": f"SSH MaxAuthTries is {max_auth} (high)",
                "detail": "Lower this to 3-4 to limit brute-force attempts per connection.",
                "setting": "MaxAuthTries",
                "current": max_auth,
                "recommended": "3",
            })
    except ValueError:
        pass

    # --- CSF Configuration ---
    checks.append({"category": "CSF Firewall Settings", "items": []})
    cat = checks[-1]["items"]

    testing = csf.get("TESTING", "0")
    if testing == "1":
        cat.append({
            "status": "fail",
            "title": "CSF is in TESTING mode",
            "detail": "Firewall rules are cleared every few minutes. Disable TESTING once you confirm access works.",
            "setting": "TESTING",
            "current": "1 (enabled)",
            "recommended": "0 (disabled)",
        })
    else:
        cat.append({
            "status": "pass",
            "title": "CSF TESTING mode is off",
            "current": "0",
        })

    restrict_syslog = csf.get("RESTRICT_SYSLOG", "0")
    if restrict_syslog == "0":
        cat.append({
            "status": "warn",
            "title": "RESTRICT_SYSLOG is disabled",
            "detail": "Attackers could spoof syslog entries to bypass LFD. Enable for better log integrity.",
            "setting": "RESTRICT_SYSLOG",
            "current": "0",
            "recommended": "3 (strict)",
        })

    lf_sshd = csf.get("LF_SSHD", "0")
    if lf_sshd == "0":
        cat.append({
            "status": "fail",
            "title": "SSH brute-force protection is DISABLED",
            "detail": "LF_SSHD should be set to block IPs after failed SSH login attempts.",
            "setting": "LF_SSHD",
            "current": "0 (disabled)",
            "recommended": "5",
        })
    else:
        cat.append({
            "status": "pass",
            "title": f"SSH brute-force protection active (block after {lf_sshd} failures)",
            "current": lf_sshd,
        })

    lf_ftpd = csf.get("LF_FTPD", "0")
    if lf_ftpd == "0":
        has_ftp = os.path.exists("/usr/sbin/vsftpd") or os.path.exists("/usr/sbin/proftpd")
        if has_ftp:
            cat.append({
                "status": "warn",
                "title": "FTP brute-force protection disabled but FTP server detected",
                "setting": "LF_FTPD",
                "current": "0",
                "recommended": "10",
            })

    lf_permblock = csf.get("LF_PERMBLOCK", "0")
    if lf_permblock == "0":
        cat.append({
            "status": "warn",
            "title": "Auto permanent-block for repeat offenders is off",
            "detail": "Persistent attackers will keep getting temporary blocks that expire. Enable LF_PERMBLOCK.",
            "setting": "LF_PERMBLOCK",
            "current": "0",
            "recommended": "1",
        })

    ps_limit = csf.get("PS_LIMIT", "0")
    if ps_limit == "0":
        cat.append({
            "status": "warn",
            "title": "Port scan detection is disabled",
            "detail": "Enable PS_LIMIT to detect and block port scanning.",
            "setting": "PS_LIMIT",
            "current": "0",
            "recommended": "10",
        })

    ct_limit = csf.get("CT_LIMIT", "0")
    if ct_limit == "0":
        cat.append({
            "status": "warn",
            "title": "Connection tracking is disabled",
            "detail": "CT_LIMIT protects against DDoS by blocking IPs with too many connections.",
            "setting": "CT_LIMIT",
            "current": "0",
            "recommended": "300",
        })

    lf_alert = csf.get("LF_ALERT_TO", "")
    if not lf_alert:
        cat.append({
            "status": "warn",
            "title": "No email set for block alerts",
            "detail": "Set LF_ALERT_TO so you get notified when IPs are blocked.",
            "setting": "LF_ALERT_TO",
            "current": "(empty)",
            "recommended": "your-email@domain.com",
        })

    # Check Docker mode
    docker_check = _run(["docker", "info", "--format", "{{.ID}}"])
    docker_setting = csf.get("DOCKER", "0")
    if docker_check and docker_setting != "1":
        cat.append({
            "status": "fail",
            "title": "Docker is running but DOCKER mode is OFF in CSF",
            "detail": "CSF will break Docker container networking. Enable DOCKER=1 immediately.",
            "setting": "DOCKER",
            "current": "0",
            "recommended": "1",
        })
    elif docker_check and docker_setting == "1":
        cat.append({
            "status": "pass",
            "title": "Docker mode is correctly enabled",
            "current": "1",
        })

    # --- System Security ---
    checks.append({"category": "System Security", "items": []})
    cat = checks[-1]["items"]

    # Check for unattended upgrades
    if os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
        auto_up = _read("/etc/apt/apt.conf.d/20auto-upgrades")
        if 'Unattended-Upgrade "1"' in auto_up:
            cat.append({
                "status": "pass",
                "title": "Automatic security updates are enabled",
            })
        else:
            cat.append({
                "status": "warn",
                "title": "Automatic security updates may be disabled",
                "detail": "Enable unattended-upgrades to auto-install security patches.",
                "recommended": "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades",
            })
    elif os.path.exists("/etc/yum/pluginconf.d/auto-update.conf"):
        cat.append({"status": "pass", "title": "Automatic updates configured (yum)"})
    else:
        cat.append({
            "status": "warn",
            "title": "Automatic security updates status unknown",
            "detail": "Consider enabling unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL/CentOS).",
        })

    # Fail2ban conflict check
    if os.path.exists("/usr/bin/fail2ban-client") or os.path.exists("/usr/bin/fail2ban-server"):
        f2b_active = _run(["systemctl", "is-active", "fail2ban"]).strip()
        if f2b_active == "active":
            cat.append({
                "status": "warn",
                "title": "Fail2Ban is running alongside CSF",
                "detail": "Both CSF/LFD and Fail2Ban do the same job. Running both can cause conflicts. Consider disabling Fail2Ban.",
                "recommended": "systemctl disable --now fail2ban",
            })

    # Open ports check
    ss_out = _run(["ss", "-tlnp"])
    if ss_out:
        listening = []
        for line in ss_out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                if ":*" not in addr:
                    port_match = re.search(r':(\d+)$', addr)
                    if port_match:
                        p = port_match.group(1)
                        proc = parts[-1] if len(parts) > 5 else ""
                        if p not in [p2 for p2, _ in listening]:
                            listening.append((p, proc))

        tcp_in = csf.get("TCP_IN", "")
        allowed = set(tcp_in.replace(" ", "").split(",")) if tcp_in else set()

        for port, proc in listening:
            if port not in allowed and port not in ("25",):
                cat.append({
                    "status": "info",
                    "title": f"Port {port} is listening but not in TCP_IN",
                    "detail": f"Process: {proc}. If this service needs external access, add {port} to TCP_IN.",
                    "current": f"Port {port} listening, not in allowed list",
                })

    # IPv6 check
    ipv6_conf = csf.get("IPV6", "0")
    has_ipv6 = os.path.exists("/proc/net/if_inet6")
    if has_ipv6 and ipv6_conf == "0":
        cat.append({
            "status": "warn",
            "title": "Server has IPv6 but CSF IPv6 firewall is disabled",
            "detail": "IPv6 traffic is not being firewalled. Enable IPV6 in csf.conf if your server uses IPv6.",
            "setting": "IPV6",
            "current": "0",
            "recommended": "1",
        })

    # --- Kernel Modules (existing check) ---
    checks.append({"category": "Kernel iptables Modules", "items": []})
    cat = checks[-1]["items"]

    csftest = _run(["perl", "/usr/local/csf/bin/csftest.pl"])
    if csftest:
        for line in csftest.splitlines():
            line = line.strip()
            if not line:
                continue
            if "OK" in line:
                cat.append({"status": "pass", "title": line})
            elif "FATAL" in line or "FAILED" in line:
                cat.append({"status": "fail", "title": line})
            elif "WARNING" in line or "WARN" in line:
                cat.append({"status": "warn", "title": line})

    # Summary counts
    total = sum(len(c["items"]) for c in checks)
    passes = sum(1 for c in checks for i in c["items"] if i["status"] == "pass")
    warns = sum(1 for c in checks for i in c["items"] if i["status"] == "warn")
    fails = sum(1 for c in checks for i in c["items"] if i["status"] == "fail")
    infos = sum(1 for c in checks for i in c["items"] if i["status"] == "info")

    return {
        "checks": checks,
        "summary": {"total": total, "pass": passes, "warn": warns, "fail": fails, "info": infos},
    }
