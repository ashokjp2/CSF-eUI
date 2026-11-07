import os
import re
import subprocess
import json
from datetime import datetime


CERT_DIR = "/etc/csfv2/ssl"
LE_LIVE_DIR = "/etc/letsencrypt/live"
CSFV2_CONF = "/etc/csfv2/csfv2.conf"
START_SCRIPT = "/opt/csfv2/start.sh"


def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def get_ssl_status():
    status = {
        "current_cert": None,
        "certbot_installed": False,
        "certbot_certs": [],
        "self_signed": False,
        "hostname": "",
        "http_redirect": False,
    }

    # Get hostname
    code, out, _ = _run(["hostname", "-f"])
    status["hostname"] = out if code == 0 else "unknown"

    # Check certbot
    code, _, _ = _run(["which", "certbot"])
    status["certbot_installed"] = code == 0

    # List certbot certificates
    if status["certbot_installed"]:
        code, out, _ = _run(["certbot", "certificates"], timeout=15)
        if code == 0 and out:
            certs = []
            current = {}
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Certificate Name:"):
                    if current:
                        certs.append(current)
                    current = {"name": line.split(":", 1)[1].strip()}
                elif line.startswith("Domains:") and current:
                    current["domains"] = line.split(":", 1)[1].strip()
                elif line.startswith("Expiry Date:") and current:
                    current["expiry"] = line.split(":", 1)[1].strip().split("(")[0].strip()
                elif line.startswith("Certificate Path:") and current:
                    current["cert_path"] = line.split(":", 1)[1].strip()
                elif line.startswith("Private Key Path:") and current:
                    current["key_path"] = line.split(":", 1)[1].strip()
            if current:
                certs.append(current)
            status["certbot_certs"] = certs

    # Check current cert in use — from csfv2.conf env vars or defaults in start.sh
    csfv2_conf = _read(CSFV2_CONF)
    cert_path = "/etc/csfv2/ssl/server.crt"
    key_path_current = "/etc/csfv2/ssl/server.key"

    for line in csfv2_conf.splitlines():
        line = line.strip()
        if line.startswith("SSL_CERT="):
            cert_path = line.split("=", 1)[1].strip().strip('"').strip("'")
        elif line.startswith("SSL_KEY="):
            key_path_current = line.split("=", 1)[1].strip().strip('"').strip("'")

    if os.path.isfile(cert_path):
        status["current_cert"] = {
            "cert_path": cert_path,
            "key_path": key_path_current,
        }
        # Check if self-signed
        code, out, _ = _run([
            "openssl", "x509", "-in", cert_path,
            "-noout", "-subject", "-issuer", "-dates",
        ])
        if code == 0:
            subject = ""
            issuer = ""
            not_after = ""
            for line in out.splitlines():
                if line.startswith("subject="):
                    subject = line.split("=", 1)[1].strip()
                elif line.startswith("issuer="):
                    issuer = line.split("=", 1)[1].strip()
                elif line.startswith("notAfter="):
                    not_after = line.split("=", 1)[1].strip()
            status["current_cert"]["subject"] = subject
            status["current_cert"]["issuer"] = issuer
            status["current_cert"]["expiry"] = not_after
            status["self_signed"] = subject == issuer
            # Check if it's a LE cert
            if "Let's Encrypt" in issuer or "R3" in issuer or "R10" in issuer or "R11" in issuer:
                status["current_cert"]["provider"] = "Let's Encrypt"
            elif subject == issuer:
                status["current_cert"]["provider"] = "Self-Signed"
            else:
                status["current_cert"]["provider"] = "Other CA"

    # Check renewal timer
    code, out, _ = _run(["systemctl", "is-active", "certbot.timer"])
    status["renewal_timer"] = out.strip() == "active" if code == 0 else False

    return status


def install_certbot():
    code, _, err = _run(["which", "certbot"])
    if code == 0:
        return {"success": True, "message": "Certbot is already installed"}
    # Try installing
    code, out, err = _run(["apt-get", "install", "-y", "certbot"], timeout=120)
    if code != 0:
        code, out, err = _run(["dnf", "install", "-y", "certbot"], timeout=120)
    if code != 0:
        return {"success": False, "error": f"Failed to install certbot: {err}"}
    return {"success": True, "message": "Certbot installed successfully"}


def ensure_certbot():
    """Auto-install certbot if not present."""
    code, _, _ = _run(["which", "certbot"])
    if code == 0:
        return True
    result = install_certbot()
    return result.get("success", False)


def ensure_acme_sh():
    """Install acme.sh if not present."""
    acme_path = "/root/.acme.sh/acme.sh"
    if os.path.isfile(acme_path):
        return True
    code, out, err = _run([
        "bash", "-c",
        "curl -fsSL https://get.acme.sh | sh -s -- --install-online"
    ], timeout=120)
    return os.path.isfile(acme_path)


def request_zerossl(domain, email="", method="standalone", webroot_path=""):
    """Request a ZeroSSL certificate using acme.sh."""
    if not domain:
        return {"success": False, "error": "Domain is required"}
    if not email:
        return {"success": False, "error": "Email is required for ZeroSSL"}

    if not ensure_acme_sh():
        return {"success": False, "error": "Failed to install acme.sh"}

    acme = "/root/.acme.sh/acme.sh"

    # Register with ZeroSSL if needed
    _run([acme, "--register-account", "-m", email, "--server", "zerossl"], timeout=60)

    # Request cert
    if method == "webroot":
        wr = webroot_path or _find_webroot()
        if not wr:
            return {"success": False, "error": "No webroot directory found. Enter the document root."}
        os.makedirs(os.path.join(wr, ".well-known", "acme-challenge"), exist_ok=True)
        code, out, err = _run([
            acme, "--issue",
            "--webroot", wr,
            "--server", "zerossl",
            "-d", domain,
        ], timeout=180)
    elif method == "redirect":
        port80_service = _find_port80_service()
        if port80_service:
            _run(port80_service["stop"], timeout=15)
        code, out, err = _run([
            acme, "--issue",
            "--standalone",
            "--server", "zerossl",
            "-d", domain,
        ], timeout=180)
        if port80_service:
            _run(port80_service["start"], timeout=15)
    else:
        code, out, err = _run([
            acme, "--issue",
            "--standalone",
            "--server", "zerossl",
            "-d", domain,
        ], timeout=180)

    if code != 0:
        return {"success": False, "error": err or out or "acme.sh failed"}

    cert_dir = f"/root/.acme.sh/{domain}_ecc"
    if not os.path.isdir(cert_dir):
        cert_dir = f"/root/.acme.sh/{domain}"

    cert_path = os.path.join(cert_dir, "fullchain.cer")
    key_path = os.path.join(cert_dir, f"{domain}.key")

    if not os.path.isfile(cert_path):
        cert_path = os.path.join(cert_dir, f"{domain}.cer")

    if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
        return {"success": False, "error": f"Certificate files not found after acme.sh run. Check {cert_dir}"}

    # Install to a stable location
    install_dir = "/etc/csfv2/ssl/zerossl"
    os.makedirs(install_dir, exist_ok=True)
    installed_cert = os.path.join(install_dir, "fullchain.pem")
    installed_key = os.path.join(install_dir, "privkey.pem")

    _run([
        acme, "--install-cert", "-d", domain,
        "--cert-file", os.path.join(install_dir, "cert.pem"),
        "--key-file", installed_key,
        "--fullchain-file", installed_cert,
        "--reloadcmd", "systemctl restart csfv2",
    ], timeout=30)

    return {
        "success": True,
        "cert_path": installed_cert,
        "key_path": installed_key,
        "message": f"ZeroSSL certificate issued for {domain}. Apply it to use with CSFv2.",
    }


def _find_port80_service():
    """Detect what's using port 80 and return stop/start commands."""
    code, out, _ = _run(["ss", "-tlnp", "sport", "=", ":80"])
    if code != 0 or "LISTEN" not in out:
        return None
    if "docker-proxy" in out or "traefik" in out.lower():
        # Find the Docker container on port 80
        code2, containers, _ = _run(["bash", "-c",
            "docker ps --format '{{.Names}}' --filter 'publish=80'"])
        if code2 == 0 and containers.strip():
            name = containers.strip().splitlines()[0]
            return {
                "stop": ["docker", "stop", name],
                "start": ["docker", "start", name],
                "name": name,
            }
    if "nginx" in out:
        return {"stop": ["systemctl", "stop", "nginx"], "start": ["systemctl", "start", "nginx"], "name": "nginx"}
    if "apache" in out or "httpd" in out:
        svc = "apache2" if os.path.isfile("/usr/sbin/apache2") else "httpd"
        return {"stop": ["systemctl", "stop", svc], "start": ["systemctl", "start", svc], "name": svc}
    return None


def _find_webroot():
    """Find a suitable webroot directory from nginx/apache/dokploy."""
    candidates = [
        "/var/www/html",
        "/usr/share/nginx/html",
        "/var/www",
        "/srv/www",
    ]
    # Check nginx configs for root directives
    for conf_dir in ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"]:
        if os.path.isdir(conf_dir):
            for fn in os.listdir(conf_dir):
                fp = os.path.join(conf_dir, fn)
                try:
                    with open(fp) as f:
                        for line in f:
                            m = re.match(r'\s*root\s+([^;]+);', line)
                            if m:
                                root = m.group(1).strip()
                                if os.path.isdir(root):
                                    candidates.insert(0, root)
                except OSError:
                    pass
    for c in candidates:
        if os.path.isdir(c):
            return c
    return None


def request_letsencrypt(domain, email="", method="standalone", webroot_path=""):
    """Request a Let's Encrypt certificate.
    method: standalone (port 80), webroot, or redirect (iptables redirect 80->8750)
    """
    if not domain:
        return {"success": False, "error": "Domain is required"}

    if not ensure_certbot():
        return {"success": False, "error": "Failed to auto-install certbot. Try: apt install certbot"}

    if method == "webroot":
        wr = webroot_path or _find_webroot()
        if not wr:
            return {"success": False, "error": "No webroot directory found. Enter the document root of your web server (e.g. /var/www/html)."}
        os.makedirs(os.path.join(wr, ".well-known", "acme-challenge"), exist_ok=True)
        cmd = [
            "certbot", "certonly",
            "--webroot",
            "--webroot-path", wr,
            "--non-interactive",
            "--agree-tos",
            "-d", domain,
        ]
    elif method == "redirect":
        # Temporarily stop whatever is on port 80, use standalone, then restart it
        port80_service = _find_port80_service()
        if port80_service:
            _run(port80_service["stop"], timeout=15)
        cmd = [
            "certbot", "certonly",
            "--standalone",
            "--non-interactive",
            "--agree-tos",
            "--preferred-challenges", "http",
            "-d", domain,
        ]
    else:
        cmd = [
            "certbot", "certonly",
            "--standalone",
            "--non-interactive",
            "--agree-tos",
            "--preferred-challenges", "http",
            "-d", domain,
        ]

    if email:
        cmd.extend(["--email", email])
    else:
        cmd.append("--register-unsafely-without-email")

    code, out, err = _run(cmd, timeout=120)

    # Restart port 80 service if we stopped it
    if method == "redirect" and port80_service:
        _run(port80_service["start"], timeout=15)
    if code != 0:
        return {"success": False, "error": err or out or "Certbot failed"}

    cert_path = f"{LE_LIVE_DIR}/{domain}/fullchain.pem"
    key_path = f"{LE_LIVE_DIR}/{domain}/privkey.pem"

    if not os.path.isfile(cert_path):
        return {"success": False, "error": "Certificate files not found after certbot run"}

    return {
        "success": True,
        "cert_path": cert_path,
        "key_path": key_path,
        "message": f"Certificate issued for {domain}. Apply it to use with CSFv2.",
    }


def generate_self_signed(domain=""):
    """Generate a self-signed certificate."""
    os.makedirs(CERT_DIR, exist_ok=True)
    cert_path = os.path.join(CERT_DIR, "server.crt")
    key_path = os.path.join(CERT_DIR, "server.key")

    subject = f"/CN={domain}" if domain else "/CN=CSFv2"
    code, out, err = _run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", key_path, "-out", cert_path,
        "-days", "365", "-nodes",
        "-subj", subject,
    ])
    if code != 0:
        return {"success": False, "error": err}

    return {
        "success": True,
        "cert_path": cert_path,
        "key_path": key_path,
        "message": "Self-signed certificate generated (valid 365 days).",
    }


def apply_certificate(cert_path, key_path):
    """Update csfv2.conf to use the given certificate."""
    if not os.path.isfile(cert_path):
        return {"success": False, "error": f"Certificate not found: {cert_path}"}
    if not os.path.isfile(key_path):
        return {"success": False, "error": f"Key not found: {key_path}"}

    os.makedirs(os.path.dirname(CSFV2_CONF), exist_ok=True)
    conf = _read(CSFV2_CONF)
    lines = conf.splitlines() if conf else []

    # Update or add SSL_CERT and SSL_KEY
    found_cert = False
    found_key = False
    for i, line in enumerate(lines):
        if line.strip().startswith("SSL_CERT="):
            lines[i] = f'SSL_CERT="{cert_path}"'
            found_cert = True
        elif line.strip().startswith("SSL_KEY="):
            lines[i] = f'SSL_KEY="{key_path}"'
            found_key = True
    if not found_cert:
        lines.append(f'SSL_CERT="{cert_path}"')
    if not found_key:
        lines.append(f'SSL_KEY="{key_path}"')

    try:
        with open(CSFV2_CONF, "w") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        return {"success": False, "error": str(e)}

    return {
        "success": True,
        "message": "Certificate applied. Restart CSFv2 to use the new certificate.",
        "needs_restart": True,
    }


def setup_auto_renewal(domain):
    """Set up a cron job for certbot auto-renewal with CSFv2 restart hook."""
    hook_script = f"""#!/bin/bash
systemctl restart csfv2
"""
    hook_path = "/etc/letsencrypt/renewal-hooks/deploy/csfv2-restart.sh"
    os.makedirs(os.path.dirname(hook_path), exist_ok=True)
    try:
        with open(hook_path, "w") as f:
            f.write(hook_script)
        os.chmod(hook_path, 0o755)
    except OSError as e:
        return {"success": False, "error": f"Failed to create renewal hook: {e}"}

    # Enable certbot timer if available
    _run(["systemctl", "enable", "certbot.timer"])
    _run(["systemctl", "start", "certbot.timer"])

    # Also add cron as fallback
    cron_line = "0 3 * * * certbot renew --quiet --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/csfv2-restart.sh"
    code, existing, _ = _run(["crontab", "-l"])
    if "certbot renew" not in (existing or ""):
        new_cron = (existing + "\n" if existing else "") + cron_line + "\n"
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cron", delete=False) as f:
            f.write(new_cron)
            tmp = f.name
        _run(["crontab", tmp])
        os.unlink(tmp)

    return {
        "success": True,
        "message": "Auto-renewal configured. Certbot will renew certificates automatically and restart CSFv2.",
    }


def test_renewal():
    """Dry run renewal test."""
    code, out, err = _run(["certbot", "renew", "--dry-run"], timeout=60)
    if code == 0:
        return {"success": True, "message": "Renewal test passed.", "output": out}
    return {"success": False, "error": err or out}


def revoke_certificate(cert_path=""):
    """Revoke a Let's Encrypt certificate."""
    if not cert_path:
        return {"success": False, "error": "No certificate path provided"}
    if not os.path.isfile(cert_path):
        return {"success": False, "error": f"Certificate not found: {cert_path}"}
    code, out, err = _run([
        "certbot", "revoke", "--cert-path", cert_path,
        "--non-interactive", "--no-delete-after-revoke",
    ], timeout=60)
    if code != 0:
        # Try acme.sh revoke
        acme = "/root/.acme.sh/acme.sh"
        if os.path.isfile(acme):
            code, out, err = _run([acme, "--revoke", "-d", cert_path], timeout=60)
    if code != 0:
        return {"success": False, "error": err or out or "Revoke failed"}
    return {"success": True, "message": "Certificate revoked successfully."}


def validate_cert_key(cert_path, key_path):
    """Check that a certificate and key match."""
    code1, cert_mod, _ = _run(["openssl", "x509", "-noout", "-modulus", "-in", cert_path])
    code2, key_mod, _ = _run(["openssl", "rsa", "-noout", "-modulus", "-in", key_path])
    if code1 != 0:
        return {"success": False, "error": "Invalid certificate file"}
    if code2 != 0:
        return {"success": False, "error": "Invalid key file"}
    if cert_mod != key_mod:
        return {"success": False, "error": "Certificate and key do not match"}
    return {"success": True}


def get_ip_preference():
    """Read current IPv4/IPv6 preference from /etc/gai.conf."""
    content = _read("/etc/gai.conf")
    if "precedence ::ffff:0:0/96  100" in content:
        return {"preference": "prefer_ipv4"}
    # Check if IPv6 is disabled
    code, out, _ = _run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"])
    if code == 0 and out.strip() == "1":
        return {"preference": "ipv4_only"}
    return {"preference": "default"}


def set_ip_preference(pref):
    """Set IPv4/IPv6 preference system-wide."""
    gai_path = "/etc/gai.conf"
    content = _read(gai_path)
    # Remove any existing preference line we added
    lines = [l for l in content.splitlines() if l.strip() != "precedence ::ffff:0:0/96  100"]

    if pref == "prefer_ipv4":
        lines.append("precedence ::ffff:0:0/96  100")
        # Re-enable IPv6 if it was disabled
        _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"])
        _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"])
    elif pref == "ipv4_only":
        # Disable IPv6 entirely
        _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"])
        _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"])
    else:
        # Default: re-enable IPv6, remove preference
        _run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"])
        _run(["sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"])

    try:
        with open(gai_path, "w") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        return {"success": False, "error": str(e)}

    return {"success": True, "message": f"IP preference set to: {pref}"}
