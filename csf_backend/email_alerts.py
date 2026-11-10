import os
import re
import smtplib
import ssl
import subprocess
from email.mime.text import MIMEText

CSF_CONF = "/etc/csf/csf.conf"
CSFV2_CONF = "/etc/csfv2/csfv2.conf"

_SMTP_KEYS = ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM", "SMTP_TLS")

ALERT_SETTINGS = [
    ("LF_ALERT_TO", "Alert email address", "Email address for all LFD alerts"),
    ("LF_ALERT_FROM", "Alert from address", "Sender address for alert emails"),
    ("LF_EMAIL_ALERT", "Login failure alerts", "Send email on login failures (1=on, 0=off)"),
    ("LF_PERMBLOCK_ALERT", "Permanent block alerts", "Email when an IP is permanently blocked"),
    ("LF_NETBLOCK_ALERT", "Netblock alerts", "Email when a netblock is blocked"),
    ("LF_DISTFTP_ALERT", "Distributed FTP alerts", "Email on distributed FTP attacks"),
    ("LF_DISTSMTP_ALERT", "Distributed SMTP alerts", "Email on distributed SMTP attacks"),
    ("LT_EMAIL_ALERT", "Login tracking alerts", "Email on excessive logins"),
    ("CT_EMAIL_ALERT", "Connection tracking alerts", "Email when connection limit is hit"),
    ("PS_EMAIL_ALERT", "Port scan alerts", "Email when a port scan is detected"),
    ("LF_INTEGRITY_ALERT", "File integrity alerts", "Email when system files change"),
    ("LF_EXPLOIT_ALERT", "Exploit alerts", "Email on suspected exploit attempts"),
    ("LF_QUEUE_ALERT", "Mail queue alerts", "Email on large mail queue"),
]


def _read_conf():
    try:
        with open(CSF_CONF) as f:
            return f.read()
    except OSError:
        return ""


def _read_csfv2_conf():
    result = {}
    try:
        with open(CSFV2_CONF) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return result


def _write_csfv2_keys(updates: dict):
    """Update specific KEY=value lines in csfv2.conf; add missing keys at end."""
    try:
        with open(CSFV2_CONF) as f:
            lines = f.readlines()
    except OSError:
        lines = []

    written = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in updates:
                v = updates[k]
                new_lines.append(f"{k}={v}\n")
                written.add(k)
                continue
        new_lines.append(line)

    for k, v in updates.items():
        if k not in written:
            new_lines.append(f"{k}={v}\n")

    with open(CSFV2_CONF, "w") as f:
        f.writelines(new_lines)


def get_smtp_config():
    conf = _read_csfv2_conf()
    return {k: conf.get(k, "") for k in _SMTP_KEYS}


def save_smtp_config(host, port, user, password, from_addr, tls):
    updates = {
        "SMTP_HOST": host.strip(),
        "SMTP_PORT": str(port).strip(),
        "SMTP_USER": user.strip(),
        "SMTP_FROM": from_addr.strip(),
        "SMTP_TLS": str(tls).strip(),
    }
    # only write password if provided (empty = keep existing)
    if password.strip():
        updates["SMTP_PASSWORD"] = password.strip()
    _write_csfv2_keys(updates)


def _send_via_smtp(to_addr, subject, body):
    conf = _read_csfv2_conf()
    host = conf.get("SMTP_HOST", "").strip()
    port = int(conf.get("SMTP_PORT", "587") or "587")
    user = conf.get("SMTP_USER", "").strip()
    password = conf.get("SMTP_PASSWORD", "").strip()
    from_addr = conf.get("SMTP_FROM", "").strip() or user
    tls_mode = conf.get("SMTP_TLS", "1").strip()  # 1=STARTTLS, 2=SSL, 0=plain

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr

    try:
        if tls_mode == "2":
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
                if user:
                    s.login(user, password)
                s.sendmail(from_addr, [to_addr], msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                if tls_mode == "1":
                    s.starttls(context=ssl.create_default_context())
                if user:
                    s.login(user, password)
                s.sendmail(from_addr, [to_addr], msg.as_string())
        return {"success": True}
    except smtplib.SMTPAuthenticationError:
        return {"success": False, "error": "SMTP authentication failed — check user/password"}
    except smtplib.SMTPException as e:
        return {"success": False, "error": f"SMTP error: {e}"}
    except OSError as e:
        return {"success": False, "error": f"Connection error: {e}"}


def get_alert_settings():
    conf = _read_conf()
    settings = []
    for key, label, description in ALERT_SETTINGS:
        value = ""
        m = re.search(rf'^{key}\s*=\s*"([^"]*)"', conf, re.MULTILINE)
        if m:
            value = m.group(1)
        settings.append({
            "key": key,
            "label": label,
            "description": description,
            "value": value,
        })
    return settings


def update_alert_setting(key, value):
    valid_keys = {k for k, _, _ in ALERT_SETTINGS}
    if key not in valid_keys:
        return {"success": False, "error": f"Invalid setting: {key}"}

    try:
        with open(CSF_CONF) as f:
            content = f.read()
    except OSError as e:
        return {"success": False, "error": str(e)}

    pattern = rf'^({key}\s*=\s*)"[^"]*"'
    new_content, count = re.subn(pattern, rf'\1"{value}"', content, count=1, flags=re.MULTILINE)
    if count == 0:
        return {"success": False, "error": f"Setting {key} not found in csf.conf"}

    try:
        with open(CSF_CONF, "w") as f:
            f.write(new_content)
    except OSError as e:
        return {"success": False, "error": str(e)}

    return {"success": True, "message": f"{key} updated to {value}"}


def get_admin_email():
    """Return LF_ALERT_TO from csf.conf, or empty string if not set."""
    conf = _read_conf()
    m = re.search(r'^LF_ALERT_TO\s*=\s*"([^"]*)"', conf, re.MULTILINE)
    return m.group(1).strip() if m else ""


def _smtp_configured():
    conf = _read_csfv2_conf()
    return bool(conf.get("SMTP_HOST", "").strip())


def send_verification_email(to_addr, subject, body):
    """Send a plain-text email, using SMTP config if set, else system mail."""
    if not to_addr:
        return {"success": False, "error": "No admin email configured (LF_ALERT_TO is empty)"}
    if _smtp_configured():
        return _send_via_smtp(to_addr, subject, body)
    try:
        r = subprocess.run(
            ["mail", "-s", subject, to_addr],
            input=body,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if r.returncode == 0:
            return {"success": True}
        return {"success": False, "error": r.stderr.strip() or "mail command failed"}
    except FileNotFoundError:
        return {"success": False, "error": "System mail command not available — configure SMTP above"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Mail send timed out"}


def test_email(to_addr):
    """Send a test alert email."""
    if not to_addr:
        return {"success": False, "error": "Email address required"}
    if _smtp_configured():
        result = _send_via_smtp(to_addr, "CSFv2 Test Alert", "CSFv2 test alert — email is working.")
        if result.get("success"):
            result["message"] = f"Test email sent to {to_addr}"
        return result
    try:
        r = subprocess.run(
            ["mail", "-s", "CSFv2 Test Alert", to_addr],
            input="CSFv2 test alert — email is working.",
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            return {"success": True, "message": f"Test email sent to {to_addr}"}
        return {"success": False, "error": r.stderr or "mail command failed"}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"success": False, "error": "mail command not available — configure SMTP above"}
