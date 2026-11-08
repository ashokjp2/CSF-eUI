import os
import re
import subprocess

CSF_CONF = "/etc/csf/csf.conf"

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


def send_verification_email(to_addr, subject, body):
    """Send a plain-text email using the system mail command."""
    if not to_addr:
        return {"success": False, "error": "No admin email configured (LF_ALERT_TO is empty)"}
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
        return {"success": False, "error": "System mail command not available"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Mail send timed out"}


def test_email(to_addr):
    """Send a test alert email."""
    if not to_addr:
        return {"success": False, "error": "Email address required"}
    try:
        r = subprocess.run(
            ["bash", "-c", f'echo "CSFv2 test alert - email alerts are working" | mail -s "CSFv2 Test Alert" "{to_addr}"'],
            capture_output=True, text=True, timeout=15,
        )
        if r.returncode == 0:
            return {"success": True, "message": f"Test email sent to {to_addr}"}
        return {"success": False, "error": r.stderr or "mail command failed"}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"success": False, "error": "mail command not available"}
