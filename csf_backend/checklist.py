"""Onboarding checklist for the dashboard: what a new install still needs."""
import os
import time

from csf_backend import csf_wrapper as csf, auth, notifications, config_backup, port_defaults, auto_update, ssl_manager


def build(username, passkey_problem=""):
    conf = csf.load_csf_conf()
    items = []

    def add(key, ok, title, detail, href):
        items.append({"key": key, "ok": bool(ok), "title": title, "detail": detail, "href": href})

    add("testing", conf.get("TESTING", "1") == "0", "Turn off TESTING mode",
        "While TESTING = 1 the firewall clears its rules every 5 minutes; nothing is really blocked.", "/config?q=TESTING")

    try:
        ssh_port = port_defaults._detect_ssh()
    except Exception:
        ssh_port = "22"
    tcp_in = {p.strip() for p in conf.get("TCP_IN", "").split(",")}
    # A health-check finding the user accepted/ignored ("Port N is listening but not in TCP_IN") counts as handled.
    try:
        from csf_backend import hardening_checks
        suffix = f":port-{ssh_port}-is-listening-but-not-in-tcp-in"
        ssh_waived = any(k.endswith(suffix) for k in hardening_checks.load_accepted())
    except Exception:
        ssh_waived = False
    add("ssh", ssh_port in tcp_in or ssh_waived, f"SSH port {ssh_port} is allowed in TCP_IN",
        "If SSH is not in TCP_IN you will be locked out the moment the firewall starts.", "/qconfig")

    add("2fa", auth.second_factor_status(username)["enabled"], "Protect this UI with a passkey",
        "This UI controls the firewall; a password alone is not enough.", "/settings#twofactor")
    items[-1]["action"] = "passkey"
    items[-1]["problem"] = passkey_problem

    nconf = notifications.load_config()
    chan = any(notifications._channel_ready(n, nconf["channels"][n]) for n in notifications.CHANNELS)
    add("notify", chan or bool(conf.get("LF_ALERT_TO")), "Set up alerts",
        "Get told when LFD goes down or something is blocked — Telegram, Slack, Discord, webhook or email.", "/notifications")

    backups = config_backup.list_backups()
    recent = bool(backups) and (time.time() - os.path.getmtime(os.path.join(config_backup.BACKUP_DIR, backups[0]["filename"]))) < 30 * 86400
    add("backup", recent, "Take a configuration backup", "A backup from the last 30 days means a mistake is a two-click restore.", "/backup-restore")

    try:
        upd = auto_update.load() or {}
        upd_on = bool(upd.get("auto_check")) or bool(upd.get("auto_install"))
    except Exception:
        upd_on = False
    add("updates", upd_on, "Enable update checks", "Know when a new CSF-eUI version is out.", "/updates")

    try:
        st = ssl_manager.get_ssl_status()
        cur = st.get("current_cert") or {}
        self_signed = (not cur) or bool(st.get("self_signed", True)) or cur.get("provider") == "Self-Signed"
    except Exception:
        self_signed = True
    add("ssl", not self_signed, "Use a real HTTPS certificate", "A Let's Encrypt certificate removes the browser warning and stops password theft on the wire.", "/ssl")

    add("docker", conf.get("DOCKER", "0") == "1" or not os.path.exists("/var/run/docker.sock"), "Tell CSF about Docker",
        "With Docker installed, DOCKER = 1 lets CSF manage container traffic.", "/config?q=DOCKER")

    done = sum(1 for i in items if i["ok"])
    return {"items": items, "done": done, "total": len(items)}
