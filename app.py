#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import secrets
import functools
import threading
import hmac
import traceback
import logging
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify, Response,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from csf_backend import csf_wrapper as csf
from csf_backend import docker_manager as docker
from csf_backend import wireguard_manager as wg
from csf_backend import auth
from csf_backend import system_stats
from csf_backend import ip_utils
from csf_backend import quick_config
from csf_backend import docker_log_monitor
from csf_backend import service_integration
from csf_backend import lfd_files
from csf_backend import csfpost_editor
from csf_backend import csfpost_model
from csf_backend import security_check
from csf_backend import hardening_checks
from csf_backend import port_defaults
from csf_backend import log_viewer
from csf_backend import ip_lookup
from csf_backend import config_backup
from csf_backend import health_score
from csf_backend import setting_help
from csf_backend import ssl_manager
from csf_backend import updater as app_updater
from csf_backend import auto_update as auto_update_cfg
from csf_backend import setup_wizard
from csf_backend import log_search
from csf_backend import plain_rules
from csf_backend import attack_analytics
from csf_backend import country_manager
from csf_backend import process_monitor
from csf_backend import connections
from csf_backend import audit_log
from csf_backend import alert_history
from csf_backend import port_scanner
from csf_backend import lfd_blocks
from csf_backend import geoip_map
from csf_backend import scheduled_tasks
from csf_backend import bandwidth
from csf_backend import login_history
from csf_backend import backup_restore
from csf_backend import email_alerts
from csf_backend import notifications
from csf_backend import safe_apply
from csf_backend import ip_report
from csf_backend import api_tokens
from csf_backend import config_history
from csf_backend import servers as fleet
from csf_backend import explain as explain_mod
from csf_backend import page_help
from csf_backend import actions_journal
from csf_backend import suggestions
from csf_backend import blocklist_feeds
from csf_backend import scheduled_rules
from csf_backend import presets
from csf_backend import checklist
from csf_backend import impact
from csf_backend import digest
from csf_backend import remote_backup
import socket
import time
from flask import g

app = Flask(__name__)
logging.basicConfig(
    filename="/var/log/csfv2.log",
    level=logging.ERROR,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
app.logger.setLevel(logging.ERROR)

# A normal application update pulls files under /opt/csfv2 but does not
# rewrite systemd units under /etc. Repair legacy timer units when the newly
# pulled application starts, so existing servers need no manual migration.
if os.path.isdir("/run/systemd/system") and getattr(os, "geteuid", lambda: 1)() == 0:
    for _timer_message in app_updater._repair_update_timer():
        if _timer_message.startswith("WARNING"):
            app.logger.error(_timer_message)
app.secret_key = (os.environ.get("CSFV2_SECRET_KEY")
                  or os.environ.get("SECRET_KEY")
                  or secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 43200  # 12 hours


@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://code.jquery.com https://maxcdn.bootstrapcdn.com; "
        "style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://maxcdn.bootstrapcdn.com https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "frame-ancestors 'self';"
    )
    return response


@app.context_processor
def inject_app_version():
    return {"app_version": app_updater.get_current_version()}


def _get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": _get_csrf_token()}


# Legacy glyphicon name -> Tabler icon name, for backend data that still carries glyphicon names
_TI_MAP = {
    "refresh": "refresh", "plus": "plus", "info-sign": "info-circle", "ok": "check", "hourglass": "hourglass",
    "trash": "trash", "warning-sign": "alert-triangle", "floppy-disk": "device-floppy", "search": "search",
    "ok-circle": "circle-check", "globe": "world", "flash": "bolt", "cog": "settings", "ban-circle": "ban",
    "remove": "x", "upload": "upload", "transfer": "arrows-exchange", "lock": "lock", "envelope": "mail",
    "wrench": "tool", "list-alt": "list-details", "eye-open": "eye", "th-list": "list", "cloud": "cloud",
    "chevron-down": "chevron-down", "repeat": "repeat", "play": "player-play", "list": "list", "link": "link",
    "certificate": "certificate", "time": "clock", "remove-sign": "circle-x", "random": "arrows-shuffle",
    "pencil": "pencil", "floppy-save": "device-floppy", "fire": "flame", "exclamation-sign": "alert-circle",
    "download": "download", "cloud-download": "cloud-download", "unchecked": "square", "question-sign": "help-circle",
    "ok-sign": "circle-check", "chevron-up": "chevron-up", "stop": "player-stop", "shield": "shield",
    "pause": "player-pause", "log-in": "login", "hdd": "server", "folder-open": "folder-open", "flag": "flag",
    "file": "file", "edit": "edit", "console": "terminal-2", "check": "checkbox", "alert": "alert-triangle",
    "user": "user", "tasks": "list-check", "star": "star", "signal": "antenna-bars-5", "share-alt": "share",
    "send": "send", "resize-full": "arrows-maximize", "remove-circle": "circle-x", "open": "upload", "off": "power",
    "minus": "minus", "map-marker": "map-pin", "filter": "filter", "dashboard": "layout-dashboard",
    "comment": "message", "bell": "bell", "arrow-right": "arrow-right", "arrow-left": "arrow-left",
    "eye-close": "eye-off", "ban": "ban", "heart": "heart", "calendar": "calendar", "home": "home",
    "tag": "tag", "tags": "tags", "book": "book", "briefcase": "briefcase", "stats": "chart-bar",
    "phone": "phone", "earphone": "phone", "bullhorn": "speakerphone", "equalizer": "adjustments",
    "th": "layout-grid", "inbox": "inbox", "lamp": "bulb", "log": "file-text", "plane": "plane",
    "picture": "photo", "copy": "copy", "import": "file-import", "export": "file-export", "pushpin": "pin",
    "question": "help-circle", "exclamation": "alert-circle", "list-check": "list-check", "save": "device-floppy",
    "new-window": "external-link", "cloud-upload": "cloud-upload", "knight": "chess-knight", "flask": "flask",
    "tower": "building-broadcast-tower", "road": "road", "leaf": "leaf", "tint": "droplet", "sort": "arrows-sort",
}


@app.template_filter("ti")
def ti_icon(name):
    """Jinja filter: map a glyphicon name (optionally followed by extra classes) to Tabler classes."""
    parts = str(name or "").replace("glyphicon-", "").split()
    if not parts:
        return "circle-dot"
    return " ".join([_TI_MAP.get(parts[0], parts[0])] + parts[1:])


VIEWER_POST_OK = ("/settings", "/quick/search", "/logs/tail", "/logs/grep", "/login", "/logout", "/api/ip/lookup")


@app.before_request
def check_api_token():
    """Bearer-token access for /api/v1/*: no session, no CSRF."""
    if not request.path.startswith("/api/v1/"):
        return
    header = request.headers.get("Authorization", "")
    tok = api_tokens.authenticate(header[7:].strip()) if header.startswith("Bearer ") else None
    if not tok:
        return jsonify({"error": "Invalid or missing API token"}), 401
    g.api_token = tok


@app.before_request
def check_csrf():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    if request.path.startswith("/.well-known/") or request.path.startswith("/api/v1/"):
        return
    if request.path == "/login":
        return
    if session.get("role") == "viewer" and not any(request.path.startswith(p) for p in VIEWER_POST_OK):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.path.startswith("/api/") or request.is_json:
            return jsonify({"success": False, "error": "Your account is read-only"}), 403
        flash("Your account is read-only", "warning")
        return redirect(request.referrer or "/")
    # Accept token from header (AJAX) or form field
    token = (request.headers.get("X-CSRFToken")
             or request.form.get("csrf_token")
             or (request.get_json(silent=True) or {}).get("csrf_token"))
    if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
        return jsonify({"error": "CSRF validation failed"}), 403
    # Safe apply: keep a known-good snapshot before the first firewall config change
    if session.get("logged_in") and safe_apply.is_change_path(request.path):
        try:
            safe_apply.snapshot_baseline()
        except Exception as e:
            logging.getLogger(__name__).warning("safe-apply baseline failed: %s", e)


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in") and not getattr(g, "api_token", None):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def _is_admin():
    return session.get("role", "admin") == "admin"


def _actor():
    tok = getattr(g, "api_token", None)
    return f"token:{tok['name']}" if tok else session.get("username", "")


def _wants_json():
    return (request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in request.headers.get("Accept", "")
            or request.is_json)


def _require_scope(scope):
    tok = getattr(g, "api_token", None)
    if tok and scope not in tok.get("scopes", []):
        return jsonify({"error": f"Token lacks the '{scope}' scope"}), 403
    return None




def get_firewall_status():
    enabled = csf.is_enabled()
    testing = csf.is_testing() if enabled else False
    lfd = csf.lfd_status()
    lfd_running = lfd["success"] and "active (running)" in lfd.get("stdout", "")
    return {
        "enabled": enabled,
        "testing": testing,
        "lfd_running": lfd_running,
        "version": csf.get_version(),
    }


# --- Auth routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        remote_ip = request.remote_addr
        ok, msg = auth.authenticate(username, password, remote_ip)
        if ok:
            if auth.totp_status(username)["enabled"]:
                session.clear()
                session["pending_2fa"] = {"username": username, "expires": int(time.time()) + 300}
                return redirect(url_for("login_2fa"))
            _complete_login(username, remote_ip)
            return redirect(url_for("dashboard"))
        login_history.record_login(username, remote_ip, False)
        notifications.event("ui_login_failed", "Failed UI login", f"Failed login for '{username}' from {remote_ip}")
        flash(msg, "danger")
    return render_template("login.html")


def _complete_login(username, remote_ip):
    session.pop("pending_2fa", None)
    session["logged_in"] = True
    session["username"] = username
    session["role"] = auth.get_role(username)
    session.permanent = True
    login_history.record_login(username, remote_ip, True)
    notifications.event("ui_login", "UI login", f"'{username}' signed in from {remote_ip}")


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    pending = session.get("pending_2fa") or {}
    if not pending.get("username") or time.time() > pending.get("expires", 0):
        session.pop("pending_2fa", None)
        flash("Sign in again to continue", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        remote_ip = request.remote_addr
        if auth.totp_check_login(pending["username"], request.form.get("code", "")):
            _complete_login(pending["username"], remote_ip)
            return redirect(url_for("dashboard"))
        auth.record_failed(auth.load_auth_config(), remote_ip)
        login_history.record_login(pending["username"], remote_ip, False)
        flash("Invalid authentication code", "danger")
    return render_template("login_2fa.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Dashboard ---

@app.route("/")
@login_required
def dashboard():
    status = get_firewall_status()
    conf = csf.load_csf_conf()
    has_cluster = bool(conf.get("CLUSTER_SENDTO", ""))
    has_docker = docker.is_docker_installed()
    has_wg = wg.is_installed()
    has_coolify = docker.is_coolify_installed() if has_docker else False
    system = system_stats.get_system_overview()
    return render_template(
        "dashboard.html",
        status=status,
        conf=conf,
        has_cluster=has_cluster,
        has_docker=has_docker,
        has_wireguard=has_wg,
        has_coolify=has_coolify,
        system=system,
    )


# --- CSF Actions ---

@app.route("/action/<action>", methods=["POST"])
@login_required
def csf_action(action):
    result = None
    redirect_to = request.form.get("redirect_to", "/")

    actions = {
        "start": csf.csf_start,
        "stop": csf.csf_stop,
        "restart": csf.csf_restart,
        "restartq": csf.csf_restart_q,
        "enable": csf.csf_enable,
        "disable": csf.csf_disable,
        "lfdstart": csf.lfd_start,
        "lfdstop": csf.lfd_stop,
        "lfdrestart": csf.lfd_restart,
        "restartboth": csf.restart_both,
        "flushall": csf.flush_all_blocks,
        "flushtemp": csf.flush_temp,
        "csftest": csf.run_csf_test,
    }

    if action == "csftest":
        report = security_check.run_full_check()
        return render_template("server_check.html", report=report, status=get_firewall_status())

    if action in ("restart", "restartq", "restartboth"):
        safe_apply.clear_baseline()   # an ordinary restart applies whatever is on disk

    if action == "sshd_edit":
        data = request.form
        key = data.get("key", "")
        value = data.get("value", "")
        if not key or not value:
            return jsonify({"success": False, "error": "Missing key or value"})
        result = security_check.update_sshd_setting(key, value)
        audit_log.log_event("config", session.get("username", ""), request.remote_addr, f"SSHD {key}={value}")
        return jsonify(result)

    ASYNC_ACTIONS = {"restart", "restartboth", "restartq", "start", "enable"}

    if action in actions:
        if action in ASYNC_ACTIONS:
            fn = actions[action]
            threading.Thread(target=fn, daemon=True).start()
            msg = "Firewall restart initiated. This may take a minute — the firewall will reload in the background."
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": True, "stdout": msg, "stderr": "", "returncode": 0})
            flash(msg, "success")
        else:
            result = actions[action]()
            if result["success"]:
                flash(f"Action '{action}' completed successfully.", "success")
            else:
                flash(f"Action '{action}' failed: {result.get('stderr', '')}", "danger")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(result)
    else:
        flash(f"Unknown action: {action}", "danger")

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(result or {"success": False})
    return redirect(redirect_to)


# --- Quick Actions ---

@app.route("/quick/allow", methods=["POST"])
@login_required
def quick_allow():
    ip = request.form.get("ip", "").strip()
    comment = request.form.get("comment", "").strip()
    if not ip:
        flash("IP address required", "danger")
        return redirect("/")
    result = csf.allow_ip(ip, comment)
    if result["success"]:
        actions_journal.record("allow", f"Allowed {ip}", {"action": "remove_allow", "ip": ip}, _actor())
        audit_log.log_event("action", _actor(), request.remote_addr, f"Allowed {ip} {comment}".strip())
    if _wants_json():
        return jsonify(result)
    if result["success"]:
        flash(f"Allowed {ip}", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect("/")


@app.route("/quick/deny", methods=["POST"])
@login_required
def quick_deny():
    ip = request.form.get("ip", "").strip()
    comment = request.form.get("comment", "").strip()
    if not ip:
        flash("IP address required", "danger")
        return redirect("/")
    result = csf.deny_ip(ip, comment)
    if result["success"]:
        actions_journal.record("deny", f"Blocked {ip}", {"action": "remove_deny", "ip": ip}, _actor())
        audit_log.log_event("action", _actor(), request.remote_addr, f"Blocked {ip} {comment}".strip())
    if _wants_json():
        return jsonify(result)
    if result["success"]:
        flash(f"Denied {ip}", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect("/")


@app.route("/quick/ignore", methods=["POST"])
@login_required
def quick_ignore():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("IP address required", "danger")
        return redirect("/")
    result = csf.add_ignore(ip)
    actions_journal.record("ignore", f"Added {ip} to csf.ignore", {"action": "remove_ignore", "ip": ip}, _actor())
    audit_log.log_event("action", _actor(), request.remote_addr, f"Ignored {ip}")
    if _wants_json():
        return jsonify({"success": True} if not isinstance(result, dict) else {"success": result.get("success", True), **result})
    flash(f"Added {ip} to ignore list", "success")
    return redirect("/")


@app.route("/quick/unblock", methods=["POST"])
@login_required
def quick_unblock():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("IP address required", "danger")
        return redirect("/")
    result = csf.unblock_ip(ip)
    if result.get("success"):
        actions_journal.record("unblock", f"Unblocked {ip}", {"action": "deny", "ip": ip, "comment": "re-blocked by undo"}, _actor())
        audit_log.log_event("action", _actor(), request.remote_addr, f"Unblocked {ip}")
    if _wants_json():
        return jsonify(result)
    if result["success"]:
        flash(f"Unblocked {ip}", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect("/")


@app.route("/api/deny/flush", methods=["POST"])
@login_required
def api_flush_deny():
    return jsonify(csf.flush_deny())


@app.route("/quick/search", methods=["POST"])
@login_required
def quick_search():
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("IP address required", "danger")
        return redirect("/")
    result = csf.search_ip(ip)
    return render_template(
        "search_results.html",
        ip=ip,
        result=result,
        status=get_firewall_status(),
    )


# --- Temp blocks ---

@app.route("/temp", methods=["GET"])
@login_required
def temp_list():
    entries = csf.get_temp_list()
    return render_template(
        "temp_blocks.html",
        entries=entries,
        status=get_firewall_status(),
    )


@app.route("/temp/add", methods=["POST"])
@login_required
def temp_add():
    ip = request.form.get("ip", "").strip()
    action = request.form.get("do", "block")
    timeout = int(request.form.get("timeout", "3600"))
    dur = request.form.get("dur", "seconds")
    ports = request.form.get("ports", "*").strip() or "*"
    comment = request.form.get("comment", "").strip()

    multipliers = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}
    timeout_secs = timeout * multipliers.get(dur, 1)

    if action == "block":
        result = csf.temp_deny(ip, timeout_secs, ports, comment)
    else:
        result = csf.temp_allow(ip, timeout_secs, ports, comment)

    if result["success"]:
        flash(f"Temporary {action} added for {ip}", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect(url_for("temp_list"))


@app.route("/temp/remove/<entry_type>/<path:ip>", methods=["POST"])
@login_required
def temp_remove(entry_type, ip):
    if entry_type == "deny":
        result = csf.remove_temp_deny(ip)
    else:
        result = csf.remove_temp_allow(ip)
    if result["success"]:
        flash(f"Removed temporary {entry_type} for {ip}", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect(url_for("temp_list"))


@app.route("/temp/toperm/<path:ip>", methods=["POST"])
@login_required
def temp_to_perm(ip):
    result = csf.temp_to_perm(ip)
    if result["success"]:
        flash(f"Converted {ip} to permanent deny", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect(url_for("temp_list"))


# --- Config ---

@app.route("/config")
@login_required
def config_view():
    sections = csf.load_csf_conf_full()
    return render_template(
        "config.html",
        sections=sections,
        defaults=csf.load_defaults(),
        status=get_firewall_status(),
    )


@app.route("/config/save", methods=["POST"])
@login_required
def config_save():
    changes = {}
    for key, value in request.form.items():
        if key.startswith("cfg_"):
            real_key = key[4:]
            changes[real_key] = value
    diff = config_history.diff(changes)
    result = csf.save_csf_conf(changes)
    if result.get("success") and diff:
        config_history.record(diff, session.get("username", ""))
        audit_log.log_event("config_change", session.get("username", ""), request.remote_addr,
                            "csf.conf: " + ", ".join(f"{d['key']}={d['new']!r}" for d in diff[:8]) + (" …" if len(diff) > 8 else ""))
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(result)
    if result["success"]:
        flash("Configuration saved. Restart CSF+LFD to apply changes.", "warning")
    else:
        flash(f"Error saving config: {result.get('error', 'Unknown')}", "danger")
    return redirect(url_for("config_view"))


# --- LFD interactive editors ---

ICON_MAP = {
    "ignore": "eye-close",
    "dirwatch": "folder-open",
    "dyndns": "globe",
    "blocklists": "list",
    "syslogusers": "user",
    "logfiles": "file",
}


@app.route("/lfd/<filetype>")
@login_required
def lfd_edit(filetype):
    info = lfd_files.get_file_info(filetype)
    if info is None:
        flash("Unknown LFD file type", "danger")
        return redirect("/")
    return render_template(
        "lfd_editor.html",
        filetype=filetype,
        info=info,
        icon=ICON_MAP.get(filetype, "file"),
        status=get_firewall_status(),
    )


@app.route("/lfd/<filetype>/save", methods=["POST"])
@login_required
def lfd_save(filetype):
    data = request.get_json(force=True)
    entries = data.get("entries", [])
    if filetype == "blocklists":
        result = lfd_files.save_blocklist_entries(entries)
    else:
        result = lfd_files.save_simple_entries(filetype, entries)
    return jsonify(result)


# --- File editor ---

@app.route("/files/<filetype>")
@login_required
def file_edit(filetype):
    # Four file types get the friendly UI; raw=1 query param forces the textarea editor
    smart_types = {"allow", "deny", "smtpauth", "redirect"}
    if filetype in smart_types and not request.args.get("raw"):
        info = lfd_files.get_csf_file_info(filetype)
        if info is None:
            flash("Unknown file type", "danger")
            return redirect("/")
        return render_template(
            "csf_file_editor.html",
            filetype=filetype,
            info=info,
            status=get_firewall_status(),
        )

    file_map = {
        "allow": (csf.CSF_ALLOW, "csf.allow - Allowed IPs", "both"),
        "deny": (csf.CSF_DENY, "csf.deny - Denied IPs", "both"),
        "ignore": (csf.CSF_IGNORE, "csf.ignore - LFD Ignore List", "lfd"),
        "redirect": (csf.CSF_REDIRECT, "csf.redirect - Port/IP Redirect", "both"),
        "smtpauth": (csf.CSF_SMTPAUTH, "csf.smtpauth - SMTP AUTH Restrict", "both"),
        "blocklists": (csf.CSF_BLOCKLISTS, "csf.blocklists - Block Lists", "both"),
        "dirwatch": (csf.CSF_DIRWATCH, "csf.dirwatch - Directory Watching", "lfd"),
        "dyndns": (csf.CSF_DYNDNS, "csf.dyndns - Dynamic DNS", "lfd"),
        "syslogusers": (csf.CSF_SYSLOGUSERS, "csf.syslogusers - Syslog Users", "lfd"),
        "logfiles": (csf.CSF_LOGFILES, "csf.logfiles - Custom Log Files", "lfd"),
        "cloudflare": (csf.CSF_CLOUDFLARE, "csf.cloudflare - CloudFlare IPs", "none"),
        "rblconf": (csf.CSF_RBLCONF, "csf.rblconf - RBL Configuration", "none"),
        "resellers": (csf.CSF_RESELLERS, "csf.resellers - Reseller Accounts", "none"),
    }
    if filetype not in file_map:
        flash("Unknown file type", "danger")
        return redirect("/")

    filepath, title, restart_type = file_map[filetype]
    content = csf.read_file(filepath)
    return render_template(
        "file_editor.html",
        filetype=filetype,
        filepath=filepath,
        title=title,
        content=content,
        restart_type=restart_type,
        status=get_firewall_status(),
    )


@app.route("/files/<filetype>/save", methods=["POST"])
@login_required
def file_save(filetype):
    file_map = {
        "allow": (csf.CSF_ALLOW, "both"),
        "deny": (csf.CSF_DENY, "both"),
        "ignore": (csf.CSF_IGNORE, "lfd"),
        "redirect": (csf.CSF_REDIRECT, "both"),
        "smtpauth": (csf.CSF_SMTPAUTH, "both"),
        "blocklists": (csf.CSF_BLOCKLISTS, "both"),
        "dirwatch": (csf.CSF_DIRWATCH, "lfd"),
        "dyndns": (csf.CSF_DYNDNS, "lfd"),
        "syslogusers": (csf.CSF_SYSLOGUSERS, "lfd"),
        "logfiles": (csf.CSF_LOGFILES, "lfd"),
        "cloudflare": (csf.CSF_CLOUDFLARE, "none"),
        "rblconf": (csf.CSF_RBLCONF, "none"),
        "resellers": (csf.CSF_RESELLERS, "none"),
    }
    if filetype not in file_map:
        flash("Unknown file type", "danger")
        return redirect("/")

    filepath, restart_type = file_map[filetype]
    content = request.form.get("content", "")
    result = csf.save_file(filepath, content)
    if result["success"]:
        if restart_type == "both":
            flash("File saved. Restart CSF+LFD to apply changes.", "warning")
        elif restart_type == "lfd":
            flash("File saved. Restart LFD to apply changes.", "warning")
        else:
            flash("File saved.", "success")
    else:
        flash(f"Error: {result.get('error', 'Unknown')}", "danger")
    return redirect(url_for("file_edit", filetype=filetype))


@app.route("/api/csf-file/<filetype>/save", methods=["POST"])
@login_required
def csf_file_save_api(filetype):
    """AJAX endpoint for the smart file editors (allow/deny/smtpauth/redirect)."""
    data = request.get_json(silent=True) or {}
    entries = data.get("entries", [])
    result = lfd_files.save_csf_file_entries(filetype, entries)
    return jsonify(result)


# --- csfpost.sh / csfpre.sh editor ---

def _csfpost_script(value=None):
    script = value or request.args.get("script") or "csfpost"
    return script if script in ("csfpost", "csfpre") else "csfpost"


@app.route("/csfpost")
@login_required
def csfpost_view():
    script = _csfpost_script()
    info = csfpost_editor.get_script_info(script)
    return render_template(
        "csfpost.html",
        info=info,
        script=script,
        templates=csfpost_editor.RULE_TEMPLATES,
        choices=csfpost_editor.FORM_CHOICES,
        form_fields=csfpost_model.FORM_FIELDS,
        target_opts=csfpost_model.TARGET_OPT_FIELDS,
        servers=fleet.list_servers(),
        status=get_firewall_status(),
    )


@app.route("/api/csfpost/tree")
@login_required
def csfpost_tree():
    return jsonify(csfpost_editor.get_tree(_csfpost_script()))


# Kept for older bookmarks / scripts that still call /parse.
@app.route("/api/csfpost/parse")
@login_required
def csfpost_parse():
    script = _csfpost_script()
    return jsonify({"rules": csfpost_editor.parse_rules(csfpost_editor.read_script(script))})


@app.route("/api/csfpost/save", methods=["POST"])
@login_required
def csfpost_save():
    data = request.get_json(silent=True) or {}
    script = _csfpost_script(data.get("script"))
    result = csfpost_editor.save_script(data.get("content", ""), script)
    if result.get("success"):
        result.update(csfpost_editor.get_tree(script))
        result["message"] = "Saved. Restart CSF+LFD to apply changes."
        audit_log.log_event("config_change", _actor(), request.remote_addr,
                            f"Edited {script}.sh (raw editor)")
    return jsonify(result)


@app.route("/api/csfpost/edit", methods=["POST"])
@login_required
def csfpost_edit():
    """One structural change - add, edit, move, enable/disable or delete a rule."""
    data = request.get_json(silent=True) or {}
    script = _csfpost_script(data.get("script"))
    op = data.get("op", "")
    result = csfpost_editor.apply_edit(script, op, data.get("payload") or {})
    if result.get("success") and not result.get("unchanged"):
        audit_log.log_event("config_change", _actor(), request.remote_addr,
                            f"{script}.sh: {op}")
    return jsonify(result)


@app.route("/api/csfpost/check", methods=["POST"])
@login_required
def csfpost_check():
    data = request.get_json(silent=True) or {}
    return jsonify(csfpost_editor.check_syntax(data.get("content", "")))


@app.route("/api/csfpost/dry-run", methods=["POST"])
@login_required
def csfpost_dry_run():
    data = request.get_json(silent=True) or {}
    content = data.get("content")
    if content is None:
        content = csfpost_editor.read_script(_csfpost_script(data.get("script")))
    return jsonify(csfpost_editor.dry_run(content))


@app.route("/api/csfpost/preview", methods=["POST"])
@login_required
def csfpost_preview():
    data = request.get_json(silent=True) or {}
    return jsonify(csfpost_editor.preview_rule(data.get("spec") or {}))


@app.route("/api/csfpost/build-rule", methods=["POST"])
@login_required
def csfpost_build_rule():
    data = request.get_json(silent=True) or {}
    return jsonify(csfpost_editor.build_rule(data.get("template_id", ""),
                                             data.get("params", {})))


# --- Backups -------------------------------------------------------------

@app.route("/api/csfpost/backups")
@login_required
def csfpost_backups():
    script = _csfpost_script()
    return jsonify({"backups": csfpost_editor.list_backups(script)})


@app.route("/api/csfpost/backup")
@login_required
def csfpost_backup_read():
    script = _csfpost_script()
    content = csfpost_editor.read_backup(script, request.args.get("file", ""))
    if content is None:
        return jsonify({"success": False, "error": "Backup not found"}), 404
    return jsonify({"success": True, "content": content})


@app.route("/api/csfpost/restore", methods=["POST"])
@login_required
def csfpost_restore():
    data = request.get_json(silent=True) or {}
    script = _csfpost_script(data.get("script"))
    result = csfpost_editor.restore_backup(script, data.get("file", ""))
    if result.get("success"):
        audit_log.log_event("config_change", _actor(), request.remote_addr,
                            f"Restored {script}.sh from backup {data.get('file', '')}")
    return jsonify(result)


# --- Portable bundles: recreate this script on another server ------------

@app.route("/api/csfpost/export")
@login_required
def csfpost_export():
    script = _csfpost_script()
    bundle = csfpost_editor.export_bundle(script)
    if request.args.get("download"):
        payload = json.dumps(bundle, indent=2)
        return Response(
            payload, mimetype="application/json",
            headers={"Content-Disposition":
                     f'attachment; filename="{script}-{bundle["exported"]}.csfv2.json"'})
    if request.args.get("shell"):
        return Response(bundle["content"] or "", mimetype="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="{script}.sh"'})
    return jsonify(bundle)


@app.route("/api/csfpost/import", methods=["POST"])
@login_required
def csfpost_import():
    data = request.get_json(silent=True) or {}
    script = _csfpost_script(data.get("script"))
    mode = data.get("mode", "append")
    if mode not in ("append", "merge", "replace"):
        return jsonify({"success": False, "error": "Unknown import mode"}), 400
    if data.get("raw") is not None:
        result = csfpost_editor.import_raw(script, data.get("raw", ""), mode)
    else:
        result = csfpost_editor.import_bundle(script, data.get("bundle") or {},
                                              mode, data.get("items"))
    if result.get("success"):
        audit_log.log_event("config_change", _actor(), request.remote_addr,
                            f"Imported rules into {script}.sh ({mode})")
    return jsonify(result)


@app.route("/api/csfpost/pull", methods=["POST"])
@login_required
def csfpost_pull():
    """Fetch another server's script so it can be previewed and imported here."""
    data = request.get_json(silent=True) or {}
    server = fleet._get_server(data.get("server", ""))
    if not server:
        return jsonify({"success": False, "error": "Unknown server"}), 404
    script = _csfpost_script(data.get("script"))
    r = fleet._request(server, "/api/v1/csfpost?script=" + script)
    if not r.get("ok"):
        return jsonify({"success": False, "error": r.get("error") or "Request failed"})
    return jsonify({"success": True, "bundle": r.get("data") or {},
                    "server": server["name"]})


@app.route("/api/csfpost/push", methods=["POST"])
@login_required
def csfpost_push():
    """Send this server's script to other CSF-eUI servers."""
    data = request.get_json(silent=True) or {}
    script = _csfpost_script(data.get("script"))
    mode = data.get("mode", "append")
    if mode not in ("append", "merge", "replace"):
        return jsonify({"success": False, "error": "Unknown import mode"}), 400
    bundle = csfpost_editor.export_bundle(script)
    body = {"script": script, "mode": mode, "bundle": bundle,
            "restart": bool(data.get("restart"))}
    if data.get("items") is not None:
        body["items"] = data["items"]
    targets = [s for s in fleet._load()["servers"] if s["id"] in (data.get("servers") or [])]
    out = []
    for server in targets:
        r = fleet._request(server, "/api/v1/csfpost", body)
        payload = r.get("data") or {}
        out.append({
            "id": server["id"], "name": server["name"],
            "ok": bool(r.get("ok")) and bool(payload.get("success")),
            "error": r.get("error") or payload.get("error", ""),
            "ms": r.get("ms"),
        })
    if out:
        audit_log.log_event("config_change", _actor(), request.remote_addr,
                            f"Pushed {script}.sh ({mode}) to " + ", ".join(x["name"] for x in out))
    return jsonify({"success": True, "results": out})


# --- Templates ---

@app.route("/templates")
@login_required
def template_list():
    templates = csf.list_templates()
    return render_template(
        "templates.html",
        templates=templates,
        status=get_firewall_status(),
    )


@app.route("/templates/<name>")
@login_required
def template_edit(name):
    safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
    filepath = os.path.join(csf.CSF_TPL_DIR, safe_name)
    content = csf.read_file(filepath)
    return render_template(
        "file_editor.html",
        filetype=f"template:{safe_name}",
        filepath=filepath,
        title=f"Template: {safe_name}",
        content=content,
        restart_type="none",
        status=get_firewall_status(),
    )


@app.route("/templates/<name>/save", methods=["POST"])
@login_required
def template_save(name):
    safe_name = "".join(c for c in name if c.isalnum() or c in "._-")
    filepath = os.path.join(csf.CSF_TPL_DIR, safe_name)
    content = request.form.get("content", "")
    result = csf.save_file(filepath, content)
    if result["success"]:
        flash("Template saved.", "success")
    else:
        flash(f"Error: {result.get('error', 'Unknown')}", "danger")
    return redirect(url_for("template_edit", name=safe_name))


# --- Status ---

@app.route("/status")
@login_required
def firewall_status():
    result = csf.get_status()
    result6 = csf.get_status6() if csf.load_csf_conf().get("IPV6", "0") == "1" else None
    return render_template(
        "status.html",
        result=result,
        result6=result6,
        status=get_firewall_status(),
    )


@app.route("/ports")
@login_required
def view_ports():
    result = csf.get_listening_ports()
    return render_template(
        "ports.html",
        result=result,
        status=get_firewall_status(),
    )


# --- Logs ---

@app.route("/logs")
@login_required
def logs_view():
    available = log_viewer.get_available_logs()
    current_log = request.args.get("log", "lfd")
    search = request.args.get("search", "")
    return render_template(
        "log_viewer.html",
        available_logs=available,
        current_log=current_log,
        search=search,
        status=get_firewall_status(),
    )


_ALLOWED_LOG_DIRS = (
    "/var/log/",
    "/var/lib/csf/",
    "/etc/csf/",
    "/tmp/csfv2",
)

_ALLOWED_LOG_FILES = {
    "/var/log/lfd.log",
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/kern.log",
    "/var/log/firewall",
}


def _is_allowed_logfile(path):
    real = os.path.realpath(path)
    for d in _ALLOWED_LOG_DIRS:
        if real.startswith(d):
            return True
    return real in _ALLOWED_LOG_FILES


@app.route("/logs/tail", methods=["POST"])
@login_required
def logs_tail():
    logfile = request.form.get("logfile", "")
    lines = int(request.form.get("lines", 50))
    if lines > 5000:
        lines = 5000
    if not logfile or not _is_allowed_logfile(logfile):
        return jsonify({"error": "Log file not permitted"})
    if not os.path.exists(logfile):
        return jsonify({"error": "Log file not found"})
    output = csf.tail_log(logfile, lines)
    return jsonify({"output": output})


@app.route("/logs/grep", methods=["POST"])
@login_required
def logs_grep():
    logfile = request.form.get("logfile", "")
    pattern = request.form.get("pattern", "")
    case_i = request.form.get("case_insensitive") == "1"
    extended = request.form.get("extended") == "1"
    if not logfile or not pattern:
        return jsonify({"error": "Log file and pattern required"})
    if not _is_allowed_logfile(logfile):
        return jsonify({"error": "Log file not permitted"})
    if not os.path.exists(logfile):
        return jsonify({"error": "Log file not found"})
    output = csf.grep_log(logfile, pattern, case_i, extended)
    return jsonify({"output": output})


# --- Profiles ---

@app.route("/profiles")
@login_required
def profiles_view():
    profiles = csf.list_profiles()
    backups = csf.list_backups()
    return render_template(
        "profiles.html",
        profiles=profiles,
        backups=backups,
        status=get_firewall_status(),
    )


@app.route("/profiles/apply", methods=["POST"])
@login_required
def profile_apply():
    name = request.form.get("profile", "")
    if not name:
        flash("No profile selected", "danger")
        return redirect(url_for("profiles_view"))
    result = csf.apply_profile(name)
    if result["success"]:
        flash(f"Profile '{name}' applied. Restart CSF+LFD.", "warning")
    else:
        flash(result["stderr"], "danger")
    return redirect(url_for("profiles_view"))


@app.route("/profiles/backup", methods=["POST"])
@login_required
def profile_backup():
    name = request.form.get("name", "manual")
    result = csf.create_backup(name)
    if result["success"]:
        flash(f"Backup created: {result['name']}", "success")
    else:
        flash("Backup failed", "danger")
    return redirect(url_for("profiles_view"))


# --- Cluster ---

@app.route("/cluster/<action>", methods=["POST"])
@login_required
def cluster_action(action):
    ip = request.form.get("ip", "").strip()
    comment = request.form.get("comment", "").strip()
    cluster_actions = {
        "ping": lambda: csf.cluster_ping(),
        "allow": lambda: csf.cluster_allow(ip, comment),
        "deny": lambda: csf.cluster_deny(ip, comment),
        "remove_deny": lambda: csf.cluster_remove_deny(ip),
        "remove_allow": lambda: csf.cluster_remove_allow(ip),
        "grep": lambda: csf.cluster_grep(ip),
        "restart": lambda: csf.cluster_restart(),
    }
    if action not in cluster_actions:
        flash(f"Unknown cluster action: {action}", "danger")
        return redirect("/")
    result = cluster_actions[action]()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(result)
    if result["success"]:
        flash(f"Cluster {action} completed", "success")
    else:
        flash(result.get("stderr", "Failed"), "danger")
    return redirect("/")


# --- Docker ---

@app.route("/docker")
@login_required
def docker_view():
    if not docker.is_docker_installed():
        flash("Docker is not installed", "warning")
        return redirect("/")
    containers = docker.list_containers(all_containers=True)
    networks = docker.list_networks()
    port_mappings = docker.get_docker_ports()
    coolify_containers = docker.get_coolify_containers() if docker.is_coolify_installed() else []
    docker_rules = docker.get_docker_iptables_rules()
    nat_rules = docker.get_docker_nat_rules()
    return render_template(
        "docker.html",
        containers=containers,
        networks=networks,
        port_mappings=port_mappings,
        coolify_containers=coolify_containers,
        docker_rules=docker_rules,
        nat_rules=nat_rules,
        is_coolify=docker.is_coolify_installed(),
        docker_version=docker.get_docker_version(),
        status=get_firewall_status(),
    )


@app.route("/docker/container/<container_id>/<action>", methods=["POST"])
@login_required
def docker_container_action(container_id, action):
    if action not in ("start", "stop", "restart"):
        return jsonify({"success": False, "error": "Invalid action"}), 400
    result = docker.container_action(container_id, action)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify(result)
    flash(f"Container {action}: {'OK' if result['success'] else result['stderr']}",
          "success" if result["success"] else "danger")
    return redirect(url_for("docker_view"))


@app.route("/docker/rules", methods=["POST"])
@login_required
def docker_generate_rules():
    rules = docker.generate_docker_csf_rules()
    return jsonify({"rules": rules})


@app.route("/docker/container/<container_id>")
@login_required
def docker_container_detail(container_id):
    details = docker.get_container_details(container_id)
    if not details:
        flash("Container not found", "danger")
        return redirect(url_for("docker_view"))
    return render_template(
        "docker_detail.html",
        container=details,
        status=get_firewall_status(),
    )


# --- WireGuard ---

@app.route("/wireguard")
@login_required
def wireguard_view():
    if not wg.is_installed():
        flash("WireGuard is not installed", "warning")
        return redirect("/")
    configs = wg.list_configs()
    interfaces = {}
    for conf in configs:
        if conf["active"]:
            interfaces[conf["interface"]] = wg.get_interface_status(conf["interface"])
    return render_template(
        "wireguard.html",
        configs=configs,
        interfaces=interfaces,
        wg_version=wg.get_version(),
        status=get_firewall_status(),
    )


@app.route("/wireguard/<iface>")
@login_required
def wireguard_detail(iface):
    safe = "".join(c for c in iface if c.isalnum())
    config_content = wg.read_config(safe)
    if config_content is None:
        flash("Interface not found", "danger")
        return redirect(url_for("wireguard_view"))
    parsed = wg.parse_config(config_content)
    wg_status = wg.get_interface_status(safe) if wg.is_interface_up(safe) else None
    transfer = wg.get_transfer_stats(safe) if wg.is_interface_up(safe) else {}
    return render_template(
        "wireguard_detail.html",
        iface=safe,
        config_content=config_content,
        parsed=parsed,
        wg_status=wg_status,
        transfer=transfer,
        status=get_firewall_status(),
    )


@app.route("/wireguard/<iface>/up", methods=["POST"])
@login_required
def wireguard_up(iface):
    safe = "".join(c for c in iface if c.isalnum())
    result = wg.interface_up(safe)
    if result["success"]:
        flash(f"WireGuard {safe} started", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect(url_for("wireguard_view"))


@app.route("/wireguard/<iface>/down", methods=["POST"])
@login_required
def wireguard_down(iface):
    safe = "".join(c for c in iface if c.isalnum())
    result = wg.interface_down(safe)
    if result["success"]:
        flash(f"WireGuard {safe} stopped", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect(url_for("wireguard_view"))


@app.route("/wireguard/<iface>/restart", methods=["POST"])
@login_required
def wireguard_restart(iface):
    safe = "".join(c for c in iface if c.isalnum())
    result = wg.interface_restart(safe)
    if result["success"]:
        flash(f"WireGuard {safe} restarted", "success")
    else:
        flash(result["stderr"], "danger")
    return redirect(url_for("wireguard_view"))


@app.route("/wireguard/<iface>/save", methods=["POST"])
@login_required
def wireguard_save_config(iface):
    safe = "".join(c for c in iface if c.isalnum())
    content = request.form.get("content", "")
    result = wg.save_config(safe, content)
    if result["success"]:
        flash("WireGuard config saved. Restart interface to apply.", "warning")
    else:
        flash(result.get("error", "Save failed"), "danger")
    return redirect(url_for("wireguard_detail", iface=safe))


@app.route("/wireguard/genkey", methods=["POST"])
@login_required
def wireguard_genkey():
    keys = wg.generate_keypair()
    if keys:
        return jsonify(keys)
    return jsonify({"error": "Key generation failed"}), 500


@app.route("/wireguard/<iface>/addpeer", methods=["POST"])
@login_required
def wireguard_add_peer(iface):
    safe = "".join(c for c in iface if c.isalnum())
    public_key = request.form.get("public_key", "").strip()
    allowed_ips = request.form.get("allowed_ips", "").strip()
    endpoint = request.form.get("endpoint", "").strip() or None
    psk = request.form.get("preshared_key", "").strip() or None
    keepalive = request.form.get("persistent_keepalive", "").strip() or None

    if not public_key or not allowed_ips:
        flash("Public key and allowed IPs required", "danger")
        return redirect(url_for("wireguard_detail", iface=safe))

    result = wg.add_peer(safe, public_key, allowed_ips, endpoint, psk, keepalive)
    if result["success"]:
        flash("Peer added", "success")
    else:
        flash(result.get("error", "Failed"), "danger")
    return redirect(url_for("wireguard_detail", iface=safe))


@app.route("/wireguard/<iface>/removepeer", methods=["POST"])
@login_required
def wireguard_remove_peer(iface):
    safe = "".join(c for c in iface if c.isalnum())
    public_key = request.form.get("public_key", "").strip()
    if not public_key:
        flash("Public key required", "danger")
        return redirect(url_for("wireguard_detail", iface=safe))
    result = wg.remove_peer(safe, public_key)
    if result["success"]:
        flash("Peer removed", "success")
    else:
        flash(result.get("error", "Failed"), "danger")
    return redirect(url_for("wireguard_detail", iface=safe))


@app.route("/wireguard/<iface>/genclient", methods=["POST"])
@login_required
def wireguard_gen_client(iface):
    safe = "".join(c for c in iface if c.isalnum())
    client_ip = request.form.get("client_ip", "").strip()
    server_endpoint = request.form.get("server_endpoint", "").strip()
    server_pubkey = request.form.get("server_public_key", "").strip()
    dns = request.form.get("dns", "1.1.1.1").strip()

    if not all([client_ip, server_endpoint, server_pubkey]):
        return jsonify({"error": "All fields required"}), 400

    result = wg.generate_client_config(safe, client_ip, server_endpoint, server_pubkey, dns)
    if result:
        return jsonify(result)
    return jsonify({"error": "Generation failed"}), 500


# --- Settings ---

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings_view():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "change_password":
            new_pass = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            if not new_pass or len(new_pass) < 8:
                flash("Password must be at least 8 characters", "danger")
            elif new_pass != confirm:
                flash("Passwords do not match", "danger")
            else:
                username = session.get("username", "admin")
                if auth.change_password(username, new_pass):
                    flash("Password changed successfully", "success")
                else:
                    flash("Password change failed", "danger")
        elif action == "change_username":
            new_username = request.form.get("new_username", "").strip()
            confirm_pass = request.form.get("current_password", "")
            if not new_username or len(new_username) < 3:
                flash("Username must be at least 3 characters", "danger")
            elif not new_username.replace("_", "").replace("-", "").isalnum():
                flash("Username may only contain letters, numbers, hyphens, and underscores", "danger")
            elif new_username == session.get("username", "admin"):
                flash("New username is the same as your current username", "warning")
            else:
                admin_email = email_alerts.get_admin_email()
                if not admin_email:
                    flash("Cannot change username: no admin email configured in LF_ALERT_TO (needed to send verification link)", "danger")
                else:
                    old_username = session.get("username", "admin")
                    ok, token_or_err = auth.create_username_change_token(old_username, new_username, confirm_pass)
                    if not ok:
                        flash(f"Username change failed: {token_or_err}", "danger")
                    else:
                        link = url_for("confirm_username", token=token_or_err, _external=True)
                        body = (
                            f"A username change was requested for the CSFv2 firewall UI.\n\n"
                            f"  Current username: {old_username}\n"
                            f"  New username:     {new_username}\n\n"
                            f"To confirm, click this link (valid for 15 minutes):\n{link}\n\n"
                            f"If you did not request this, ignore this email — no change will be made.\n"
                        )
                        result = email_alerts.send_verification_email(
                            admin_email,
                            f"[CSFv2] Confirm username change to '{new_username}'",
                            body,
                        )
                        if result["success"]:
                            flash(f"Verification email sent to {admin_email}. Click the link in the email to confirm the change.", "info")
                        else:
                            flash(f"Could not send verification email: {result['error']}", "danger")
        elif action == "totp_setup":
            session["totp_setup_secret"] = auth.totp_generate_secret()
            return redirect(url_for("settings_view") + "#twofactor")
        elif action == "totp_enable":
            secret = session.get("totp_setup_secret", "")
            if not secret:
                flash("Start the two-factor setup again", "danger")
            else:
                ok, result = auth.totp_enable(session.get("username", "admin"), secret, request.form.get("code", ""))
                if ok:
                    session.pop("totp_setup_secret", None)
                    session["totp_backup_codes"] = result
                    flash("Two-factor authentication is on", "success")
                else:
                    flash(result, "danger")
            return redirect(url_for("settings_view") + "#twofactor")
        elif action == "totp_cancel":
            session.pop("totp_setup_secret", None)
            session.pop("totp_backup_codes", None)
            return redirect(url_for("settings_view") + "#twofactor")
        elif action == "totp_disable":
            ok, msg = auth.totp_disable(session.get("username", "admin"),
                                        request.form.get("current_password", ""), request.form.get("code", ""))
            flash(msg, "success" if ok else "danger")
            return redirect(url_for("settings_view") + "#twofactor")
        elif action in ("add_user", "set_role", "delete_user", "token_create", "token_revoke"):
            if not _is_admin():
                flash("Only admins can manage users and tokens", "danger")
                return redirect(url_for("settings_view"))
            me = session.get("username", "")
            if action == "add_user":
                u = request.form.get("username", "").strip()
                pw = request.form.get("password", "")
                role = request.form.get("role", "viewer")
                if not u or len(u) < 3 or not u.replace("_", "").replace("-", "").isalnum():
                    flash("Username must be 3+ characters: letters, numbers, - or _", "danger")
                elif len(pw) < 8:
                    flash("Password must be at least 8 characters", "danger")
                elif u in auth.load_auth_config().get("users", {}):
                    flash("That username already exists", "danger")
                else:
                    auth.create_user(u, pw, role)
                    audit_log.log_event("config_change", me, request.remote_addr, f"Added user '{u}' with role {role}")
                    flash(f"User '{u}' added as {role}", "success")
            elif action == "set_role":
                ok, msg = auth.set_role(request.form.get("username", ""), request.form.get("role", ""))
                if ok:
                    audit_log.log_event("config_change", me, request.remote_addr, f"Set role of '{request.form.get('username')}' to {request.form.get('role')}")
                flash(msg, "success" if ok else "danger")
            elif action == "delete_user":
                ok, msg = auth.delete_user(request.form.get("username", ""), me)
                if ok:
                    audit_log.log_event("config_change", me, request.remote_addr, f"Deleted user '{request.form.get('username')}'")
                flash(msg, "success" if ok else "danger")
            elif action == "token_create":
                raw = api_tokens.create(request.form.get("name", ""), request.form.getlist("scopes"), me)
                session["new_api_token"] = raw
                audit_log.log_event("config_change", me, request.remote_addr, f"Created API token '{request.form.get('name', '')}'")
            elif action == "token_revoke":
                if api_tokens.revoke(request.form.get("token_id", "")):
                    audit_log.log_event("config_change", me, request.remote_addr, f"Revoked API token {request.form.get('token_id')}")
                    flash("Token revoked", "success")
            return redirect(url_for("settings_view") + ("#tokens" if action.startswith("token") else "#users"))
        return redirect(url_for("settings_view"))
    admin_email = email_alerts.get_admin_email()
    username = session.get("username", "admin")
    setup_secret = session.get("totp_setup_secret")
    return render_template(
        "settings.html", status=get_firewall_status(), admin_email=admin_email,
        totp=auth.totp_status(username),
        totp_setup_secret=setup_secret,
        totp_setup_uri=auth.totp_uri(setup_secret, username) if setup_secret else None,
        totp_backup_codes=session.pop("totp_backup_codes", None),
        is_admin=_is_admin(), users=auth.list_users() if _is_admin() else [], roles=auth.ROLES,
        tokens=api_tokens.list_tokens() if _is_admin() else [], token_scopes=api_tokens.SCOPES,
        new_api_token=session.pop("new_api_token", None),
        host_url=request.host_url.rstrip("/"),
    )


@app.route("/settings/confirm-username")
@login_required
def confirm_username():
    token = request.args.get("token", "")
    if not token:
        flash("Missing verification token", "danger")
        return redirect(url_for("settings_view"))
    ok, new_username_or_err = auth.confirm_username_change(token)
    if ok:
        session["username"] = new_username_or_err
        flash(f"Username successfully changed to '{new_username_or_err}'", "success")
    else:
        flash(f"Verification failed: {new_username_or_err}", "danger")
    return redirect(url_for("settings_view"))


# --- API endpoints for AJAX ---

@app.route("/api/status")
@login_required
def api_status():
    return jsonify(get_firewall_status())


@app.route("/api/temp")
@login_required
def api_temp_list():
    return jsonify(csf.get_temp_list())


@app.route("/api/docker/containers")
@login_required
def api_docker_containers():
    if not docker.is_docker_installed():
        return jsonify([])
    return jsonify(docker.list_containers(all_containers=True))


@app.route("/api/system")
@login_required
def api_system():
    return jsonify(system_stats.get_system_overview())


@app.route("/api/system/detail/<metric>")
@login_required
def api_system_detail(metric):
    import subprocess
    if metric == "cpu":
        top = subprocess.run(
            ["ps", "aux", "--sort=-pcpu"], capture_output=True, text=True, timeout=5
        )
        lines = top.stdout.strip().split("\n")[:11]
        return jsonify({"title": "Top CPU Processes", "lines": lines})
    elif metric == "memory":
        top = subprocess.run(
            ["ps", "aux", "--sort=-rss"], capture_output=True, text=True, timeout=5
        )
        lines = top.stdout.strip().split("\n")[:11]
        free = subprocess.run(
            ["free", "-h"], capture_output=True, text=True, timeout=5
        )
        return jsonify({
            "title": "Memory Details",
            "lines": lines,
            "extra": free.stdout.strip(),
        })
    elif metric == "uptime":
        uptime = subprocess.run(
            ["uptime", "-s"], capture_output=True, text=True, timeout=5
        )
        who = subprocess.run(
            ["who"], capture_output=True, text=True, timeout=5
        )
        return jsonify({
            "title": "Uptime & Sessions",
            "lines": [
                "System started: " + uptime.stdout.strip(),
                "",
                "Active sessions:",
            ] + (who.stdout.strip().split("\n") if who.stdout.strip() else ["(none)"]),
        })
    elif metric == "connections":
        ss = subprocess.run(
            ["ss", "-tun", "state", "established"],
            capture_output=True, text=True, timeout=5
        )
        lines = ss.stdout.strip().split("\n")[:21]
        return jsonify({"title": "Active Connections (top 20)", "lines": lines})
    elif metric == "blocked":
        import re as _re
        perm_entries = []
        try:
            with open("/etc/csf/csf.deny") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split("#", 1)
                        ip = parts[0].strip()
                        comment = parts[1].strip() if len(parts) > 1 else ""
                        country = ""
                        country_match = _re.search(r'\(([A-Z]{2})/', comment)
                        if country_match:
                            country = country_match.group(1)
                        perm_entries.append({
                            "ip": ip,
                            "comment": comment,
                            "country": country,
                            "type": "permanent",
                        })
        except OSError:
            pass
        temp_entries = []
        temp_result = csf.run_csf(["-t"])
        temp_text = (temp_result.get("stdout", "") or "").strip()
        for line in temp_text.split("\n"):
            line = line.strip()
            ip_match = _re.match(r'(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', line)
            if ip_match:
                ip = ip_match.group(1)
                comment = line[len(ip):].strip().lstrip("|").strip()
                temp_entries.append({
                    "ip": ip,
                    "comment": comment,
                    "country": "",
                    "type": "temporary",
                })
        return jsonify({
            "title": f"Blocked IPs ({len(perm_entries)} permanent, {len(temp_entries)} temporary)",
            "format": "blocked_table",
            "permanent": perm_entries,
            "temporary": temp_entries,
            "perm_count": len(perm_entries),
            "temp_count": len(temp_entries),
        })
    else:
        return jsonify({"title": "Unknown", "lines": []})


@app.route("/api/wireguard/status")
@login_required
def api_wg_status():
    if not wg.is_installed():
        return jsonify({})
    result = {}
    for conf in wg.list_configs():
        if conf["active"]:
            result[conf["interface"]] = wg.get_interface_status(conf["interface"])
    return jsonify(result)


# --- IP Geolocation & Reputation ---

@app.route("/api/geoip/<ip>")
@login_required
def api_geoip(ip):
    geo = ip_utils.geolocate_ip(ip)
    return jsonify(geo or {})


@app.route("/api/geoip/batch", methods=["POST"])
@login_required
def api_geoip_batch():
    ips = request.json.get("ips", []) if request.is_json else []
    return jsonify(ip_utils.geolocate_batch(ips))


@app.route("/api/reputation/<ip>")
@login_required
def api_reputation(ip):
    conf = csf.load_csf_conf()
    api_key = conf.get("CSFV2_ABUSEIPDB_KEY", "")
    if not api_key:
        csfv2_conf_path = "/etc/csfv2/csfv2.conf"
        try:
            with open(csfv2_conf_path) as f:
                for line in f:
                    if line.startswith("ABUSEIPDB_KEY="):
                        api_key = line.split("=", 1)[1].strip()
        except OSError:
            pass
    if not api_key:
        return jsonify({"error": "AbuseIPDB API key not configured. Add ABUSEIPDB_KEY to /etc/csfv2/csfv2.conf"}), 400
    result = ip_utils.check_abuseipdb(ip, api_key)
    return jsonify(result or {"error": "Lookup failed"})


@app.route("/api/lfd/events")
@login_required
def api_lfd_events():
    lines = request.args.get("lines", 30, type=int)
    events = ip_utils.get_lfd_events(lines)
    return jsonify(events)


# --- Bulk IP Operations ---

@app.route("/bulk/action", methods=["POST"])
@login_required
def bulk_ip_action():
    action = request.form.get("action", "")
    ips_raw = request.form.get("ips", "")
    comment = request.form.get("comment", "")
    ips = [ip.strip() for ip in ips_raw.replace(",", "\n").split("\n") if ip.strip()]

    if not ips:
        return jsonify({"success": False, "error": "No IPs provided"})
    if action not in ("allow", "deny", "unblock", "tempdeny", "tempallow"):
        return jsonify({"success": False, "error": "Invalid action"})

    results = []
    for ip in ips[:100]:
        if action == "allow":
            r = csf.allow_ip(ip, comment)
        elif action == "deny":
            r = csf.deny_ip(ip, comment)
        elif action == "unblock":
            r = csf.unblock_ip(ip)
        elif action == "tempdeny":
            ttl = request.form.get("ttl", "3600")
            r = csf.temp_deny(ip, ttl, comment=comment)
        elif action == "tempallow":
            ttl = request.form.get("ttl", "3600")
            r = csf.temp_allow(ip, ttl, comment=comment)
        results.append({"ip": ip, "success": r.get("success", False), "output": r.get("stdout", "")})

    success_count = sum(1 for r in results if r["success"])
    return jsonify({
        "success": True,
        "processed": len(results),
        "succeeded": success_count,
        "failed": len(results) - success_count,
        "results": results,
    })


# --- Firewall Rule Builder ---

@app.route("/rules/builder")
@login_required
def rule_builder():
    return render_template("rule_builder.html", status=get_firewall_status())


@app.route("/rules/build", methods=["POST"])
@login_required
def rule_build():
    rule_type = request.form.get("type", "allow")
    ip = request.form.get("ip", "")
    ports = request.form.get("ports", "")
    protocol = request.form.get("protocol", "tcp")
    direction = request.form.get("direction", "in")
    comment = request.form.get("comment", "")

    if not ip:
        return jsonify({"success": False, "error": "IP address required"})

    if ports:
        rule_line = f"{protocol}|{direction}|d={ports}|s={ip}"
    else:
        rule_line = ip

    if comment:
        rule_line += f" #{comment}"

    if rule_type == "allow":
        content = csf.read_file("allow")
        csf.save_file("allow", content + "\n" + rule_line + "\n")
    elif rule_type == "deny":
        content = csf.read_file("deny")
        csf.save_file("deny", content + "\n" + rule_line + "\n")

    return jsonify({
        "success": True,
        "rule": rule_line,
        "file": f"csf.{rule_type}",
        "message": f"Rule added to csf.{rule_type}. Restart CSF to apply.",
    })


# --- Quick Config ---

@app.route("/qconfig")
@login_required
def qconfig():
    import json as _json
    ports = quick_config.get_port_config()
    country = quick_config.get_country_config()
    conn = quick_config.get_connection_config()
    dyndns = quick_config.get_dyndns()
    misc = quick_config.get_misc_config()
    monitor_status = docker_log_monitor.get_monitor_status()
    api_keys = quick_config.get_api_keys()
    ports_json = _json.dumps(quick_config.WELL_KNOWN_PORTS)
    alerts = quick_config.get_alerts_config()
    cloudflare = quick_config.get_cloudflare_config()
    security = quick_config.get_security_config()
    return render_template(
        "quick_config.html",
        status=get_firewall_status(),
        ports=ports,
        ports_json=ports_json,
        country=country,
        country_codes=quick_config.COUNTRY_CODES,
        conn=conn,
        dyndns=dyndns,
        misc=misc,
        monitor_status=monitor_status,
        api_keys=api_keys,
        alerts=alerts,
        cloudflare=cloudflare,
        security=security,
    )


@app.route("/qconfig/ports", methods=["POST"])
@login_required
def qconfig_ports():
    key = request.form.get("key", "")
    ports = request.form.get("ports", "")
    return jsonify(quick_config.save_port_config(key, ports))


@app.route("/api/port-defaults", methods=["GET"])
@login_required
def api_port_defaults():
    return jsonify(port_defaults.generate_defaults())


@app.route("/api/port-defaults/apply", methods=["POST"])
@login_required
def api_port_defaults_apply():
    data = request.get_json(force=True)
    selections = data.get("selections", {})
    return jsonify(port_defaults.apply_defaults(selections))


@app.route("/api/ports/recommendations")
@login_required
def api_ports_recommendations():
    return jsonify(port_defaults.get_port_recommendations())


@app.route("/api/ports/add-port", methods=["POST"])
@login_required
def api_ports_add_port():
    key = request.form.get("key", "")
    port = request.form.get("port", "").strip()
    return jsonify(port_defaults.add_single_port(key, port))


@app.route("/api/port-tags/<key>")
@login_required
def api_port_tags(key):
    all_ports = quick_config.get_port_config()
    if key not in all_ports:
        return jsonify({"success": False, "error": "Invalid key"})
    return jsonify({"success": True, **all_ports[key]})


# --- Log Viewer API ---

@app.route("/api/logs/view")
@login_required
def api_logs_view():
    logname = request.args.get("log", "lfd")
    lines = int(request.args.get("lines", "200"))
    search = request.args.get("search", "")
    category = request.args.get("category", "all")
    return jsonify(log_viewer.get_log(logname, lines, search, category))


# --- IP Lookup ---

@app.route("/ip-lookup")
@login_required
def ip_lookup_view():
    ip = request.args.get("ip", "")
    result = None
    try:
        if ip:
            result = ip_lookup.lookup_ip(ip)
        return render_template(
            "ip_lookup.html",
            ip=ip,
            result=result,
            status=get_firewall_status(),
        )
    except Exception:
        app.logger.error("ip_lookup_view error for ip=%r:\n%s", ip, traceback.format_exc())
        raise


@app.route("/api/ip/lookup")
@login_required
def api_ip_lookup():
    ip = request.args.get("ip", "")
    if not ip:
        return jsonify({"error": "No IP provided"})
    return jsonify(ip_lookup.lookup_ip(ip))


# --- Config Backup & Restore ---

@app.route("/backups")
@login_required
def backups_view():
    backups = config_backup.list_backups()
    return render_template(
        "backups.html",
        backups=backups,
        file_count=len(config_backup.CSF_FILES),
        status=get_firewall_status(),
    )


@app.route("/api/backup/create", methods=["POST"])
@login_required
def api_backup_create():
    data = request.get_json(force=True)
    label = data.get("label", "")
    return jsonify(remote_backup.maybe_upload(config_backup.create_backup(label)))


@app.route("/api/backup/restore", methods=["POST"])
@login_required
def api_backup_restore():
    data = request.get_json(force=True)
    filename = data.get("filename", "")
    return jsonify(config_backup.restore_backup(filename))


@app.route("/api/backup/delete", methods=["POST"])
@login_required
def api_backup_delete():
    data = request.get_json(force=True)
    filename = data.get("filename", "")
    return jsonify(config_backup.delete_backup(filename))


# --- Health Score ---

@app.route("/health")
@login_required
def health_view():
    score_data = health_score.calculate_score()
    return render_template(
        "health_score.html",
        score=score_data,
        status=get_firewall_status(),
    )


@app.route("/api/health")
@login_required
def api_health():
    return jsonify(health_score.calculate_score())


_SSH_FIX_SETTINGS = {
    "Port", "PermitRootLogin", "PasswordAuthentication", "X11Forwarding", "MaxAuthTries",
    "PermitEmptyPasswords", "PermitUserEnvironment", "AllowTcpForwarding", "AllowAgentForwarding",
    "LoginGraceTime", "ClientAliveInterval",
}
_CSF_FIX_SETTINGS = {
    "TESTING", "RESTRICT_SYSLOG", "LF_SSHD", "LF_FTPD", "LF_PERMBLOCK",
    "PS_LIMIT", "CT_LIMIT", "DOCKER", "IPV6",
    "SYNFLOOD", "PORTFLOOD", "CONNLIMIT", "ICMP_IN_RATE", "LF_DISTATTACK", "LF_NETBLOCK",
    "DENY_IP_LIMIT", "SMTP_BLOCK", "LF_DIRWATCH", "LF_INTEGRITY", "LF_SSH_EMAIL_ALERT", "LF_SU_EMAIL_ALERT", "CC_SRC",
}


@app.route("/api/health/accept", methods=["POST"])
@login_required
def api_health_accept():
    """Accept a finding with a reason (it stops affecting the score) or un-accept it."""
    if not _is_admin():
        return jsonify({"success": False, "error": "Viewer accounts cannot change this"}), 403
    data = request.get_json(silent=True) or {}
    item_id = str(data.get("id", "")).strip()[:120]
    if not item_id:
        return jsonify({"success": False, "error": "Missing id"})
    if data.get("unaccept"):
        hardening_checks.unaccept(item_id)
        audit_log.log_event("config", session.get("username", ""), request.remote_addr, f"Health finding re-enabled: {item_id}")
        return jsonify({"success": True})
    reason = str(data.get("reason", "")).strip()
    hide = bool(data.get("ignore"))
    rec = hardening_checks.accept(item_id, reason, session.get("username", ""), hide=hide)
    audit_log.log_event("config", session.get("username", ""), request.remote_addr,
                        f"Health finding {'ignored' if hide else 'accepted'}: {item_id}" + (f" — {reason}" if reason else ""))
    return jsonify({"success": True, "accepted": rec})


@app.route("/api/health/quick-fix", methods=["POST"])
@login_required
def api_health_quick_fix():
    data = request.get_json(silent=True) or {}
    setting = str(data.get("setting", "")).strip()
    value = str(data.get("value", "")).strip()
    action = str(data.get("action", "")).strip()

    # Non-csf.conf one-click fixes
    if action == "sysctl":
        result = hardening_checks.apply_sysctl(str(data.get("key", "")), str(data.get("value", "")))
        if result.get("success"):
            audit_log.log_event("config", session.get("username", ""), request.remote_addr,
                                f"Health quick-fix: sysctl {data.get('key')}={data.get('value')}")
        return jsonify(result)
    if action == "restrict_port":
        try:
            port, proto = int(data.get("port")), ("udp" if data.get("proto") == "udp" else "tcp")
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Bad port"})
        result = docker.set_port_restriction(port, proto, True)
        if result.get("success"):
            actions_journal.record("health_fix", f"Health fix: restricted container port {port}/{proto}",
                                   {"action": "unrestrict_port", "port": port, "proto": proto}, _actor())
            audit_log.log_event("config", session.get("username", ""), request.remote_addr,
                                f"Health quick-fix: restricted docker port {port}/{proto}")
            result["message"] = f"Port {port}/{proto} is now reachable only from other containers and localhost."
        return jsonify(result)
    if action in ("remove_ports", "chmod", "ntp", "disable_feed"):
        if not _is_admin():
            return jsonify({"success": False, "error": "Viewer accounts cannot change this"}), 403
        result = hardening_checks.apply_action(action, data, _actor())
        if result.get("success"):
            audit_log.log_event("config", session.get("username", ""), request.remote_addr,
                                f"Health quick-fix: {result.get('message') or action}")
            if result.get("undo"):
                actions_journal.record("health_fix", "Health fix: " + (result.get("message") or action), result["undo"], _actor())
        return jsonify(result)

    if not setting or not value:
        return jsonify({"success": False, "error": "Missing setting or value"})

    if setting in _SSH_FIX_SETTINGS:
        result = security_check.update_sshd_setting(setting, value)
        if result.get("success"):
            audit_log.log_event("config", session.get("username", ""), request.remote_addr,
                                f"Health quick-fix: sshd {setting}={value}")
        return jsonify(result)

    if setting in _CSF_FIX_SETTINGS:
        old = csf.load_csf_conf().get(setting, "")
        save_result = csf.save_csf_conf({setting: value})
        if not save_result.get("success"):
            return jsonify(save_result)
        config_history.record([{"key": setting, "old": old, "new": value}], session.get("username", ""))
        actions_journal.record("health_fix", f"Health fix: {setting} = {value}", {"action": "set_conf", "key": setting, "value": old}, _actor())
        audit_log.log_event("config", session.get("username", ""), request.remote_addr,
                            f"Health quick-fix: csf {setting}={value}")
        # No immediate restart: the safe-apply bar offers a restart with automatic rollback
        return jsonify({"success": True, "safe_apply": True,
                        "message": f"{setting} set to {value}. Use “Apply safely” in the bar at the top to restart with automatic rollback."})

    return jsonify({"success": False, "error": f"Setting '{setting}' is not allowed for quick-fix"})


# --- Setting Help / Tooltips ---

@app.route("/api/setting-help")
@login_required
def api_setting_help_all():
    return jsonify(setting_help.get_all_help())


@app.route("/api/setting-help/<setting>")
@login_required
def api_setting_help(setting):
    h = setting_help.get_help(setting)
    if h:
        return jsonify(h)
    return jsonify({"plain": "No help available for this setting."})


# --- SSL Certificate Management ---

@app.route("/ssl")
@login_required
def ssl_view():
    ssl_status = ssl_manager.get_ssl_status()
    return render_template(
        "ssl_manage.html",
        ssl=ssl_status,
        status=get_firewall_status(),
    )


@app.route("/.well-known/acme-challenge/<token>")
def acme_challenge(token):
    challenge_dir = os.path.join(os.path.dirname(__file__), "static", ".well-known", "acme-challenge")
    fpath = os.path.join(challenge_dir, token)
    if os.path.isfile(fpath):
        with open(fpath) as f:
            return Response(f.read(), mimetype="text/plain")
    return "Not found", 404


@app.route("/api/ssl/install-certbot", methods=["POST"])
@login_required
def api_ssl_install_certbot():
    return jsonify(ssl_manager.install_certbot())


@app.route("/api/ssl/letsencrypt", methods=["POST"])
@login_required
def api_ssl_letsencrypt():
    data = request.get_json(force=True)
    domain = data.get("domain", "")
    email = data.get("email", "")
    auto_renew = data.get("auto_renew", True)

    method = data.get("method", "standalone")
    webroot_path = data.get("webroot_path", "")
    result = ssl_manager.request_letsencrypt(domain, email, method=method, webroot_path=webroot_path)
    if not result["success"]:
        return jsonify(result)

    # Apply certificate
    apply_result = ssl_manager.apply_certificate(result["cert_path"], result["key_path"])
    if not apply_result["success"]:
        return jsonify(apply_result)

    # Set up auto-renewal if requested
    if auto_renew:
        ssl_manager.setup_auto_renewal(domain)

    return jsonify({
        "success": True,
        "message": f"Let's Encrypt certificate for {domain} installed and applied. Restart CSFv2 to use it.",
        "needs_restart": True,
    })


@app.route("/api/ssl/zerossl", methods=["POST"])
@login_required
def api_ssl_zerossl():
    data = request.get_json(force=True)
    domain = data.get("domain", "")
    email = data.get("email", "")
    method = data.get("method", "standalone")
    webroot_path = data.get("webroot_path", "")
    result = ssl_manager.request_zerossl(domain, email, method=method, webroot_path=webroot_path)
    if not result["success"]:
        return jsonify(result)
    apply_result = ssl_manager.apply_certificate(result["cert_path"], result["key_path"])
    if not apply_result["success"]:
        return jsonify(apply_result)
    return jsonify({
        "success": True,
        "message": f"ZeroSSL certificate for {domain} installed and applied. Restart CSFv2 to use it.",
        "needs_restart": True,
    })


@app.route("/api/ssl/self-signed", methods=["POST"])
@login_required
def api_ssl_self_signed():
    data = request.get_json(force=True)
    domain = data.get("domain", "")
    result = ssl_manager.generate_self_signed(domain)
    if not result["success"]:
        return jsonify(result)
    apply_result = ssl_manager.apply_certificate(result["cert_path"], result["key_path"])
    if not apply_result["success"]:
        return jsonify(apply_result)
    return jsonify({
        "success": True,
        "message": "Self-signed certificate generated and applied. Restart CSFv2 to use it.",
        "needs_restart": True,
    })


@app.route("/api/ssl/apply", methods=["POST"])
@login_required
def api_ssl_apply():
    data = request.get_json(force=True)
    return jsonify(ssl_manager.apply_certificate(
        data.get("cert_path", ""),
        data.get("key_path", ""),
    ))


@app.route("/api/ssl/test-renewal")
@login_required
def api_ssl_test_renewal():
    return jsonify(ssl_manager.test_renewal())


@app.route("/api/restart-csfv2", methods=["POST"])
@login_required
def api_restart_csfv2():
    """Restart the CSFv2 service itself."""
    import threading
    def delayed_restart():
        import time
        time.sleep(1)
        subprocess.run(["systemctl", "restart", "csfv2"], timeout=15)
    threading.Thread(target=delayed_restart, daemon=True).start()
    return jsonify({"success": True, "message": "CSFv2 is restarting. Page will reload in a few seconds."})


@app.route("/api/ssl/revoke", methods=["POST"])
@login_required
def api_ssl_revoke():
    data = request.get_json(force=True)
    cert_path = data.get("cert_path", "")
    return jsonify(ssl_manager.revoke_certificate(cert_path))


@app.route("/api/ssl/download/<filetype>")
@login_required
def api_ssl_download(filetype):
    """Download current cert or key."""
    from flask import send_file
    status = ssl_manager.get_ssl_status()
    if not status.get("current_cert"):
        return "No certificate configured", 404
    if filetype == "cert":
        path = status["current_cert"]["cert_path"]
        fname = "server.crt"
    elif filetype == "key":
        path = status["current_cert"]["key_path"]
        fname = "server.key"
    else:
        return "Invalid type", 400
    if not os.path.isfile(path):
        return "File not found", 404
    return send_file(path, as_attachment=True, download_name=fname)


@app.route("/api/ssl/upload", methods=["POST"])
@login_required
def api_ssl_upload():
    """Upload custom certificate and key."""
    cert_file = request.files.get("cert")
    key_file = request.files.get("key")
    if not cert_file or not key_file:
        return jsonify({"success": False, "error": "Both certificate and key files are required"})
    upload_dir = "/etc/csfv2/ssl/custom"
    os.makedirs(upload_dir, exist_ok=True)
    cert_path = os.path.join(upload_dir, "server.crt")
    key_path = os.path.join(upload_dir, "server.key")
    cert_file.save(cert_path)
    key_file.save(key_path)
    # Validate the cert/key pair
    result = ssl_manager.validate_cert_key(cert_path, key_path)
    if not result["success"]:
        os.unlink(cert_path)
        os.unlink(key_path)
        return jsonify(result)
    apply_result = ssl_manager.apply_certificate(cert_path, key_path)
    return jsonify(apply_result)


@app.route("/api/network/ip-preference", methods=["GET", "POST"])
@login_required
def api_ip_preference():
    if request.method == "GET":
        return jsonify(ssl_manager.get_ip_preference())
    data = request.get_json(force=True)
    pref = data.get("preference", "default")
    return jsonify(ssl_manager.set_ip_preference(pref))


@app.route("/updates")
@login_required
def updates_view():
    info = app_updater.get_version_info(force=True)
    return render_template("updates.html", status=get_firewall_status(), info=info)


@app.route("/api/version/check")
@login_required
def api_version_check():
    force = request.args.get("force", "0") == "1"
    return jsonify(app_updater.get_version_info(force=force))


@app.route("/api/version/update-stream")
@login_required
def api_version_update_stream():
    from flask import stream_with_context
    force = request.args.get("force", "0") == "1"
    return Response(
        stream_with_context(app_updater.run_update_stream(force=force)),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/version/auto-update-config", methods=["GET", "POST"])
@login_required
def api_auto_update_config():
    if request.method == "GET":
        return jsonify(auto_update_cfg.load())
    data = request.get_json(force=True)
    try:
        saved = auto_update_cfg.save(data)
        return jsonify({"ok": True, "config": saved})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/version/timer-status")
@login_required
def api_version_timer_status():
    import shutil
    import subprocess

    timer_unit = "csfv2-update-check.timer"
    systemctl = shutil.which("systemctl") or "/usr/bin/systemctl"

    try:
        state = subprocess.run(
            [systemctl, "show", timer_unit,
             "--property=LoadState,ActiveState,SubState,UnitFileState",
             "--no-pager"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        properties = {}
        for line in state.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                properties[key] = value

        installed = properties.get("LoadState") == "loaded"
        active = installed and properties.get("ActiveState") == "active"
        return jsonify({
            "active": active,
            "installed": installed,
            "enabled": properties.get("UnitFileState") in {"enabled", "static"},
            "state": properties.get("SubState") or properties.get("ActiveState", "unknown"),
            "error": state.stderr.strip() if state.returncode != 0 else "",
        })
    except (OSError, subprocess.TimeoutExpired) as exc:
        return jsonify({
            "active": False,
            "installed": False,
            "enabled": False,
            "state": "unknown",
            "error": str(exc),
        })


@app.route("/api/ssl/http-redirect", methods=["GET", "POST"])
@login_required
def api_ssl_http_redirect():
    nginx_conf = "/etc/nginx/conf.d/csfv2-redirect.conf"
    if request.method == "GET":
        return jsonify({"enabled": os.path.exists(nginx_conf)})
    data = request.get_json(force=True)
    enabled = bool(data.get("enabled", False))
    import subprocess
    try:
        if enabled:
            # Write nginx redirect block: port 80 → https://host:8750
            conf_content = (
                "# CSF-eUI HTTP redirect — managed by CSF-eUI, do not edit manually\n"
                "server {\n"
                "    listen 80;\n"
                "    listen [::]:80;\n"
                "    server_name _;\n"
                "    location /.well-known/acme-challenge/ { root /var/www/html; }\n"
                "    location / { return 301 https://$host:8750$request_uri; }\n"
                "}\n"
            )
            with open(nginx_conf, "w") as f:
                f.write(conf_content)
            # Test nginx config, then reload
            test = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=10)
            if test.returncode != 0:
                os.unlink(nginx_conf)
                return jsonify({"success": False, "error": "nginx config test failed: " + test.stderr})
            subprocess.run(["nginx", "-s", "reload"], timeout=10)
            return jsonify({"success": True, "enabled": True,
                            "message": "nginx now redirects HTTP (port 80) → HTTPS port 8750."})
        else:
            if os.path.exists(nginx_conf):
                os.unlink(nginx_conf)
                subprocess.run(["nginx", "-s", "reload"], timeout=10)
            return jsonify({"success": True, "enabled": False,
                            "message": "HTTP redirect disabled. Port 80 no longer redirected."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/qconfig/country", methods=["POST"])
@login_required
def qconfig_country():
    changes = {k: request.form.get(k, "") for k in ("CC_DENY", "CC_ALLOW")}
    return jsonify(quick_config.save_country_config(changes))


@app.route("/qconfig/connections", methods=["POST"])
@login_required
def qconfig_connections():
    changes = {}
    for key in request.form:
        changes[key] = request.form[key]
    return jsonify(quick_config.save_connection_config(changes))


@app.route("/qconfig/dyndns", methods=["POST"])
@login_required
def qconfig_dyndns():
    data = request.get_json(force=True) if request.is_json else {}
    entries = data.get("entries", [])
    return jsonify(quick_config.save_dyndns(entries))


@app.route("/qconfig/apikeys", methods=["POST"])
@login_required
def qconfig_apikeys():
    keys = {"ABUSEIPDB_KEY": request.form.get("ABUSEIPDB_KEY", "")}
    return jsonify(quick_config.save_api_keys(keys))


@app.route("/qconfig/misc", methods=["POST"])
@login_required
def qconfig_misc():
    changes = {}
    for key in request.form:
        changes[key] = request.form[key]
    return jsonify(quick_config.save_misc_config(changes))


@app.route("/qconfig/alerts", methods=["POST"])
@login_required
def qconfig_alerts():
    changes = {}
    for key in request.form:
        changes[key] = request.form[key]
    return jsonify(quick_config.save_alerts_config(changes))


@app.route("/qconfig/cloudflare", methods=["POST"])
@login_required
def qconfig_cloudflare():
    changes = {}
    for key in request.form:
        changes[key] = request.form[key]
    return jsonify(quick_config.save_cloudflare_config(changes))


@app.route("/qconfig/security", methods=["POST"])
@login_required
def qconfig_security():
    changes = {}
    for key in request.form:
        changes[key] = request.form[key]
    return jsonify(quick_config.save_security_config(changes))


@app.route("/api/docker/scan")
@login_required
def api_docker_scan():
    return jsonify(docker_log_monitor.scan_all_monitors())


@app.route("/api/services/detect")
@login_required
def api_services_detect():
    return jsonify(service_integration.get_integration_status())


@app.route("/api/services/port-check")
@login_required
def api_services_port_check():
    return jsonify(service_integration.check_service_ports())


@app.route("/api/services/add-ports", methods=["POST"])
@login_required
def api_services_add_ports():
    tcp = [p.strip() for p in request.form.get("tcp", "").split(",") if p.strip()]
    udp = [p.strip() for p in request.form.get("udp", "").split(",") if p.strip()]
    return jsonify(service_integration.add_service_ports(tcp, udp))


@app.route("/qconfig/services/ignore", methods=["POST"])
@login_required
def qconfig_services_ignore():
    subnet = request.form.get("subnet", "").strip()
    action = request.form.get("action", "add")
    comment = request.form.get("comment", "")
    if not subnet:
        return jsonify({"success": False, "error": "No subnet provided"})
    if action == "add":
        result = service_integration.add_to_csf_ignore(subnet, comment)
    else:
        result = service_integration.remove_from_csf_ignore(subnet)
    return jsonify(result)


@app.route("/qconfig/services/pignore", methods=["POST"])
@login_required
def qconfig_services_pignore():
    entry = request.form.get("entry", "").strip()
    comment = request.form.get("comment", "")
    if not entry:
        return jsonify({"success": False, "error": "No entry provided"})
    result = service_integration.add_to_csf_pignore(entry, comment)
    return jsonify(result)


@app.route("/qconfig/services/autofix", methods=["POST"])
@login_required
def qconfig_services_autofix():
    return jsonify(service_integration.auto_fix_all())


# --- Setup Wizard ---

@app.route("/wizard")
@login_required
def wizard():
    state = setup_wizard.get_wizard_state()
    return render_template("wizard.html", status=get_firewall_status(), wizard=state)


@app.route("/api/wizard/apply", methods=["POST"])
@login_required
def wizard_apply():
    data = request.get_json(force=True)
    setting = data.get("setting", "")
    value = data.get("value", "")
    if not setting or not value:
        return jsonify({"success": False, "error": "Setting and value required"})
    if str(setting).lower() in security_check.SSHD_SAFE_SETTINGS:
        result = security_check.update_sshd_setting(setting, value)
        if result.get("success"):
            audit_log.log_event(
                "config", session.get("username", ""), request.remote_addr,
                f"Wizard SSHD {setting}={value}",
            )
        return jsonify(result)
    csf.save_csf_conf({setting: value})
    return jsonify({"success": True, "message": f"{setting} set to {value}. Restart CSF to apply."})


# --- Log Search ---

@app.route("/logs/search")
@login_required
def logs_search_page():
    return render_template("log_search.html", status=get_firewall_status())


@app.route("/api/logs/search")
@login_required
def api_logs_search():
    query = request.args.get("query", "")
    log_name = request.args.get("log", "")
    action_type = request.args.get("action", "")
    time_range = request.args.get("range", "24h")
    results = log_search.search_logs(query, log_name, action_type, time_range)
    return jsonify({"results": results})


# --- Firewall Timeline ---

@app.route("/timeline")
@login_required
def timeline_page():
    return render_template("timeline.html", status=get_firewall_status())


@app.route("/api/timeline")
@login_required
def api_timeline():
    hours = int(request.args.get("hours", 24))
    hours = min(hours, 720)
    data = log_search.get_timeline_data(hours)
    return jsonify(data)


# --- Plain-English Rule Builder ---

@app.route("/api/rules/parse", methods=["POST"])
@login_required
def api_rules_parse():
    data = request.get_json(force=True)
    text = data.get("text", "")
    if not text:
        return jsonify({"success": False, "error": "Enter a rule description"})
    return jsonify(plain_rules.parse_rule(text))


@app.route("/api/rules/apply", methods=["POST"])
@login_required
def api_rules_apply():
    data = request.get_json(force=True)
    rule = data.get("rule", {})
    if not rule:
        return jsonify({"success": False, "error": "No rule provided"})
    return jsonify(plain_rules.apply_rule(rule))


# --- Attack Analytics ---

@app.route("/analytics")
@login_required
def analytics_page():
    return render_template("analytics.html", status=get_firewall_status())


@app.route("/api/analytics")
@login_required
def api_analytics():
    hours = int(request.args.get("hours", 24))
    hours = min(hours, 720)
    return jsonify(attack_analytics.get_analytics(hours))


# --- Country Block Manager ---

@app.route("/countries")
@login_required
def countries_page():
    data = country_manager.get_country_config()
    return render_template("countries.html", status=get_firewall_status(), countries=data)


@app.route("/api/country/add", methods=["POST"])
@login_required
def api_country_add():
    data = request.get_json(force=True)
    return jsonify(country_manager.add_country(data.get("list", "deny"), data.get("code", "")))


@app.route("/api/country/remove", methods=["POST"])
@login_required
def api_country_remove():
    data = request.get_json(force=True)
    return jsonify(country_manager.remove_country(data.get("list", "deny"), data.get("code", "")))


@app.route("/api/country/set", methods=["POST"])
@login_required
def api_country_set():
    data = request.get_json(force=True)
    return jsonify(country_manager.update_country_list(data.get("list", "deny"), data.get("codes", [])))


# --- IP Allow/Deny List Manager ---

@app.route("/ip-lists")
@login_required
def ip_lists_page():
    return render_template("ip_lists.html", status=get_firewall_status())


@app.route("/api/ip-lists")
@login_required
def api_ip_lists():
    import re as _re
    allow_entries = []
    deny_entries = []

    for fname, entries in [("allow", allow_entries), ("deny", deny_entries)]:
        try:
            with open(f"/etc/csf/csf.{fname}") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("#", 1)
                    ip = parts[0].strip()
                    comment = parts[1].strip() if len(parts) > 1 else ""
                    entries.append({"ip": ip, "comment": comment})
        except OSError:
            pass

    return jsonify({"allow": allow_entries, "deny": deny_entries})


@app.route("/api/ip-lists/allow", methods=["POST"])
@login_required
def api_ip_lists_allow():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    comment = data.get("comment", "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"})
    line = ip
    if comment:
        line += f" # {comment}"
    result = csf.run_csf(["-a", ip, comment])
    return jsonify({
        "success": result.get("returncode", 1) == 0,
        "message": f"{ip} added to csf.allow",
        "output": result.get("stdout", ""),
    })


@app.route("/api/ip-lists/deny", methods=["POST"])
@login_required
def api_ip_lists_deny():
    data = request.get_json(force=True)
    ip = data.get("ip", "").strip()
    comment = data.get("comment", "").strip()
    if not ip:
        return jsonify({"success": False, "error": "IP required"})
    result = csf.run_csf(["-d", ip, comment])
    return jsonify({
        "success": result.get("returncode", 1) == 0,
        "message": f"{ip} added to csf.deny",
        "output": result.get("stdout", ""),
    })


@app.route("/api/ip-lists/remove", methods=["POST"])
@login_required
def api_ip_lists_remove():
    data = request.get_json(force=True)
    list_type = data.get("list", "")
    ip = data.get("ip", "").strip()
    if not ip or list_type not in ("allow", "deny"):
        return jsonify({"success": False, "error": "Invalid parameters"})

    if list_type == "allow":
        result = csf.run_csf(["-ar", ip])
    else:
        result = csf.run_csf(["-dr", ip])

    return jsonify({
        "success": result.get("returncode", 1) == 0,
        "message": f"{ip} removed from csf.{list_type}",
        "output": result.get("stdout", ""),
    })


# --- Process Monitor ---

@app.route("/processes")
@login_required
def processes_view():
    return render_template("processes.html")


@app.route("/api/processes")
@login_required
def api_processes():
    sort_by = request.args.get("sort", "cpu")
    limit = int(request.args.get("limit", "50"))
    return jsonify(process_monitor.get_processes(sort_by=sort_by, limit=limit))


@app.route("/api/processes/ports")
@login_required
def api_listening_ports():
    return jsonify(process_monitor.get_listening_ports())


@app.route("/api/processes/kill", methods=["POST"])
@login_required
def api_kill_process():
    data = request.get_json(force=True)
    pid = data.get("pid")
    if not pid:
        return jsonify({"success": False, "error": "No PID"})
    result = process_monitor.kill_process(int(pid))
    audit_log.log_event("action", session.get("username", ""), request.remote_addr, f"Kill PID {pid}")
    return jsonify(result)


# --- Active Connections ---

@app.route("/connections")
@login_required
def connections_view():
    return render_template("connections.html")


@app.route("/api/connections")
@login_required
def api_connections():
    return jsonify(connections.get_connections())


# --- Audit Log ---

@app.route("/audit")
@login_required
def audit_view():
    return render_template("audit.html")


@app.route("/api/audit")
@login_required
def api_audit():
    event_type = request.args.get("type", "")
    limit = int(request.args.get("limit", "100"))
    return jsonify({"events": audit_log.get_events(limit=limit, event_type=event_type)})


# --- Alert History ---

@app.route("/alerts")
@login_required
def alerts_view():
    return render_template("alerts.html")


@app.route("/api/alerts")
@login_required
def api_alerts():
    hours = int(request.args.get("hours", "24"))
    return jsonify(alert_history.get_alerts(hours=hours))


# --- Port Scanner ---

@app.route("/port-scan")
@login_required
def port_scan_view():
    return render_template("port_scan.html")


@app.route("/api/port-scan")
@login_required
def api_port_scan():
    return jsonify(port_scanner.scan_self())


@app.route("/api/port-scan/rule", methods=["POST"])
@login_required
def api_port_scan_rule():
    data = request.get_json(silent=True) or {}
    action = str(data.get("action", "")).strip().lower()
    port = str(data.get("port", "")).strip()

    if action == "add":
        result = port_defaults.add_single_port("TCP_IN", port)
    elif action == "remove":
        result = port_defaults.remove_single_port("TCP_IN", port)
    else:
        return jsonify({"success": False, "error": "Invalid rule action"})

    if result.get("success"):
        audit_log.log_event(
            "config", session.get("username", ""), request.remote_addr,
            f"Port scanner: {result.get('message', action + ' TCP_IN ' + port)}",
        )
    return jsonify(result)


# --- LFD Blocks ---

@app.route("/lfd-blocks")
@login_required
def page_lfd_blocks():
    return render_template("lfd_blocks.html")

@app.route("/api/lfd-blocks")
@login_required
def api_lfd_blocks():
    return jsonify(lfd_blocks.get_lfd_blocks())

@app.route("/api/lfd-blocks/timeline")
@login_required
def api_lfd_blocks_timeline():
    hours = min(max(int(request.args.get("hours", 24)), 1), 168)
    return jsonify(lfd_blocks.get_block_timeline(hours))


@app.route("/api/lfd-blocks/stats")
@login_required
def api_lfd_blocks_stats():
    return jsonify(lfd_blocks.get_lfd_stats())


# --- GeoIP Map ---

@app.route("/geoip-map")
@login_required
def page_geoip_map():
    return render_template("geoip_map.html")

@app.route("/api/geoip-map")
@login_required
def api_geoip_map():
    hours = request.args.get("hours", type=int)
    if hours:
        return jsonify(geoip_map.get_block_replay(min(hours, 24 * 30)))
    return jsonify(geoip_map.get_blocked_ips_geo())


# --- Scheduled Tasks ---

@app.route("/scheduled-tasks")
@login_required
def page_scheduled_tasks():
    return render_template("scheduled_tasks.html")

@app.route("/api/scheduled-tasks", methods=["GET"])
@login_required
def api_scheduled_tasks_list():
    jobs = scheduled_tasks.get_all_cron_jobs()
    presets = [{"label": p["name"], "schedule": p["schedule"], "command": p["command"]} for p in scheduled_tasks.PRESETS]
    return jsonify({"jobs": jobs, "presets": presets})

@app.route("/api/scheduled-tasks", methods=["POST"])
@login_required
def api_scheduled_tasks_add():
    data = request.get_json(force=True)
    return jsonify(scheduled_tasks.add_cron_job(data.get("schedule", ""), data.get("command", "")))

@app.route("/api/scheduled-tasks/delete", methods=["POST"])
@login_required
def api_scheduled_tasks_del():
    data = request.get_json(force=True)
    return jsonify(scheduled_tasks.delete_cron_job(data))

@app.route("/api/scheduled-tasks/edit", methods=["POST"])
@login_required
def api_scheduled_tasks_edit():
    data = request.get_json(force=True)
    job = data.get("job", {})
    return jsonify(scheduled_tasks.edit_cron_job(job, data.get("schedule", ""), data.get("command", "")))


# --- Bandwidth Monitor ---

@app.route("/bandwidth")
@login_required
def page_bandwidth():
    return render_template("bandwidth.html")

@app.route("/api/bandwidth")
@login_required
def api_bandwidth():
    data = bandwidth.get_bandwidth_summary()
    data["iptables_counters"] = bandwidth.get_iptables_traffic()
    return jsonify(data)


# --- Login History ---

@app.route("/login-history")
@login_required
def page_login_history():
    return render_template("login_history.html")

@app.route("/api/login-history")
@login_required
def api_login_history():
    return jsonify({"entries": login_history.get_history()})

@app.route("/api/login-history/stats")
@login_required
def api_login_history_stats():
    return jsonify(login_history.get_stats())


# --- Backup & Restore ---

@app.route("/backup-restore")
@login_required
def page_backup_restore():
    return render_template("backup_restore.html")

@app.route("/api/backups", methods=["GET"])
@login_required
def api_backups_list():
    return jsonify(backup_restore.list_backups())

@app.route("/api/backups", methods=["POST"])
@login_required
def api_backups_create():
    data = request.get_json(force=True)
    result = backup_restore.create_backup(data.get("label", ""))
    if result.get("success") and not result.get("path"):
        result["path"] = os.path.join(backup_restore.BACKUP_DIR, result.get("filename") or (result.get("name", "") + ".tar.gz"))
    return jsonify(remote_backup.maybe_upload(result))

@app.route("/api/backups/upload", methods=["POST"])
@login_required
def api_backups_upload():
    return jsonify(backup_restore.upload_backup(request.files.get("backup_file")))

@app.route("/api/backups/restore", methods=["POST"])
@login_required
def api_backups_restore():
    data = request.get_json(force=True)
    return jsonify(backup_restore.restore_backup(data.get("filename", "")))

@app.route("/api/backups/download/<filename>")
@login_required
def api_backups_download(filename):
    from flask import send_file
    path = backup_restore.download_path(filename)
    if not path:
        return jsonify({"error": "Not found"}), 404
    return send_file(path, as_attachment=True)

@app.route("/api/backups/<filename>", methods=["DELETE"])
@login_required
def api_backups_delete(filename):
    return jsonify(backup_restore.delete_backup(filename))


# --- Email Alerts ---

@app.route("/email-alerts")
@login_required
def page_email_alerts():
    return render_template("email_alerts.html")

@app.route("/api/email-alerts", methods=["GET"])
@login_required
def api_email_alerts_get():
    return jsonify(email_alerts.get_alert_settings())

@app.route("/api/email-alerts", methods=["POST"])
@login_required
def api_email_alerts_update():
    data = request.get_json(force=True)
    return jsonify(email_alerts.update_alert_setting(data.get("key", ""), data.get("value", "")))

@app.route("/api/email-alerts/test", methods=["POST"])
@login_required
def api_email_alerts_test():
    data = request.get_json(force=True)
    return jsonify(email_alerts.test_email(data.get("email", "")))

@app.route("/api/smtp-config", methods=["GET"])
@login_required
def api_smtp_config_get():
    cfg = email_alerts.get_smtp_config()
    cfg.pop("SMTP_PASSWORD", None)  # never send password to browser
    return jsonify(cfg)

@app.route("/api/smtp-config", methods=["POST"])
@login_required
def api_smtp_config_save():
    data = request.get_json(force=True)
    email_alerts.save_smtp_config(
        host=data.get("SMTP_HOST", ""),
        port=data.get("SMTP_PORT", "587"),
        user=data.get("SMTP_USER", ""),
        password=data.get("SMTP_PASSWORD", ""),
        from_addr=data.get("SMTP_FROM", ""),
        tls=data.get("SMTP_TLS", "1"),
    )
    return jsonify({"success": True, "message": "SMTP configuration saved"})


# --- Initialization ---

# --- Push notifications ---

@app.route("/notifications")
@login_required
def notifications_page():
    return render_template("notifications.html", status=get_firewall_status())


@app.route("/api/notifications", methods=["GET"])
@login_required
def api_notifications_get():
    return jsonify(notifications.public_config())


@app.route("/api/notifications", methods=["POST"])
@login_required
def api_notifications_save():
    data = request.get_json(silent=True) or {}
    try:
        notifications.save_config(data)
        audit_log.log_event("config_change", session.get("username", ""), request.remote_addr, "Updated push notification settings")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/notifications/events")
@login_required
def api_notifications_events():
    return jsonify({"events": notifications.recent_events(50)})


@app.route("/api/notifications/test", methods=["POST"])
@login_required
def api_notifications_test():
    data = request.get_json(silent=True) or {}
    return jsonify(notifications.test_channel(data.get("channel", ""), data.get("values") or {}))


# --- IP report ---

@app.route("/ip/<path:ip>")
@login_required
def ip_report_page(ip):
    return render_template("ip_report.html", r=ip_report.build(ip), status=get_firewall_status())


# --- Token API (v1): Authorization: Bearer csf_... ---

@app.route("/api/v1/status")
@login_required
def api_v1_status():
    err = _require_scope("read")
    if err:
        return err
    return jsonify(_status_summary())


def _status_summary():
    st = get_firewall_status()
    st["temp_blocks"] = len(csf.get_temp_list())
    st["app_version"] = app_updater.get_current_version()
    st["hostname"] = socket.gethostname()
    try:
        st["update_available"] = bool(app_updater.get_version_info().get("update_available"))
    except Exception:
        st["update_available"] = False
    return st


# --- Multi-server view ---

@app.route("/servers")
@login_required
def servers_page():
    return render_template("servers.html", status=get_firewall_status())


@app.route("/api/servers", methods=["GET"])
@login_required
def api_servers_list():
    local = _status_summary()
    local.update({"id": "local", "name": socket.gethostname(), "url": request.host_url.rstrip("/"), "ok": True, "local": True, "ms": None})
    return jsonify({"servers": fleet.list_servers(), "status": [local] + fleet.all_status()})


@app.route("/api/servers", methods=["POST"])
@login_required
def api_servers_add():
    if not _is_admin():
        return jsonify({"success": False, "error": "Admins only"}), 403
    d = request.get_json(silent=True) or {}
    ok, res = fleet.add_server(d.get("name"), d.get("url"), d.get("token"), d.get("verify_tls", True))
    if ok:
        audit_log.log_event("config_change", _actor(), request.remote_addr, f"Added remote server {d.get('name')} ({d.get('url')})")
    return jsonify({"success": ok, "id" if ok else "error": res})


@app.route("/api/servers/<sid>", methods=["DELETE"])
@login_required
def api_servers_delete(sid):
    if not _is_admin():
        return jsonify({"success": False, "error": "Admins only"}), 403
    ok = fleet.remove_server(sid)
    if ok:
        audit_log.log_event("config_change", _actor(), request.remote_addr, f"Removed remote server {sid}")
    return jsonify({"success": ok})


@app.route("/api/servers/<sid>/test", methods=["POST"])
@login_required
def api_servers_test(sid):
    return jsonify(fleet.test_server(sid))


@app.route("/api/servers/action", methods=["POST"])
@login_required
def api_servers_action():
    d = request.get_json(silent=True) or {}
    action, ip = d.get("action", ""), (d.get("ip") or "").strip()
    if action not in fleet.ACTIONS or not ip_report.valid_ip(ip):
        return jsonify({"success": False, "error": "Invalid action or IP"}), 400
    results = []
    if d.get("local"):
        comment = d.get("comment") or "multi-server push"
        if action == "allow":
            r = csf.allow_ip(ip, comment)
        elif action == "deny":
            r = csf.deny_ip(ip, comment)
        elif action == "temp-deny":
            r = csf.temp_deny(ip, int(d.get("seconds") or 3600), "*", comment)
        else:
            r = csf.unblock_ip(ip)
        results.append({"id": "local", "name": socket.gethostname() + " (this server)", "ok": bool(r.get("success")),
                        "error": "" if r.get("success") else (r.get("stderr") or r.get("stdout") or "failed")[:160]})
    results += fleet.fan_out(action, ip, d.get("servers") or [], d.get("comment", ""), d.get("seconds") or 3600)
    audit_log.log_event("action", _actor(), request.remote_addr,
                        f"Multi-server {action} {ip}: " + ", ".join(f"{x['name']}={'ok' if x['ok'] else 'fail'}" for x in results))
    return jsonify({"success": True, "results": results})


@app.route("/api/v1/ip/<path:ip>")
@login_required
def api_v1_ip(ip):
    err = _require_scope("read")
    if err:
        return err
    r = ip_report.build(ip)
    r.pop("geo", None)
    return jsonify(r)


def _v1_ip_action(scope, fn, label):
    err = _require_scope(scope)
    if err:
        return err
    data = request.get_json(silent=True) or request.form
    ip = (data.get("ip") or "").strip()
    if not ip_report.valid_ip(ip):
        return jsonify({"success": False, "error": "Invalid IP"}), 400
    result = fn(ip, data)
    audit_log.log_event("action", _actor(), request.remote_addr, f"API {label} {ip}")
    return jsonify({"success": bool(result.get("success")), "ip": ip, "output": (result.get("stdout") or result.get("stderr") or "")[:500]})


@app.route("/api/v1/allow", methods=["POST"])
@login_required
def api_v1_allow():
    return _v1_ip_action("allow", lambda ip, d: csf.allow_ip(ip, d.get("comment", "API")), "allow")


@app.route("/api/v1/deny", methods=["POST"])
@login_required
def api_v1_deny():
    return _v1_ip_action("deny", lambda ip, d: csf.deny_ip(ip, d.get("comment", "API")), "deny")


@app.route("/api/v1/temp-deny", methods=["POST"])
@login_required
def api_v1_temp_deny():
    return _v1_ip_action("deny", lambda ip, d: csf.temp_deny(ip, int(d.get("seconds", 3600)), d.get("ports", "*"), d.get("comment", "API")), "temp-deny")


@app.route("/api/v1/unblock", methods=["POST"])
@login_required
def api_v1_unblock():
    return _v1_ip_action("unblock", lambda ip, d: csf.unblock_ip(ip), "unblock")


# --- Config diff / history ---

@app.route("/api/config/diff", methods=["POST"])
@login_required
def api_config_diff():
    changes = {k[4:]: v for k, v in request.form.items() if k.startswith("cfg_")}
    return jsonify({"changes": config_history.diff(changes)})


@app.route("/api/config/history")
@login_required
def api_config_history():
    return jsonify({"history": config_history.recent(40)})


# --- Docker exposure ---

@app.route("/api/docker/exposure")
@login_required
def api_docker_exposure():
    return jsonify(docker.get_exposure_map())


@app.route("/api/docker/exposure/restrict", methods=["POST"])
@login_required
def api_docker_exposure_restrict():
    data = request.get_json(silent=True) or {}
    try:
        port = int(data.get("port", 0))
    except (TypeError, ValueError):
        port = 0
    proto = "udp" if data.get("proto") == "udp" else "tcp"
    if not 0 < port < 65536:
        return jsonify({"success": False, "error": "Invalid port"}), 400
    enable = bool(data.get("enable", True))
    res = docker.set_port_restriction(port, proto, enable)
    audit_log.log_event("action", _actor(), request.remote_addr,
                        f"{'Restricted' if enable else 'Unrestricted'} Docker port {port}/{proto}")
    if res.get("success"):
        actions_journal.record("docker_port", f"{'Restricted' if enable else 'Unrestricted'} Docker port {port}/{proto}",
                               {"action": "unrestrict_port" if enable else "restrict_port", "port": port, "proto": proto}, _actor())
    return jsonify(res)


# --- Explanations, in-context help, undo ---

@app.route("/api/explain")
@login_required
def api_explain():
    return jsonify(explain_mod.CODES)


@app.route("/api/page-help")
@login_required
def api_page_help():
    return jsonify(page_help.get(request.args.get("path", "/")))


@app.route("/api/actions/recent")
@login_required
def api_actions_recent():
    return jsonify({"actions": actions_journal.recent(10)})


@app.route("/api/actions/undo", methods=["POST"])
@login_required
def api_actions_undo():
    d = request.get_json(silent=True) or {}
    r = actions_journal.undo(d.get("id", ""))
    if r.get("success"):
        audit_log.log_event("action", _actor(), request.remote_addr, f"Undo: {r.get('label')}")
    return jsonify(r)


# --- Block suggestions (/24 and ASN) and impact preview ---

@app.route("/api/suggestions")
@login_required
def api_suggestions():
    return jsonify(suggestions.suggest(lookup_asn=request.args.get("asn", "1") == "1"))


@app.route("/api/suggestions/block", methods=["POST"])
@login_required
def api_suggestions_block():
    d = request.get_json(silent=True) or {}
    target = (d.get("target") or "").strip()
    r = suggestions.block_cidr(target, d.get("comment", ""))
    if r.get("success"):
        actions_journal.record("block_cidr", f"Blocked network {target}", {"action": "remove_deny", "ip": target}, _actor())
        audit_log.log_event("action", _actor(), request.remote_addr, f"Blocked network {target} (suggestion)")
    return jsonify({"success": bool(r.get("success")), "error": (r.get("stderr") or r.get("error") or "")[:200]})


@app.route("/api/impact")
@login_required
def api_impact():
    kind = request.args.get("type", "block")
    target = request.args.get("target", "")
    return jsonify(impact.block(target) if kind == "block" else impact.port(target))


# --- Blocklist feeds ---

@app.route("/blocklist-feeds")
@login_required
def blocklist_feeds_page():
    return render_template("blocklist_feeds.html", status=get_firewall_status())


@app.route("/api/blocklist-feeds")
@login_required
def api_blocklist_feeds():
    return jsonify({"feeds": blocklist_feeds.status(), "presets": {k: v[3] for k, v in blocklist_feeds.PRESETS.items()}})


@app.route("/api/blocklist-feeds/toggle", methods=["POST"])
@login_required
def api_blocklist_feeds_toggle():
    d = request.get_json(silent=True) or {}
    r = blocklist_feeds.set_enabled(d.get("name", ""), bool(d.get("enabled")), (d.get("url") or "").strip() or None)
    if r.get("success"):
        audit_log.log_event("config_change", _actor(), request.remote_addr, f"Blocklist feed {d.get('name')} {'enabled' if d.get('enabled') else 'disabled'}")
    return jsonify(r)


# --- Temporary SSH window ---

@app.route("/api/quick/ssh-window", methods=["POST"])
@login_required
def api_ssh_window():
    d = request.get_json(silent=True) or {}
    hours = max(1, min(24, int(d.get("hours") or 1)))
    ip = request.remote_addr
    try:
        ssh_port = port_defaults._detect_ssh()
    except Exception:
        ssh_port = "22"
    r = csf.temp_allow(ip, hours * 3600, ssh_port, f"SSH window for {session.get('username', '')}")
    ok = bool(r.get("success"))
    if ok:
        actions_journal.record("ssh_window", f"Opened SSH ({ssh_port}) to {ip} for {hours}h", {"action": "remove_temp", "type": "allow", "ip": ip}, _actor())
        audit_log.log_event("action", _actor(), request.remote_addr, f"Temporary SSH window: {ip} port {ssh_port} for {hours}h")
    return jsonify({"success": ok, "ip": ip, "port": ssh_port, "hours": hours, "error": "" if ok else (r.get("stderr") or "")[:200]})


# --- Rate-limit presets ---

@app.route("/api/presets")
@login_required
def api_presets():
    return jsonify({"presets": presets.list_presets()})


@app.route("/api/presets/apply", methods=["POST"])
@login_required
def api_presets_apply():
    d = request.get_json(silent=True) or {}
    r = presets.apply(d.get("key", ""))
    if r.get("success"):
        config_history.record(r.get("changes", []), session.get("username", ""))
        audit_log.log_event("config_change", _actor(), request.remote_addr, f"Applied rate-limit preset {d.get('key')}")
    return jsonify(r)


# --- Scheduled rules ---

@app.route("/scheduled-rules")
@login_required
def scheduled_rules_page():
    return render_template("scheduled_rules.html", status=get_firewall_status())


@app.route("/api/scheduled-rules", methods=["GET"])
@login_required
def api_scheduled_rules():
    return jsonify({"rules": scheduled_rules.list_rules(), "now": int(time.time())})


@app.route("/api/scheduled-rules", methods=["POST"])
@login_required
def api_scheduled_rules_add():
    d = request.get_json(silent=True) or {}
    if not ip_report.valid_ip((d.get("ip") or "").strip()):
        return jsonify({"success": False, "error": "Invalid IP or network"}), 400
    ok, res = scheduled_rules.add(d.get("kind"), d.get("ip", ""), d.get("start"), d.get("end"), d.get("ports", ""), d.get("comment", ""), session.get("username", ""))
    if ok:
        scheduled_rules.tick()
        audit_log.log_event("action", _actor(), request.remote_addr, f"Scheduled {d.get('kind')} {d.get('ip')} until {d.get('end')}")
    return jsonify({"success": ok, "id" if ok else "error": res})


@app.route("/api/scheduled-rules/<rid>", methods=["POST", "DELETE"])
@login_required
def api_scheduled_rules_edit(rid):
    if request.method == "DELETE":
        return jsonify({"success": scheduled_rules.delete(rid)})
    d = request.get_json(silent=True) or {}
    if d.get("op") == "extend":
        return jsonify({"success": scheduled_rules.extend(rid, d.get("end"))})
    if d.get("op") == "expire":
        return jsonify({"success": scheduled_rules.expire_now(rid)})
    return jsonify({"success": False, "error": "Unknown op"}), 400


# --- Weekly digest ---

@app.route("/api/digest/send", methods=["POST"])
@login_required
def api_digest_send():
    return jsonify(digest.send())


@app.route("/api/digest/preview")
@login_required
def api_digest_preview():
    return jsonify({"body": digest.compose()})


# --- Activity timeline (everything that changed, in one list) ---

@app.route("/activity")
@login_required
def activity_page():
    return render_template("activity.html", status=get_firewall_status())


@app.route("/api/activity")
@login_required
def api_activity():
    items = []
    for e in audit_log.get_events(300):
        try:
            ts = int(time.mktime(time.strptime(e.get("ts", ""), "%Y-%m-%d %H:%M:%S")))
        except (ValueError, TypeError):
            ts = 0
        items.append({"ts": ts, "source": "audit", "kind": e.get("type", ""), "who": e.get("user", ""), "ip": e.get("ip", ""), "what": e.get("detail", "")})
    for h in config_history.recent(100):
        items.append({"ts": h.get("ts", 0), "source": "config", "kind": "config_change", "who": h.get("user", ""), "ip": "",
                      "what": "csf.conf: " + ", ".join(f"{c['key']}: {c['old']} → {c['new']}" for c in h.get("changes", [])[:6])})
    for n in notifications.recent_events(100):
        items.append({"ts": n.get("ts", 0), "source": "event", "kind": n.get("kind", ""), "who": "system", "ip": "", "what": n.get("title", "") + (" — " + n["body"].split("\n")[0] if n.get("body") else "")})
    for a in actions_journal.recent(50):
        items.append({"ts": a.get("ts", 0), "source": "action", "kind": a.get("kind", ""), "who": a.get("user", ""), "ip": "",
                      "what": a.get("label", "") + (" (undone)" if a.get("undone") else "")})
    try:
        with open("/var/log/csfv2.log") as f:
            for line in f.readlines()[-400:]:
                if "safe-apply:" in line:
                    try:
                        ts = int(time.mktime(time.strptime(line[1:20], "%Y-%m-%d %H:%M:%S")))
                    except ValueError:
                        ts = 0
                    items.append({"ts": ts, "source": "safe-apply", "kind": "safe_apply", "who": "system", "ip": "", "what": line.split("safe-apply:", 1)[1].strip()})
    except OSError:
        pass
    items.sort(key=lambda i: -i["ts"])
    return jsonify({"items": items[:500]})


# --- Onboarding checklist ---

@app.route("/api/checklist")
@login_required
def api_checklist():
    try:
        return jsonify(checklist.build(session.get("username", "")))
    except Exception as e:
        return jsonify({"items": [], "done": 0, "total": 0, "error": str(e)})


# --- Off-server backups ---

@app.route("/api/remote-backup", methods=["GET"])
@login_required
def api_remote_backup_get():
    return jsonify(remote_backup.public())


@app.route("/api/remote-backup", methods=["POST"])
@login_required
def api_remote_backup_save():
    if not _is_admin():
        return jsonify({"success": False, "error": "Admins only"}), 403
    remote_backup.save(request.get_json(silent=True) or {})
    audit_log.log_event("config_change", _actor(), request.remote_addr, "Updated off-server backup settings")
    return jsonify({"success": True})


@app.route("/api/remote-backup/test", methods=["POST"])
@login_required
def api_remote_backup_test():
    return jsonify(remote_backup.test())


# --- Mobile emergency view ---

@app.route("/m")
@login_required
def mobile_page():
    return render_template("mobile.html", status=get_firewall_status(), my_ip=request.remote_addr)


# --- Guided tasks ---

@app.route("/tasks")
@login_required
def tasks_page():
    try:
        ssh_port = port_defaults._detect_ssh()
    except Exception:
        ssh_port = "22"
    return render_template("tasks.html", status=get_firewall_status(), my_ip=request.remote_addr, ssh_port=ssh_port,
                           tcp_in=csf.load_csf_conf().get("TCP_IN", ""))


# --- Token API additions: config profiles and inbound hooks ---

PROFILE_KEYS = ("TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT", "TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT", "CC_DENY", "CC_ALLOW", "CC_ALLOW_FILTER",
                "CT_LIMIT", "CT_INTERVAL", "CT_BLOCK_TIME", "CONNLIMIT", "PORTFLOOD", "SYNFLOOD", "SYNFLOOD_RATE", "SYNFLOOD_BURST",
                "LF_SSHD", "LF_SSHD_PERM", "LF_FTPD", "LF_SMTPAUTH", "LF_POP3D", "LF_IMAPD", "LF_HTACCESS", "LF_MODSEC", "LF_DISTATTACK",
                "PS_LIMIT", "PS_INTERVAL", "LF_PERMBLOCK", "LF_PERMBLOCK_COUNT", "LF_PERMBLOCK_INTERVAL", "DENY_IP_LIMIT", "DENY_TEMP_IP_LIMIT",
                "LF_APACHE_404", "LF_APACHE_403", "RESTRICT_SYSLOG", "DOCKER")


@app.route("/api/v1/config", methods=["GET"])
@login_required
def api_v1_config_get():
    err = _require_scope("read")
    if err:
        return err
    conf = csf.load_csf_conf()
    return jsonify({k: conf.get(k, "") for k in PROFILE_KEYS if k in conf})


@app.route("/api/v1/config", methods=["POST"])
@login_required
def api_v1_config_set():
    err = _require_scope("config")
    if err:
        return err
    d = request.get_json(silent=True) or {}
    values = {k: str(v) for k, v in (d.get("values") or {}).items() if k in PROFILE_KEYS}
    diff = config_history.diff(values)
    if d.get("dry_run"):
        return jsonify({"success": True, "changes": diff})
    if not diff:
        return jsonify({"success": True, "changes": []})
    r = csf.save_csf_conf(values)
    if r.get("success"):
        config_history.record(diff, _actor())
        audit_log.log_event("config_change", _actor(), request.remote_addr, f"Profile pushed: {len(diff)} setting(s)")
        if d.get("restart"):
            csf.restart_both()
    return jsonify({"success": bool(r.get("success")), "changes": diff, "error": r.get("error", "")})


@app.route("/api/v1/csfpost", methods=["GET"])
@login_required
def api_v1_csfpost_get():
    """Export csfpost.sh / csfpre.sh as a portable bundle."""
    err = _require_scope("script")
    if err:
        return err
    return jsonify(csfpost_editor.export_bundle(_csfpost_script()))


@app.route("/api/v1/csfpost", methods=["POST"])
@login_required
def api_v1_csfpost_set():
    """Import a bundle sent by another CSF-eUI server."""
    err = _require_scope("script")
    if err:
        return err
    d = request.get_json(silent=True) or {}
    script = _csfpost_script(d.get("script"))
    mode = d.get("mode", "append")
    if mode not in ("append", "merge", "replace"):
        return jsonify({"success": False, "error": "Unknown import mode"}), 400
    if d.get("raw") is not None:
        result = csfpost_editor.import_raw(script, d.get("raw", ""), mode)
    else:
        result = csfpost_editor.import_bundle(script, d.get("bundle") or {},
                                              mode, d.get("items"))
    # The node tree is large and the caller does not need it over the wire.
    result.pop("nodes", None)
    result.pop("content", None)
    if result.get("success"):
        audit_log.log_event("config_change", _actor(), request.remote_addr,
                            f"{script}.sh imported over API ({mode})")
        if d.get("restart"):
            restart = csf.restart_both()
            result["restarted"] = bool(restart.get("success"))
    return jsonify(result)


@app.route("/api/v1/hook/<source>", methods=["POST"])
@login_required
def api_v1_hook(source):
    """Inbound webhook from Fail2ban, CrowdSec, a WAF or anything else: {ip, action?, duration?, fleet?}."""
    d = request.get_json(silent=True) or request.form
    ip = (d.get("ip") or d.get("source_ip") or d.get("value") or "").strip()
    action = (d.get("action") or d.get("type") or "deny").lower()
    action = {"ban": "deny", "block": "deny", "unban": "unblock", "release": "unblock", "temp": "temp-deny", "tempban": "temp-deny"}.get(action, action)
    if action not in ("deny", "temp-deny", "unblock", "allow") or not ip_report.valid_ip(ip):
        return jsonify({"success": False, "error": "Need a valid ip and an action of deny/temp-deny/unblock/allow"}), 400
    scope = {"deny": "deny", "temp-deny": "deny", "unblock": "unblock", "allow": "allow"}[action]
    err = _require_scope(scope)
    if err:
        return err
    comment = f"{source} hook" + (f": {d.get('reason')}" if d.get("reason") else "")
    if action == "deny":
        r = csf.deny_ip(ip, comment)
    elif action == "temp-deny":
        r = csf.temp_deny(ip, int(d.get("duration") or d.get("seconds") or 3600), "*", comment)
    elif action == "allow":
        r = csf.allow_ip(ip, comment)
    else:
        r = csf.unblock_ip(ip)
    results = [{"name": socket.gethostname(), "ok": bool(r.get("success"))}]
    if d.get("fleet") in (True, "1", "true", "yes"):
        fa = {"deny": "deny", "temp-deny": "temp-deny", "unblock": "unblock", "allow": "allow"}[action]
        results += [{"name": x["name"], "ok": x["ok"]} for x in fleet.fan_out(fa, ip, [s["id"] for s in fleet.list_servers()], comment, int(d.get("duration") or 3600))]
    audit_log.log_event("action", _actor(), request.remote_addr, f"Hook {source}: {action} {ip} → " + ", ".join(f"{x['name']}={'ok' if x['ok'] else 'fail'}" for x in results))
    return jsonify({"success": bool(r.get("success")), "ip": ip, "action": action, "results": results})


# --- Push a config profile from this server to fleet servers ---

@app.route("/api/servers/profile", methods=["POST"])
@login_required
def api_servers_profile():
    d = request.get_json(silent=True) or {}
    keys = [k for k in (d.get("keys") or []) if k in PROFILE_KEYS] or list(PROFILE_KEYS)
    conf = csf.load_csf_conf()
    values = {k: conf.get(k, "") for k in keys if k in conf}
    body = {"values": values, "dry_run": bool(d.get("dry_run", True)), "restart": bool(d.get("restart"))}
    targets = [s for s in fleet._load()["servers"] if s["id"] in (d.get("servers") or [])]
    out = []
    for s in targets:
        r = fleet._request(s, "/api/v1/config", body)
        data = r.get("data") or {}
        out.append({"id": s["id"], "name": s["name"], "ok": r["ok"] and bool(data.get("success", True)), "error": r.get("error") or data.get("error", ""), "changes": data.get("changes", [])})
    if not body["dry_run"]:
        audit_log.log_event("config_change", _actor(), request.remote_addr, f"Pushed profile ({len(values)} keys) to " + ", ".join(x["name"] for x in out))
    return jsonify({"success": True, "results": out, "keys": keys})


# --- Safe apply (restart with automatic rollback) ---

@app.route("/api/safe-apply/status")
@login_required
def api_safe_apply_status():
    return jsonify(safe_apply.status())


@app.route("/api/safe-apply/start", methods=["POST"])
@login_required
def api_safe_apply_start():
    data = request.get_json(silent=True) or {}
    return jsonify(safe_apply.arm(data.get("seconds", safe_apply.DEFAULT_SECONDS)))


@app.route("/api/safe-apply/confirm", methods=["POST"])
@login_required
def api_safe_apply_confirm():
    return jsonify(safe_apply.confirm())


@app.route("/api/safe-apply/dismiss", methods=["POST"])
@login_required
def api_safe_apply_dismiss():
    return jsonify(safe_apply.dismiss_rollback())


def init_app():
    auth.init_auth()
    auth.setup_initial_user()
    notifications.start_watcher()


init_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("CSFV2_HOST", "0.0.0.0"),
        port=int(os.environ.get("CSFV2_PORT", "8750")),
        debug=os.environ.get("CSFV2_DEBUG", "0") == "1",
        ssl_context="adhoc" if os.environ.get("CSFV2_SSL", "0") == "1" else None,
    )
