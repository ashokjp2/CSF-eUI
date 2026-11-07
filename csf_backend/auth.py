import hashlib
import hmac
import os
import json
import time
from pathlib import Path

AUTH_CONF = "/etc/csfv2/auth.json"
SESSION_DIR = "/var/lib/csfv2/sessions"
UI_ALLOW = "/etc/csfv2/ui.allow"
UI_BAN = "/etc/csfv2/ui.ban"
LOGIN_LOG = "/var/log/csfv2.log"
MAX_FAILED = 5
LOCKOUT_SECS = 900


def init_auth():
    os.makedirs(os.path.dirname(AUTH_CONF), exist_ok=True)
    os.makedirs(SESSION_DIR, exist_ok=True)


def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32).hex()
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000)
    return f"{salt}${h.hex()}"


def verify_password(password, stored):
    if "$" not in stored:
        return False
    salt, expected = stored.split("$", 1)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000)
    return hmac.compare_digest(h.hex(), expected)


def load_auth_config():
    if not os.path.exists(AUTH_CONF):
        return {"users": {}, "failed_attempts": {}}
    with open(AUTH_CONF) as f:
        return json.load(f)


def save_auth_config(config):
    os.makedirs(os.path.dirname(AUTH_CONF), exist_ok=True)
    with open(AUTH_CONF, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(AUTH_CONF, 0o600)


def create_user(username, password):
    config = load_auth_config()
    config.setdefault("users", {})[username] = {
        "password": hash_password(password),
        "created": int(time.time()),
    }
    save_auth_config(config)


def authenticate(username, password, remote_ip=None):
    config = load_auth_config()

    if remote_ip and not is_ip_allowed(remote_ip):
        log_event(f"Access denied for IP {remote_ip} - not in allow list")
        return False, "IP not allowed"

    if remote_ip and is_ip_banned(remote_ip):
        log_event(f"Access denied for banned IP {remote_ip}")
        return False, "IP banned"

    failed = config.get("failed_attempts", {})
    if remote_ip and remote_ip in failed:
        attempts = failed[remote_ip]
        if attempts.get("count", 0) >= MAX_FAILED:
            lockout_until = attempts.get("last_attempt", 0) + LOCKOUT_SECS
            if time.time() < lockout_until:
                remaining = int(lockout_until - time.time())
                return False, f"Too many failed attempts. Try again in {remaining}s"
            else:
                del failed[remote_ip]

    users = config.get("users", {})
    if username not in users:
        record_failed(config, remote_ip)
        return False, "Invalid credentials"

    if not verify_password(password, users[username]["password"]):
        record_failed(config, remote_ip)
        return False, "Invalid credentials"

    if remote_ip and remote_ip in failed:
        del failed[remote_ip]
    save_auth_config(config)

    log_event(f"Successful login: {username} from {remote_ip}")
    return True, "OK"


def record_failed(config, remote_ip):
    if not remote_ip:
        return
    failed = config.setdefault("failed_attempts", {})
    if remote_ip not in failed:
        failed[remote_ip] = {"count": 0}
    failed[remote_ip]["count"] = failed[remote_ip].get("count", 0) + 1
    failed[remote_ip]["last_attempt"] = int(time.time())
    save_auth_config(config)
    log_event(
        f"Failed login attempt from {remote_ip} "
        f"(attempt {failed[remote_ip]['count']})"
    )


def is_ip_allowed(ip):
    if not os.path.exists(UI_ALLOW):
        return True
    allowed = set()
    with open(UI_ALLOW) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                allowed.add(line)
    if not allowed:
        return True
    return ip in allowed


def is_ip_banned(ip):
    if not os.path.exists(UI_BAN):
        return False
    with open(UI_BAN) as f:
        for line in f:
            if line.strip() == ip:
                return True
    return False


def change_password(username, new_password):
    config = load_auth_config()
    if username not in config.get("users", {}):
        return False
    config["users"][username]["password"] = hash_password(new_password)
    save_auth_config(config)
    return True


def log_event(message):
    try:
        os.makedirs(os.path.dirname(LOGIN_LOG), exist_ok=True)
        with open(LOGIN_LOG, "a") as f:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{ts}] {message}\n")
    except OSError:
        pass


def setup_initial_user():
    config = load_auth_config()
    if config.get("users"):
        return False
    create_user("admin", "admin")
    log_event("Initial admin user created - CHANGE PASSWORD IMMEDIATELY")
    return True
