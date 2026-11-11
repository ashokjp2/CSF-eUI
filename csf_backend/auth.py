import hashlib
import hmac
import os
import json
import secrets
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


TOKEN_TTL = 900  # 15 minutes


def create_username_change_token(old_username, new_username, password):
    """Validate password and store a pending token; return (ok, token_or_error)."""
    config = load_auth_config()
    users = config.get("users", {})
    if old_username not in users:
        return False, "User not found"
    if new_username in users and new_username != old_username:
        return False, "Username already taken"
    if not verify_password(password, users[old_username]["password"]):
        return False, "Invalid password"
    token = secrets.token_urlsafe(32)
    config["pending_username_change"] = {
        "token": token,
        "old": old_username,
        "new": new_username,
        "expires": int(time.time()) + TOKEN_TTL,
    }
    save_auth_config(config)
    log_event(f"Username change token issued: '{old_username}' → '{new_username}'")
    return True, token


def confirm_username_change(token):
    """Apply the pending username change if the token matches and hasn't expired."""
    config = load_auth_config()
    pending = config.get("pending_username_change")
    if not pending:
        return False, "No pending username change"
    if time.time() > pending.get("expires", 0):
        config.pop("pending_username_change", None)
        save_auth_config(config)
        return False, "Verification link has expired — please request a new one"
    if not hmac.compare_digest(token, pending["token"]):
        return False, "Invalid verification token"
    old, new = pending["old"], pending["new"]
    users = config.get("users", {})
    if old not in users:
        return False, "Original user no longer exists"
    if new in users and new != old:
        return False, "Username already taken"
    users[new] = users.pop(old)
    config.pop("pending_username_change", None)
    save_auth_config(config)
    log_event(f"Username changed from '{old}' to '{new}' (email confirmed)")
    return True, new


# --- Two-factor authentication (TOTP, RFC 6238; no third-party dependency) ---

import base64
import struct

TOTP_ISSUER = "CSF-eUI"


def totp_generate_secret():
    """Return a new 160-bit base32 secret for an authenticator app."""
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def totp_code(secret, timestamp=None, step=30, digits=6):
    """Compute the TOTP code for a base32 secret at the given time."""
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((timestamp or time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret, code, window=1):
    """Accept the current code and one step either side to allow for clock drift."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit():
        return False
    now = time.time()
    for i in range(-window, window + 1):
        if hmac.compare_digest(totp_code(secret, now + i * 30), code):
            return True
    return False


def totp_uri(secret, username):
    return f"otpauth://totp/{TOTP_ISSUER}:{username}?secret={secret}&issuer={TOTP_ISSUER}&digits=6&period=30"


def totp_status(username):
    """Return {'enabled': bool, 'backup_codes_left': int} for a user."""
    user = load_auth_config().get("users", {}).get(username, {})
    t = user.get("totp") or {}
    return {"enabled": bool(t.get("enabled")), "backup_codes_left": len(t.get("backup_codes", []))}


def totp_enable(username, secret, code):
    """Verify the first code from the app, then enable 2FA. Returns (ok, backup_codes_or_error)."""
    if not totp_verify(secret, code):
        return False, "The code did not match. Check the time on your phone and try again."
    config = load_auth_config()
    user = config.get("users", {}).get(username)
    if user is None:
        return False, "User not found"
    plain_codes = [secrets.token_hex(4) for _ in range(8)]
    user["totp"] = {
        "enabled": True,
        "secret": secret,
        "enabled_at": int(time.time()),
        "backup_codes": [hashlib.sha256(c.encode()).hexdigest() for c in plain_codes],
    }
    save_auth_config(config)
    log_event(f"Two-factor authentication enabled for {username}")
    return True, plain_codes


def totp_disable(username, password, code):
    """Disable 2FA; requires the password and a current code (or backup code)."""
    config = load_auth_config()
    user = config.get("users", {}).get(username)
    if user is None:
        return False, "User not found"
    if not verify_password(password, user["password"]):
        return False, "Invalid password"
    if not totp_check_login(username, code):
        return False, "Invalid authentication code"
    user.pop("totp", None)
    save_auth_config(config)
    log_event(f"Two-factor authentication disabled for {username}")
    return True, "Two-factor authentication disabled"


def totp_check_login(username, code):
    """Verify a login code: TOTP first, then single-use backup codes."""
    config = load_auth_config()
    user = config.get("users", {}).get(username, {})
    t = user.get("totp") or {}
    if not t.get("enabled"):
        return True
    if totp_verify(t.get("secret", ""), code):
        return True
    digest = hashlib.sha256((code or "").strip().lower().encode()).hexdigest()
    codes = t.get("backup_codes", [])
    for stored in codes:
        if hmac.compare_digest(stored, digest):
            codes.remove(stored)
            save_auth_config(config)
            log_event(f"Backup code used for {username} ({len(codes)} left)")
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
