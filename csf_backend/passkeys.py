"""Passkeys (WebAuthn / FIDO2) as a second sign-in step, alongside TOTP.

Each user may register any number of passkeys (Windows Hello, Touch ID, a phone,
a YubiKey...). They are stored in auth.json under the user as:

    "passkeys": [{"id": <base64url credential id>, "public_key": <base64url COSE key>,
                  "sign_count": int, "transports": [...], "name": str,
                  "created": epoch, "last_used": epoch|None, "aaguid": str,
                  "backed_up": bool}]

A passkey is bound to the hostname it was registered on (the relying-party ID), so it
only works when the UI is opened by that name, never by IP address. The browser also
refuses WebAuthn on a self-signed or otherwise untrusted certificate.

Verification is done by py_webauthn (`webauthn` on PyPI). It is imported lazily so the
app still starts if the package is not installed yet; the UI then explains why.
"""

import ipaddress
import json
import time

from csf_backend import auth

RP_NAME = "CSF-eUI"
CHALLENGE_TTL = 300

AVAILABLE = False
_IMPORT_ERROR = ""
_wa = None
_INSTALL_DIR = "/opt/csfv2"
_install_started = False


def _try_import():
    """Import py_webauthn into module globals. Safe to call again after a late pip install."""
    global AVAILABLE, _IMPORT_ERROR, _wa
    global base64url_to_bytes, bytes_to_base64url, options_to_json, generate_user_handle
    global parse_registration_credential_json
    global AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor
    global ResidentKeyRequirement, UserVerificationRequirement
    if AVAILABLE:
        return True
    try:
        import importlib
        importlib.invalidate_caches()
        import webauthn as _wa_mod
        from webauthn.helpers import (base64url_to_bytes, bytes_to_base64url, options_to_json,
                                      generate_user_handle, parse_registration_credential_json)
        from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                              ResidentKeyRequirement, UserVerificationRequirement)
        _wa = _wa_mod
        AVAILABLE = True
        _IMPORT_ERROR = ""
    except Exception as e:  # package missing until pip has run
        _IMPORT_ERROR = str(e)
        AVAILABLE = False
    return AVAILABLE


_try_import()


def availability():
    """Return (ok, reason) telling whether the server can verify passkeys at all."""
    if AVAILABLE or _try_import():
        return True, ""
    return False, ("The 'webauthn' Python package is not installed on the server yet "
                   f"({_IMPORT_ERROR}). CSF-eUI installs it in the background at startup and on every update; "
                   "reload this page in a minute.")


def ensure_installed():
    """Self-applying dependency: if py_webauthn is missing, pip-install requirements in the background.

    Called once at application startup. A plain file deploy or git pull does not run pip, so
    without this a server would have the passkey UI but no verifier until the next update.
    The lazy import above picks the package up without a restart.
    """
    global _install_started
    import os
    import subprocess
    import threading
    if AVAILABLE or _install_started:
        return
    pip_bin = os.path.join(_INSTALL_DIR, "venv/bin/pip")
    req = os.path.join(_INSTALL_DIR, "requirements.txt")
    if not (os.path.exists(pip_bin) and os.path.exists(req)):
        return
    _install_started = True

    def _run():
        try:
            subprocess.run([pip_bin, "install", "-q", "-r", req], cwd=_INSTALL_DIR,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        except Exception:
            pass
        _try_import()

    threading.Thread(target=_run, name="csfv2-passkeys-pip", daemon=True).start()


def rp_id_from_host(host):
    """The relying-party ID for a request Host header, or None when it is an IP address."""
    host = (host or "").strip().lower()
    if host.startswith("["):  # [v6]:port
        host = host[1:].split("]", 1)[0]
    else:
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if not host or host == "localhost":
        return host or None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def host_problem(host, is_secure):
    """Plain-English reason the current page cannot use passkeys, or '' when it can."""
    if not is_secure:
        return "Passkeys only work over HTTPS."
    if rp_id_from_host(host) is None:
        return (f"Passkeys are tied to a hostname and cannot be used when the UI is opened by IP address ({host}). "
                "Open the UI by its domain name instead.")
    return ""


# --- storage -------------------------------------------------------------

def _user(config, username):
    return config.get("users", {}).get(username)


def list_passkeys(username):
    user = auth.load_auth_config().get("users", {}).get(username, {})
    return [{"id": p["id"], "name": p.get("name") or "Passkey", "created": p.get("created"),
             "last_used": p.get("last_used"), "backed_up": bool(p.get("backed_up"))}
            for p in user.get("passkeys", [])]


def has_passkey(username):
    return bool(auth.load_auth_config().get("users", {}).get(username, {}).get("passkeys"))


def any_registered():
    """True when at least one account has a passkey (decides whether the login page offers one)."""
    return any(d.get("passkeys") for d in auth.load_auth_config().get("users", {}).values())


def find_user_by_credential(cred_id):
    """Username owning a credential id, or None. Credential ids are unique per authenticator."""
    for u, d in auth.load_auth_config().get("users", {}).items():
        if any(p.get("id") == cred_id for p in d.get("passkeys", [])):
            return u
    return None


def remove_passkey(username, cred_id, password):
    """Delete one passkey. Requires the account password. Returns (ok, message)."""
    config = auth.load_auth_config()
    user = _user(config, username)
    if user is None:
        return False, "User not found"
    if not auth.verify_password(password, user["password"]):
        return False, "Invalid password"
    keys = user.get("passkeys", [])
    kept = [p for p in keys if p["id"] != cred_id]
    if len(kept) == len(keys):
        return False, "Passkey not found"
    removed = next(p for p in keys if p["id"] == cred_id)
    if kept:
        user["passkeys"] = kept
    else:
        user.pop("passkeys", None)
        user.pop("passkey_recovery", None)
    auth.save_auth_config(config)
    auth.log_event(f"Passkey '{removed.get('name', '')}' removed for {username} ({len(kept)} left)")
    return True, f"Passkey '{removed.get('name', '')}' removed"


def rename_passkey(username, cred_id, name):
    config = auth.load_auth_config()
    user = _user(config, username)
    if user is None:
        return False, "User not found"
    for p in user.get("passkeys", []):
        if p["id"] == cred_id:
            p["name"] = _clean_name(name)
            auth.save_auth_config(config)
            return True, "Renamed"
    return False, "Passkey not found"


def _clean_name(name):
    name = " ".join((name or "").split())[:60]
    return name or "Passkey"


# --- registration --------------------------------------------------------

def registration_options(username, host):
    """Build the browser's create() options. Returns (options_json_str, challenge_b64url)."""
    ok, reason = availability()
    if not ok:
        raise RuntimeError(reason)
    rp_id = rp_id_from_host(host)
    if rp_id is None:
        raise RuntimeError(host_problem(host, True))
    config = auth.load_auth_config()
    user = _user(config, username)
    if user is None:
        raise RuntimeError("User not found")
    # A stable per-user handle so the authenticator can tell accounts apart; never the username.
    handle = user.get("passkey_handle")
    if not handle:
        handle = bytes_to_base64url(generate_user_handle())
        user["passkey_handle"] = handle
        auth.save_auth_config(config)
    exclude = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["id"]))
               for p in user.get("passkeys", [])]
    opts = _wa.generate_registration_options(
        rp_id=rp_id, rp_name=RP_NAME,
        user_id=base64url_to_bytes(handle), user_name=username, user_display_name=username,
        exclude_credentials=exclude or None,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED),
        timeout=120000,
    )
    return options_to_json(opts), bytes_to_base64url(opts.challenge)


def registration_verify(username, host, origin, challenge_b64url, credential_json, name):
    """Check the browser's create() result and store the new passkey.

    Returns (ok, result): result is {"name", "recovery_codes": [...]|None} or an error string.
    """
    ok, reason = availability()
    if not ok:
        return False, reason
    rp_id = rp_id_from_host(host)
    if rp_id is None:
        return False, host_problem(host, True)
    try:
        verified = _wa.verify_registration_response(
            credential=credential_json,
            expected_challenge=base64url_to_bytes(challenge_b64url),
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except Exception as e:
        return False, f"The browser's response could not be verified: {e}"
    try:
        transports = [t.value if hasattr(t, "value") else str(t)
                      for t in (parse_registration_credential_json(credential_json).response.transports or [])]
    except Exception:
        transports = []
    config = auth.load_auth_config()
    user = _user(config, username)
    if user is None:
        return False, "User not found"
    cred_id = bytes_to_base64url(verified.credential_id)
    keys = user.setdefault("passkeys", [])
    if any(p["id"] == cred_id for p in keys):
        return False, "This passkey is already registered"
    keys.append({
        "id": cred_id,
        "public_key": bytes_to_base64url(verified.credential_public_key),
        "sign_count": int(verified.sign_count or 0),
        "transports": transports,
        "name": _clean_name(name),
        "created": int(time.time()),
        "last_used": None,
        "aaguid": str(verified.aaguid or ""),
        "backed_up": bool(getattr(verified, "credential_backed_up", False)),
    })
    auth.save_auth_config(config)
    auth.log_event(f"Passkey '{keys[-1]['name']}' registered for {username} ({len(keys)} total)")
    recovery = auth.ensure_recovery_codes(username)
    return True, {"name": keys[-1]["name"], "recovery_codes": recovery}


# --- sign-in -------------------------------------------------------------

def authentication_options(username, host, passwordless=False):
    """Build the browser's get() options. Returns (options_json_str, challenge_b64url).

    As the second step after a password, the user is known and only their keys are offered.
    Passwordless (from the login page) the passkey is the whole sign-in, so the device must
    verify the person (PIN, fingerprint, face); with no username the browser shows its own
    account picker from the discoverable credentials it holds for this site.
    """
    ok, reason = availability()
    if not ok:
        raise RuntimeError(reason)
    rp_id = rp_id_from_host(host)
    if rp_id is None:
        raise RuntimeError(host_problem(host, True))
    allow = None
    if username:
        keys = auth.load_auth_config().get("users", {}).get(username, {}).get("passkeys", [])
        if not keys:
            raise RuntimeError("No passkey registered for this account")
        allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(p["id"])) for p in keys]
    elif not passwordless:
        raise RuntimeError("Username required")
    opts = _wa.generate_authentication_options(
        rp_id=rp_id, allow_credentials=allow,
        user_verification=(UserVerificationRequirement.REQUIRED if passwordless
                           else UserVerificationRequirement.PREFERRED),
        timeout=120000)
    return options_to_json(opts), bytes_to_base64url(opts.challenge)


def authentication_verify(username, host, origin, challenge_b64url, credential_json, require_uv=False):
    """Check the browser's get() result against the stored passkey. Returns (ok, message).

    require_uv: insist the authenticator verified the person (passwordless sign-in)."""
    ok, reason = availability()
    if not ok:
        return False, reason
    rp_id = rp_id_from_host(host)
    if rp_id is None:
        return False, host_problem(host, True)
    try:
        cred_id = (credential_json if isinstance(credential_json, dict)
                   else json.loads(credential_json)).get("id", "")
    except Exception:
        return False, "Malformed response"
    config = auth.load_auth_config()
    user = _user(config, username)
    if user is None:
        return False, "User not found"
    stored = next((p for p in user.get("passkeys", []) if p["id"] == cred_id), None)
    if stored is None:
        return False, "Unknown passkey"
    try:
        verified = _wa.verify_authentication_response(
            credential=credential_json,
            expected_challenge=base64url_to_bytes(challenge_b64url),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=base64url_to_bytes(stored["public_key"]),
            credential_current_sign_count=int(stored.get("sign_count") or 0),
            require_user_verification=require_uv,
        )
    except Exception as e:
        return False, f"Passkey check failed: {e}"
    stored["sign_count"] = int(verified.new_sign_count or 0)
    stored["last_used"] = int(time.time())
    auth.save_auth_config(config)
    return True, stored.get("name", "Passkey")
