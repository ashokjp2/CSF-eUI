"""Scoped API tokens for scripts and CI (Authorization: Bearer <token>)."""
import hashlib
import hmac
import json
import os
import secrets
import time
from csf_backend.auth import _auth_transaction

TOKENS_PATH = "/etc/csfv2/tokens.json"
SCOPES = {
    "read":    "Read status, temp blocks and IP reports",
    "allow":   "Add IPs to csf.allow",
    "deny":    "Add IPs to csf.deny / temp blocks",
    "unblock": "Remove IPs from deny lists and temp blocks",
    "config":  "Receive configuration profiles pushed from another server",
    "script":  "Read and import csfpost.sh / csfpre.sh rules",
}


def _load():
    try:
        with open(TOKENS_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"tokens": []}


def _save(data):
    os.makedirs(os.path.dirname(TOKENS_PATH), exist_ok=True)
    with open(TOKENS_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(TOKENS_PATH, 0o600)


def _digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def list_tokens():
    return [{k: v for k, v in t.items() if k != "hash"} for t in _load()["tokens"]]


@_auth_transaction
def create(name, scopes, created_by=""):
    name = (name or "").strip()[:60] or "token"
    scopes = [s for s in scopes if s in SCOPES] or ["read"]
    raw = "csf_" + secrets.token_urlsafe(32)
    data = _load()
    data["tokens"].append({
        "id": secrets.token_hex(4), "name": name, "scopes": scopes, "hash": _digest(raw),
        "created": int(time.time()), "created_by": created_by, "last_used": None, "prefix": raw[:10],
    })
    _save(data)
    return raw


@_auth_transaction
def revoke(token_id):
    data = _load()
    before = len(data["tokens"])
    data["tokens"] = [t for t in data["tokens"] if t["id"] != token_id]
    _save(data)
    return len(data["tokens"]) < before


@_auth_transaction
def authenticate(raw):
    """Return the token record for a bearer string, or None. Updates last_used."""
    if not raw or not raw.startswith("csf_"):
        return None
    d = _digest(raw)
    data = _load()
    for t in data["tokens"]:
        if hmac.compare_digest(t["hash"], d):
            t["last_used"] = int(time.time())
            try:
                _save(data)
            except OSError:
                pass
            return t
    return None
