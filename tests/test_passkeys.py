"""Passkey (WebAuthn) registration and sign-in against a software authenticator.

Run from the project root:  python tests/test_passkeys.py
Needs the 'webauthn' package (pip install -r requirements.txt).
"""
import hashlib
import json
import os
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from csf_backend import auth, passkeys
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

tmp = tempfile.mkdtemp()
auth.AUTH_CONF = os.path.join(tmp, "auth.json")
auth.LOGIN_LOG = os.path.join(tmp, "csfv2.log")

HOST = "fw.example.com:8750"
RP_ID = "fw.example.com"
ORIGIN = "https://fw.example.com:8750"

fails = []
def check(name, cond, extra=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + (("  " + extra) if extra and not cond else ""))
    if not cond:
        fails.append(name)


# --- a minimal software authenticator (ES256, attestation "none") ---

class SoftKey:
    def __init__(self):
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.counter = 0

    def _cose_key(self):
        nums = self.priv.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def _auth_data(self, flags, with_cred):
        data = hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + struct.pack(">I", self.counter)
        if with_cred:
            data += bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose_key()
        return data

    def create(self, options):
        client_data = json.dumps({"type": "webauthn.create", "challenge": options["challenge"],
                                  "origin": ORIGIN, "crossOrigin": False}).encode()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": self._auth_data(0x45, True)})
        return {"id": bytes_to_base64url(self.cred_id), "rawId": bytes_to_base64url(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": bytes_to_base64url(client_data),
                             "attestationObject": bytes_to_base64url(att), "transports": ["internal"]}}

    def get(self, options, origin=ORIGIN):
        self.counter += 1
        client_data = json.dumps({"type": "webauthn.get", "challenge": options["challenge"],
                                  "origin": origin, "crossOrigin": False}).encode()
        auth_data = self._auth_data(0x05, False)
        sig = self.priv.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": bytes_to_base64url(self.cred_id), "rawId": bytes_to_base64url(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": bytes_to_base64url(client_data),
                             "authenticatorData": bytes_to_base64url(auth_data), "signature": bytes_to_base64url(sig)}}


# --- host rules ---
check("rp id strips port", passkeys.rp_id_from_host("fw.example.com:8750") == "fw.example.com")
check("rp id refuses IPv4", passkeys.rp_id_from_host("66.96.83.33:8750") is None)
check("rp id refuses IPv6", passkeys.rp_id_from_host("[2001:db8::1]:8750") is None)
check("host problem for http", "HTTPS" in passkeys.host_problem("fw.example.com", False))
check("host problem for IP", "IP address" in passkeys.host_problem("1.2.3.4:8750", True))
check("no host problem for domain", passkeys.host_problem("fw.example.com:8750", True) == "")

# --- registration ---
auth.create_user("admin", "secret-pw")
key = SoftKey()
opts_json, challenge = passkeys.registration_options("admin", HOST)
opts = json.loads(opts_json)
check("registration options carry rp id", opts["rp"]["id"] == RP_ID)
check("challenge matches options", opts["challenge"] == challenge)
check("user handle is not the username", opts["user"]["id"] != bytes_to_base64url(b"admin"))

ok, res = passkeys.registration_verify("admin", HOST, ORIGIN, challenge, key.create(opts), "  Work   laptop ")
check("registration verifies", ok, str(res))
check("passkey name is cleaned", ok and res["name"] == "Work laptop")
check("recovery codes issued for passkey-only user", ok and len(res["recovery_codes"] or []) == 8)
listed = passkeys.list_passkeys("admin")
check("passkey listed", len(listed) == 1 and listed[0]["name"] == "Work laptop")
check("transports stored", auth.load_auth_config()["users"]["admin"]["passkeys"][0]["transports"] == ["internal"])

st = auth.second_factor_status("admin")
check("second factor enabled via passkey", st["enabled"] and st["passkeys"] == 1 and not st["totp"])
check("user_has_second_factor sees passkey", auth.user_has_second_factor(auth.load_auth_config()["users"]["admin"]))
check("list_users reports twofa", auth.list_users()[0]["twofa"] and auth.list_users()[0]["passkeys"] == 1)

ok2, res2 = passkeys.registration_verify("admin", HOST, ORIGIN, challenge, key.create(opts), "dup")
check("same credential refused twice", not ok2)

# wrong origin / wrong challenge
_, ch_b = passkeys.registration_options("admin", HOST)
ok3, res3 = passkeys.registration_verify("admin", HOST, "https://evil.example.com", ch_b, SoftKey().create(json.loads(_)), "x")
check("registration with wrong origin refused", not ok3)

# --- sign-in ---
a_json, a_ch = passkeys.authentication_options("admin", HOST)
a_opts = json.loads(a_json)
check("auth options list the credential", a_opts["allowCredentials"][0]["id"] == bytes_to_base64url(key.cred_id))
ok, name = passkeys.authentication_verify("admin", HOST, ORIGIN, a_ch, key.get(a_opts))
check("assertion verifies", ok, str(name))
check("sign count advanced", auth.load_auth_config()["users"]["admin"]["passkeys"][0]["sign_count"] == 1)
check("last_used set", passkeys.list_passkeys("admin")[0]["last_used"] is not None)

a_json, a_ch = passkeys.authentication_options("admin", HOST)
key.counter = 0  # a cloned key would present a counter no higher than the one already seen
ok, msg = passkeys.authentication_verify("admin", HOST, ORIGIN, a_ch, key.get(json.loads(a_json)))
check("stale sign counter (cloned key) refused", not ok)
key.counter = 5

a_json, a_ch = passkeys.authentication_options("admin", HOST)
ok, msg = passkeys.authentication_verify("admin", HOST, ORIGIN, a_ch, key.get(json.loads(a_json), origin="https://evil.example.com"))
check("assertion from wrong origin refused", not ok)

a_json, a_ch = passkeys.authentication_options("admin", HOST)
other = SoftKey()
ok, msg = passkeys.authentication_verify("admin", HOST, ORIGIN, a_ch, other.get(json.loads(a_json)))
check("unknown credential refused", not ok and "Unknown" in msg)

try:
    passkeys.authentication_options("admin", "66.96.83.33:8750")
    check("auth options refuse IP host", False)
except RuntimeError as e:
    check("auth options refuse IP host", "IP address" in str(e))

# --- recovery codes work at the code prompt; TOTP untouched ---
code = res["recovery_codes"][0]
check("recovery code accepted", auth.totp_check_login("admin", code))
check("recovery code is single use", not auth.totp_check_login("admin", code))
check("garbage code refused", not auth.totp_check_login("admin", "nope"))
check("recovery count dropped", auth.second_factor_status("admin")["recovery_codes_left"] == 7)
check("no new recovery set while one exists", auth.ensure_recovery_codes("admin") is None)

# --- rename / remove ---
cid = listed[0]["id"]
check("rename", passkeys.rename_passkey("admin", cid, "Desk")[0] and passkeys.list_passkeys("admin")[0]["name"] == "Desk")
check("remove needs password", not passkeys.remove_passkey("admin", cid, "wrong")[0])
check("remove", passkeys.remove_passkey("admin", cid, "secret-pw")[0])
u = auth.load_auth_config()["users"]["admin"]
check("last passkey removal clears recovery codes", "passkeys" not in u and "passkey_recovery" not in u)
check("second factor off again", not auth.second_factor_status("admin")["enabled"])
check("password-only user passes code check", auth.totp_check_login("admin", ""))

print()
print("FAILED: " + ", ".join(fails) if fails else "all passed")
sys.exit(1 if fails else 0)
