"""Local security regressions; all credentials, sessions and archives use temp dirs.

Run: python -m pytest tests/test_security.py
No server access or real firewall commands are needed.
"""
import importlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from csf_backend import auth, api_tokens, backup_restore, csf_wrapper, notifications
from csf_backend import docker_manager, wireguard_manager


@pytest.fixture
def site(tmp_path, monkeypatch):
    if os.name == "nt":
        # Linux account lookup is outside these HTTP/authentication tests.
        monkeypatch.setitem(sys.modules, "pwd", types.ModuleType("pwd"))
    monkeypatch.setattr(auth, "AUTH_CONF", str(tmp_path / "auth.json"))
    monkeypatch.setattr(auth, "SESSION_DIR", str(tmp_path / "sessions"))
    monkeypatch.setattr(auth, "LOGIN_LOG", str(tmp_path / "login.log"))
    monkeypatch.setattr(auth, "UI_ALLOW", str(tmp_path / "ui.allow"))
    monkeypatch.setattr(auth, "UI_BAN", str(tmp_path / "ui.ban"))
    monkeypatch.setattr(api_tokens, "TOKENS_PATH", str(tmp_path / "tokens.json"))
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: None)
    monkeypatch.setattr(notifications, "start_watcher", lambda: None)
    monkeypatch.setattr(notifications, "event", lambda *a, **k: None)
    auth.create_user("admin", "correct-password")
    auth.create_user("viewer", "viewer-password", "viewer")
    module = importlib.import_module("app")
    module.app.config.update(TESTING=True, SECRET_KEY="security-test-only")
    monkeypatch.setattr(module.login_history, "record_login", lambda *a: None)
    monkeypatch.setattr(module.safe_apply, "snapshot_baseline", lambda: None)
    return module


def sign_in(site, client, username="admin"):
    with client.session_transaction() as state:
        state["csrf_token"] = "test-csrf"
    response = client.post("/login", data={
        "username": username, "password": "correct-password" if username == "admin" else "viewer-password",
        "csrf_token": "test-csrf"})
    assert response.status_code == 302
    with client.session_transaction() as state:
        return state.get("csrf_token")


def csrf(client):
    with client.session_transaction() as state:
        state["csrf_token"] = "test-csrf"
    return {"X-CSRFToken": "test-csrf"}


def test_password_login_requires_csrf(site):
    client = site.app.test_client()
    assert client.post("/login", data={"username": "admin", "password": "correct-password"}).status_code == 403
    sign_in(site, client)
    with client.session_transaction() as state:
        assert state["logged_in"]
        assert state["auth_fingerprint"]
        assert state["session_id"]
        assert state.get("csrf_token") != "test-csrf"


@pytest.mark.parametrize("payload", [{"csrf_token": ["bad"]}, {"csrf_token": "\u2603"}, ["bad"]])
def test_malformed_csrf_fails_closed(site, payload):
    assert site.app.test_client().post("/api/backups", json=payload).status_code == 403


@pytest.mark.parametrize("change", ["password", "delete", "role"])
def test_account_changes_apply_to_active_sessions(site, change):
    client = site.app.test_client()
    sign_in(site, client)
    config = auth.load_auth_config()
    if change == "password":
        auth.change_password("admin", "replacement-password")
    elif change == "delete":
        del config["users"]["admin"]
        auth.save_auth_config(config)
    else:
        config["users"]["admin"]["role"] = "viewer"
        auth.save_auth_config(config)
    response = client.post("/api/reboot-server", json={}, headers=csrf(client))
    assert response.status_code == (403 if change == "role" else 302)
    assert not response.is_json or not response.json.get("success")


def test_logout_revokes_copied_cookie(site):
    client = site.app.test_client()
    sign_in(site, client)
    cookie = client.get_cookie("session").value
    client.get("/logout")
    client.set_cookie("session", cookie)
    assert client.get("/api/status").status_code == 302


def test_two_factor_lockout_and_pending_account_binding(site, monkeypatch):
    config = auth.load_auth_config()
    config["users"]["admin"]["totp"] = {"enabled": True, "secret": auth.totp_generate_secret()}
    auth.save_auth_config(config)
    client = site.app.test_client()
    sign_in(site, client)
    for _ in range(5):
        assert client.post("/login/2fa", data={"code": "invalid"}, headers=csrf(client)).status_code == 200
    assert client.post("/login/2fa", data={"code": "invalid"}, headers=csrf(client)).status_code == 429
    assert client.post("/api/passkeys/login/options", json={}, headers=csrf(client)).status_code == 429
    assert client.post("/api/passkeys/login/verify", json={}, headers=csrf(client)).status_code == 429
    # A valid password must not reset an unfinished second-factor lockout.
    assert not auth.authenticate("admin", "correct-password", "127.0.0.1")[0]
    auth.change_password("admin", "replacement-password")
    assert client.get("/login/2fa").status_code == 302
    assert not auth.totp_check_login("deleted-user", "anything")


def test_failed_attempts_not_lost_between_threads(site):
    stale = auth.load_auth_config()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: auth.record_failed(stale, "192.0.2.1"), range(20)))
    assert auth.load_auth_config()["failed_attempts"]["192.0.2.1"]["count"] == 20


def test_username_link_cannot_switch_another_account(site):
    ok, token = auth.create_username_change_token("admin", "renamed-admin", "correct-password")
    assert ok
    assert not auth.confirm_username_change(token, "viewer")[0]
    assert "admin" in auth.load_auth_config()["users"]
    assert auth.confirm_username_change(token, "admin")[0]


def test_no_default_admin_created(site):
    auth.save_auth_config({"users": {}})
    with pytest.raises(RuntimeError):
        auth.setup_initial_user()
    assert auth.load_auth_config()["users"] == {}


def test_update_requires_post_csrf_and_admin(site, monkeypatch):
    called = []
    monkeypatch.setattr(site.app_updater, "run_update_stream", lambda **kwargs: iter(called.append(True) or ["data: __DONE_OK__\n\n"]))
    client = site.app.test_client()
    sign_in(site, client, "viewer")
    assert client.get("/api/version/update-stream").status_code == 405
    assert client.post("/api/version/update-stream", headers=csrf(client)).status_code == 403
    assert not called
    sign_in(site, client)
    assert client.post("/api/version/update-stream").status_code == 403
    response = client.post("/api/version/update-stream", headers=csrf(client))
    assert response.status_code == 200 and b"__DONE_OK__" in response.data
    assert called == [True]


def test_api_scope_and_revocation(site, monkeypatch):
    token = api_tokens.create("read-only", ["read"])
    client = site.app.test_client()
    monkeypatch.setattr(site.csf, "allow_ip", lambda *a: pytest.fail("CSF must not run"))
    headers = {"Authorization": "Bearer " + token}
    assert client.post("/api/v1/allow", json={"ip": "192.0.2.1"}, headers=headers).status_code == 403
    api_tokens.revoke(api_tokens.list_tokens()[0]["id"])
    assert client.get("/api/v1/status", headers=headers).status_code == 401


@pytest.mark.parametrize("value", ['22"\nTESTING = "1', "22\n", '22\\"', "22\x00"])
def test_config_injection_rejected_without_writing(tmp_path, monkeypatch, value):
    conf = tmp_path / "csf.conf"
    conf.write_text('TCP_IN = "22,443"\nTESTING = "0"\n')
    original = conf.read_bytes()
    monkeypatch.setattr(csf_wrapper, "CSF_CONF", str(conf))
    assert not csf_wrapper.save_csf_conf({"TCP_IN": value})["success"]
    assert conf.read_bytes() == original
    assert csf_wrapper.save_csf_conf({"TCP_IN": "22,80,443"})["success"]


@pytest.mark.parametrize("kind", ["traversal", "symlink", "duplicate", "oversize", "bad_metadata"])
def test_malicious_archives_rejected(tmp_path, monkeypatch, kind):
    path = tmp_path / "bad.tar.gz"
    monkeypatch.setattr(backup_restore, "MAX_UPLOAD_BYTES", 1024)
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("../outside" if kind == "traversal" else "csf.conf")
        if kind == "symlink":
            info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
        data = b"x" * (2048 if kind == "oversize" else 1)
        info.size = 0 if kind == "symlink" else len(data)
        tar.addfile(info, io.BytesIO(data))
        if kind == "duplicate":
            tar.addfile(info, io.BytesIO(data))
        if kind == "bad_metadata":
            for name in backup_restore.SSL_ARCHIVE_FILES:
                member = tarfile.TarInfo(name)
                member.size = 2
                tar.addfile(member, io.BytesIO(b"[]"))
    assert not backup_restore._validate_archive(path)[0]


def test_command_helpers_reject_shell_strings(monkeypatch):
    assert not docker_manager.run_cmd("echo pwned; whoami")["success"]
    assert not wireguard_manager.run_cmd("echo pwned; whoami")["success"]


def test_all_protected_routes_reject_anonymous_requests(site, monkeypatch):
    public = {"static", "login", "login_2fa", "logout", "acme_challenge",
              "api_passkey_login_options", "api_passkey_login_verify"}
    monkeypatch.setattr(site.subprocess, "run", lambda *a, **k: pytest.fail("Anonymous request executed a command"))
    count = 0
    for rule in site.app.url_map.iter_rules():
        if rule.endpoint in public:
            continue
        path = re.sub(r"<[^>]+>", "probe", rule.rule)
        for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
            response = site.app.test_client().open(path, method=method)
            assert response.status_code in (302, 401, 403), (method, path, response.status_code)
            count += 1
    assert count > 200


def test_viewer_cannot_mutate_any_admin_route(site, monkeypatch):
    client = site.app.test_client()
    sign_in(site, client, "viewer")
    monkeypatch.setattr(site.subprocess, "run", lambda *a, **k: pytest.fail("Viewer request executed a command"))
    count = 0
    for rule in site.app.url_map.iter_rules():
        path = re.sub(r"<[^>]+>", "probe", rule.rule)
        if path in site.VIEWER_POST_OK:
            continue
        for method in sorted(rule.methods & {"POST", "PUT", "PATCH", "DELETE"}):
            response = client.open(path, method=method, headers=csrf(client))
            assert response.status_code in (302, 401, 403), (method, path, response.status_code)
            if response.status_code == 302:
                assert response.headers["Location"] == "/"
            count += 1
    assert count > 100


def test_remote_backup_rejects_local_execution_destinations(site, monkeypatch):
    from csf_backend import remote_backup
    monkeypatch.setattr(remote_backup, "_run", lambda *a, **k: pytest.fail("Invalid destination ran a command"))
    for config in [
        {"method": "sftp", "sftp": {"host": "-oProxyCommand=whoami", "user": "root", "path": "/backups"}},
        {"method": "sftp", "sftp": {"host": "example.com", "user": "-oProxyCommand=whoami", "path": "/backups"}},
        {"method": "sftp", "sftp": {"host": "example.com", "user": "root", "path": "/tmp/$(whoami)"}},
        {"method": "webdav", "webdav": {"url": "file:///etc/cron.d/attack"}},
    ]:
        monkeypatch.setattr(remote_backup, "load", lambda c=config: c)
        assert not remote_backup.upload("/backup.tar.gz")["success"]


def test_second_factor_replay_rejected(site):
    challenge = "test-challenge"
    nonce = auth.issue_challenge(challenge)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: auth.consume_challenge(nonce, challenge), range(4)))
    assert sum(results) == 1
    config = auth.load_auth_config()
    secret = auth.totp_generate_secret()
    config["users"]["admin"]["totp"] = {"enabled": True, "secret": secret}
    auth.save_auth_config(config)
    code = auth.totp_code(secret)
    assert auth.totp_check_login("admin", code)
    assert not auth.totp_check_login("admin", code)


def test_ip_restrictions_apply_to_existing_sessions(site):
    client = site.app.test_client()
    sign_in(site, client)
    Path(auth.UI_BAN).write_text("127.0.0.1\n")
    assert client.get("/api/status").status_code == 302


def test_wireguard_key_generation_never_uses_shell(monkeypatch):
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return types.SimpleNamespace(returncode=0, stdout="test-key\n", stderr="")
    monkeypatch.setattr(wireguard_manager.subprocess, "run", run)
    assert wireguard_manager.generate_keypair()["public_key"] == "test-key"
    assert wireguard_manager.generate_preshared_key() == "test-key"
    assert all(isinstance(command, list) and kwargs["shell"] is False for command, kwargs in calls)
    assert calls[1][1]["input"] == "test-key\n"


def test_update_client_template_and_javascript(site, tmp_path):
    node = os.environ.get("CSFV2_NODE_TEST_BIN") or shutil.which("node")
    if not node:
        pytest.skip("Node is needed for JavaScript syntax validation")
    with site.app.test_request_context("/updates"):
        rendered = site.render_template("updates.html", info={"update_available": True, "latest": "9.9.9"}, status={})
    assert "method: 'POST', headers: {'X-CSRFToken':" in rendered
    assert "new EventSource('/api/version/update-stream'" not in rendered
    scripts = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", rendered, re.S)
    script_path = tmp_path / "update-client.js"
    script_path.write_text("\n".join(scripts), encoding="utf-8")
    subprocess.run([node, "--check", str(script_path)], check=True, capture_output=True)


def test_shared_html_escaping_and_process_rendering(site, tmp_path):
    node = os.environ.get("CSFV2_NODE_TEST_BIN") or shutil.which("node")
    if not node:
        pytest.skip("Node is needed for HTML injection regressions")
    source = Path("static/js/csfv2.js").read_text(encoding="utf-8")
    # Load the real client library without running browser startup callbacks.
    script = "const vm = require('vm'), assert = require('assert');\n"
    script += "const sandbox = {$: () => ({ready: () => {}}), document: {}, window: {}};\n"
    script += "vm.runInNewContext(" + json.dumps(source) + ", sandbox);\n"
    script += "assert.strictEqual(sandbox.CSFv2.escapeHtml(\"<img src=x onerror='evil()'>\\\"&\"), '&lt;img src=x onerror=&#39;evil()&#39;&gt;&quot;&amp;');\n"
    script += "assert.strictEqual(sandbox.CSFv2.escapeHtml(null), '');\n"
    # Exercise the process-table callback with attacker-controlled command data.
    template = Path("templates/processes.html").read_text(encoding="utf-8")
    process_script = re.search(r"<script>(.*?)</script>", template, re.S)[1]
    script += "let output = {}; const chain = {on:()=>chain,html:(s)=>{output.table=s;return chain;},text:()=>chain};\n"
    script += "sandbox.$ = function(arg) {if(typeof arg === 'function') arg();return chain;};\n"
    script += "sandbox.$.getJSON = function(url, args, cb) {if (url !== '/api/processes') return; cb({processes:[{pid:1,user:'root',command:'\\\"><img src=x onerror=evil()>',cpu:1,mem:1,stat:'S',start:'now',time:'0'}]});};\n"
    # The command cell uses the existing jQuery text encoder; stub that surface.
    script = script.replace("text:()=>chain", "text:(s)=>{chain.value=s;return chain;}")
    script = script.replace("html:(s)=>{output.table=s;return chain;}", "html:(s)=>{if(s===undefined)return sandbox.CSFv2.escapeHtml(chain.value);output.table=s;return chain;}")
    script += "vm.runInNewContext(" + json.dumps(process_script) + ",sandbox);\n"
    script += "assert(!output.table.includes('<img')); assert(output.table.includes('&quot;&gt;&lt;img'));\n"
    path = tmp_path / "xss-regression.js"
    path.write_text(script, encoding="utf-8")
    subprocess.run([node, str(path)], check=True, capture_output=True)


def test_totp_disable_does_not_resurrect_recovery_code(site):
    import hashlib
    config = auth.load_auth_config()
    user = config["users"]["admin"]
    user["totp"] = {"enabled": True, "secret": auth.totp_generate_secret()}
    user["passkeys"] = [{"id": "test-key"}]
    user["passkey_recovery"] = [hashlib.sha256(b"recovery-code").hexdigest()]
    auth.save_auth_config(config)
    assert auth.totp_disable("admin", "correct-password", "recovery-code")[0]
    assert not auth.totp_check_login("admin", "recovery-code")


def test_fleet_redirect_does_not_forward_bearer_token():
    from csf_backend import servers
    import urllib.request
    request = urllib.request.Request("https://trusted.example/api/v1/status", headers={"Authorization": "Bearer secret"})
    assert servers._NoRedirect().redirect_request(request, None, 302, "Found", {}, "https://other.example/") is None


def test_remote_backup_test_uses_private_temporary_archive(site, monkeypatch):
    from csf_backend import remote_backup
    paths = []
    monkeypatch.setattr(remote_backup, "load", lambda: {"method": "sftp"})
    def upload(path):
        paths.append(path)
        assert Path(path).is_file()
        return {"success": True}
    monkeypatch.setattr(remote_backup, "upload", upload)
    assert remote_backup.test()["success"]
    assert not Path(paths[0]).exists()


@pytest.mark.parametrize("ip", ["-h", "--version", "1.2.3.4 extra", "1.2.3.4\n5.6.7.8", "", "not-an-ip"])
def test_csf_ip_arguments_rejected_before_execution(monkeypatch, ip):
    monkeypatch.setattr(csf_wrapper, "run_csf", lambda *a, **k: pytest.fail("csf must not run"))
    for fn in (csf_wrapper.allow_ip, csf_wrapper.deny_ip, csf_wrapper.unblock_ip,
               csf_wrapper.remove_temp_deny, csf_wrapper.temp_to_perm):
        assert not fn(ip)["success"]
    assert not csf_wrapper.temp_deny(ip, 60)["success"]


def test_csf_comment_cannot_add_lines_or_arguments(monkeypatch):
    calls = []
    monkeypatch.setattr(csf_wrapper, "run_csf", lambda args, **k: calls.append(args) or {"success": True, "stdout": "", "stderr": "", "returncode": 0})
    csf_wrapper.allow_ip("192.0.2.1", "ok\ntcp|in|d=1-65535|s=0/0")
    csf_wrapper.temp_deny("192.0.2.2", "600", "22,80-90", "x\r\ny")
    assert calls[0] == ["-a", "192.0.2.1", "oktcp|in|d=1-65535|s=0/0"]
    assert calls[1] == ["-td", "192.0.2.2", "600", "-p", "22,80-90", "xy"]
    assert not csf_wrapper.temp_deny("192.0.2.2", "abc")["success"]
    assert not csf_wrapper.temp_deny("192.0.2.2", 60, "22;reboot")["success"]
    assert len(calls) == 2


def test_action_redirect_stays_on_site(site, monkeypatch):
    client = site.app.test_client()
    sign_in(site, client)
    monkeypatch.setattr(site.csf, "csf_enable", lambda: {"success": True, "stdout": "", "stderr": ""})
    for target in ["https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)"]:
        response = client.post("/action/enable", data={"redirect_to": target}, headers=csrf(client))
        assert response.status_code == 302 and response.headers["Location"] == "/", target
    response = client.post("/action/enable", data={"redirect_to": "/status?x=1"}, headers=csrf(client))
    assert response.headers["Location"] == "/status?x=1"


def test_password_change_requires_current_password(site):
    client = site.app.test_client()
    sign_in(site, client)
    form = {"action": "change_password", "new_password": "another-password", "confirm_password": "another-password"}
    client.post("/settings", data=form, headers=csrf(client))
    assert auth.authenticate("admin", "correct-password", "127.0.0.1")[0]
    client.post("/settings", data=dict(form, current_password="wrong"), headers=csrf(client))
    assert auth.authenticate("admin", "correct-password", "127.0.0.1")[0]
    client.post("/settings", data=dict(form, current_password="correct-password"), headers=csrf(client))
    assert auth.authenticate("admin", "another-password", "127.0.0.1")[0]


@pytest.mark.parametrize("cid", ["--privileged", "-a", "", "x;y", "a b"])
def test_docker_ids_cannot_become_flags(monkeypatch, cid):
    monkeypatch.setattr(docker_manager, "run_cmd", lambda *a, **k: pytest.fail("docker must not run"))
    assert not docker_manager.container_action(cid, "start")["success"]
    assert docker_manager.get_container_details(cid) is None
    assert docker_manager.get_network_details(cid) is None


def test_wireguard_peer_fields_cannot_inject_config(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard_manager, "WG_CONF_DIR", str(tmp_path))
    monkeypatch.setattr(wireguard_manager, "is_interface_up", lambda iface: False)
    conf = tmp_path / "wg0.conf"
    conf.write_text("[Interface]\nPrivateKey = x\n")
    key = "A" * 43 + "="
    bad = [
        (key + "\nPostUp = reboot", "10.0.0.2/32", None),
        (key, "10.0.0.2/32\nPostUp = reboot", None),
        (key, "10.0.0.2/32", "host:51820\nPostUp = reboot"),
        ("not-a-key", "10.0.0.2/32", None),
        (key, "10.0.0.2/32", "$(whoami):1"),
    ]
    for public_key, allowed, endpoint in bad:
        assert not wireguard_manager.add_peer("wg0", public_key, allowed, endpoint)["success"]
    assert conf.read_text() == "[Interface]\nPrivateKey = x\n"
    assert wireguard_manager.add_peer("wg0", key, "10.0.0.2/32, fd00::2/128", "vpn.example.com:51820", None, "25")["success"]
    assert "PostUp" not in conf.read_text() and "fd00::2/128" in conf.read_text()
    assert wireguard_manager.generate_client_config("wg0", "10.0.0.3/32", "1.2.3.4:51820", key, "1.1.1.1\nPostUp=x") is None


def test_ssl_revoke_limited_to_certificate_directories(tmp_path, monkeypatch):
    from csf_backend import ssl_manager
    monkeypatch.setattr(ssl_manager, "_run", lambda *a, **k: pytest.fail("certbot must not run"))
    secret = tmp_path / "shadow"
    secret.write_text("x")
    assert not ssl_manager.revoke_certificate(str(secret))["success"]
    assert not ssl_manager.revoke_certificate("--help")["success"]
