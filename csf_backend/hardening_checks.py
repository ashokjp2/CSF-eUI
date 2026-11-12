"""Extra Health Check items: default-config loopholes, Docker exposure, accounts, CSF-eUI itself, system.

Each item: {id, status (pass|warn|fail|info), title, detail, weight (1 low, 2 normal, 3 critical),
            setting/fix_value (csf.conf or sshd quick fix), or fix (dict for other one-click fixes),
            link (page to open)}.
Accepted items (admin chose to live with a finding) are stored in ACCEPT_PATH and become status
"accepted" so they stop dragging the score down while staying visible.
"""
import json
import os
import re
import subprocess
import time

ACCEPT_PATH = "/var/lib/csfv2/health_accepted.json"
LAST_PATH = "/var/lib/csfv2/health_last.json"
SYSCTL_FILE = "/etc/sysctl.d/90-csfv2-hardening.conf"

# sysctl keys the quick-fix endpoint may set (key: recommended value)
SYSCTL_SAFE = {
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv6.conf.all.accept_redirects": "0",
    "kernel.kptr_restrict": "1",
    "kernel.dmesg_restrict": "1",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
}
DB_PORTS = {"3306": "MySQL/MariaDB", "5432": "PostgreSQL", "6379": "Redis", "27017": "MongoDB",
            "9200": "Elasticsearch", "11211": "Memcached", "5984": "CouchDB", "8086": "InfluxDB",
            "9000": "MinIO/ClickHouse", "2379": "etcd", "4369": "RabbitMQ/Erlang", "5672": "RabbitMQ"}
PANEL_PORTS = {"8000": "Coolify", "3000": "Dokploy/Grafana", "9443": "Portainer", "9000": "Portainer/Coolify"}
MAIL_FTP_PORTS = {"21": "FTP", "110": "POP3", "143": "IMAP", "993": "IMAPS", "995": "POP3S", "465": "SMTPS", "587": "Submission"}


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _ports(value):
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def _listening():
    """{port: (bind_addr, process)} for TCP listeners."""
    out = {}
    for line in _run(["ss", "-tlnpH"]).splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        addr = parts[3]
        m = re.match(r"^(.*):(\d+)$", addr)
        if not m:
            continue
        bind, port = m.group(1), m.group(2)
        proc = ""
        pm = re.search(r'users:\(\("([^"]+)"', line)
        if pm:
            proc = pm.group(1)
        prev = out.get(port)
        public = bind in ("0.0.0.0", "*", "[::]", "::")
        if prev is None or (public and not prev[2]):
            out[port] = (bind, proc, public)
    return out


def _ui_port():
    for line in _read("/etc/csfv2/csfv2.conf").splitlines():
        if line.strip().startswith("CSFV2_PORT="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("CSFV2_PORT", "8750")


def _docker_json(args):
    out = _run(["docker"] + args, timeout=15)
    if not out:
        return []
    try:
        return json.loads(out)
    except ValueError:
        return []


# ---------------------------------------------------------------- accept / history

def load_accepted():
    return _json(ACCEPT_PATH, {})


def accept(item_id, reason, user="", hide=False):
    """Accept (stays visible, stops counting) or ignore (hide=True: removed from the list until restored)."""
    data = load_accepted()
    data[item_id] = {"reason": (reason or "").strip()[:200], "user": user, "at": int(time.time()), "hide": bool(hide)}
    os.makedirs(os.path.dirname(ACCEPT_PATH), exist_ok=True)
    with open(ACCEPT_PATH, "w") as f:
        json.dump(data, f, indent=2)
    return data[item_id]


def unaccept(item_id):
    data = load_accepted()
    removed = data.pop(item_id, None)
    os.makedirs(os.path.dirname(ACCEPT_PATH), exist_ok=True)
    with open(ACCEPT_PATH, "w") as f:
        json.dump(data, f, indent=2)
    return removed is not None


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:60]


def finalise(checks):
    """Give every item a stable id, apply accepted state, mark what changed since the last run,
    and remember the current statuses. Called by security_check.run_full_check()."""
    accepted = load_accepted()
    last = _json(LAST_PATH, {})
    rank = {"pass": 0, "info": 1, "accepted": 1, "ignored": 1, "warn": 2, "fail": 3}
    now = {}
    for cat in checks:
        for item in cat["items"]:
            if not item.get("id"):
                item["id"] = _slug(cat["category"]) + ":" + _slug(item.get("setting") or item["title"])
            item.setdefault("weight", 3 if item["status"] == "fail" else 1 if item["status"] == "info" else 2)
            if item["id"] in accepted and item["status"] in ("warn", "fail", "info"):
                item["accepted"] = accepted[item["id"]]
                item["status"] = "ignored" if accepted[item["id"]].get("hide") else "accepted"
            prev = last.get(item["id"])
            if prev is not None and rank.get(item["status"], 0) > rank.get(prev, 0):
                item["changed"] = "worse"
            elif prev is None and item["status"] in ("warn", "fail"):
                item["changed"] = "new"
            now[item["id"]] = item["status"]
    try:
        os.makedirs(os.path.dirname(LAST_PATH), exist_ok=True)
        with open(LAST_PATH, "w") as f:
            json.dump(now, f)
    except OSError:
        pass
    return checks


# ---------------------------------------------------------------- sysctl fix

def apply_sysctl(key, value):
    if key not in SYSCTL_SAFE:
        return {"success": False, "error": f"sysctl {key} is not allowed"}
    lines = [l for l in _read(SYSCTL_FILE).splitlines() if l.strip() and not l.strip().startswith(key + " ")]
    lines.append(f"{key} = {value}")
    try:
        os.makedirs(os.path.dirname(SYSCTL_FILE), exist_ok=True)
        with open(SYSCTL_FILE, "w") as f:
            f.write("# Managed by CSF-eUI Health Check\n" + "\n".join(lines) + "\n")
    except OSError as e:
        return {"success": False, "error": str(e)}
    r = subprocess.run(["sysctl", "-w", f"{key}={value}"], capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        return {"success": False, "error": r.stderr.strip() or "sysctl failed"}
    return {"success": True, "message": f"{key} = {value} applied now and saved in {SYSCTL_FILE}"}


# ---------------------------------------------------------------- other one-click fixes

CHMOD_SAFE = {"/etc/csfv2/auth.json": 0o600, "/etc/csfv2/tokens.json": 0o600, "/etc/csf/csf.conf": 0o644}


def apply_action(action, data, user=""):
    """One-click fixes that are not a single csf.conf / sshd / sysctl value.
    Returns {success, message, undo?, safe_apply?}."""
    if action == "remove_ports":
        from csf_backend import csf_wrapper as csf
        ports = [str(p).strip() for p in (data.get("ports") or []) if str(p).strip().isdigit()][:50]
        if not ports:
            return {"success": False, "error": "No ports given"}
        conf = csf.load_csf_conf()
        old = conf.get("TCP_IN", "")
        new = ",".join(p for p in _ports(old) if p not in ports)
        if new == old:
            return {"success": False, "error": "Those ports are not in TCP_IN any more"}
        r = csf.save_csf_conf({"TCP_IN": new})
        if not r.get("success"):
            return r
        return {"success": True, "safe_apply": True, "undo": {"action": "set_conf", "key": "TCP_IN", "value": old},
                "message": f"Removed {', '.join(ports)} from TCP_IN. Use “Apply safely” in the bar at the top to restart with automatic rollback."}
    if action == "chmod":
        path = str(data.get("path", ""))
        if path not in CHMOD_SAFE:
            return {"success": False, "error": "That file cannot be changed from here"}
        mode = CHMOD_SAFE[path]
        if path.startswith("/etc/csf/csf.conf"):
            mode = 0o644
        try:
            os.chmod(path, mode)
        except OSError as e:
            return {"success": False, "error": str(e)}
        return {"success": True, "message": f"{path} is now mode {oct(mode)[2:]}"}
    if action == "ntp":
        r = subprocess.run(["timedatectl", "set-ntp", "true"], capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return {"success": False, "error": r.stderr.strip() or "timedatectl failed"}
        return {"success": True, "message": "Time synchronisation (NTP) switched on"}
    if action == "disable_feed":
        from csf_backend import blocklist_feeds
        name = str(data.get("name", "")).strip()
        r = blocklist_feeds.set_enabled(name, False)
        if not r.get("success"):
            return r
        return {"success": True, "safe_apply": True, "undo": {"action": "feed_enable", "name": name},
                "message": f"Blocklist feed {name} disabled. Use “Apply safely” at the top to restart LFD."}
    return {"success": False, "error": f"Unknown action {action}"}


# ---------------------------------------------------------------- the checks

def _firewall_rules(csf, listening):
    items = []
    tcp_in = _ports(csf.get("TCP_IN"))
    idle = [p for p in tcp_in if p.isdigit() and p not in listening]
    if idle:
        items.append({"status": "warn", "weight": 2, "link": "/ports", "fix": {"action": "remove_ports", "ports": idle},
                      "title": f"{len(idle)} open port{'s' if len(idle) > 1 else ''} in TCP_IN with nothing listening: {', '.join(idle[:12])}{'…' if len(idle) > 12 else ''}",
                      "detail": "CSF's default TCP_IN opens mail, FTP and other ports whether or not you run those services. Every open port is a door for the next service that starts there.",
                      "how": "Remove the ports you do not use from TCP_IN (the button does this; undo is in the bell menu). Keep a port only if a service will listen there soon."})
    else:
        items.append({"status": "pass", "title": "Every port in TCP_IN has a service behind it"})
    mail_ftp = [p for p in tcp_in if p in MAIL_FTP_PORTS and p not in listening]
    if mail_ftp:
        items.append({"status": "warn", "weight": 1, "link": "/ports", "fix": {"action": "remove_ports", "ports": mail_ftp},
                      "title": "Mail/FTP ports open but no mail or FTP server running: " + ", ".join(f"{p} ({MAIL_FTP_PORTS[p]})" for p in mail_ftp),
                      "detail": "These come from CSF's default list. On a Docker/web server they are not needed.",
                      "how": "Remove them from TCP_IN, or ignore this check if you plan to run a mail server here."})
    for key, label in (("TCP_OUT", "outbound TCP"), ("UDP_OUT", "outbound UDP")):
        v = (csf.get(key) or "").strip()
        if v == "1:65535" or v == "0:65535":
            items.append({"status": "info", "weight": 1, "link": "/config?q=" + key,
                          "title": f"All {label} ports are open ({key} = {v})",
                          "detail": "Fine for most servers, but a compromised container can then reach anything. Restricting outbound ports is an advanced hardening step."})

    syn = csf.get("SYNFLOOD", "0")
    if syn == "0":
        items.append({"status": "warn", "weight": 2, "setting": "SYNFLOOD", "fix_value": "1",
                      "title": "SYN flood protection is off",
                      "detail": "SYNFLOOD rate-limits half-open connections so a flood cannot exhaust the server. Keep SYNFLOOD_RATE at the default unless you have a very busy site."})
    else:
        items.append({"status": "pass", "title": "SYN flood protection is on"})
    if not (csf.get("CONNLIMIT") or "").strip():
        items.append({"status": "info", "weight": 1, "setting": "CONNLIMIT", "fix_value": "22;5,80;50,443;50",
                      "title": "No concurrent-connection limits (CONNLIMIT is empty)",
                      "detail": "Caps how many connections one IP may hold open per port. Protects against slow-loris style attacks."})
    icmp = csf.get("ICMP_IN", "1")
    if icmp == "1" and not (csf.get("ICMP_IN_RATE") or "").strip():
        items.append({"status": "info", "weight": 1, "setting": "ICMP_IN_RATE", "fix_value": "1/s",
                      "title": "Ping is allowed with no rate limit",
                      "detail": "Set ICMP_IN_RATE so a ping flood is dropped instead of answered."})
    if csf.get("LF_DISTATTACK", "0") == "0":
        items.append({"status": "warn", "weight": 2, "setting": "LF_DISTATTACK", "fix_value": "1",
                      "title": "Distributed attack detection is off",
                      "detail": "LF_DISTATTACK catches many IPs attacking the same account slowly, which per-IP limits miss."})
    if csf.get("LF_NETBLOCK", "0") == "0":
        items.append({"status": "info", "weight": 1, "setting": "LF_NETBLOCK", "fix_value": "1",
                      "title": "Network-range blocking is off",
                      "detail": "LF_NETBLOCK blocks a whole /24 once enough of its addresses are blocked individually, which is how botnets usually look."})
    try:
        trig, interval = int(csf.get("LF_TRIGGER", "0") or 0), int(csf.get("LF_INTERVAL", "3600") or 3600)
        if trig > 20 or interval < 600:
            items.append({"status": "warn", "weight": 2, "link": "/config?q=LF_TRIGGER",
                          "title": f"Brute-force threshold is loose (LF_TRIGGER={trig}, LF_INTERVAL={interval}s)",
                          "detail": "An attacker can make this many attempts in the window before anything happens. CSF defaults (0 = per-service limits, 3600 s) are tighter.",
                          "how": "Set LF_TRIGGER back to 0 (per-service limits such as LF_SSHD apply) and LF_INTERVAL to 3600 on the Config page."})
    except ValueError:
        pass
    try:
        limit = int(csf.get("DENY_IP_LIMIT", "200") or 200)
        deny_count = sum(1 for l in _read("/etc/csf/csf.deny").splitlines() if l.strip() and not l.startswith("#"))
        if deny_count >= limit - 5:
            items.append({"status": "warn", "weight": 2, "setting": "DENY_IP_LIMIT", "fix_value": str(limit * 2),
                          "title": f"csf.deny is full ({deny_count} of {limit})",
                          "detail": "New permanent blocks push the oldest ones out. Raise DENY_IP_LIMIT or block by network instead."})
    except ValueError:
        pass
    cc = (csf.get("CC_DENY") or "").strip() or (csf.get("CC_ALLOW_FILTER") or "").strip()
    if cc and not (csf.get("MM_LICENSE_KEY") or "").strip() and csf.get("CC_SRC", "1") == "1":
        items.append({"status": "fail", "weight": 3, "link": "/countries", "setting": "CC_SRC", "fix_value": "2",
                      "title": "Country blocking is set but there is no MaxMind licence key",
                      "detail": "With CC_SRC=1 CSF needs MM_LICENSE_KEY to download country lists. Without it CC_DENY silently does nothing.",
                      "how": "Switch CC_SRC to 2 (db-ip, no key needed) with the button, or add a free MaxMind key as MM_LICENSE_KEY on the Config page."})
    broad = []
    for fn in ("csf.allow", "csf.ignore"):
        for l in _read(f"/etc/csf/{fn}").splitlines():
            s = l.split("#")[0].strip()
            if not s:
                continue
            if re.search(r"(^|=)0\.0\.0\.0/0\b", s) or re.search(r"\b\d+\.\d+\.\d+\.\d+/(?:[1-9]|1[0-5])\b", s) or re.search(r"\bs=0/0", s):
                broad.append(f"{fn}: {s[:40]}")
    if broad:
        items.append({"status": "fail", "weight": 3, "link": "/ip-lists",
                      "title": f"Very broad whitelist entries found ({len(broad)})",
                      "detail": "These bypass the firewall for huge address ranges: " + "; ".join(broad[:3]) + ".",
                      "how": "Open IP Lists and replace each entry with the exact IPs or /24 ranges you need. Entries you added on purpose (e.g. a CDN range) can be accepted here."})
    pub_ignore = [l.strip() for l in _read("/etc/csf/csf.ignore").splitlines()
                  if re.match(r"^\d+\.\d+\.\d+\.\d+", l.strip()) and not re.match(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", l.strip())]
    if pub_ignore:
        items.append({"status": "info", "weight": 1, "link": "/ip-lists",
                      "title": f"{len(pub_ignore)} public IP{'s' if len(pub_ignore) > 1 else ''} in csf.ignore are never blocked by LFD",
                      "detail": "Make sure each one is really yours: " + ", ".join(pub_ignore[:5])})
    if csf.get("SMTP_BLOCK", "0") == "0" and "25" not in listening:
        items.append({"status": "warn", "weight": 2, "setting": "SMTP_BLOCK", "fix_value": "1",
                      "title": "Outgoing SMTP is unrestricted on a server without a mail server",
                      "detail": "A compromised container or script can send spam straight out on port 25 and get your IP blacklisted. SMTP_BLOCK only allows the local mail service to send."})
    try:
        from csf_backend import blocklist_feeds
        feeds = blocklist_feeds.status()
        bad = [f for f in feeds if f["enabled"] and f["health"] in ("stale", "never", "needs-key", "empty")]
        for f in bad:
            why = {"never": "LFD has never fetched it. Usually LFD was not restarted after the feed was enabled, or the URL is unreachable from this server.",
                   "needs-key": "Its URL still contains YOUR_KEY, so every download fails.",
                   "empty": "The last download contained no addresses, so the list is dead or the URL now returns an error page.",
                   "stale": f"It was last updated {f.get('age_h', '?')} hours ago, well past its refresh interval, so downloads are failing."}[f["health"]]
            how = {"never": "Restart LFD with “Apply safely” and check again in a few minutes. If it stays empty, test the URL from the server.",
                   "needs-key": "Open Blocklist Feeds and put your real key in the URL, or disable the feed.",
                   "empty": "Check the URL on the Blocklist Feeds page; if the list has been discontinued, disable it.",
                   "stale": "Check the URL and that outbound HTTPS is allowed; disable the feed if the list no longer exists."}[f["health"]]
            items.append({"status": "warn", "weight": 2, "link": "/blocklist-feeds", "fix": {"action": "disable_feed", "name": f["name"]},
                          "id": "firewall-rules-loopholes:feed-" + f["name"].lower(),
                          "title": f"Blocklist feed {f['name']} is enabled but not working",
                          "detail": "A feed that is switched on but has no fresh data blocks nothing. " + why, "how": how})
        if not bad and not any(f["enabled"] for f in feeds):
            items.append({"status": "info", "weight": 1, "link": "/blocklist-feeds",
                          "title": "No blocklist feed enabled",
                          "detail": "Free feeds such as Spamhaus DROP block known-bad networks before they ever reach your services."})
    except Exception:
        pass
    for key, label in (("LF_DIRWATCH", "watching /tmp for suspicious files"), ("LF_INTEGRITY", "system binary integrity checks")):
        if csf.get(key, "0") == "0":
            items.append({"status": "info", "weight": 1, "setting": key, "fix_value": "300" if key == "LF_DIRWATCH" else "3600",
                          "title": f"{key} is off: not {label}",
                          "detail": "LFD can alert you when exploit files appear in /tmp or when system binaries change."})
    if csf.get("LF_SSH_EMAIL_ALERT", "1") == "0" and (csf.get("LF_ALERT_TO") or "").strip():
        items.append({"status": "info", "weight": 1, "setting": "LF_SSH_EMAIL_ALERT", "fix_value": "1",
                      "title": "No alert on SSH logins", "detail": "Get an email whenever someone logs in by SSH, so an unexpected login is noticed."})
    if csf.get("LF_SU_EMAIL_ALERT", "1") == "0" and (csf.get("LF_ALERT_TO") or "").strip():
        items.append({"status": "info", "weight": 1, "setting": "LF_SU_EMAIL_ALERT", "fix_value": "1",
                      "title": "No alert on su / sudo to root"})
    if (csf.get("LF_ALERT_TO") or "").strip():
        mailer = csf.get("SENDMAIL", "/usr/sbin/sendmail")
        if not os.path.exists(mailer) and not (csf.get("LF_ALERT_SMTP") or "").strip():
            items.append({"status": "warn", "weight": 2, "link": "/email-alerts",
                          "title": "Alert email is set but no mailer exists to send it",
                          "detail": f"{mailer} is missing and LF_ALERT_SMTP is empty, so LFD alerts are silently dropped.",
                          "how": "Configure an SMTP server on the Email Alerts page, or clear LF_ALERT_TO and use a Telegram/Slack/Discord channel instead."})
    return items


def _docker(csf, listening, tcp_in):
    items = []
    if not _run(["docker", "info", "--format", "{{.ID}}"], timeout=15):
        return items
    try:
        from csf_backend import docker_manager
        exposure = docker_manager.get_exposure_map()
    except Exception:
        exposure = {"rows": [], "open_count": 0}
    public_rows = [r for r in exposure["rows"] if r["reach"] == "internet" and not r["is_proxy"]]
    not_in_tcp = [r for r in public_rows if not r["in_tcp_in"]]
    if not_in_tcp:
        items.append({"status": "warn", "weight": 2, "link": "/docker#exposure",
                      "title": f"{len(not_in_tcp)} container port{'s' if len(not_in_tcp) > 1 else ''} reachable from the internet outside TCP_IN",
                      "detail": "Docker publishes ports past the normal firewall rules. These are open even though TCP_IN does not list them: "
                                + ", ".join(f"{r['container']}:{r['port']}" for r in not_in_tcp[:6]) + ". Restrict the ones that only need the proxy or other containers."})
    elif exposure["rows"]:
        items.append({"status": "pass", "title": "No container port is exposed outside TCP_IN"})
    for r in public_rows:
        p = str(r["port"])
        if p in DB_PORTS or str(r.get("cport")) in DB_PORTS:
            label = DB_PORTS.get(p) or DB_PORTS.get(str(r.get("cport")))
            items.append({"status": "fail", "weight": 3, "fix": {"action": "restrict_port", "port": r["port"], "proto": r["proto"]},
                          "title": f"{label} in container {r['container']} is reachable from the internet on port {p}",
                          "detail": "Databases and caches should never be public; most have weak or no default authentication. Restrict keeps it reachable from other containers and localhost only."})
        elif p in PANEL_PORTS and not r.get("behind_proxy"):
            items.append({"status": "warn", "weight": 2, "fix": {"action": "restrict_port", "port": r["port"], "proto": r["proto"]},
                          "title": f"Admin panel ({PANEL_PORTS[p]}) on port {p} is open to the internet",
                          "detail": "Put it behind the reverse proxy with HTTPS, or restrict the port to your IP."})
    # host-level services too
    for p, (bind, proc, public) in listening.items():
        if public and p in DB_PORTS and p in tcp_in:
            items.append({"status": "fail", "weight": 3, "link": "/ports", "fix": {"action": "remove_ports", "ports": [p]},
                          "title": f"{DB_PORTS[p]} ({proc or 'host service'}) listens on all interfaces and port {p} is in TCP_IN",
                          "detail": "The database answers to the whole internet.",
                          "how": f"Remove {p} from TCP_IN with the button (apps on this server and in containers still reach it), or bind the service to 127.0.0.1 in its own config."})
    ids = _run(["docker", "ps", "-q"], timeout=15).split()
    if ids:
        info = _docker_json(["inspect"] + ids[:200])
        sock, priv, caps, dapi = [], [], [], []
        for c in info:
            name = (c.get("Name") or "").lstrip("/")
            for m in c.get("Mounts") or []:
                if (m.get("Source") or "").rstrip("/") in ("/var/run/docker.sock", "/run/docker.sock"):
                    sock.append(name)
            hc = c.get("HostConfig") or {}
            if hc.get("Privileged"):
                priv.append(name)
            if any(x in ("NET_ADMIN", "SYS_ADMIN", "ALL") for x in (hc.get("CapAdd") or [])):
                caps.append(name)
        if sock:
            proxyish = [n for n in sock if any(h in n.lower() for h in ("coolify", "traefik", "caddy", "portainer", "watchtower", "dokploy"))]
            others = [n for n in sock if n not in proxyish]
            if others:
                items.append({"status": "fail", "weight": 3, "link": "/docker",
                              "title": "Containers with the Docker socket mounted: " + ", ".join(others[:5]),
                              "detail": "Access to /var/run/docker.sock is root on the host. Only orchestration tools should have it.",
                              "how": "Remove the socket volume from the container's compose file, or use a socket proxy (e.g. tecnativa/docker-socket-proxy) that exposes only the API calls it needs. If this container is your orchestrator, accept the finding."})
            if proxyish:
                items.append({"status": "info", "weight": 1,
                              "title": "Orchestration containers with Docker socket access: " + ", ".join(proxyish[:5]),
                              "detail": "Expected for Coolify/Traefik/Portainer, but keep them updated: a bug there is a root bug."})
        if priv:
            items.append({"status": "warn", "weight": 2, "link": "/docker",
                          "title": "Privileged containers: " + ", ".join(priv[:5]),
                          "detail": "--privileged disables container isolation.",
                          "how": "Remove privileged: true from the compose file and add only the capabilities the app needs under cap_add. Accept this if the container must manage hardware or the network."})
        if caps:
            items.append({"status": "info", "weight": 1, "title": "Containers with NET_ADMIN/SYS_ADMIN: " + ", ".join(caps[:5])})
    for p in ("2375", "2376"):
        if p in listening and listening[p][2]:
            items.append({"status": "fail", "weight": 3,
                          "title": f"Docker API is listening on TCP port {p}",
                          "detail": "Anyone who can reach it controls every container as root." + (" Port 2375 is also unencrypted." if p == "2375" else ""),
                          "how": "Remove the -H tcp://... option from the Docker daemon (daemon.json or the systemd unit) and use the Unix socket. If a remote tool needs it, allow only its IP in csf.allow and keep the port out of TCP_IN."})
    if csf.get("DOCKER", "0") == "1":
        chains = _run(["iptables", "-S", "DOCKER-USER"])
        if not chains:
            items.append({"status": "fail", "weight": 3, "link": "/docker",
                          "title": "DOCKER mode is on but the DOCKER-USER chain is missing",
                          "detail": "CSF cannot filter container traffic without it.",
                          "how": "Restart the firewall with “Apply safely”. If the chain is still missing, check that Docker is running and that /etc/csf/csfpost.sh exists and is executable."})
    ipfwd = _read("/proc/sys/net/ipv4/ip_forward").strip()
    if ipfwd == "1" and not ids and csf.get("DOCKER", "0") != "1":
        items.append({"status": "info", "weight": 1, "title": "IP forwarding is enabled but nothing uses it",
                      "detail": "Docker and WireGuard need it; otherwise set net.ipv4.ip_forward = 0."})
    return items


def _accounts(sshd):
    items = []
    for key, bad, fixv, title, detail, w in (
        ("permitemptypasswords", "yes", "no", "Empty passwords are allowed for SSH", "Any account without a password can log in.", 3),
        ("permituserenvironment", "yes", "no", "SSH users may set their own environment", "Lets a compromised key run arbitrary code at login. Disable it.", 2),
        ("allowtcpforwarding", "yes", "no", "SSH TCP forwarding is enabled", "A stolen SSH login can then tunnel to internal services and containers. Disable unless you use SSH tunnels.", 1),
        ("allowagentforwarding", "yes", "no", "SSH agent forwarding is enabled", "A compromised server can then use your local keys. Disable it.", 1),
    ):
        val = sshd.get(key, "yes" if key not in ("permitemptypasswords", "permituserenvironment") else "no").lower()
        if val == bad:
            items.append({"status": "fail" if w == 3 else "warn" if w == 2 else "info", "weight": w,
                          "setting": {"permitemptypasswords": "PermitEmptyPasswords", "permituserenvironment": "PermitUserEnvironment",
                                      "allowtcpforwarding": "AllowTcpForwarding", "allowagentforwarding": "AllowAgentForwarding"}[key],
                          "fix_value": fixv, "title": title, "detail": detail})
    try:
        grace = sshd.get("logingracetime", "120")
        secs = int(re.sub(r"[^\d]", "", grace) or 120) * (60 if grace.endswith("m") else 1)
        if secs > 60:
            items.append({"status": "info", "weight": 1, "setting": "LoginGraceTime", "fix_value": "30",
                          "title": f"SSH LoginGraceTime is {grace}", "detail": "Unauthenticated connections may stay open this long, which helps connection-exhaustion attacks. 30 seconds is plenty."})
    except ValueError:
        pass
    if sshd.get("clientaliveinterval", "0") in ("0", ""):
        items.append({"status": "info", "weight": 1, "setting": "ClientAliveInterval", "fix_value": "300",
                      "title": "Idle SSH sessions never time out", "detail": "Set ClientAliveInterval so a forgotten session on a shared machine is closed."})
    if not sshd.get("allowusers") and not sshd.get("allowgroups"):
        items.append({"status": "info", "weight": 1,
                      "title": "SSH does not restrict which accounts may log in",
                      "detail": "Service accounts could be used for SSH if their password leaks.",
                      "how": "Add a line such as “AllowUsers root deploy” to /etc/ssh/sshd_config and run “systemctl reload ssh”. Test a new login in a second terminal before closing the current one."})
    # system accounts
    passwd = _read("/etc/passwd")
    uid0 = [l.split(":")[0] for l in passwd.splitlines() if l.count(":") >= 6 and l.split(":")[2] == "0" and l.split(":")[0] != "root"]
    if uid0:
        items.append({"status": "fail", "weight": 3, "title": "Extra accounts with UID 0 (root power): " + ", ".join(uid0),
                      "detail": "Only root should have UID 0.",
                      "how": "Run “userdel <name>” for accounts you do not recognise, or give a legitimate admin a normal UID and sudo rights instead."})
    shadow = _read("/etc/shadow")
    if shadow:
        empty = [l.split(":")[0] for l in shadow.splitlines() if l.count(":") >= 2 and l.split(":")[1] == ""]
        if empty:
            items.append({"status": "fail", "weight": 3, "title": "Accounts with an empty password: " + ", ".join(empty[:5]),
                          "detail": "Anyone can log in as these users without a password.",
                          "how": "Lock each one with “passwd -l <user>”, or set a password with “passwd <user>”."})
        login_shells = {l.split(":")[0] for l in passwd.splitlines() if l.count(":") >= 6 and l.split(":")[6].rstrip() in ("/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/zsh")}
        pw_users = [l.split(":")[0] for l in shadow.splitlines() if l.count(":") >= 2 and l.split(":")[1] not in ("", "*", "!", "!!") and not l.split(":")[1].startswith("!")]
        pw_shell = sorted(set(pw_users) & login_shells)
        if len(pw_shell) > 3:
            items.append({"status": "info", "weight": 1, "title": f"{len(pw_shell)} accounts have a password and a login shell",
                          "detail": ", ".join(pw_shell[:8]) + ". Each is a brute-force target if password SSH login is on."})
    keys = _read("/root/.ssh/authorized_keys")
    nkeys = sum(1 for l in keys.splitlines() if l.strip() and not l.startswith("#"))
    if nkeys > 3:
        items.append({"status": "info", "weight": 1, "title": f"root has {nkeys} authorised SSH keys",
                      "detail": "Review /root/.ssh/authorized_keys and remove keys of people or machines that no longer need access."})
    sudo_text = _read("/etc/sudoers") + "".join(_read(os.path.join("/etc/sudoers.d", f)) for f in (os.listdir("/etc/sudoers.d") if os.path.isdir("/etc/sudoers.d") else []))
    nopass = [l.strip() for l in sudo_text.splitlines() if "NOPASSWD" in l and not l.strip().startswith("#") and "ALL" in l]
    if nopass:
        items.append({"status": "warn", "weight": 2, "title": f"{len(nopass)} sudo rule{'s' if len(nopass) > 1 else ''} allow root without a password",
                      "detail": "A stolen SSH key for that user is then full root with no second hurdle: " + "; ".join(nopass[:2])[:160],
                      "how": "Edit the rule with “visudo” (or the file in /etc/sudoers.d) and remove NOPASSWD:, or limit it to the exact commands an automation user needs. Accept it if this is a deploy user that must run unattended."})
    return items


def _csf_eui(csf, listening, tcp_in):
    items = []
    try:
        from csf_backend import auth
        conf = auth.load_auth_config()
        users = conf.get("users", {})
        admins = [u for u, d in users.items() if d.get("role", "admin") == "admin"]
        for u, d in users.items():
            if u == "admin" and auth.verify_password("admin", d.get("password", "")):
                items.append({"status": "fail", "weight": 3, "link": "/settings",
                              "title": "The admin account still uses the default password",
                              "detail": "Change it on the Settings page now."})
        no2fa = [u for u in admins if not (users[u].get("totp") or {}).get("enabled")]
        if no2fa:
            items.append({"status": "warn", "weight": 2, "link": "/settings",
                          "title": "Admin accounts without two-factor authentication: " + ", ".join(no2fa),
                          "detail": "With 2FA a leaked password alone is not enough to control the firewall."})
        else:
            items.append({"status": "pass", "title": "All admin accounts use two-factor authentication"})
        if len(admins) > 2:
            items.append({"status": "info", "weight": 1, "link": "/settings",
                          "title": f"{len(admins)} accounts have full admin rights",
                          "detail": "Give people who only need to look the viewer role."})
    except Exception:
        pass
    try:
        from csf_backend import api_tokens
        stale = [t["name"] for t in api_tokens.list_tokens()
                 if (not t.get("last_used") or time.time() - t["last_used"] > 90 * 86400) and time.time() - t.get("created", time.time()) > 90 * 86400]
        if stale:
            items.append({"status": "info", "weight": 1, "link": "/settings",
                          "title": "API tokens unused for 90 days: " + ", ".join(stale[:5]),
                          "detail": "Revoke tokens nobody uses; each is a password that never expires."})
    except Exception:
        pass
    try:
        from csf_backend import ssl_manager
        st = ssl_manager.get_ssl_status()
        cert = st.get("current_cert") or {}
        if st.get("self_signed"):
            items.append({"status": "info", "weight": 1, "link": "/ssl",
                          "title": "The control panel uses a self-signed certificate",
                          "detail": "Browsers warn every time and you cannot tell a fake page from the real one. Get a free Let's Encrypt or ZeroSSL certificate on the SSL page."})
        exp = cert.get("expiry")
        if exp:
            try:
                from datetime import datetime
                dt = datetime.strptime(exp.replace("  ", " "), "%b %d %H:%M:%S %Y %Z")
                days = (dt - datetime.utcnow()).days
                if days < 14:
                    items.append({"status": "fail" if days < 3 else "warn", "weight": 2, "link": "/ssl",
                                  "title": f"Control panel certificate expires in {days} day{'s' if days != 1 else ''}"})
            except ValueError:
                pass
    except Exception:
        pass
    try:
        from csf_backend import backup_restore, remote_backup
        backups = backup_restore.list_backups()
        newest = max((b.get("created", "") for b in backups), default="")
        age_days = None
        if newest:
            from datetime import datetime
            age_days = (datetime.now() - datetime.strptime(newest, "%Y-%m-%d %H:%M:%S")).days
        if age_days is None or age_days > 30:
            items.append({"status": "warn", "weight": 2, "link": "/backup-restore",
                          "title": "No firewall backup in the last 30 days" if age_days is not None else "No firewall backup has ever been made",
                          "detail": "A backup lets you restore every rule and list in one click after a mistake or a rebuild."})
        if not remote_backup.load().get("enabled"):
            items.append({"status": "info", "weight": 1, "link": "/backup-restore",
                          "title": "Backups are only kept on this server",
                          "detail": "If the server is lost, so are they. Configure an off-server copy (SFTP, WebDAV or rclone) on the Backups page."})
    except Exception:
        pass
    try:
        from csf_backend import updater, auto_update
        vi = updater.get_version_info()
        if vi.get("update_available"):
            items.append({"status": "warn", "weight": 2, "link": "/update",
                          "title": f"CSF-eUI update available ({vi['current']} → {vi['latest']})"})
        if not auto_update.load().get("auto_check", True):
            items.append({"status": "info", "weight": 1, "link": "/update", "title": "Update checks are switched off"})
    except Exception:
        pass
    try:
        from csf_backend import notifications
        nconf = notifications.load_config()
        ready = [n for n, ch in nconf.get("channels", {}).items() if ch.get("enabled") and notifications._channel_ready(n, ch)]
        if not ready and not (csf.get("LF_ALERT_TO") or "").strip():
            items.append({"status": "warn", "weight": 2, "link": "/notifications",
                          "title": "No way to reach you: no alert email and no notification channel",
                          "detail": "Blocks, outages and rollbacks happen silently. Set LF_ALERT_TO or connect Telegram/Slack/Discord."})
    except Exception:
        pass
    return items


def _system(csf, listening, tcp_in):
    items = []
    if os.path.exists("/var/run/reboot-required"):
        pkgs = _read("/var/run/reboot-required.pkgs").split()
        items.append({"status": "warn", "weight": 2,
                      "title": "A reboot is needed to finish installing updates" + (f" ({', '.join(pkgs[:3])})" if pkgs else ""),
                      "detail": "Until then the old kernel or libraries (with their known holes) are still running.",
                      "how": "Reboot at a quiet time: “reboot” over SSH. Containers with a restart policy come back by themselves."})
    for key, want in SYSCTL_SAFE.items():
        path = "/proc/sys/" + key.replace(".", "/")
        cur = _read(path).strip()
        if cur and cur != want:
            if key.startswith("net.ipv6") and not os.path.exists("/proc/net/if_inet6"):
                continue
            items.append({"status": "warn" if key in ("net.ipv4.tcp_syncookies", "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.accept_redirects") else "info",
                          "weight": 2 if key in ("net.ipv4.tcp_syncookies", "net.ipv4.conf.all.rp_filter") else 1,
                          "fix": {"action": "sysctl", "key": key, "value": want},
                          "title": f"Kernel setting {key} is {cur} (recommended {want})",
                          "detail": {"net.ipv4.tcp_syncookies": "Protects against SYN floods at the kernel level.",
                                     "net.ipv4.conf.all.rp_filter": "Drops packets with spoofed source addresses.",
                                     "net.ipv4.conf.all.accept_redirects": "Stops attackers on the network from rerouting your traffic.",
                                     "net.ipv4.conf.all.send_redirects": "A server should not send ICMP redirects.",
                                     "net.ipv4.conf.all.accept_source_route": "Source-routed packets are only used for spoofing.",
                                     "net.ipv4.conf.all.log_martians": "Logs packets with impossible addresses so LFD can see probes.",
                                     "kernel.kptr_restrict": "Hides kernel addresses from unprivileged users (exploit mitigation).",
                                     "kernel.dmesg_restrict": "Hides kernel logs from unprivileged users.",
                                     "fs.protected_hardlinks": "Prevents hard-link based privilege escalation in /tmp.",
                                     "fs.protected_symlinks": "Prevents symlink based privilege escalation in /tmp."}.get(key, "")})
    # services on all interfaces that are only needed locally
    for p, (bind, proc, public) in listening.items():
        if public and p in DB_PORTS and p not in tcp_in:
            items.append({"status": "info", "weight": 1,
                          "title": f"{DB_PORTS[p]} ({proc or 'service'}) listens on all interfaces (port {p})",
                          "detail": "The firewall blocks it today, but one wrong TCP_IN edit would expose it.",
                          "how": "Set the service's bind address to 127.0.0.1 (e.g. bind-address in my.cnf, bind in redis.conf, listen_addresses in postgresql.conf) and restart it."})
    # /tmp noexec
    mounts = _read("/proc/mounts")
    tmp = next((l for l in mounts.splitlines() if l.split()[1:2] == ["/tmp"]), "")
    if tmp and "noexec" not in tmp:
        items.append({"status": "info", "weight": 1, "title": "/tmp is mounted without noexec",
                      "detail": "Most drop-and-run malware executes from /tmp.",
                      "how": "Add noexec,nosuid,nodev to the /tmp line in /etc/fstab and run “mount -o remount /tmp”. Some package installs need exec in /tmp; remount without noexec for those."})
    # world-writable config files
    ww = []
    for d in ("/etc/csf", "/etc/csfv2", "/etc/ssh"):
        try:
            for fn in os.listdir(d):
                fp = os.path.join(d, fn)
                if os.path.isfile(fp) and os.stat(fp).st_mode & 0o002:
                    ww.append(fp)
        except OSError:
            pass
    if ww:
        items.append({"status": "fail", "weight": 3, "title": "World-writable configuration files: " + ", ".join(ww[:4]),
                      "detail": "Any local user or container with a host mount could rewrite firewall rules.",
                      "how": "Run “chmod o-w <file>” on each one, then check which process created them with those permissions."})
    for fp, maxmode in CHMOD_SAFE.items():
        try:
            mode = os.stat(fp).st_mode & 0o777
            if mode & ~maxmode:
                items.append({"status": "warn", "weight": 2, "fix": {"action": "chmod", "path": fp, "mode": oct(maxmode)[2:]},
                              "title": f"{fp} is readable by other users (mode {oct(mode)[2:]})",
                              "detail": "Password hashes or tokens inside it could be read by any local account.",
                              "how": f"Set it to {oct(maxmode)[2:]} with the button."})
        except OSError:
            pass
    # time sync
    ts = _run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    if ts and ts.strip() == "no":
        items.append({"status": "warn", "weight": 2, "fix": {"action": "ntp"}, "title": "The clock is not synchronised (NTP off)",
                      "detail": "Two-factor codes, certificate checks and log timestamps all depend on the right time.",
                      "how": "Switch NTP on with the button (runs timedatectl set-ntp true). If it stays unsynchronised, allow UDP port 123 outbound."})
    # logging
    for svc in ("rsyslog", "systemd-journald"):
        if _run(["systemctl", "is-active", svc]).strip() == "active":
            break
    else:
        items.append({"status": "fail", "weight": 3, "title": "No system logger is running (rsyslog / journald)",
                      "detail": "LFD reads logs to detect attacks. Without a logger it is blind.",
                      "how": "Run “systemctl enable --now rsyslog” (or systemd-journald) and restart LFD."})
    try:
        size = os.path.getsize("/var/log/lfd.log")
        if size > 200 * 1024 * 1024:
            items.append({"status": "warn", "weight": 2, "title": f"lfd.log is {size // (1024 * 1024)} MB",
                          "detail": "Log rotation is not working for /var/log/lfd.log. Large logs slow analytics and can fill the disk.",
                          "how": "Run “logrotate -f /etc/logrotate.d/lfd” and check that the logrotate timer is active (systemctl status logrotate.timer)."})
    except OSError:
        pass
    if not os.path.exists("/etc/logrotate.d/lfd") and not any("lfd" in _read(os.path.join("/etc/logrotate.d", f)) for f in (os.listdir("/etc/logrotate.d") if os.path.isdir("/etc/logrotate.d") else [])):
        items.append({"status": "info", "weight": 1, "title": "No logrotate rule for lfd.log",
                      "detail": "CSF usually installs one.",
                      "how": "Create /etc/logrotate.d/lfd containing: /var/log/lfd.log { weekly rotate 4 compress missingok notifempty }"})
    # disk space
    try:
        st = os.statvfs("/")
        free_pct = st.f_bavail * 100 // max(st.f_blocks, 1)
        if free_pct < 10:
            items.append({"status": "fail" if free_pct < 5 else "warn", "weight": 2,
                          "title": f"Root filesystem has only {free_pct}% free",
                          "detail": "When the disk fills, LFD stops logging and blocking, and the UI cannot save changes.",
                          "how": "Free space with “docker system prune”, “apt clean” and “journalctl --vacuum-size=200M”, then look for large logs with “du -xh / | sort -h | tail”."})
    except OSError:
        pass
    return items


def run(csf, sshd):
    """Return extra categories for run_full_check()."""
    listening = _listening()
    tcp_in = set(_ports(csf.get("TCP_IN")))
    cats = []
    for name, fn in (("Firewall Rules & Loopholes", lambda: _firewall_rules(csf, listening)),
                     ("Docker & Containers", lambda: _docker(csf, listening, tcp_in)),
                     ("Accounts & Access", lambda: _accounts(sshd)),
                     ("CSF-eUI Itself", lambda: _csf_eui(csf, listening, tcp_in)),
                     ("System Hardening", lambda: _system(csf, listening, tcp_in))):
        try:
            items = fn()
        except Exception as e:  # one broken probe must not kill the whole report
            items = [{"status": "info", "weight": 1, "title": f"Check group could not run: {e}"}]
        if items:
            cats.append({"category": name, "items": items})
    return cats
