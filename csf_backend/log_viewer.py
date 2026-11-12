import os
import re
import time
import datetime
import subprocess
from collections import defaultdict


LOG_FILES = {
    "lfd": "/var/log/lfd.log",
    "auth": "/var/log/auth.log",
    "syslog": "/var/log/syslog",
    "kern": "/var/log/kern.log",
    "iptables": "/var/log/messages",
}

# Plain-English names shown in the Log File dropdown
LOG_LABELS = {
    "lfd": "Firewall activity (LFD)",
    "auth": "Logins & sudo (auth.log)",
    "syslog": "System messages (syslog)",
    "kern": "Kernel & dropped packets (kern.log)",
    "iptables": "General messages",
}

MAX_LINES = 2000

# Filter categories shown in the page; the value is the label
CATEGORIES = {
    "block": "Blocks & attacks",
    "login": "Logins",
    "process": "Process checks",
    "service": "Service start/stop",
    "change": "File & account changes",
    "other": "Other",
}

# Human names for well-known ports, used in dropped-packet explanations
PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP mail", 53: "DNS", 80: "HTTP web",
    110: "POP3 mail", 123: "NTP time", 143: "IMAP mail", 443: "HTTPS web", 445: "SMB file sharing",
    465: "SMTPS mail", 587: "mail submission", 993: "IMAPS mail", 995: "POP3S mail",
    1433: "MS SQL", 2375: "Docker API", 2376: "Docker API (TLS)", 3306: "MySQL", 3389: "Remote Desktop",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "web (8000)", 8080: "web (8080)",
    8443: "web (8443)", 8750: "this control panel", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB", 51820: "WireGuard VPN",
}

_IPV4 = r'(\d{1,3}(?:\.\d{1,3}){3})'

_SYSLOG_RE = re.compile(
    r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    r'|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)'
    r'\s+(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$'
)


def _tail(path, lines=200):
    if not os.path.isfile(path):
        return []
    try:
        r = subprocess.run(
            ["tail", "-n", str(lines), path],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip().split("\n") if r.stdout.strip() else []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Line parsing helpers
# ---------------------------------------------------------------------------

def _split_line(line):
    m = _SYSLOG_RE.match(line)
    if not m:
        return {"ts": "", "host": "", "proc": "", "pid": "", "msg": line}
    return m.groupdict(default="")


def _parse_ts(ts):
    """Return epoch seconds for a syslog or ISO timestamp, or None."""
    if not ts:
        return None
    try:
        if ts[0].isdigit():
            s = ts
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            s = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', s)
            return datetime.datetime.fromisoformat(s).timestamp()
        now = datetime.datetime.now()
        dt = datetime.datetime.strptime(f"{now.year} {ts}", "%Y %b %d %H:%M:%S")
        if dt > now + datetime.timedelta(days=1):
            dt = dt.replace(year=now.year - 1)
        return dt.timestamp()
    except Exception:
        return None


def _display_time(ts, epoch):
    """Return (date, clock) strings such as ('Nov 12', '14:03:14')."""
    if epoch is not None:
        dt = datetime.datetime.fromtimestamp(epoch)
        return dt.strftime("%b %d").replace(" 0", " "), dt.strftime("%H:%M:%S")
    if ts:
        parts = ts.split()
        if len(parts) == 3:
            return f"{parts[0]} {parts[1]}", parts[2]
    return "", ts


def _ago(epoch):
    if epoch is None:
        return ""
    d = max(0, int(time.time() - epoch))
    if d < 60:
        return "just now"
    if d < 3600:
        return f"{d // 60} min ago"
    if d < 86400:
        h = d // 3600
        return f"{h} hr ago"
    days = d // 86400
    return f"{days} day{'s' if days != 1 else ''} ago"


def _duration(seconds):
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    if s < 60:
        return f"{s} sec"
    if s < 3600:
        return f"{s // 60} min"
    if s < 86400:
        h, m = divmod(s, 3600)
        return f"{h} hr" + (f" {m // 60} min" if m // 60 else "")
    d, rem = divmod(s, 86400)
    h = rem // 3600
    return f"{d} day{'s' if d != 1 else ''}" + (f" {h} hr" if h else "")


def _parse_ip(line):
    m = re.search(_IPV4, line)
    return m.group(1) if m else None


def _country(text):
    """'US/United States/-' -> ' in United States'; '-/-/-' -> ''."""
    if not text:
        return ""
    parts = text.split("/")
    name = parts[1].strip() if len(parts) > 1 else ""
    if name and name != "-":
        return f" in {name}"
    return ""


def _strip_stars(msg):
    return re.sub(r'\*([^*]+)\*', r'\1', msg).strip()


def _block_phrase(rest):
    """Explain the trailing '- *Blocked in csf* for 3600 secs [LF_SSHD]' part."""
    low = rest.lower()
    if "*blocked in csf*" in low or "*blocked*" in low or "*perm block*" in low:
        m = re.search(r'for (\d+) secs', rest)
        tag = re.search(r'\[([A-Z_0-9]+)\]', rest)
        tagtxt = f" (rule {tag.group(1)})" if tag else ""
        if m:
            return f" The IP has been blocked for {_duration(m.group(1))}{tagtxt}."
        return f" The IP has been blocked permanently{tagtxt}."
    if "ignored" in low or "*ignore*" in low:
        return " Not blocked, because this IP is on the ignore/allow list."
    return ""


def _proc_fields(msg):
    f = {}
    for key in ("PID", "PPID", "Kill", "User", "Time", "EXE", "Mem", "Count", "Load"):
        m = re.search(rf'\b{key}:(\S+)', msg)
        if m:
            f[key] = m.group(1)
    m = re.search(r'CMD:(.*)$', msg)
    if m:
        f["CMD"] = m.group(1).strip()
    return f


_INTERPRETERS = re.compile(r'^(python[\d.]*|perl[\d.]*|node(js)?|ruby[\d.]*|php[\d.]*|bash|sh|dash|zsh|java)$')


def _proc_sentence(f, verb):
    exe = os.path.basename(f.get("EXE", ""))
    cmd_parts = f.get("CMD", "").split()
    if not exe and cmd_parts:
        exe = os.path.basename(cmd_parts[0])
    if not exe:
        exe = "a process"
    elif _INTERPRETERS.match(exe) and len(cmd_parts) > 1 and not cmd_parts[1].startswith("-"):
        exe = f"{os.path.basename(cmd_parts[1])} (a {exe} program)"
    user = f.get("User", "")
    s = f"{verb} {exe}"
    if user:
        s += f" run by user {user}"
    if f.get("Time"):
        s += f", running for {_duration(f['Time'])}"
    if f.get("Mem"):
        s += f", using {f['Mem']} MB of memory"
    s += "."
    kill = f.get("Kill")
    if kill == "0":
        s += " LFD only reported it; nothing was stopped."
    elif kill == "1":
        s += " LFD stopped (killed) the process."
    return s


# ---------------------------------------------------------------------------
# Explainers: each returns (kind, text, level, category) or None
#   level: bad | warn | ok | info
# ---------------------------------------------------------------------------

def _explain_lfd(msg):
    low = msg.lower()

    m = re.search(r'\*SSH login\* from (\S+) into the (\S+) account using (\S+) authentication(.*)', msg, re.I)
    if m:
        ip, user, method, rest = m.groups()
        how = "an SSH key" if "publickey" in method.lower() else "a password" if "password" in method.lower() else method
        text = f"{user} logged in over SSH from {ip} using {how}."
        if "ignored" in rest.lower():
            text += " LFD noted it but sent no alert, because this IP or login type is set to be ignored."
        else:
            text += " LFD sent a login alert email."
        level = "ok" if "publickey" in method.lower() else "warn"
        return ("SSH login", text, level, "login")

    m = re.search(r'\((\w+)\) Failed (.+?) from (\S+) \(([^)]*)\): (\d+) in the last (\d+) secs(.*)', msg)
    if m:
        svc, what, ip, cc, n, secs, rest = m.groups()
        text = f"{n} failed {what} attempts from {ip}{_country(cc)} in the last {_duration(secs)}." + _block_phrase(rest)
        blocked = "*blocked" in rest.lower()
        return ("Blocked" if blocked else "Failed logins", text, "bad" if blocked else "warn", "block")

    m = re.search(r'\*Port Scan\* detected from (\S+) \(([^)]*)\)\. (\d+) hits in the last (\d+) seconds(.*)', msg, re.I)
    if m:
        ip, cc, n, secs, rest = m.groups()
        text = f"Port scan from {ip}{_country(cc)}: {n} connection attempts to closed ports in {_duration(secs)}." + _block_phrase(rest)
        return ("Port scan", text, "bad", "block")

    m = re.search(r'\(CT\) IP (\S+) \(([^)]*)\) found to have (\d+) connections(.*)', msg)
    if m:
        ip, cc, n, rest = m.groups()
        text = f"{ip}{_country(cc)} had {n} connections open at once, more than the allowed limit." + _block_phrase(rest)
        return ("Too many connections", text, "bad", "block")

    if "distributed" in low and "attack" in low:
        return ("Distributed attack", _strip_stars(msg) + " Failed logins for one account came from several IPs at once, which looks like a coordinated attack." + _block_phrase(msg), "bad", "block")

    m = re.search(r'\*System Integrity\* has detected modified file\(s\): (.*)', msg, re.I)
    if m:
        files = m.group(1).strip()
        text = (f"These system program files changed since the last check: {files}. "
                "This is expected right after a software update; if you did not update anything, find out why they changed.")
        return ("File change", text, "warn", "change")

    m = re.search(r'\*Directory Watching\* has detected a change in (.*)', msg, re.I)
    if m:
        return ("File change", f"A file changed inside a watched folder: {m.group(1).strip()}. LFD watches these folders for unexpected uploads.", "warn", "change")

    if "*suspicious file*" in low:
        return ("Suspicious file", _strip_stars(msg), "warn", "change")

    if "*user processing*" in low:
        f = _proc_fields(msg)
        text = ("Routine check: " + _proc_sentence(f, "found").replace("found ", "", 1)
                + " Long-running programs are listed by Process Tracking so you can spot anything unexpected; system services like this are normal.")
        return ("Process check", text, "info", "process")

    if "*suspicious process*" in low:
        return ("Suspicious process", _proc_sentence(_proc_fields(msg), "LFD flagged") + " Check that you recognise this program.", "warn", "process")

    if "excessive resource usage" in low:
        return ("High resource use", _proc_sentence(_proc_fields(msg), "Heavy resource use by"), "warn", "process")

    if "account" in low and any(w in low for w in ("modif", "creat", "delet", "chang")):
        return ("Account change", _strip_stars(msg) + " A user account on this server was added, removed or changed.", "warn", "change")

    if "load average" in low or "*load*" in low:
        return ("High load", _strip_stars(msg) + " The server was busier than the alert threshold allows.", "warn", "other")

    if "*relay*" in low or ("relay" in low and "mail" in low):
        return ("Mail relay", _strip_stars(msg) + " A lot of email was sent through this server.", "warn", "other")

    if "unblock" in low or ("removed" in low and "block" in low) or "*tempblock*" in low and "expire" in low:
        ip = _parse_ip(msg)
        return ("Unblocked", f"The temporary block on {ip or 'an IP'} expired and was lifted." if ip else _strip_stars(msg), "ok", "block")

    if "*blocked in csf*" in low or "*blocked*" in low or "*perm block*" in low:
        return ("Blocked", _strip_stars(re.sub(r'\s*-\s*\*Blocked.*$', '', msg, flags=re.I)) + "." + _block_phrase(msg), "bad", "block")

    if "blocklist" in low:
        bad = "error" in low or "fail" in low or "unable" in low
        m = re.search(r'Retrieving blocklist (\S+) from (\S+)', msg, re.I)
        if m and not bad:
            return ("Blocklist", f"LFD downloaded the {m.group(1)} blocklist feed (a list of known-bad IPs) from {m.group(2)}.", "info", "other")
        return ("Blocklist", _strip_stars(msg).rstrip(".") + ". " + ("A blocklist feed could not be downloaded, so the firewall keeps using the last copy." if bad else "This is a feed of known-bad IPs that CSF blocks automatically."), "bad" if bad else "info", "other")

    if "daemon started" in low or ("lfd" in low and "started" in low) or "started on" in low:
        return ("LFD started", "LFD (the firewall watchdog) started up.", "ok", "service")
    if "daemon stopped" in low or "stopping" in low or ("lfd" in low and "stopped" in low):
        return ("LFD stopped", "LFD (the firewall watchdog) was stopped.", "warn", "service")
    if "restarting" in low or "restart" in low:
        return ("Restart", _strip_stars(msg), "info", "service")
    if ("csf.conf" in low and "reload" in low) or "reloading" in low:
        return ("Reload", _strip_stars(msg) + " The firewall rules were reloaded.", "info", "service")

    if "*warning*" in low:
        return ("Warning", _strip_stars(msg), "warn", "other")
    if "*error*" in low or low.startswith("error"):
        return ("Error", _strip_stars(msg), "bad", "other")
    if "*ui*" in low or "csf ui" in low:
        return ("Panel", _strip_stars(msg), "info", "login")
    if "*cluster*" in low:
        return ("Cluster", _strip_stars(msg), "info", "service")
    return None


def _explain_auth(proc, msg):
    low = msg.lower()
    p = proc.lower()

    m = re.search(r'Accepted (\S+) for (\S+) from (\S+) port \d+', msg)
    if m:
        method, user, ip = m.groups()
        how = "an SSH key" if method == "publickey" else "a password" if method in ("password", "keyboard-interactive/pam") else method
        return ("SSH login", f"{user} logged in over SSH from {ip} using {how}.", "ok" if method == "publickey" else "warn", "login")

    m = re.search(r'Failed (\S+) for (invalid user )?(\S+) from (\S+)', msg)
    if m:
        method, invalid, user, ip = m.groups()
        text = f"Failed SSH login: wrong {'password' if method == 'password' else method} for '{user}' from {ip}."
        if invalid:
            text += " That username does not exist here, so this is almost certainly a bot guessing names."
        return ("Failed login", text, "warn", "login")

    m = re.search(r'Invalid user (\S*) from (\S+)', msg)
    if m:
        user, ip = m.groups()
        return ("Failed login", f"Someone at {ip} tried to log in over SSH as '{user or '(blank)'}', a username that does not exist here.", "warn", "login")

    m = re.search(r'maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+)', msg)
    if m:
        user, ip = m.groups()
        return ("Failed login", f"Too many failed login attempts for '{user}' from {ip}; SSH closed the connection.", "warn", "login")

    m = re.search(r'(?:Connection closed|Disconnected from|Received disconnect from)\s+(?:by\s+)?(?:(authenticating|invalid) user (\S+) )?(\S+) port \d+', msg)
    if m:
        state, user, ip = m.groups()
        if state:
            return ("Disconnect", f"{ip} gave up before finishing a login as '{user}'. Bots that probe SSH often do this.", "info", "login")
        return ("Disconnect", f"{ip} disconnected from SSH.", "info", "login")

    m = re.search(r'Did not receive identification string from (\S+)', msg)
    if m:
        return ("Probe", f"{m.group(1)} connected to the SSH port but never spoke SSH. Usually a scanner checking whether the port is open.", "info", "login")

    m = re.search(r'Unable to negotiate with (\S+) port \d+: no matching (.+?) found', msg)
    if m:
        return ("Incompatible client", f"An SSH client at {m.group(1)} uses an outdated encryption method ({m.group(2)}); the connection was refused.", "info", "login")

    m = re.search(r'pam_unix\((\S+?):session\): session (opened|closed) for user (\S+?)(?:\(|\s|$)', msg)
    if m:
        svc, state, user = m.groups()
        if svc == "cron":
            return ("Scheduled task", f"A scheduled task (cron) {'started' if state == 'opened' else 'finished'} running as {user}.", "info", "other")
        what = {"sshd": "SSH", "sudo": "sudo", "su": "su", "login": "console login", "systemd-user": "user services"}.get(svc, svc)
        return ("Session", f"{what} session {'started' if state == 'opened' else 'ended'} for {user}.", "info", "login")

    m = re.search(r'^\s*(\S+) :.*COMMAND=(.*)$', msg)
    if m and p == "sudo":
        return ("sudo", f"{m.group(1)} ran a command as administrator (sudo): {m.group(2).strip()}", "info", "login")
    if p == "sudo" and "incorrect password" in low:
        return ("sudo", "Someone typed a wrong password for sudo. " + _strip_stars(msg), "warn", "login")

    m = re.search(r'New session (\S+) of user (\S+)', msg)
    if m:
        return ("Session", f"New login session for {m.group(2)}.", "info", "login")
    m = re.search(r'Removed session (\S+)', msg)
    if m:
        return ("Session", "A login session ended.", "info", "login")

    if p in ("useradd", "usermod", "userdel", "groupadd", "groupdel", "passwd", "chpasswd", "chage"):
        return ("Account change", f"{proc}: {msg}", "warn", "change")
    if "authentication failure" in low:
        return ("Failed login", "A password check failed: " + msg, "warn", "login")
    if "session opened" in low:
        return ("Session", msg, "info", "login")
    return None


def _explain_kernel(msg):
    m = re.search(r'Firewall: \*(\w+?)(?: Blocked| Drop| Dropped)?\*.*?SRC=(\S+) DST=(\S+).*?PROTO=(\w+)(?:.*?SPT=(\d+) DPT=(\d+))?', msg)
    if not m:
        m2 = re.search(r'\bSRC=(\S+) DST=(\S+).*?PROTO=(\w+)(?:.*?SPT=(\d+) DPT=(\d+))?', msg)
        if not m2:
            return None
        src, dst, proto, spt, dpt = m2.groups()
        chain = ""
    else:
        chain, src, dst, proto, spt, dpt = m.groups()
    chain_up = (chain or "").upper()
    direction = "outgoing" if "OUT" in chain_up else "incoming"
    text = f"The firewall dropped an {direction} {proto} packet from {src}"
    if dpt:
        name = PORT_NAMES.get(int(dpt))
        text += f" to port {dpt}" + (f" ({name})" if name else "")
    text += "."
    level, kind = "info", "Dropped by firewall"
    if "SYNFLOOD" in chain_up:
        kind, level, text = "Flood protection", "warn", text + " It was part of a SYN flood (too many half-open connections)."
    elif "PORTFLOOD" in chain_up:
        kind, level, text = "Flood protection", "warn", text + " Too many new connections to that port in a short time."
    elif "CONNLIMIT" in chain_up:
        kind, level, text = "Connection limit", "warn", text + " That IP already had too many connections open."
    elif "INVALID" in chain_up:
        text += " The packet was malformed or did not belong to a known connection."
    elif "UDPFLOOD" in chain_up:
        kind, level = "Flood protection", "warn"
    elif direction == "incoming":
        text += " That port is not open in TCP_IN/UDP_IN, so this is the firewall doing its job."
    return (kind, text, level, "block")


def _explain_syslog(proc, msg):
    low = msg.lower()
    p = proc.lower()
    if p == "cron" or p == "crond":
        m = re.search(r'\((\S+)\) CMD \((.*)\)', msg)
        if m:
            return ("Scheduled task", f"Scheduled task ran as {m.group(1)}: {m.group(2).strip()}", "info", "other")
    if p == "systemd":
        if low.startswith("started "):
            return ("Service started", "Started: " + msg[8:].rstrip("."), "ok", "service")
        if low.startswith("stopped ") or low.startswith("stopping "):
            return ("Service stopped", msg.rstrip("."), "info", "service")
        if "failed" in low:
            return ("Service failed", msg.rstrip("."), "bad", "service")
        if low.startswith("starting "):
            return ("Service starting", msg.rstrip("."), "info", "service")
        if "reloaded" in low or "reloading" in low:
            return ("Service reload", msg.rstrip("."), "info", "service")
    if "out of memory" in low or "oom-killer" in low or "killed process" in low:
        return ("Out of memory", "The server ran out of memory and the kernel stopped a program: " + msg, "bad", "other")
    if "segfault" in low:
        return ("Program crash", "A program crashed: " + msg, "bad", "other")
    if "link is up" in low or "link up" in low:
        return ("Network", "A network link came up: " + msg, "ok", "other")
    if "link is down" in low or "link down" in low:
        return ("Network", "A network link went down: " + msg, "warn", "other")
    if p.startswith("dockerd") or p == "containerd":
        level = "bad" if "error" in low or "fail" in low else "warn" if "warn" in low else "info"
        return ("Docker", msg, level, "other")
    return None


def explain_line(line, logname="lfd"):
    """Turn one raw log line into a plain-English description.

    Returns a dict with: date, clock, ago, host, proc, msg, kind, text,
    level (bad|warn|ok|info), category, ip, raw.
    """
    parts = _split_line(line)
    msg = parts["msg"]
    proc = parts["proc"]
    epoch = _parse_ts(parts["ts"])
    date, clock = _display_time(parts["ts"], epoch)

    result = None
    plow = proc.lower()
    if plow == "lfd" or logname == "lfd":
        result = _explain_lfd(msg)
    if result is None and (plow in ("sshd", "sudo", "su", "cron", "systemd-logind", "login", "useradd", "usermod", "userdel", "passwd", "groupadd", "chpasswd") or logname == "auth"):
        result = _explain_auth(proc, msg)
    if result is None and (plow == "kernel" or "SRC=" in msg):
        result = _explain_kernel(msg)
    if result is None:
        result = _explain_syslog(proc, msg)
    if result is None and plow == "sshd":
        result = _explain_auth(proc, msg)

    if result is None:
        low = line.lower()
        if "*blocked" in low or "denied" in low:
            level, kind, cat = "bad", "Blocked", "block"
        elif "failed" in low or "error" in low or "fatal" in low:
            level, kind, cat = "bad", "Error", "other"
        elif "warning" in low or "warn" in low:
            level, kind, cat = "warn", "Warning", "other"
        elif "allow" in low or "success" in low or "started" in low:
            level, kind, cat = "ok", "OK", "other"
        else:
            level, kind, cat = "info", (proc or "Note"), "other"
        text = _strip_stars(msg) if msg else line
        if proc and proc.lower() not in ("lfd", "kernel") and kind in ("Note", proc):
            kind = proc
        result = (kind, text, level, cat)

    kind, text, level, cat = result
    return {
        "date": date,
        "clock": clock,
        "ago": _ago(epoch),
        "epoch": epoch,
        "host": parts["host"],
        "proc": proc,
        "msg": msg,
        "kind": kind,
        "text": text,
        "level": level,
        "category": cat,
        "ip": _parse_ip(line),
        "raw": line,
    }


_SEVERITY = {"bad": "danger", "warn": "warning", "ok": "success", "info": "info"}


def get_log(logname, lines=200, search="", category="all"):
    path = LOG_FILES.get(logname)
    if not path:
        return {"error": f"Unknown log: {logname}", "entries": []}

    try:
        lines = int(lines)
    except (TypeError, ValueError):
        lines = 200
    lines = max(10, min(lines, MAX_LINES))

    raw_lines = _tail(path, lines * 2 if search or category != "all" else lines)
    entries = []
    for line in raw_lines:
        if not line.strip():
            continue
        if search and search.lower() not in line.lower():
            continue
        ex = explain_line(line, logname)
        cat = ex["category"]
        if category != "all" and cat != category:
            continue

        entries.append({
            "text": line,
            "category": cat,
            "severity": _SEVERITY.get(ex["level"], "info"),
            "ip": ex["ip"],
            "date": ex["date"],
            "clock": ex["clock"],
            "ago": ex["ago"],
            "kind": ex["kind"],
            "plain": ex["text"],
            "level": ex["level"],
        })

    entries = entries[-lines:]

    stats = defaultdict(int)
    for e in entries:
        stats[e["category"]] += 1

    return {
        "logname": logname,
        "label": LOG_LABELS.get(logname, logname),
        "path": path,
        "entries": entries,
        "stats": dict(stats),
        "total": len(entries),
        "max_lines": MAX_LINES,
    }


def get_available_logs():
    return {k: v for k, v in LOG_FILES.items() if os.path.isfile(v)}
