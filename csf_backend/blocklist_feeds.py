"""Blocklist feed health: what csf.blocklists subscribes to, whether each feed is fetched, and how many IPs it adds."""
import os
import re
import time

BLOCKLISTS = "/etc/csf/csf.blocklists"
STATE_DIR = "/var/lib/csf"

# Well-known free feeds (name, interval secs, max ips, url, description)
PRESETS = {
    "SPAMDROP": (86400, 0, "https://www.spamhaus.org/drop/drop.txt", "Spamhaus DROP — hijacked and criminal networks. Safe to enable."),
    "SPAMEDROP": (86400, 0, "https://www.spamhaus.org/drop/edrop.txt", "Spamhaus EDROP — extended DROP list."),
    "DSHIELD": (86400, 0, "https://www.dshield.org/block.txt", "DShield — top attacking networks reported by sensors worldwide."),
    "TOR": (86400, 0, "https://check.torproject.org/exit-addresses", "Tor exit nodes — blocks anonymous Tor users (may block legitimate privacy-minded visitors)."),
    "BFB": (86400, 0, "https://danger.rulez.sk/projects/bruteforceblocker/blist.php", "BruteForceBlocker — SSH brute-forcers reported by other servers."),
    "CIARMY": (86400, 0, "https://www.ciarmy.com/list/ci-badguys.txt", "CINS Army — poorly reputed IPs from the CINS sensor network."),
    "BDE": (3600, 0, "https://api.blocklist.de/getlast.php?time=3600", "Blocklist.de — attackers reported in the last hour (needs hourly fetch)."),
    "GREENSNOW": (86400, 0, "https://blocklist.greensnow.co/greensnow.txt", "GreenSnow — brute force and scanning sources."),
    "ABUSEIPDB": (86400, 10000, "https://api.abuseipdb.com/api/v2/blacklist?key=YOUR_KEY&plaintext", "AbuseIPDB blacklist — requires a free API key in the URL."),
}


def _read():
    try:
        with open(BLOCKLISTS) as f:
            return f.read()
    except OSError:
        return ""


def status():
    """Each feed line (enabled or commented preset) with fetch health."""
    raw = _read()
    feeds = {}
    for line in raw.splitlines():
        s = line.strip()
        enabled = not s.startswith("#")
        body = s.lstrip("# ").strip()
        parts = [p.strip() for p in body.split("|")]
        if len(parts) < 4 or not re.match(r"^[A-Z0-9_]+$", parts[0]):
            continue
        name = parts[0]
        feeds[name] = {"name": name, "enabled": enabled, "interval": parts[1], "max": parts[2], "url": parts[3],
                       "preset": PRESETS.get(name, (0, 0, "", ""))[3]}
    for name, (iv, mx, url, desc) in PRESETS.items():
        feeds.setdefault(name, {"name": name, "enabled": False, "interval": str(iv), "max": str(mx), "url": url, "preset": desc, "missing": True})
    now = time.time()
    for f in feeds.values():
        path = os.path.join(STATE_DIR, f"csf.block.{f['name']}")
        f["path"] = path
        if os.path.isfile(path):
            st = os.stat(path)
            try:
                with open(path) as fh:
                    f["ips"] = sum(1 for l in fh if l.strip() and not l.startswith("#"))
            except OSError:
                f["ips"] = 0
            f["last_fetch"] = int(st.st_mtime)
            f["age_h"] = round((now - st.st_mtime) / 3600, 1)
            try:
                iv = int(f["interval"] or 86400)
            except ValueError:
                iv = 86400
            f["health"] = "ok" if (now - st.st_mtime) < iv * 2 + 600 else "stale"
            if f["ips"] == 0:
                f["health"] = "empty"
        else:
            f["ips"] = 0
            f["last_fetch"] = None
            f["health"] = "never" if f["enabled"] else "off"
        if "YOUR_KEY" in f["url"]:
            f["health"] = "needs-key"
    order = {"stale": 0, "empty": 1, "never": 2, "needs-key": 3, "ok": 4, "off": 5}
    return sorted(feeds.values(), key=lambda f: (order.get(f["health"], 9), f["name"]))


_IP_RE = re.compile(r"(?<![\w.:/])((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|[0-9a-fA-F:]{3,39}(?:/\d{1,3})?)(?![\w.:/])")


def _extract_ips(text, limit):
    import ipaddress
    out, seen = [], set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        for tok in _IP_RE.findall(line)[:1]:
            try:
                net = ipaddress.ip_network(tok, strict=False)
            except ValueError:
                continue
            if net.is_private or net.is_loopback or net.is_multicast:
                continue
            s = str(net.network_address) if net.num_addresses == 1 else str(net)
            if s not in seen:
                seen.add(s)
                out.append(s)
            if limit and len(out) >= limit:
                return out
    return out


def force_fetch(name):
    """Download one enabled feed right now and rewrite its state file, ignoring the interval."""
    if not re.match(r"^[A-Z0-9_]+$", name or ""):
        return {"success": False, "error": "Bad feed name"}
    feed = next((f for f in status() if f["name"] == name), None)
    if not feed or not feed["enabled"]:
        return {"success": False, "error": "Feed is not enabled"}
    url = feed["url"]
    if "YOUR_KEY" in url:
        return {"success": False, "error": "Set the API key first"}
    if not url.lower().startswith(("http://", "https://")):
        return {"success": False, "error": "Unsupported URL scheme"}
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CSF-eUI blocklist fetch"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read(20 * 1024 * 1024 + 1)
        if len(data) > 20 * 1024 * 1024:
            return {"success": False, "error": "Feed is larger than 20 MB"}
        text = data.decode("utf-8", "replace")
    except Exception as e:
        return {"success": False, "error": f"Download failed: {e}"}
    try:
        mx = int(feed["max"] or 0)
    except ValueError:
        mx = 0
    ips = _extract_ips(text, mx)
    if not ips:
        return {"success": False, "error": "Downloaded, but no usable addresses were found; existing list kept"}
    path = os.path.join(STATE_DIR, f"csf.block.{name}")
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(ips) + "\n")
        os.replace(tmp, path)
    except OSError as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "count": len(ips), "restart_needed": True}


def set_enabled(name, enabled, url=None):
    """Toggle a feed by (un)commenting its line; add a preset line if missing."""
    if not re.match(r"^[A-Z0-9_]+$", name or ""):
        return {"success": False, "error": "Bad feed name"}
    raw = _read()
    lines = raw.splitlines()
    found = False
    for i, line in enumerate(lines):
        body = line.strip().lstrip("# ").strip()
        if body.split("|")[0].strip() == name and body.count("|") >= 3:
            found = True
            if url:
                parts = [p.strip() for p in body.split("|")]
                parts[3] = url
                body = "|".join(parts)
            lines[i] = body if enabled else "#" + body
    if not found:
        if name not in PRESETS:
            return {"success": False, "error": "Unknown feed; add it in the editor"}
        iv, mx, purl, _ = PRESETS[name]
        body = f"{name}|{iv}|{mx}|{url or purl}"
        lines.append(body if enabled else "#" + body)
    try:
        with open(BLOCKLISTS, "w") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "restart_needed": True}
