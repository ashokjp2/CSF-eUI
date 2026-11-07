import json
import os
import time
import urllib.request
import urllib.error
import re

CACHE_FILE = "/var/lib/csfv2/ip_cache.json"
CACHE_TTL = 86400 * 7

def _load_cache():
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

def _save_cache(cache):
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except OSError:
        pass

def geolocate_ip(ip):
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return None
    if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.")):
        return {"ip": ip, "country": "Private", "country_code": "XX", "city": "LAN", "isp": "Private Network"}

    cache = _load_cache()
    if ip in cache and time.time() - cache[ip].get("_ts", 0) < CACHE_TTL:
        return cache[ip]

    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,regionName,isp,org,as",
            headers={"User-Agent": "CSFv2"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            result = {
                "ip": ip,
                "country": data.get("country", ""),
                "country_code": data.get("countryCode", "XX"),
                "city": data.get("city", ""),
                "region": data.get("regionName", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "as": data.get("as", ""),
                "_ts": time.time(),
            }
            cache[ip] = result
            _save_cache(cache)
            return result
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
        pass
    return {"ip": ip, "country": "Unknown", "country_code": "XX", "city": "", "isp": ""}


def geolocate_batch(ips):
    results = {}
    for ip in ips[:50]:
        geo = geolocate_ip(ip)
        if geo:
            results[ip] = geo
    return results


def check_abuseipdb(ip, api_key):
    if not api_key or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return None
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={
                "Key": api_key,
                "Accept": "application/json",
            }
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        d = data.get("data", {})
        return {
            "ip": ip,
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "country_code": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "is_whitelisted": d.get("isWhitelisted", False),
            "last_reported": d.get("lastReportedAt", ""),
        }
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
        return None


def get_lfd_events(lines=50):
    events = []
    log_paths = ["/var/log/lfd.log", "/var/log/syslog"]
    for log_path in log_paths:
        if not os.path.exists(log_path):
            continue
        try:
            with open(log_path) as f:
                all_lines = f.readlines()
            for line in all_lines[-500:]:
                if "lfd" not in line.lower():
                    continue
                event = _parse_lfd_line(line)
                if event:
                    events.append(event)
        except OSError:
            continue
    events.sort(key=lambda e: e.get("raw", ""), reverse=True)
    return events[:lines]


def _parse_lfd_line(line):
    line = line.strip()
    if not line:
        return None

    event = {"raw": line, "type": "info", "icon": "info-sign"}

    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    if ip_match:
        event["ip"] = ip_match.group(1)

    lower = line.lower()
    if any(w in lower for w in ("blocked", "denied", "ban", "drop")):
        event["type"] = "block"
        event["icon"] = "ban-circle"
    elif any(w in lower for w in ("allowed", "accept", "unblock")):
        event["type"] = "allow"
        event["icon"] = "ok-circle"
    elif any(w in lower for w in ("failed", "invalid", "error")):
        event["type"] = "warning"
        event["icon"] = "warning-sign"
    elif any(w in lower for w in ("started", "restart", "loaded")):
        event["type"] = "service"
        event["icon"] = "cog"

    ts_match = re.match(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
    if ts_match:
        event["timestamp"] = ts_match.group(1)
    else:
        ts_match2 = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d+:\d+:\d+)', line)
        if ts_match2:
            event["timestamp"] = ts_match2.group(1)

    return event
