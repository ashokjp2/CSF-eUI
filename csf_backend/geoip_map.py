import os
import json
import subprocess
import re
import urllib.request


CACHE_FILE = "/var/lib/csfv2/geoip_cache.json"


def _load_cache():
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)


def lookup_ip(ip):
    """Lookup geo data for a single IP using ip-api.com."""
    cache = _load_cache()
    if ip in cache:
        return cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org"
        req = urllib.request.Request(url, headers={"User-Agent": "CSFv2"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {
                "country": data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
            }
            cache[ip] = result
            if len(cache) > 5000:
                keys = list(cache.keys())
                for k in keys[:1000]:
                    del cache[k]
            _save_cache(cache)
            return result
    except Exception:
        pass
    return None


def lookup_batch(ips):
    """Lookup multiple IPs. Returns dict of ip -> geo data."""
    cache = _load_cache()
    results = {}
    to_lookup = []

    for ip in ips:
        if ip in cache:
            results[ip] = cache[ip]
        else:
            to_lookup.append(ip)

    # ip-api.com batch endpoint (max 100 per request)
    for i in range(0, len(to_lookup), 100):
        batch = to_lookup[i:i+100]
        try:
            payload = json.dumps([{"query": ip, "fields": "status,query,country,countryCode,regionName,city,lat,lon,isp,org"} for ip in batch]).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "CSFv2"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            for item in data:
                if item.get("status") == "success":
                    ip = item["query"]
                    result = {
                        "country": item.get("country", ""),
                        "country_code": item.get("countryCode", ""),
                        "region": item.get("regionName", ""),
                        "city": item.get("city", ""),
                        "lat": item.get("lat", 0),
                        "lon": item.get("lon", 0),
                        "isp": item.get("isp", ""),
                        "org": item.get("org", ""),
                    }
                    results[ip] = result
                    cache[ip] = result
        except Exception:
            pass

    _save_cache(cache)
    return results


def get_blocked_ips_geo():
    """Get geo data for all denied IPs."""
    try:
        r = subprocess.run(["csf", "-l"], capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return {"ips": [], "error": "csf -l failed"}
    except Exception:
        return {"ips": [], "error": "csf command failed"}

    ips = set()
    for line in r.stdout.splitlines():
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            ip = m.group(1)
            if not ip.startswith("127.") and not ip.startswith("0."):
                ips.add(ip)

    ip_list = list(ips)[:200]
    geo_data = lookup_batch(ip_list)

    markers = []
    for ip in ip_list:
        if ip in geo_data:
            g = geo_data[ip]
            if g.get("lat") and g.get("lon"):
                markers.append({
                    "ip": ip,
                    "lat": g["lat"],
                    "lon": g["lon"],
                    "country": g["country"],
                    "city": g.get("city", ""),
                    "isp": g.get("isp", ""),
                })

    country_counts = {}
    for m in markers:
        c = m["country"]
        country_counts[c] = country_counts.get(c, 0) + 1
    top_countries = sorted(country_counts.items(), key=lambda x: -x[1])[:15]

    return {
        "markers": markers,
        "total_ips": len(ip_list),
        "mapped": len(markers),
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
    }
