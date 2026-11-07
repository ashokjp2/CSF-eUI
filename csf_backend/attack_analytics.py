import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta


LOG_FILES = ["/var/log/lfd.log", "/var/log/auth.log", "/var/log/syslog"]


def _read_tail(path, max_lines=10000):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, max_lines * 300)
            f.seek(max(0, size - chunk))
            data = f.read().decode("utf-8", errors="replace")
            return data.splitlines()[-max_lines:]
    except OSError:
        return []


def get_analytics(hours=24):
    ip_counter = Counter()
    country_counter = Counter()
    attack_types = Counter()
    ip_countries = {}
    ip_reasons = defaultdict(list)
    hourly = defaultdict(int)

    now = datetime.now()
    cutoff = now - timedelta(hours=hours)

    for path in LOG_FILES:
        for line in _read_tail(path):
            is_block = False
            if any(kw in line for kw in ("Blocked", "BLOCK", "block", "Failed password",
                                          "Failed SSH", "SYN flood", "Invalid user",
                                          "authentication failure")):
                is_block = True

            if not is_block:
                continue

            ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
            country_match = re.search(r'\(([A-Z]{2})/', line)
            country = country_match.group(1) if country_match else ""

            # Classify attack type
            if "Failed password" in line or "Failed SSH" in line or "sshd" in line.lower():
                atype = "SSH Brute-Force"
            elif "SYN flood" in line:
                atype = "SYN Flood"
            elif "Invalid user" in line:
                atype = "Invalid User"
            elif "port scan" in line.lower() or "PS_LIMIT" in line:
                atype = "Port Scan"
            elif "CT_LIMIT" in line:
                atype = "Connection Flood"
            elif "distributed" in line.lower():
                atype = "Distributed Attack"
            elif "authentication failure" in line:
                atype = "Auth Failure"
            else:
                atype = "Other Block"

            attack_types[atype] += 1

            for ip in ips[:1]:
                ip_counter[ip] += 1
                if country:
                    ip_countries[ip] = country
                    country_counter[country] += 1
                reason = line.strip()
                if len(reason) > 120:
                    reason = reason[:120] + "..."
                if len(ip_reasons[ip]) < 3:
                    ip_reasons[ip].append(reason)

            # Hourly bucket
            ts_match = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2})', line)
            if ts_match:
                try:
                    ts = datetime.strptime(f"{now.year} {ts_match.group(1)}", "%Y %b %d %H:%M")
                    if ts > now:
                        ts = ts.replace(year=now.year - 1)
                    if ts >= cutoff:
                        hourly[ts.strftime("%H:00")] += 1
                except ValueError:
                    pass

    # Top 20 attackers
    top_ips = []
    for ip, count in ip_counter.most_common(20):
        top_ips.append({
            "ip": ip,
            "count": count,
            "country": ip_countries.get(ip, ""),
            "reasons": ip_reasons.get(ip, []),
        })

    # Top 15 countries
    top_countries = []
    country_names = {
        "CN": "China", "RU": "Russia", "US": "United States", "BR": "Brazil",
        "IN": "India", "DE": "Germany", "NL": "Netherlands", "KR": "South Korea",
        "FR": "France", "GB": "United Kingdom", "VN": "Vietnam", "ID": "Indonesia",
        "JP": "Japan", "TW": "Taiwan", "UA": "Ukraine", "RO": "Romania",
        "PK": "Pakistan", "BD": "Bangladesh", "IR": "Iran", "TR": "Turkey",
        "TH": "Thailand", "PH": "Philippines", "AR": "Argentina", "MX": "Mexico",
        "IT": "Italy", "ES": "Spain", "PL": "Poland", "CO": "Colombia",
        "SG": "Singapore", "HK": "Hong Kong", "AD": "Andorra", "NG": "Nigeria",
        "EG": "Egypt", "ZA": "South Africa", "SE": "Sweden", "CA": "Canada",
        "AU": "Australia", "MY": "Malaysia", "KP": "North Korea", "SA": "Saudi Arabia",
    }
    for cc, count in country_counter.most_common(15):
        top_countries.append({
            "code": cc,
            "name": country_names.get(cc, cc),
            "count": count,
        })

    # Attack type breakdown
    type_list = [{"type": t, "count": c} for t, c in attack_types.most_common()]

    # Hourly heatmap (24 hours)
    hour_data = []
    for h in range(24):
        key = f"{h:02d}:00"
        hour_data.append({"hour": key, "count": hourly.get(key, 0)})

    total_attacks = sum(ip_counter.values())

    return {
        "top_ips": top_ips,
        "top_countries": top_countries,
        "attack_types": type_list,
        "hourly": hour_data,
        "total_attacks": total_attacks,
        "unique_ips": len(ip_counter),
        "unique_countries": len(country_counter),
        "hours": hours,
    }
