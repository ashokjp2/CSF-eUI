import subprocess
import re
import json


def lookup_ip(ip):
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return {"error": "Invalid IP address"}

    info = {"ip": ip, "sections": []}

    # Whois lookup
    try:
        r = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=10,
        )
        whois_data = {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if ":" in line and not line.startswith("%") and not line.startswith("#"):
                key, _, val = line.partition(":")
                val = val.strip()
                key = key.strip().lower()
                if val and key in (
                    "orgname", "org-name", "organisation", "netname", "country",
                    "descr", "abuse-mailbox", "cidr", "inetnum", "netrange",
                ):
                    whois_data[key] = val
        if whois_data:
            info["sections"].append({
                "title": "WHOIS Information",
                "icon": "globe",
                "items": [{"key": k.title(), "value": v} for k, v in whois_data.items()],
            })
    except Exception:
        pass

    # CSF status for this IP
    try:
        # Check deny list
        r = subprocess.run(
            ["grep", "-n", ip, "/etc/csf/csf.deny"],
            capture_output=True, text=True, timeout=5,
        )
        if r.stdout.strip():
            info["sections"].append({
                "title": "CSF Status",
                "icon": "ban-circle",
                "status": "blocked",
                "items": [
                    {"key": "Status", "value": "PERMANENTLY BLOCKED"},
                    {"key": "Entry", "value": r.stdout.strip().split("\n")[0]},
                ],
            })
        else:
            # Check allow list
            r2 = subprocess.run(
                ["grep", "-n", ip, "/etc/csf/csf.allow"],
                capture_output=True, text=True, timeout=5,
            )
            if r2.stdout.strip():
                info["sections"].append({
                    "title": "CSF Status",
                    "icon": "ok-circle",
                    "status": "allowed",
                    "items": [
                        {"key": "Status", "value": "ALLOWED"},
                        {"key": "Entry", "value": r2.stdout.strip().split("\n")[0]},
                    ],
                })
            else:
                # Check temp blocks
                r3 = subprocess.run(
                    ["csf", "-t"], capture_output=True, text=True, timeout=10,
                )
                if ip in (r3.stdout or ""):
                    info["sections"].append({
                        "title": "CSF Status",
                        "icon": "time",
                        "status": "temp_blocked",
                        "items": [{"key": "Status", "value": "TEMPORARILY BLOCKED"}],
                    })
                else:
                    info["sections"].append({
                        "title": "CSF Status",
                        "icon": "question-sign",
                        "status": "none",
                        "items": [{"key": "Status", "value": "Not in any CSF list"}],
                    })
    except Exception:
        pass

    # Recent log activity for this IP
    try:
        r = subprocess.run(
            ["grep", "-c", ip, "/var/log/lfd.log"],
            capture_output=True, text=True, timeout=5,
        )
        count = int(r.stdout.strip()) if r.stdout.strip() else 0
        r2 = subprocess.run(
            ["grep", ip, "/var/log/lfd.log"],
            capture_output=True, text=True, timeout=5,
        )
        recent = r2.stdout.strip().split("\n")[-5:] if r2.stdout.strip() else []
        info["sections"].append({
            "title": "LFD Log Activity",
            "icon": "list-alt",
            "items": [
                {"key": "Total mentions", "value": str(count)},
            ],
            "log_lines": recent,
        })
    except Exception:
        pass

    # Reverse DNS
    try:
        r = subprocess.run(
            ["dig", "+short", "-x", ip],
            capture_output=True, text=True, timeout=5,
        )
        rdns = r.stdout.strip()
        if rdns:
            info["sections"].append({
                "title": "Reverse DNS",
                "icon": "search",
                "items": [{"key": "PTR Record", "value": rdns}],
            })
    except Exception:
        pass

    return info
