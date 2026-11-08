import subprocess
import json
import ipaddress
import shutil
import socket
from urllib.request import Request, urlopen


def lookup_ip(ip):
    ip = (ip or "").strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "Invalid IP address"}

    info = {"ip": ip, "sections": []}

    # WHOIS lookup. Prefer the local command, then use RDAP when whois is not
    # installed on a minimal server image.
    whois_data = _lookup_whois_command(ip)
    if not whois_data:
        whois_data = _lookup_rdap(ip)
    info["sections"].append({
        "title": "WHOIS Information",
        "icon": "globe",
        "items": ([
            {"key": key.title(), "value": value}
            for key, value in whois_data.items()
        ] if whois_data else [
            {"key": "Status", "value": "WHOIS data unavailable"},
        ]),
    })

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

    # Reverse DNS. Use dig when available and fall back to Python's resolver.
    rdns = _lookup_reverse_dns(ip)
    info["sections"].append({
        "title": "Reverse DNS",
        "icon": "search",
        "items": ([
            {"key": "PTR Record", "value": rdns},
        ] if rdns else [
            {"key": "Status", "value": "No PTR record found"},
        ]),
    })

    return info


def _lookup_whois_command(ip):
    """Return selected WHOIS fields from the local whois executable."""
    if not shutil.which("whois"):
        return {}

    try:
        result = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}

    whois_data = {}
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if ":" not in line or line.startswith("%") or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if value and key in (
            "orgname", "org-name", "organisation", "netname", "country",
            "descr", "abuse-mailbox", "cidr", "inetnum", "netrange",
        ):
            whois_data[key] = value
    return whois_data


def _lookup_rdap(ip):
    """Return selected registration fields from the authoritative RDAP service."""
    try:
        request = Request(
            f"https://rdap.org/ip/{ip}",
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "CSFv2 IP Lookup",
            },
        )
        with urlopen(request, timeout=8) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}

    fields = {}
    if data.get("name"):
        fields["network"] = data["name"]
    if data.get("handle"):
        fields["handle"] = data["handle"]
    if data.get("startAddress") and data.get("endAddress"):
        fields["range"] = f"{data['startAddress']} - {data['endAddress']}"
    if data.get("country"):
        fields["country"] = data["country"]
    if isinstance(data.get("cidr0_cidrs"), list):
        cidrs = []
        for entry in data["cidr0_cidrs"]:
            if not isinstance(entry, dict):
                continue
            prefix = entry.get("v4prefix") or entry.get("v6prefix")
            if prefix and entry.get("length"):
                cidrs.append(f"{prefix}/{entry['length']}")
        if cidrs:
            fields["cidr"] = ", ".join(cidrs)

    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles") or []
        vcard = entity.get("vcardArray", [])
        values = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list) else []
        entity_fields = {
            entry[0]: entry[3]
            for entry in values
            if isinstance(entry, list) and len(entry) > 3 and isinstance(entry[0], str)
        }
        if "registrant" in roles or "administrative" in roles:
            organization = entity_fields.get("org") or entity_fields.get("fn")
            if organization and "organization" not in fields:
                fields["organization"] = organization
        if "abuse" in roles and "email" in entity_fields:
            fields["abuse-mailbox"] = entity_fields["email"]

    return fields


def _lookup_reverse_dns(ip):
    """Resolve a PTR record without requiring the dnsutils package."""
    if shutil.which("dig"):
        try:
            result = subprocess.run(
                ["dig", "+short", "-x", ip],
                capture_output=True, text=True, timeout=5,
            )
            rdns = (result.stdout or "").strip().splitlines()
            if rdns:
                return " ".join(rdns)
        except (OSError, subprocess.TimeoutExpired):
            pass

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip(".")
    except (OSError, socket.herror, socket.gaierror):
        return ""
