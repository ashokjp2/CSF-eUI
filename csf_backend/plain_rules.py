import re
import os
import subprocess

COUNTRY_MAP = {
    "china": "CN", "russia": "RU", "brazil": "BR", "india": "IN",
    "north korea": "KP", "iran": "IR", "vietnam": "VN", "indonesia": "ID",
    "pakistan": "PK", "nigeria": "NG", "turkey": "TR", "ukraine": "UA",
    "romania": "RO", "argentina": "AR", "egypt": "EG", "bangladesh": "BD",
    "thailand": "TH", "mexico": "MX", "philippines": "PH", "colombia": "CO",
    "south korea": "KR", "japan": "JP", "germany": "DE", "france": "FR",
    "united kingdom": "GB", "uk": "GB", "united states": "US", "usa": "US",
    "us": "US", "canada": "CA", "australia": "AU", "netherlands": "NL",
    "italy": "IT", "spain": "ES", "poland": "PL", "sweden": "SE",
    "south africa": "ZA", "taiwan": "TW", "singapore": "SG",
    "hong kong": "HK", "malaysia": "MY", "saudi arabia": "SA",
    "uae": "AE", "israel": "IL", "kenya": "KE",
}

SERVICE_PORTS = {
    "ssh": "22", "http": "80", "https": "443", "ftp": "21",
    "smtp": "25", "mail": "25,587,993", "email": "25,587,993",
    "dns": "53", "mysql": "3306", "postgres": "5432", "postgresql": "5432",
    "redis": "6379", "mongodb": "27017", "mongo": "27017",
    "web": "80,443", "http and https": "80,443",
    "rdp": "3389", "remote desktop": "3389",
    "minecraft": "25565", "teamspeak": "9987",
    "docker": "2375,2376", "wireguard": "51820",
}


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _save(path, content):
    with open(path, "w") as f:
        f.write(content)


def parse_rule(text):
    """Parse plain English into firewall rule(s)."""
    text_lower = text.lower().strip()

    results = []

    # Pattern: "Block all traffic from <country>"
    m = re.search(r'block\s+(?:all\s+)?(?:traffic\s+)?from\s+(.+)', text_lower)
    if m:
        target = m.group(1).strip().rstrip(".")
        # Check if it's a country
        cc = COUNTRY_MAP.get(target)
        if cc:
            results.append({
                "type": "country_block",
                "action": "Add to CC_DENY",
                "description": f"Block all traffic from {target.title()} ({cc})",
                "setting": "CC_DENY",
                "value": cc,
                "commands": [f'Add "{cc}" to CC_DENY in csf.conf'],
                "warning": "This blocks ALL traffic from this country, including legitimate users.",
            })
            return {"success": True, "rules": results}

        # Check if it's an IP
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', target)
        if ip_match:
            ip = ip_match.group(1)
            results.append({
                "type": "ip_block",
                "action": f"csf -d {ip}",
                "description": f"Permanently block IP {ip}",
                "file": "csf.deny",
                "line": ip,
                "commands": [f"csf -d {ip}"],
            })
            return {"success": True, "rules": results}

    # Pattern: "Allow <country>"
    m = re.search(r'allow\s+(?:all\s+)?(?:traffic\s+)?from\s+(.+)', text_lower)
    if m:
        target = m.group(1).strip().rstrip(".")
        cc = COUNTRY_MAP.get(target)
        if cc:
            results.append({
                "type": "country_allow",
                "action": "Add to CC_ALLOW",
                "description": f"Allow all traffic from {target.title()} ({cc})",
                "setting": "CC_ALLOW",
                "value": cc,
                "commands": [f'Add "{cc}" to CC_ALLOW in csf.conf'],
            })
            return {"success": True, "rules": results}

        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', target)
        if ip_match:
            ip = ip_match.group(1)
            results.append({
                "type": "ip_allow",
                "action": f"csf -a {ip}",
                "description": f"Permanently allow IP {ip}",
                "file": "csf.allow",
                "line": ip,
                "commands": [f"csf -a {ip}"],
            })
            return {"success": True, "rules": results}

    # Pattern: "Open port <N>" / "Allow port <N>"
    m = re.search(r'(?:open|allow|enable)\s+(?:port\s+)?(\d[\d,\s]*\d?)\s*(?:for\s+)?(tcp|udp|both)?', text_lower)
    if m:
        ports = re.sub(r'\s+', '', m.group(1))
        proto = m.group(2) or "tcp"
        results.append({
            "type": "port_open",
            "action": f"Add port {ports} to TCP_IN",
            "description": f"Open port(s) {ports} ({proto.upper()}) for incoming traffic",
            "setting": "TCP_IN" if proto != "udp" else "UDP_IN",
            "value": ports,
            "commands": [f'Add {ports} to {"TCP_IN" if proto != "udp" else "UDP_IN"} in csf.conf'],
        })
        if proto == "both":
            results.append({
                "type": "port_open",
                "action": f"Add port {ports} to UDP_IN",
                "description": f"Open port(s) {ports} (UDP) for incoming traffic",
                "setting": "UDP_IN",
                "value": ports,
                "commands": [f'Add {ports} to UDP_IN in csf.conf'],
            })
        return {"success": True, "rules": results}

    # Pattern: "Close port <N>" / "Block port <N>"
    m = re.search(r'(?:close|block|disable|remove)\s+(?:port\s+)?(\d[\d,\s]*\d?)', text_lower)
    if m:
        ports = re.sub(r'\s+', '', m.group(1))
        results.append({
            "type": "port_close",
            "action": f"Remove port {ports} from TCP_IN",
            "description": f"Close port(s) {ports} — remove from allowed incoming ports",
            "setting": "TCP_IN",
            "value": ports,
            "remove": True,
            "commands": [f'Remove {ports} from TCP_IN in csf.conf'],
        })
        return {"success": True, "rules": results}

    # Pattern: "Allow/Open <service>"
    m = re.search(r'(?:open|allow|enable)\s+(.+?)(?:\s+access)?$', text_lower)
    if m:
        service = m.group(1).strip().rstrip(".")
        if service in SERVICE_PORTS:
            ports = SERVICE_PORTS[service]
            results.append({
                "type": "service_open",
                "action": f"Open {service} ports ({ports})",
                "description": f"Allow {service} service — open port(s) {ports}",
                "setting": "TCP_IN",
                "value": ports,
                "commands": [f'Add {ports} to TCP_IN in csf.conf'],
            })
            return {"success": True, "rules": results}

    # Pattern: "Block/Close <service>"
    m = re.search(r'(?:close|block|disable|remove)\s+(.+?)(?:\s+access)?$', text_lower)
    if m:
        service = m.group(1).strip().rstrip(".")
        if service in SERVICE_PORTS:
            ports = SERVICE_PORTS[service]
            results.append({
                "type": "service_close",
                "action": f"Close {service} ports ({ports})",
                "description": f"Block {service} service — remove port(s) {ports}",
                "setting": "TCP_IN",
                "value": ports,
                "remove": True,
                "commands": [f'Remove {ports} from TCP_IN in csf.conf'],
            })
            return {"success": True, "rules": results}

    # Pattern: "Limit connections to <N>"
    m = re.search(r'limit\s+connections?\s+to\s+(\d+)', text_lower)
    if m:
        val = m.group(1)
        results.append({
            "type": "setting",
            "action": f"Set CT_LIMIT = {val}",
            "description": f"Limit max simultaneous connections per IP to {val}",
            "setting": "CT_LIMIT",
            "value": val,
            "commands": [f'Set CT_LIMIT = "{val}" in csf.conf'],
        })
        return {"success": True, "rules": results}

    # Pattern: "Block after <N> failed logins"
    m = re.search(r'block\s+after\s+(\d+)\s+failed\s+(?:login|ssh|attempt)', text_lower)
    if m:
        val = m.group(1)
        results.append({
            "type": "setting",
            "action": f"Set LF_SSHD = {val}",
            "description": f"Block IP after {val} failed SSH login attempts",
            "setting": "LF_SSHD",
            "value": val,
            "commands": [f'Set LF_SSHD = "{val}" in csf.conf'],
        })
        return {"success": True, "rules": results}

    # Pattern: "Enable/disable <setting>"
    m = re.search(r'(enable|disable|turn on|turn off)\s+(.+)', text_lower)
    if m:
        on = m.group(1) in ("enable", "turn on")
        feature = m.group(2).strip().rstrip(".")
        setting_map = {
            "syn flood protection": "SYNFLOOD",
            "synflood": "SYNFLOOD",
            "port scan detection": "PS_LIMIT",
            "port scanning": "PS_LIMIT",
            "docker mode": "DOCKER",
            "docker": "DOCKER",
            "ipv6": "IPV6",
            "connection tracking": "CT_LIMIT",
            "permanent block": "LF_PERMBLOCK",
            "testing mode": "TESTING",
            "testing": "TESTING",
        }
        setting = setting_map.get(feature)
        if setting:
            val = "1" if on else "0"
            if setting in ("PS_LIMIT", "CT_LIMIT") and on:
                val = "10" if setting == "PS_LIMIT" else "300"
            results.append({
                "type": "setting",
                "action": f"Set {setting} = {val}",
                "description": f"{'Enable' if on else 'Disable'} {feature}",
                "setting": setting,
                "value": val,
                "commands": [f'Set {setting} = "{val}" in csf.conf'],
            })
            return {"success": True, "rules": results}

    return {
        "success": False,
        "error": "Could not understand that rule. Try phrases like:\n"
                 "- Block all traffic from China\n"
                 "- Allow 192.168.1.0/24\n"
                 "- Open port 8080\n"
                 "- Close port 3306\n"
                 "- Allow SSH access\n"
                 "- Block after 3 failed logins\n"
                 "- Enable syn flood protection\n"
                 "- Limit connections to 200",
    }


def apply_rule(rule):
    """Apply a parsed rule."""
    from csf_backend import csf_wrapper as csf

    rule_type = rule.get("type", "")

    if rule_type in ("ip_block", "ip_allow"):
        cmd = rule["commands"][0]
        parts = cmd.split()
        code, out, err = csf._run_csf(parts[1:], timeout=30)
        return {"success": code == 0, "output": out or err}

    if rule_type in ("country_block", "country_allow"):
        setting = rule["setting"]
        cc = rule["value"]
        current = csf.get_csf_conf().get(setting, "")
        codes = [c.strip() for c in current.split(",") if c.strip()]
        if cc not in codes:
            codes.append(cc)
        csf.save_csf_conf({setting: ",".join(codes)})
        return {"success": True, "output": f"{cc} added to {setting}. Restart CSF to apply."}

    if rule_type in ("port_open", "service_open"):
        setting = rule["setting"]
        ports = rule["value"]
        current = csf.get_csf_conf().get(setting, "")
        existing = [p.strip() for p in current.split(",") if p.strip()]
        for p in ports.split(","):
            if p.strip() not in existing:
                existing.append(p.strip())
        csf.save_csf_conf({setting: ",".join(existing)})
        return {"success": True, "output": f"Port(s) {ports} added to {setting}. Restart CSF to apply."}

    if rule_type in ("port_close", "service_close"):
        setting = rule["setting"]
        ports = rule["value"]
        current = csf.get_csf_conf().get(setting, "")
        existing = [p.strip() for p in current.split(",") if p.strip()]
        for p in ports.split(","):
            if p.strip() in existing:
                existing.remove(p.strip())
        csf.save_csf_conf({setting: ",".join(existing)})
        return {"success": True, "output": f"Port(s) {ports} removed from {setting}. Restart CSF to apply."}

    if rule_type == "setting":
        csf.save_csf_conf({rule["setting"]: rule["value"]})
        return {"success": True, "output": f'{rule["setting"]} set to {rule["value"]}. Restart CSF to apply.'}

    return {"success": False, "error": "Unknown rule type"}
