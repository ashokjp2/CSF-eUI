import os
import re

CSF_DIR = "/etc/csf"

# File types with friendly UI support
CSF_FILE_MAP = {
    "allow": {
        "path": os.path.join(CSF_DIR, "csf.allow"),
        "title": "IP Allow List",
        "description": "IPs and CIDRs permanently allowed through the firewall. "
                       "Entries here bypass all other block rules — use sparingly and only for trusted sources.",
        "restart": "both",
        "format": "ip",
        "placeholder": "e.g. 203.0.113.1 or 198.51.100.0/24",
        "examples": ["203.0.113.1", "198.51.100.0/24", "2001:db8::/32"],
        "icon": "ok-sign",
        "badge_class": "success",
    },
    "deny": {
        "path": os.path.join(CSF_DIR, "csf.deny"),
        "title": "IP Deny / Block List",
        "description": "IPs and CIDRs permanently blocked by the firewall. "
                       "Traffic from these addresses is dropped before reaching any service.",
        "restart": "both",
        "format": "ip",
        "placeholder": "e.g. 198.51.100.5 or 203.0.113.0/24",
        "examples": ["198.51.100.5", "203.0.113.0/24", "10.20.30.40"],
        "icon": "ban-circle",
        "badge_class": "danger",
    },
    "smtpauth": {
        "path": os.path.join(CSF_DIR, "csf.smtpauth"),
        "title": "SMTP AUTH Allow List",
        "description": "Usernames allowed to use SMTP AUTH when SMTP_AUTH_RESTRICT is enabled. "
                       "All other accounts are blocked from authenticating via SMTP.",
        "restart": "both",
        "format": "user",
        "placeholder": "e.g. user@example.com",
        "examples": ["postmaster@example.com", "alerts@example.com"],
        "icon": "envelope",
        "badge_class": "info",
    },
    "redirect": {
        "path": os.path.join(CSF_DIR, "csf.redirect"),
        "title": "Port Redirect Rules",
        "description": "DNAT/redirect rules applied by CSF at firewall startup. "
                       "Each rule redirects traffic arriving on a source port to a different destination port (and optionally a different IP).",
        "restart": "both",
        "format": "redirect",
        "placeholder": "",
        "examples": [],
        "icon": "transfer",
        "badge_class": "warning",
    },
}

FILE_MAP = {
    "ignore": {
        "path": os.path.join(CSF_DIR, "csf.ignore"),
        "title": "LFD Ignore List",
        "description": "IPs and CIDRs that LFD should never block, even if they trigger login failure alerts. "
                       "Add your own server IPs, trusted networks, and Docker/container subnets here.",
        "restart": "lfd",
        "format": "ip",
        "placeholder": "e.g. 192.168.1.0/24",
        "examples": ["127.0.0.1", "10.0.0.0/24", "172.17.0.0/16"],
    },
    "dirwatch": {
        "path": os.path.join(CSF_DIR, "csf.dirwatch"),
        "title": "Directory Watch List",
        "description": "LFD watches these directories for suspicious script files (like exploit kits uploaded by hackers). "
                       "Add any writable directories where attackers might drop files.",
        "restart": "lfd",
        "format": "path",
        "placeholder": "e.g. /var/www/uploads",
        "examples": ["/tmp", "/var/tmp", "/dev/shm", "/var/www/html/uploads"],
    },
    "syslogusers": {
        "path": os.path.join(CSF_DIR, "csf.syslogusers"),
        "title": "Syslog Users",
        "description": "System users whose syslog access should be monitored. "
                       "When RESTRICT_SYSLOG is enabled, only these users (plus root) can access syslog.",
        "restart": "lfd",
        "format": "user",
        "placeholder": "e.g. www-data",
        "examples": ["nobody", "www-data", "mysql"],
    },
    "logfiles": {
        "path": os.path.join(CSF_DIR, "csf.logfiles"),
        "title": "Custom Log Files",
        "description": "Additional log files for LFD to monitor beyond the standard system logs. "
                       "Add application logs that may contain login failure or attack patterns.",
        "restart": "lfd",
        "format": "path",
        "placeholder": "e.g. /var/log/myapp/auth.log",
        "examples": ["/var/log/nginx/error.log", "/var/log/docker/containers.log"],
    },
    "dyndns": {
        "path": os.path.join(CSF_DIR, "csf.dyndns"),
        "title": "Dynamic DNS Hostnames",
        "description": "Hostnames that resolve to dynamic IPs. LFD periodically resolves these and "
                       "adds/updates the IPs in csf.allow so your home or office connection stays whitelisted "
                       "even when the IP changes.",
        "restart": "lfd",
        "format": "dns",
        "placeholder": "e.g. myhost.dyndns.org",
        "examples": ["home.example.com", "office.no-ip.org"],
    },
    "blocklists": {
        "path": os.path.join(CSF_DIR, "csf.blocklists"),
        "title": "IP Block Lists",
        "description": "Subscribe to public IP blocklists that are automatically downloaded and applied. "
                       "These lists contain known malicious IPs from threat intelligence feeds.",
        "restart": "both",
        "format": "blocklist",
        "placeholder": "",
        "examples": [],
    },
}


def _read_file(filepath):
    try:
        with open(filepath) as f:
            return f.read()
    except OSError:
        return ""


def _write_file(filepath, content):
    try:
        with open(filepath, "w") as f:
            f.write(content)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}


def get_file_info(filetype):
    if filetype not in FILE_MAP:
        return None
    info = FILE_MAP[filetype].copy()
    raw = _read_file(info["path"])
    info["raw"] = raw

    if info["format"] == "blocklist":
        info["entries"] = _parse_blocklists(raw)
    else:
        info["entries"] = _parse_simple(raw)

    return info


def _parse_simple(raw):
    entries = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split("#", 1)
        entry = parts[0].strip()
        comment = parts[1].strip() if len(parts) > 1 else ""
        if entry:
            entries.append({"value": entry, "comment": comment})
    return entries


def _parse_blocklists(raw):
    entries = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split("|")
        if len(parts) >= 4:
            entries.append({
                "name": parts[0].strip(),
                "interval": parts[1].strip(),
                "max": parts[2].strip(),
                "url": parts[3].strip(),
            })
    return entries


def save_simple_entries(filetype, entries):
    if filetype not in FILE_MAP:
        return {"success": False, "error": "Unknown file type"}
    info = FILE_MAP[filetype]
    raw = _read_file(info["path"])

    header_lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            header_lines.append(line)
        else:
            break

    content = "\n".join(header_lines) + "\n"
    for entry in entries:
        val = entry.get("value", "").strip()
        if not val:
            continue
        comment = entry.get("comment", "").strip()
        if comment:
            content += f"{val} #{comment}\n"
        else:
            content += f"{val}\n"

    result = _write_file(info["path"], content)
    if result["success"]:
        restart = info["restart"]
        if restart == "lfd":
            result["message"] = "Saved. Restart LFD to apply changes."
        elif restart == "both":
            result["message"] = "Saved. Restart CSF+LFD to apply changes."
        else:
            result["message"] = "Saved."
    return result


def save_blocklist_entries(entries):
    info = FILE_MAP["blocklists"]
    raw = _read_file(info["path"])

    header_lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            header_lines.append(line)
        else:
            break

    content = "\n".join(header_lines) + "\n"
    for entry in entries:
        name = entry.get("name", "").strip()
        interval = entry.get("interval", "86400").strip()
        max_entries = entry.get("max", "0").strip()
        url = entry.get("url", "").strip()
        if name and url:
            content += f"{name}|{interval}|{max_entries}|{url}\n"

    result = _write_file(info["path"], content)
    if result["success"]:
        result["message"] = "Saved. Restart CSF+LFD to apply changes."
    return result


# --- CSF file manager (allow / deny / smtpauth / redirect) ---

def get_csf_file_info(filetype):
    """Return parsed info for one of the four CSF-managed file types."""
    if filetype not in CSF_FILE_MAP:
        return None
    info = CSF_FILE_MAP[filetype].copy()
    raw = _read_file(info["path"])
    info["raw"] = raw

    if info["format"] == "redirect":
        info["entries"] = _parse_redirect(raw)
    else:
        info["entries"] = _parse_simple(raw)

    return info


def _parse_redirect(raw):
    """Parse csf.redirect lines: srcport:destport:proto[:destip]"""
    entries = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Accept colon-separated or space-separated
        if ":" in stripped:
            parts = [p.strip() for p in stripped.split(":")]
        else:
            parts = stripped.split()
        if len(parts) < 3:
            continue
        entry = {
            "src_port": parts[0],
            "dest_port": parts[1],
            "proto": parts[2].lower(),
            "dest_ip": parts[3] if len(parts) > 3 else "",
        }
        entries.append(entry)
    return entries


def save_csf_file_entries(filetype, entries):
    """Save structured entries back to one of the four CSF file types."""
    if filetype not in CSF_FILE_MAP:
        return {"success": False, "error": "Unknown file type"}

    info = CSF_FILE_MAP[filetype]
    raw = _read_file(info["path"])

    # Preserve leading comment/blank lines as a header
    header_lines = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            header_lines.append(line)
        else:
            break

    content = "\n".join(header_lines) + "\n"

    if info["format"] == "redirect":
        for entry in entries:
            src = entry.get("src_port", "").strip()
            dst = entry.get("dest_port", "").strip()
            proto = entry.get("proto", "tcp").strip().lower()
            dest_ip = entry.get("dest_ip", "").strip()
            if not src or not dst:
                continue
            if dest_ip:
                content += f"{src}:{dst}:{proto}:{dest_ip}\n"
            else:
                content += f"{src}:{dst}:{proto}\n"
    else:
        for entry in entries:
            val = entry.get("value", "").strip()
            if not val:
                continue
            comment = entry.get("comment", "").strip()
            if comment:
                content += f"{val} #{comment}\n"
            else:
                content += f"{val}\n"

    result = _write_file(info["path"], content)
    if result["success"]:
        result["message"] = "Saved. Restart CSF+LFD to apply changes."
    return result
