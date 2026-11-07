import os
import re

CSF_CONF = "/etc/csf/csf.conf"
CSF_DYNDNS = "/etc/csf/csf.dyndns"

WELL_KNOWN_PORTS = {
    "20": "FTP Data", "21": "FTP", "22": "SSH", "23": "Telnet",
    "25": "SMTP", "53": "DNS", "80": "HTTP", "110": "POP3",
    "143": "IMAP", "443": "HTTPS", "465": "SMTPS", "587": "Submission",
    "853": "DNS-over-TLS", "993": "IMAPS", "995": "POP3S",
    "3000": "Dokploy/Dev", "3306": "MySQL", "4789": "VXLAN",
    "5432": "PostgreSQL", "5900": "VNC", "6379": "Redis",
    "8080": "HTTP Alt", "8443": "HTTPS Alt", "8750": "CSFv2",
    "9090": "Cockpit", "9200": "Elasticsearch", "27017": "MongoDB",
    "51820": "WireGuard", "51821": "WG-UI",
}


def get_port_config():
    from csf_backend import csf_wrapper as csf
    conf = csf.load_csf_conf()
    result = {}
    for key in ("TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT", "TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT"):
        raw = conf.get(key, "")
        ports = [p.strip() for p in raw.split(",") if p.strip()]
        labeled = []
        for p in ports:
            labeled.append({
                "port": p,
                "label": WELL_KNOWN_PORTS.get(p, ""),
            })
        result[key] = {"raw": raw, "ports": labeled}
    return result


def save_port_config(key, ports_csv):
    from csf_backend import csf_wrapper as csf
    valid_keys = {"TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT", "TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT"}
    if key not in valid_keys:
        return {"success": False, "error": f"Invalid key: {key}"}
    cleaned = ",".join(p.strip() for p in ports_csv.split(",") if p.strip())
    csf.save_csf_conf({key: cleaned})
    return {"success": True, "message": f"{key} updated. Restart CSF to apply."}


def get_country_config():
    from csf_backend import csf_wrapper as csf
    conf = csf.load_csf_conf()
    return {
        "CC_DENY": conf.get("CC_DENY", ""),
        "CC_ALLOW": conf.get("CC_ALLOW", ""),
        "CC_ALLOW_FILTER": conf.get("CC_ALLOW_FILTER", ""),
        "CC_ALLOW_PORTS": conf.get("CC_ALLOW_PORTS", ""),
        "CC_DENY_PORTS": conf.get("CC_DENY_PORTS", ""),
        "CC_LOOKUPS": conf.get("CC_LOOKUPS", "1"),
        "CC_INTERVAL": conf.get("CC_INTERVAL", "0"),
    }

COUNTRY_CODES = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AR": "Argentina",
    "AU": "Australia", "AT": "Austria", "BD": "Bangladesh", "BY": "Belarus",
    "BE": "Belgium", "BO": "Bolivia", "BR": "Brazil", "BG": "Bulgaria",
    "KH": "Cambodia", "CA": "Canada", "CL": "Chile", "CN": "China",
    "CO": "Colombia", "HR": "Croatia", "CU": "Cuba", "CZ": "Czechia",
    "DK": "Denmark", "EC": "Ecuador", "EG": "Egypt", "FI": "Finland",
    "FR": "France", "DE": "Germany", "GH": "Ghana", "GR": "Greece",
    "HK": "Hong Kong", "HU": "Hungary", "IN": "India", "ID": "Indonesia",
    "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", "IL": "Israel",
    "IT": "Italy", "JP": "Japan", "KZ": "Kazakhstan", "KE": "Kenya",
    "KP": "North Korea", "KR": "South Korea", "KW": "Kuwait",
    "MY": "Malaysia", "MX": "Mexico", "MA": "Morocco", "NL": "Netherlands",
    "NZ": "New Zealand", "NG": "Nigeria", "NO": "Norway", "PK": "Pakistan",
    "PE": "Peru", "PH": "Philippines", "PL": "Poland", "PT": "Portugal",
    "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia", "SG": "Singapore",
    "ZA": "South Africa", "ES": "Spain", "SE": "Sweden", "CH": "Switzerland",
    "TW": "Taiwan", "TH": "Thailand", "TR": "Turkey", "UA": "Ukraine",
    "AE": "UAE", "GB": "United Kingdom", "US": "United States",
    "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam",
}


def save_country_config(changes):
    from csf_backend import csf_wrapper as csf
    valid = {"CC_DENY", "CC_ALLOW", "CC_ALLOW_FILTER", "CC_ALLOW_PORTS", "CC_DENY_PORTS"}
    filtered = {k: v for k, v in changes.items() if k in valid}
    csf.save_csf_conf(filtered)
    return {"success": True, "message": "Country blocking updated. Restart CSF to apply."}


def get_connection_config():
    from csf_backend import csf_wrapper as csf
    conf = csf.load_csf_conf()
    return {
        "CONNLIMIT": conf.get("CONNLIMIT", ""),
        "PORTFLOOD": conf.get("PORTFLOOD", ""),
        "CT_LIMIT": conf.get("CT_LIMIT", "0"),
        "CT_INTERVAL": conf.get("CT_INTERVAL", "30"),
        "CT_PORTS": conf.get("CT_PORTS", ""),
        "CT_PERMANENT": conf.get("CT_PERMANENT", "0"),
        "CT_BLOCK_TIME": conf.get("CT_BLOCK_TIME", "1800"),
        "SYNFLOOD": conf.get("SYNFLOOD", "0"),
        "SYNFLOOD_RATE": conf.get("SYNFLOOD_RATE", "100/s"),
        "SYNFLOOD_BURST": conf.get("SYNFLOOD_BURST", "150"),
        "LF_TRIGGER": conf.get("LF_TRIGGER", "0"),
        "LF_SSHD": conf.get("LF_SSHD", "5"),
        "LF_FTPD": conf.get("LF_FTPD", "10"),
        "LF_SMTPAUTH": conf.get("LF_SMTPAUTH", "5"),
        "LF_POP3D": conf.get("LF_POP3D", "10"),
        "LF_IMAPD": conf.get("LF_IMAPD", "10"),
        "LF_HTACCESS": conf.get("LF_HTACCESS", "5"),
        "LF_MODSEC": conf.get("LF_MODSEC", "5"),
    }


def save_connection_config(changes):
    from csf_backend import csf_wrapper as csf
    valid = {
        "CONNLIMIT", "PORTFLOOD", "CT_LIMIT", "CT_INTERVAL", "CT_PORTS",
        "CT_PERMANENT", "CT_BLOCK_TIME", "SYNFLOOD", "SYNFLOOD_RATE",
        "SYNFLOOD_BURST", "LF_TRIGGER", "LF_SSHD", "LF_FTPD",
        "LF_SMTPAUTH", "LF_POP3D", "LF_IMAPD", "LF_HTACCESS", "LF_MODSEC",
    }
    filtered = {k: v for k, v in changes.items() if k in valid}
    csf.save_csf_conf(filtered)
    return {"success": True, "message": "Connection limits updated. Restart CSF to apply."}


def get_dyndns():
    entries = []
    try:
        with open(CSF_DYNDNS) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line)
    except OSError:
        pass
    return entries


def save_dyndns(entries):
    try:
        header = "# csf.dyndns - Dynamic DNS hostnames\n# One hostname per line\n\n"
        with open(CSF_DYNDNS, "w") as f:
            f.write(header)
            for entry in entries:
                entry = entry.strip()
                if entry:
                    f.write(entry + "\n")
        return {"success": True, "message": "Dynamic DNS updated. Restart CSF to apply."}
    except OSError as e:
        return {"success": False, "error": str(e)}


def get_api_keys():
    keys = {"ABUSEIPDB_KEY": ""}
    try:
        with open("/etc/csfv2/csfv2.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("ABUSEIPDB_KEY="):
                    keys["ABUSEIPDB_KEY"] = line.split("=", 1)[1].strip()
    except OSError:
        pass
    return keys


def save_api_keys(keys):
    conf_path = "/etc/csfv2/csfv2.conf"
    lines = []
    found_keys = set()
    try:
        with open(conf_path) as f:
            lines = f.readlines()
    except OSError:
        pass

    for i, line in enumerate(lines):
        for key in keys:
            if line.strip().startswith(key + "="):
                lines[i] = f"{key}={keys[key]}\n"
                found_keys.add(key)

    for key in keys:
        if key not in found_keys:
            lines.append(f"{key}={keys[key]}\n")

    os.makedirs(os.path.dirname(conf_path), exist_ok=True)
    with open(conf_path, "w") as f:
        f.writelines(lines)
    return {"success": True, "message": "API keys saved."}


def get_misc_config():
    from csf_backend import csf_wrapper as csf
    conf = csf.load_csf_conf()
    return {
        "TESTING": conf.get("TESTING", "1"),
        "DOCKER": conf.get("DOCKER", "0"),
        "AUTO_UPDATES": conf.get("AUTO_UPDATES", "0"),
        "LF_DAEMON": conf.get("LF_DAEMON", "1"),
        "LF_CSF": conf.get("LF_CSF", "1"),
        "RESTRICT_SYSLOG": conf.get("RESTRICT_SYSLOG", "0"),
        "SYSLOG_CHECK": conf.get("SYSLOG_CHECK", "0"),
        "PT_SKIP_HTTP": conf.get("PT_SKIP_HTTP", "0"),
        "ICMP_IN": conf.get("ICMP_IN", "1"),
        "ICMP_OUT": conf.get("ICMP_OUT", "1"),
        "IPV6": conf.get("IPV6", "0"),
        "DENY_IP_LIMIT": conf.get("DENY_IP_LIMIT", "200"),
        "DENY_TEMP_IP_LIMIT": conf.get("DENY_TEMP_IP_LIMIT", "100"),
        "LF_PERMBLOCK": conf.get("LF_PERMBLOCK", "0"),
        "LF_PERMBLOCK_INTERVAL": conf.get("LF_PERMBLOCK_INTERVAL", "86400"),
        "LF_PERMBLOCK_COUNT": conf.get("LF_PERMBLOCK_COUNT", "4"),
    }


def save_misc_config(changes):
    from csf_backend import csf_wrapper as csf
    valid = {
        "TESTING", "DOCKER", "AUTO_UPDATES", "LF_DAEMON", "LF_CSF",
        "RESTRICT_SYSLOG", "SYSLOG_CHECK", "PT_SKIP_HTTP", "ICMP_IN",
        "ICMP_OUT", "IPV6", "DENY_IP_LIMIT", "DENY_TEMP_IP_LIMIT",
        "LF_PERMBLOCK", "LF_PERMBLOCK_INTERVAL", "LF_PERMBLOCK_COUNT",
    }
    filtered = {k: v for k, v in changes.items() if k in valid}
    csf.save_csf_conf(filtered)
    return {"success": True, "message": "Settings updated. Restart CSF to apply."}


def get_alerts_config():
    from csf_backend import csf_wrapper as csf
    conf = csf.load_csf_conf()
    return {
        "LF_ALERT_TO": conf.get("LF_ALERT_TO", ""),
        "LF_ALERT_FROM": conf.get("LF_ALERT_FROM", ""),
        "LF_EMAIL_ALERT": conf.get("LF_EMAIL_ALERT", "1"),
        "LF_TEMP_EMAIL_ALERT": conf.get("LF_TEMP_EMAIL_ALERT", "0"),
        "BLOCK_REPORT": conf.get("BLOCK_REPORT", "0"),
        "UNBLOCK_REPORT": conf.get("UNBLOCK_REPORT", "0"),
        "LF_SSH_EMAIL_ALERT": conf.get("LF_SSH_EMAIL_ALERT", "0"),
        "LF_SU_EMAIL_ALERT": conf.get("LF_SU_EMAIL_ALERT", "0"),
        "LF_CONSOLE_EMAIL_ALERT": conf.get("LF_CONSOLE_EMAIL_ALERT", "0"),
        "LF_PERMBLOCK_ALERT": conf.get("LF_PERMBLOCK_ALERT", "1"),
        "LOGSCANNER": conf.get("LOGSCANNER", "0"),
        "LOGSCANNER_INTERVAL": conf.get("LOGSCANNER_INTERVAL", "hourly"),
    }


def save_alerts_config(changes):
    from csf_backend import csf_wrapper as csf
    valid = {
        "LF_ALERT_TO", "LF_ALERT_FROM", "LF_EMAIL_ALERT",
        "LF_TEMP_EMAIL_ALERT", "BLOCK_REPORT", "UNBLOCK_REPORT",
        "LF_SSH_EMAIL_ALERT", "LF_SU_EMAIL_ALERT",
        "LF_CONSOLE_EMAIL_ALERT", "LF_PERMBLOCK_ALERT",
        "LOGSCANNER", "LOGSCANNER_INTERVAL",
    }
    filtered = {k: v for k, v in changes.items() if k in valid}
    csf.save_csf_conf(filtered)
    return {"success": True, "message": "Alert settings saved. Restart CSF to apply."}


def get_cloudflare_config():
    from csf_backend import csf_wrapper as csf
    conf = csf.load_csf_conf()
    return {
        "CF_ENABLE": conf.get("CF_ENABLE", "0"),
        "CF_BLOCK": conf.get("CF_BLOCK", "0"),
        "CF_TEMP": conf.get("CF_TEMP", "0"),
    }


def save_cloudflare_config(changes):
    from csf_backend import csf_wrapper as csf
    valid = {"CF_ENABLE", "CF_BLOCK", "CF_TEMP"}
    filtered = {k: v for k, v in changes.items() if k in valid}
    csf.save_csf_conf(filtered)
    return {"success": True, "message": "CloudFlare settings saved. Restart CSF to apply."}


def get_security_config():
    from csf_backend import csf_wrapper as csf
    conf = csf.load_csf_conf()
    return {
        "PT_LIMIT": conf.get("PT_LIMIT", "0"),
        "PT_USERMEM": conf.get("PT_USERMEM", "0"),
        "PT_USERTIME": conf.get("PT_USERTIME", "0"),
        "PT_SKIP_HTTP": conf.get("PT_SKIP_HTTP", "0"),
        "PT_DELETED": conf.get("PT_DELETED", "0"),
        "PS_INTERVAL": conf.get("PS_INTERVAL", "0"),
        "PS_LIMIT": conf.get("PS_LIMIT", "0"),
        "LF_DIRWATCH": conf.get("LF_DIRWATCH", "0"),
        "LF_INTEGRITY": conf.get("LF_INTEGRITY", "0"),
        "LF_DISTATTACK": conf.get("LF_DISTATTACK", "0"),
        "LF_DISTATTACK_UNIQ": conf.get("LF_DISTATTACK_UNIQ", "2"),
        "AT_ALERT": conf.get("AT_ALERT", "0"),
        "LF_EXPLOIT": conf.get("LF_EXPLOIT", "0"),
        "SMTP_BLOCK": conf.get("SMTP_BLOCK", "0"),
        "LF_APACHE_404": conf.get("LF_APACHE_404", "0"),
        "LF_APACHE_403": conf.get("LF_APACHE_403", "0"),
    }


def save_security_config(changes):
    from csf_backend import csf_wrapper as csf
    valid = {
        "PT_LIMIT", "PT_USERMEM", "PT_USERTIME", "PT_SKIP_HTTP",
        "PT_DELETED", "PS_INTERVAL", "PS_LIMIT",
        "LF_DIRWATCH", "LF_INTEGRITY",
        "LF_DISTATTACK", "LF_DISTATTACK_UNIQ",
        "AT_ALERT", "LF_EXPLOIT", "SMTP_BLOCK",
        "LF_APACHE_404", "LF_APACHE_403",
    }
    filtered = {k: v for k, v in changes.items() if k in valid}
    csf.save_csf_conf(filtered)
    return {"success": True, "message": "Security settings saved. Restart CSF to apply."}
