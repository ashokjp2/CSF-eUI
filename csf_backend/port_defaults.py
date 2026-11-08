import os
import re
import subprocess


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


# Services we recognise and the ports they need
SERVICE_DEFS = {
    "sshd": {
        "label": "SSH",
        "detect": lambda: _detect_ssh(),
        "tcp_in": True,
    },
    "http": {
        "label": "HTTP",
        "port": "80",
        "detect": lambda: _service_listening(80),
        "tcp_in": True,
    },
    "https": {
        "label": "HTTPS",
        "port": "443",
        "detect": lambda: _service_listening(443),
        "tcp_in": True,
    },
    "smtp": {
        "label": "SMTP",
        "port": "25",
        "detect": lambda: _service_listening(25),
        "tcp_in": True,
        "tcp_out": True,
    },
    "smtps": {
        "label": "SMTPS",
        "port": "465",
        "detect": lambda: _service_listening(465),
        "tcp_in": True,
        "tcp_out": True,
    },
    "submission": {
        "label": "SMTP Submission",
        "port": "587",
        "detect": lambda: _service_listening(587),
        "tcp_in": True,
        "tcp_out": True,
    },
    "dns": {
        "label": "DNS",
        "port": "53",
        "detect": lambda: _service_listening(53),
        "tcp_in": True,
        "udp_in": True,
        "tcp_out": True,
        "udp_out": True,
    },
    "ftp": {
        "label": "FTP",
        "port": "21",
        "detect": lambda: _service_listening(21),
        "tcp_in": True,
    },
    "mysql": {
        "label": "MySQL",
        "port": "3306",
        "detect": lambda: _service_listening(3306),
        "tcp_in": True,
    },
    "postgres": {
        "label": "PostgreSQL",
        "port": "5432",
        "detect": lambda: _service_listening(5432),
        "tcp_in": True,
    },
    "redis": {
        "label": "Redis",
        "port": "6379",
        "detect": lambda: _service_listening(6379),
        "tcp_in": True,
    },
    "mongodb": {
        "label": "MongoDB",
        "port": "27017",
        "detect": lambda: _service_listening(27017),
        "tcp_in": True,
    },
    "cockpit": {
        "label": "Cockpit",
        "port": "9090",
        "detect": lambda: _service_listening(9090),
        "tcp_in": True,
    },
    "wireguard": {
        "label": "WireGuard VPN",
        "port": "51820",
        "detect": lambda: os.path.exists("/etc/wireguard") and len([f for f in os.listdir("/etc/wireguard") if f.endswith(".conf")]) > 0,
        "udp_in": True,
        "udp_out": True,
    },
    "wg_ui": {
        "label": "WireGuard UI",
        "port": "51821",
        "detect": lambda: _service_listening(51821),
        "tcp_in": True,
    },
    "docker": {
        "label": "Docker (VXLAN)",
        "port": "4789",
        "detect": lambda: bool(_run(["docker", "info", "--format", "{{.ID}}"])),
        "udp_in": True,
        "udp_out": True,
    },
    "dokploy": {
        "label": "Dokploy",
        "port": "3000",
        "detect": lambda: _service_listening(3000),
        "tcp_in": True,
    },
    "csfv2": {
        "label": "CSFv2 UI",
        "port": "8750",
        "detect": lambda: _service_listening(8750),
        "tcp_in": True,
    },
    "pop3": {
        "label": "POP3",
        "port": "110",
        "detect": lambda: _service_listening(110),
        "tcp_in": True,
    },
    "imap": {
        "label": "IMAP",
        "port": "143",
        "detect": lambda: _service_listening(143),
        "tcp_in": True,
    },
    "imaps": {
        "label": "IMAPS",
        "port": "993",
        "detect": lambda: _service_listening(993),
        "tcp_in": True,
    },
    "pop3s": {
        "label": "POP3S",
        "port": "995",
        "detect": lambda: _service_listening(995),
        "tcp_in": True,
    },
    "elasticsearch": {
        "label": "Elasticsearch",
        "port": "9200",
        "detect": lambda: _service_listening(9200),
        "tcp_in": True,
    },
    "vnc": {
        "label": "VNC",
        "port": "5900",
        "detect": lambda: _service_listening(5900),
        "tcp_in": True,
    },
}

# Outbound ports every server needs
BASELINE_TCP_OUT = {
    "80": "HTTP (updates/packages)",
    "443": "HTTPS (updates/packages)",
    "53": "DNS lookups",
    "113": "IDENT",
    "123": "NTP",
}

BASELINE_UDP_OUT = {
    "53": "DNS lookups",
    "123": "NTP",
    "6277": "CSF cluster",
}


def _get_listening_ports():
    """Return set of (proto, port) tuples currently listening."""
    result = set()
    ss = _run(["ss", "-tlnp"])
    if ss:
        for line in ss.splitlines()[1:]:
            m = re.search(r':(\d+)\s', line)
            if m:
                result.add(("tcp", m.group(1)))
    ss = _run(["ss", "-ulnp"])
    if ss:
        for line in ss.splitlines()[1:]:
            m = re.search(r':(\d+)\s', line)
            if m:
                result.add(("udp", m.group(1)))
    return result


_listening_cache = None


def _get_listening():
    global _listening_cache
    if _listening_cache is None:
        _listening_cache = _get_listening_ports()
    return _listening_cache


def _service_listening(port):
    return ("tcp", str(port)) in _get_listening() or ("udp", str(port)) in _get_listening()


def _detect_ssh():
    """Detect SSH and return its actual port."""
    raw = _read("/etc/ssh/sshd_config")
    port = "22"
    for line in raw.splitlines():
        line = line.strip()
        if line.lower().startswith("port ") and not line.startswith("#"):
            port = line.split(None, 1)[1].strip()
            break
    inc_dir = "/etc/ssh/sshd_config.d"
    if os.path.isdir(inc_dir):
        for fn in sorted(os.listdir(inc_dir)):
            if fn.endswith(".conf"):
                for line in _read(os.path.join(inc_dir, fn)).splitlines():
                    line = line.strip()
                    if line.lower().startswith("port ") and not line.startswith("#"):
                        port = line.split(None, 1)[1].strip()
    return port


def detect_services():
    """Scan the server and return detected services with their ports."""
    global _listening_cache
    _listening_cache = None  # reset cache

    detected = []
    for svc_id, svc in SERVICE_DEFS.items():
        result = svc["detect"]()
        if result:
            port = result if isinstance(result, str) else svc.get("port", "")
            detected.append({
                "id": svc_id,
                "label": svc["label"],
                "port": port,
                "tcp_in": svc.get("tcp_in", False),
                "tcp_out": svc.get("tcp_out", False),
                "udp_in": svc.get("udp_in", False),
                "udp_out": svc.get("udp_out", False),
            })

    return detected


def generate_defaults():
    """Generate smart port defaults based on detected services."""
    detected = detect_services()

    tcp_in = set()
    tcp_out = set(BASELINE_TCP_OUT.keys())
    udp_in = set()
    udp_out = set(BASELINE_UDP_OUT.keys())

    for svc in detected:
        port = svc["port"]
        if not port:
            continue
        if svc["tcp_in"]:
            tcp_in.add(port)
        if svc["tcp_out"]:
            tcp_out.add(port)
        if svc["udp_in"]:
            udp_in.add(port)
        if svc["udp_out"]:
            udp_out.add(port)

    def sort_ports(s):
        return sorted(s, key=lambda p: int(p) if p.isdigit() else 99999)

    defaults = {
        "TCP_IN": ",".join(sort_ports(tcp_in)),
        "TCP_OUT": ",".join(sort_ports(tcp_out)),
        "UDP_IN": ",".join(sort_ports(udp_in)),
        "UDP_OUT": ",".join(sort_ports(udp_out)),
        "TCP6_IN": ",".join(sort_ports(tcp_in)),
        "TCP6_OUT": ",".join(sort_ports(tcp_out)),
        "UDP6_IN": ",".join(sort_ports(udp_in)),
        "UDP6_OUT": ",".join(sort_ports(udp_out)),
    }

    from csf_backend import csf_wrapper as csf
    conf = csf.load_csf_conf()
    current = {}
    for key in defaults:
        current[key] = conf.get(key, "")

    labels = {}
    for svc in detected:
        if svc["port"]:
            labels[svc["port"]] = svc["label"]
    labels.update({p: lbl for p, lbl in BASELINE_TCP_OUT.items()})
    labels.update({p: lbl for p, lbl in BASELINE_UDP_OUT.items()})

    return {
        "detected": detected,
        "defaults": defaults,
        "current": current,
        "labels": labels,
    }


def get_port_recommendations():
    """Return per-service port gap analysis vs current CSF config."""
    from csf_backend import csf_wrapper as csf

    conf = csf.load_csf_conf()

    def _parse_set(key):
        return {p.strip() for p in conf.get(key, "").split(",") if p.strip()}

    tcp_in = _parse_set("TCP_IN")
    tcp_out = _parse_set("TCP_OUT")
    udp_in = _parse_set("UDP_IN")
    udp_out = _parse_set("UDP_OUT")
    cc_tcp = _parse_set("CC_ALLOW_PORTS_TCP")
    cc_udp = _parse_set("CC_ALLOW_PORTS_UDP")

    detected = detect_services()
    recommendations = []

    for svc in detected:
        port = svc["port"]
        if not port:
            continue

        gaps = []
        already_open = []
        country_restricted = []

        for needed, current_set, cc_set, key, label in [
            (svc["tcp_in"],  tcp_in,  cc_tcp, "TCP_IN",  "Incoming TCP"),
            (svc["tcp_out"], tcp_out, cc_tcp, "TCP_OUT", "Outgoing TCP"),
            (svc["udp_in"],  udp_in,  cc_udp, "UDP_IN",  "Incoming UDP"),
            (svc["udp_out"], udp_out, cc_udp, "UDP_OUT", "Outgoing UDP"),
        ]:
            if needed:
                if port in current_set:
                    already_open.append({"key": key, "label": label, "port": port})
                elif port in cc_set:
                    country_restricted.append({"key": key, "label": label, "port": port})
                else:
                    gaps.append({"key": key, "label": label, "port": port})

        if gaps:
            status = "missing"
        elif country_restricted and not already_open:
            status = "country_restricted"
        else:
            status = "ok"

        recommendations.append({
            "id": svc["id"],
            "label": svc["label"],
            "port": port,
            "gaps": gaps,
            "already_open": already_open,
            "country_restricted": country_restricted,
            "status": status,
        })

    return {
        "recommendations": recommendations,
        "has_gaps": any(r["status"] == "missing" for r in recommendations),
    }


def _normalise_port(port):
    port = str(port).strip()
    if not port.isdigit() or len(port) > 5:
        return None
    port_number = int(port)
    if not 1 <= port_number <= 65535:
        return None
    return str(port_number)


def add_single_port(key, port):
    """Add one port to a CSF firewall rule key."""
    from csf_backend import csf_wrapper as csf
    valid_keys = {"TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT", "TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT"}
    port = _normalise_port(port)
    if key not in valid_keys or port is None:
        return {"success": False, "error": "Invalid key or port"}
    conf = csf.load_csf_conf()
    existing = {p.strip() for p in conf.get(key, "").split(",") if p.strip()}
    existing.add(str(port))
    new_val = ",".join(sorted(existing, key=lambda p: int(p) if p.isdigit() else 99999))
    save_result = csf.save_csf_conf({key: new_val})
    if not save_result.get("success"):
        return save_result
    return {"success": True, "message": "Port {} added to {}".format(port, key)}


def remove_single_port(key, port):
    """Remove one exact port from a CSF firewall rule key."""
    from csf_backend import csf_wrapper as csf
    valid_keys = {"TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT", "TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT"}
    port = _normalise_port(port)
    if key not in valid_keys or port is None:
        return {"success": False, "error": "Invalid key or port"}

    conf = csf.load_csf_conf()
    existing = [p.strip() for p in conf.get(key, "").split(",") if p.strip()]
    if port not in existing:
        return {"success": False, "error": "Port {} is not in {}".format(port, key)}

    new_val = ",".join(p for p in existing if p != port)
    save_result = csf.save_csf_conf({key: new_val})
    if not save_result.get("success"):
        return save_result
    return {"success": True, "message": "Port {} removed from {}".format(port, key)}


def apply_defaults(selections):
    """Apply the selected port defaults. selections is dict of key->csv."""
    from csf_backend import csf_wrapper as csf
    changes = {}
    valid_keys = {"TCP_IN", "TCP_OUT", "UDP_IN", "UDP_OUT", "TCP6_IN", "TCP6_OUT", "UDP6_IN", "UDP6_OUT"}
    for key, val in selections.items():
        if key in valid_keys:
            changes[key] = ",".join(p.strip() for p in val.split(",") if p.strip())
    if changes:
        csf.save_csf_conf(changes)
    return {"success": True, "message": "Port settings reset to smart defaults. Restart CSF to apply.", "applied": changes}
