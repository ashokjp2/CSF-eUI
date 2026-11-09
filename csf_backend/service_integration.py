import os
import re
import subprocess
from pathlib import Path

CSF_IGNORE = "/etc/csf/csf.ignore"
CSF_PIGNORE = "/etc/csf/csf.pignore"
CSFPOST = "/etc/csf/csfpost.sh"
DOCKER_RULE_MARKER = "# CSFV2-DOCKER-FORWARDING"


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def detect_docker_networks():
    networks = []
    raw = _run(["docker", "network", "ls", "--format", "{{.Name}}"])
    if not raw:
        return networks
    for name in raw.splitlines():
        name = name.strip()
        if not name or name in ("host", "none"):
            continue
        subnet = _run([
            "docker", "network", "inspect", name,
            "--format", "{{range .IPAM.Config}}{{.Subnet}}{{end}}"
        ])
        if subnet:
            networks.append({"name": name, "subnet": subnet, "type": "docker"})
    return networks


def ensure_docker_forwarding_rules():
    """Keep CSF from blocking Docker bridge and Swarm overlay forwarding."""
    if not _run(["docker", "info", "--format", "{{.ID}}"]):
        return {"success": True, "changed": False, "message": "Docker is not running."}
    # Docker can restore Traefik's port bindings without restoring its network
    # attachment after a daemon restart. Reconnect the existing proxy only
    # when it has no network, preserving its configuration and volumes.
    if _run(["docker", "ps", "-q", "-f", "name=^dokploy-traefik$"]):
        networks = _run(["docker", "inspect", "dokploy-traefik",
                         "--format", "{{json .NetworkSettings.Networks}}"])
        if networks in ("{}", "null", ""):
            _run(["docker", "network", "connect", "dokploy-network", "dokploy-traefik"])
    path = Path(CSFPOST)
    try:
        existing = path.read_text() if path.exists() else ""
        if DOCKER_RULE_MARKER in existing:
            return {"success": True, "changed": False, "message": "Docker forwarding rules already installed."}
        block = '''
# CSFV2-DOCKER-FORWARDING
# Preserve Docker bridge and Swarm overlay traffic when CSF reloads.
for IFACE in docker0 docker_gwbridge ingress; do
    iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$IFACE" -j ACCEPT
    iptables -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$IFACE" -j ACCEPT
done
'''
        path.write_text(existing.rstrip() + block)
        path.chmod(0o700)
        return {"success": True, "changed": True, "message": "Docker forwarding rules installed."}
    except OSError as exc:
        return {"success": False, "changed": False, "message": str(exc)}


def detect_wireguard_networks():
    networks = []
    raw = _run(["wg", "show", "interfaces"])
    if not raw:
        return networks
    for iface in raw.split():
        iface = iface.strip()
        if not iface:
            continue
        addr_raw = _run(["ip", "-4", "addr", "show", iface])
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", addr_raw)
        if match:
            networks.append({"name": f"wg:{iface}", "subnet": match.group(1), "type": "wireguard"})
    return networks


def detect_netbird_networks():
    networks = []
    addr_raw = _run(["ip", "-4", "addr", "show", "wt0"])
    match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", addr_raw)
    if match:
        networks.append({"name": "netbird:wt0", "subnet": match.group(1), "type": "netbird"})
    return networks


def detect_all_services():
    services = []
    services.extend(detect_docker_networks())
    services.extend(detect_wireguard_networks())
    services.extend(detect_netbird_networks())
    return services


def get_csf_ignore_entries():
    entries = []
    try:
        with open(CSF_IGNORE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line)
    except OSError:
        pass
    return entries


def get_csf_pignore_entries():
    entries = []
    try:
        with open(CSF_PIGNORE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(line)
    except OSError:
        pass
    return entries


def add_to_csf_ignore(subnet, comment=""):
    entries = get_csf_ignore_entries()
    clean = subnet.strip()
    if clean in entries:
        return {"success": True, "message": f"{clean} already in csf.ignore"}
    try:
        with open(CSF_IGNORE, "a") as f:
            if comment:
                f.write(f"\n# {comment}\n")
            f.write(clean + "\n")
        return {"success": True, "message": f"Added {clean} to csf.ignore. Restart LFD to apply."}
    except OSError as e:
        return {"success": False, "error": str(e)}


def remove_from_csf_ignore(subnet):
    clean = subnet.strip()
    try:
        with open(CSF_IGNORE) as f:
            lines = f.readlines()
        new_lines = []
        skip_comment = False
        for line in lines:
            stripped = line.strip()
            if stripped == clean:
                skip_comment = False
                continue
            if skip_comment and stripped.startswith("#"):
                skip_comment = False
                continue
            new_lines.append(line)
        with open(CSF_IGNORE, "w") as f:
            f.writelines(new_lines)
        return {"success": True, "message": f"Removed {clean} from csf.ignore. Restart LFD to apply."}
    except OSError as e:
        return {"success": False, "error": str(e)}


def add_to_csf_pignore(entry, comment=""):
    entries = get_csf_pignore_entries()
    clean = entry.strip()
    if clean in entries:
        return {"success": True, "message": f"{clean} already in csf.pignore"}
    try:
        with open(CSF_PIGNORE, "a") as f:
            if comment:
                f.write(f"\n# {comment}\n")
            f.write(clean + "\n")
        return {"success": True, "message": f"Added {clean} to csf.pignore. Restart LFD to apply."}
    except OSError as e:
        return {"success": False, "error": str(e)}


def get_integration_status():
    detected = detect_all_services()
    ignored = get_csf_ignore_entries()
    pignored = get_csf_pignore_entries()

    for svc in detected:
        svc["ignored"] = svc["subnet"] in ignored

    common_processes = [
        {"entry": "pexe:/usr/lib/postgresql/.*/bin/postgres", "label": "PostgreSQL", "ignored": False},
        {"entry": "exe:/usr/sbin/nginx", "label": "Nginx", "ignored": False},
        {"entry": "pexe:/usr/local/bin/node.*", "label": "Node.js", "ignored": False},
        {"entry": "exe:/usr/bin/redis-server", "label": "Redis", "ignored": False},
        {"entry": "user:postgres", "label": "postgres user", "ignored": False},
        {"entry": "user:www-data", "label": "www-data user", "ignored": False},
    ]
    for proc in common_processes:
        proc["ignored"] = proc["entry"] in pignored

    return {
        "networks": detected,
        "ignored_ips": ignored,
        "process_ignores": common_processes,
    }


def _parse_ports(csv):
    return set(p.strip() for p in csv.split(",") if p.strip())


def check_service_ports():
    """Return per-service port checklist across TCP_IN/OUT and UDP_IN/OUT."""
    from csf_backend import csf_wrapper as csf, wireguard_manager as wg

    conf = csf.load_csf_conf()
    tcp_in  = _parse_ports(conf.get("TCP_IN",  ""))
    tcp_out = _parse_ports(conf.get("TCP_OUT", ""))
    udp_in  = _parse_ports(conf.get("UDP_IN",  ""))
    udp_out = _parse_ports(conf.get("UDP_OUT", ""))
    cc_tcp  = _parse_ports(conf.get("CC_ALLOW_PORTS_TCP", ""))
    cc_udp  = _parse_ports(conf.get("CC_ALLOW_PORTS_UDP", ""))
    docker_on = conf.get("DOCKER", "0") == "1"

    detected = detect_all_services()
    service_types = {s["type"] for s in detected}

    def _port_check(rule_set, cc_set, port):
        if port in rule_set:
            return {"open": True, "country_restricted": False}
        if port in cc_set:
            return {"open": False, "country_restricted": True}
        return {"open": False, "country_restricted": False}

    # Build per-service entries: each has label, port_checks list, settings list
    # port_checks: {rule, port, open, reason}
    # settings:    {key, value, ok, reason}
    services = []

    # ── SSH ──────────────────────────────────────────────────────────────
    ssh_port = "22"
    try:
        raw = open("/etc/ssh/sshd_config").read()
        for line in raw.splitlines():
            line = line.strip()
            if line.lower().startswith("port ") and not line.startswith("#"):
                ssh_port = line.split(None, 1)[1].strip()
    except Exception:
        pass
    if any(s["type"] == "ssh" for s in detected) or True:  # SSH always relevant
        services.append({
            "label": "SSH",
            "icon": "glyphicon-lock",
            "port_checks": [
                {"rule": "TCP_IN",  "port": ssh_port, **_port_check(tcp_in, cc_tcp, ssh_port), "reason": "Accept SSH connections"},
            ],
            "settings": [],
        })

    # ── HTTP / HTTPS ──────────────────────────────────────────────────────
    for svc_type, label, port in [("http", "HTTP", "80"), ("https", "HTTPS", "443")]:
        if any(s["type"] == svc_type for s in detected):
            services.append({
                "label": label,
                "icon": "glyphicon-globe",
                "port_checks": [
                    {"rule": "TCP_IN",  "port": port, **_port_check(tcp_in, cc_tcp, port), "reason": "Accept web traffic"},
                    {"rule": "TCP_OUT", "port": port, **_port_check(tcp_out, cc_tcp, port), "reason": "Outbound web / package updates"},
                ],
                "settings": [],
            })

    # ── Docker ───────────────────────────────────────────────────────────
    if "docker" in service_types:
        services.append({
            "label": "Docker",
            "icon": "glyphicon-th-large",
            "port_checks": [
                {"rule": "UDP_IN",  "port": "4789", **_port_check(udp_in, cc_udp, "4789"), "reason": "VXLAN overlay network (inter-host)"},
                {"rule": "UDP_OUT", "port": "4789", **_port_check(udp_out, cc_udp, "4789"), "reason": "VXLAN overlay network (inter-host)"},
                {"rule": "TCP_OUT", "port": "80",   **_port_check(tcp_out, cc_tcp, "80"),   "reason": "Pull images from Docker Hub"},
                {"rule": "TCP_OUT", "port": "443",  **_port_check(tcp_out, cc_tcp, "443"),  "reason": "Pull images (HTTPS)"},
            ],
            "settings": [
                {"key": "DOCKER", "value": "1", "ok": docker_on, "reason": "DOCKER=1 lets CSF manage container iptables rules"},
            ],
        })

    # ── WireGuard ─────────────────────────────────────────────────────────
    if wg.is_installed():
        for cfg in wg.list_configs():
            content = wg.read_config(cfg["interface"])
            listen_port = "51820"
            if content:
                try:
                    parsed = wg.parse_config(content)
                    listen_port = parsed.get("interface", {}).get("ListenPort", "51820")
                except Exception:
                    pass
            iface = cfg["interface"]
            services.append({
                "label": "WireGuard ({})".format(iface),
                "icon": "glyphicon-random",
                "port_checks": [
                    {"rule": "UDP_IN",  "port": listen_port, **_port_check(udp_in, cc_udp, listen_port), "reason": "WireGuard VPN tunnel"},
                    {"rule": "UDP_OUT", "port": listen_port, **_port_check(udp_out, cc_udp, listen_port), "reason": "WireGuard VPN tunnel (outbound)"},
                ],
                "settings": [],
            })

    # ── Netbird ───────────────────────────────────────────────────────────
    if "netbird" in service_types:
        nb_port = "51820"
        try:
            import json
            with open("/etc/netbird/config.json") as f:
                nb_conf = json.load(f)
            nb_port = str(nb_conf.get("WireGuardPort", nb_conf.get("WgPort", "51820")))
        except Exception:
            pass
        services.append({
            "label": "Netbird",
            "icon": "glyphicon-random",
            "port_checks": [
                {"rule": "UDP_IN",  "port": nb_port, **_port_check(udp_in, cc_udp, nb_port), "reason": "Netbird WireGuard tunnel"},
                {"rule": "UDP_OUT", "port": nb_port, **_port_check(udp_out, cc_udp, nb_port), "reason": "Netbird WireGuard tunnel (outbound)"},
            ],
            "settings": [],
        })

    # ── Dokploy / Coolify ─────────────────────────────────────────────────
    for svc_type, label, port in [("dokploy", "Dokploy", "3000"), ("coolify", "Coolify", "8000")]:
        if any(s["type"] == svc_type for s in detected):
            services.append({
                "label": label,
                "icon": "glyphicon-cloud",
                "port_checks": [
                    {"rule": "TCP_IN",  "port": port, **_port_check(tcp_in, cc_tcp, port), "reason": "{} web UI".format(label)},
                    {"rule": "TCP_OUT", "port": "80",  **_port_check(tcp_out, cc_tcp, "80"),  "reason": "Outbound HTTP for deployments"},
                    {"rule": "TCP_OUT", "port": "443", **_port_check(tcp_out, cc_tcp, "443"), "reason": "Outbound HTTPS for deployments"},
                ],
                "settings": [],
            })

    # ── CSFv2 UI ──────────────────────────────────────────────────────────
    if any(s["type"] == "csfv2" for s in detected):
        services.append({
            "label": "CSFv2 UI",
            "icon": "glyphicon-fire",
            "port_checks": [
                {"rule": "TCP_IN", "port": "8750", **_port_check(tcp_in, cc_tcp, "8750"), "reason": "CSFv2 management interface"},
            ],
            "settings": [],
        })

    # ── DNS ───────────────────────────────────────────────────────────────
    if any(s["type"] in ("dns", "named", "bind") for s in detected):
        services.append({
            "label": "DNS Server",
            "icon": "glyphicon-tasks",
            "port_checks": [
                {"rule": "TCP_IN",  "port": "53", **_port_check(tcp_in, cc_tcp, "53"), "reason": "DNS TCP queries"},
                {"rule": "UDP_IN",  "port": "53", **_port_check(udp_in, cc_udp, "53"), "reason": "DNS UDP queries"},
                {"rule": "TCP_OUT", "port": "53", **_port_check(tcp_out, cc_tcp, "53"), "reason": "Outbound DNS resolution"},
                {"rule": "UDP_OUT", "port": "53", **_port_check(udp_out, cc_udp, "53"), "reason": "Outbound DNS resolution"},
            ],
            "settings": [],
        })

    # ── Baseline outbound ─────────────────────────────────────────────────
    baseline = []
    for rule, port, reason in [
        ("TCP_OUT", "80",  "HTTP package updates / apt"),
        ("TCP_OUT", "443", "HTTPS package updates"),
        ("UDP_OUT", "53",  "DNS resolution"),
        ("UDP_OUT", "123", "NTP time sync"),
    ]:
        rule_set = {"TCP_OUT": tcp_out, "UDP_OUT": udp_out}.get(rule, set())
        baseline.append({"rule": rule, "port": port, **_port_check(rule_set, cc_tcp, port), "reason": reason})
    services.append({
        "label": "Server Baseline (outbound)",
        "icon": "glyphicon-upload",
        "port_checks": baseline,
        "settings": [],
    })

    has_issues = any(
        not pc["open"] and not pc.get("country_restricted") for svc in services for pc in svc["port_checks"]
    ) or any(
        not s["ok"] for svc in services for s in svc["settings"]
    )

    return {
        "services": services,
        "has_issues": has_issues,
        "service_types": list(service_types),
    }


def add_service_ports(tcp_ports, udp_ports):
    """Add the given ports to TCP_IN / UDP_IN in csf.conf."""
    from csf_backend import csf_wrapper as csf

    conf = csf.load_csf_conf()
    changes = {}

    for key, new_ports in (("TCP_IN", tcp_ports), ("UDP_IN", udp_ports)):
        if not new_ports:
            continue
        existing = _parse_ports(conf.get(key, ""))
        added = [p for p in new_ports if p not in existing]
        if added:
            merged = sorted(existing | set(added), key=lambda x: int(x) if x.isdigit() else 99999)
            changes[key] = ",".join(merged)

    if not changes:
        return {"success": True, "message": "All ports were already present — no changes needed."}

    csf.save_csf_conf(changes)
    desc = []
    if "TCP_IN" in changes:
        desc.append(f"TCP_IN: {changes['TCP_IN']}")
    if "UDP_IN" in changes:
        desc.append(f"UDP_IN: {changes['UDP_IN']}")
    return {"success": True, "message": f"Ports added. Restart CSF to apply. Updated: {'; '.join(desc)}"}


def auto_fix_all():
    results = []
    detected = detect_all_services()
    ignored = get_csf_ignore_entries()
    for svc in detected:
        if svc["subnet"] not in ignored:
            r = add_to_csf_ignore(svc["subnet"], f"{svc['type']}: {svc['name']}")
            results.append({"subnet": svc["subnet"], "name": svc["name"], "result": r})

    common_pignore = [
        ("pexe:/usr/lib/postgresql/.*/bin/postgres", "PostgreSQL containers"),
        ("exe:/usr/sbin/nginx", "Nginx containers"),
        ("pexe:/usr/local/bin/node.*", "Node.js containers"),
        ("exe:/usr/bin/redis-server", "Redis containers"),
        ("user:postgres", "postgres user"),
        ("user:www-data", "www-data user"),
    ]
    pignored = get_csf_pignore_entries()
    for entry, comment in common_pignore:
        if entry not in pignored:
            r = add_to_csf_pignore(entry, comment)
            results.append({"entry": entry, "name": comment, "result": r})

    return {"success": True, "fixes": results, "message": f"Applied {len(results)} fixes. Restart LFD to take effect."}
