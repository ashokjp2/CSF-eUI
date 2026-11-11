import os
import re
import subprocess
from pathlib import Path
import pwd
import shutil

CSF_IGNORE = "/etc/csf/csf.ignore"
CSF_PIGNORE = "/etc/csf/csf.pignore"
CSFPOST = "/etc/csf/csfpost.sh"
DOCKER_RULE_MARKER = "# CSFV2-DOCKER-FORWARDING"
DOCKER_RULE_END_MARKER = "# END CSFV2-DOCKER-FORWARDING"


def _docker_forwarding_block():
    """Return the managed CSF hook for all active Docker bridge networks."""
    return '''
# CSFV2-DOCKER-FORWARDING
# Preserve Docker bridge and Swarm overlay traffic when CSF reloads.
# Coolify and Compose use dynamically named br-* interfaces, so do not assume
# that the default docker0 bridge is the only Docker network on the host.
DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
DOCKER_MAJOR="${DOCKER_VERSION%%.*}"
if [ "${DOCKER_MAJOR:-0}" -ge 28 ] && ! iptables -t filter -S DOCKER-FORWARD >/dev/null 2>&1; then
    # Docker owns DOCKER-FORWARD and its related chains. Let Docker recreate
    # its complete, version-specific graph instead of building partial rules.
    systemctl restart docker >/dev/null 2>&1 || true
fi
DOCKER_IFACES="docker0 docker_gwbridge ingress"
for IFACE in $(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^br-[[:xdigit:]]+$/ {print $2}'); do
    DOCKER_IFACES="$DOCKER_IFACES $IFACE"
done
for IFACE in $DOCKER_IFACES; do
    [ -d "/sys/class/net/$IFACE" ] || continue
    iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || \\
        iptables -I FORWARD 1 -i "$IFACE" -j ACCEPT
    iptables -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || \\
        iptables -I FORWARD 1 -o "$IFACE" -j ACCEPT
    for SUBNET in $(ip -4 route show dev "$IFACE" scope link 2>/dev/null | awk '$1 ~ /^[0-9]+\\./ {print $1}'); do
        iptables -t nat -C POSTROUTING -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE 2>/dev/null || \\
            iptables -t nat -A POSTROUTING -s "$SUBNET" ! -o "$IFACE" -j MASQUERADE
    done
done
# END CSFV2-DOCKER-FORWARDING
'''


def _upsert_docker_forwarding_block(existing):
    """Add or upgrade only the block previously managed by CSFv2."""
    block = _docker_forwarding_block()
    if DOCKER_RULE_END_MARKER in existing:
        return existing, False

    legacy_block = '''
# CSFV2-DOCKER-FORWARDING
# Preserve Docker bridge and Swarm overlay traffic when CSF reloads.
for IFACE in docker0 docker_gwbridge ingress; do
    iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$IFACE" -j ACCEPT
    iptables -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$IFACE" -j ACCEPT
done
'''
    if legacy_block in existing:
        return existing.replace(legacy_block, block, 1), True
    if DOCKER_RULE_MARKER not in existing:
        return existing.rstrip() + block, True

    # Older installers wrote the same managed block without indentation, so
    # exact-string replacement above misses it. Replace through the block's
    # terminating `done` while preserving any user rules after it.
    start = existing.find(DOCKER_RULE_MARKER)
    tail = existing[start:]
    end_match = re.search(r"(?m)^done\s*$", tail)
    if end_match:
        end = start + end_match.end()
        return existing[:start] + block.lstrip("\n") + existing[end:], True
    return existing.rstrip() + block, True


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def get_docker_firewall_state():
    """Capture the Docker firewall-chain state before CSF reloads iptables."""
    running = bool(_run(["docker", "info", "--format", "{{.ID}}"], timeout=15))
    return {
        "running": running,
        "forward_chain": running and bool(
            _run(["iptables", "-t", "filter", "-S", "DOCKER-FORWARD"])
        ),
    }


def restore_docker_firewall_chains(previous_state):
    """Recreate Docker-owned chains if CSF removed them during a reload.

    Docker owns these chains and must recreate them itself; manually building
    them in csfpost.sh would be incomplete and can diverge between Docker
    releases. Restart Docker only when Docker is running and the chain is
    missing, so ordinary CSF restarts do not bounce Docker unnecessarily.
    """
    if not _run(["docker", "info", "--format", "{{.ID}}"], timeout=15):
        return {"success": True, "changed": False, "message": "Docker is not running."}
    if _run(["iptables", "-t", "filter", "-S", "DOCKER-FORWARD"]):
        return {"success": True, "changed": False, "message": "Docker firewall chains are intact."}

    version = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=15)
    try:
        if int(version.split(".", 1)[0]) < 28:
            return {"success": True, "changed": False, "message": "Docker does not use modern forwarding chains."}
    except (ValueError, IndexError):
        return {"success": True, "changed": False, "message": "Docker version could not be checked."}

    try:
        result = subprocess.run(
            ["systemctl", "restart", "docker"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"success": False, "changed": False, "message": f"Docker restart failed: {exc}"}

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return {"success": False, "changed": False, "message": f"Docker restart failed: {detail}"}
    if not _run(["iptables", "-t", "filter", "-S", "DOCKER-FORWARD"]):
        return {"success": False, "changed": True, "message": "Docker restarted but DOCKER-FORWARD is still missing."}
    return {"success": True, "changed": True, "message": "Docker firewall chains restored after CSF reload."}


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
    """Keep CSF from blocking Docker bridge forwarding and container egress."""
    docker_running = bool(_run(["docker", "info", "--format", "{{.ID}}"]))
    if docker_running:
        # Docker can restore Traefik's port bindings without restoring its
        # network attachment after a daemon restart. Reconnect the existing
        # proxy only when it has no network, preserving its configuration and
        # volumes.
        if _run(["docker", "ps", "-q", "-f", "name=^dokploy-traefik$"]):
            networks = _run(["docker", "inspect", "dokploy-traefik",
                             "--format", "{{json .NetworkSettings.Networks}}"])
            if networks in ("{}", "null", ""):
                _run(["docker", "network", "connect", "dokploy-network", "dokploy-traefik"])
    path = Path(CSFPOST)
    try:
        existing = path.read_text() if path.exists() else ""
        updated, changed = _upsert_docker_forwarding_block(existing)
        if not changed:
            return {"success": True, "changed": False, "message": "Docker forwarding rules already installed."}
        path.write_text(updated)
        path.chmod(0o700)
        return {"success": True, "changed": True, "message": "Docker forwarding rules installed or updated."}
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


def get_supported_process_ignores():
    """Return safe process exemptions for supported CSF-EUI workloads."""
    rules = [
        ("exe:/usr/sbin/rsyslogd", "system logging daemon"),
        ("exe:/usr/lib/systemd/systemd-networkd", "systemd network daemon"),
        ("exe:/lib/systemd/systemd-networkd", "systemd network daemon"),
        ("exe:/usr/lib/systemd/systemd-timesyncd", "systemd time synchronization"),
        ("exe:/usr/lib/systemd/systemd-resolved", "systemd DNS resolver"),
        ("exe:/lib/systemd/systemd-resolved", "systemd DNS resolver"),
        ("exe:/usr/sbin/sshd", "OpenSSH server"),
        ("exe:/usr/bin/dockerd", "Docker daemon"),
        ("exe:/usr/bin/containerd", "Docker container runtime"),
        ("pexe:/usr/bin/containerd-shim.*", "Docker container shims"),
        ("pexe:/usr/bin/docker-proxy", "Docker published-port proxy"),
        ("pexe:/usr/local/bin/traefik", "Traefik reverse proxy"),
        ("pexe:/usr/bin/traefik", "Traefik reverse proxy"),
        ("pexe:/usr/local/bin/netbird", "NetBird VPN daemon"),
        ("pexe:/usr/bin/netbird", "NetBird VPN daemon"),
        ("pexe:/usr/local/bin/wireguard-ui", "WireGuard UI"),
        ("pexe:/usr/bin/wireguard-ui", "WireGuard UI"),
        ("pexe:/usr/local/bin/node.*", "Node.js application processes"),
        ("pexe:/usr/bin/node.*", "Node.js application processes"),
        ("exe:/usr/bin/redis-server", "Redis service"),
        ("user:postgres", "PostgreSQL service user"),
        ("user:www-data", "web service user"),
        ("user:_mta-sts", "MTA-STS service user"),
        ("user:netbird", "NetBird service user"),
        ("user:wireguard-ui", "WireGuard UI service user"),
    ]

    optional_paths = {
        "/usr/sbin/rsyslogd", "/usr/lib/systemd/systemd-networkd",
        "/lib/systemd/systemd-networkd", "/usr/lib/systemd/systemd-timesyncd",
        "/usr/lib/systemd/systemd-resolved", "/lib/systemd/systemd-resolved",
        "/usr/sbin/sshd", "/usr/bin/dockerd", "/usr/bin/containerd",
        "/usr/bin/containerd-shim-runc-v2", "/usr/bin/docker-proxy",
        "/usr/local/bin/traefik", "/usr/bin/traefik", "/usr/local/bin/netbird",
        "/usr/bin/netbird", "/usr/local/bin/wireguard-ui", "/usr/bin/wireguard-ui",
        "/usr/bin/redis-server", "/usr/local/bin/node", "/usr/bin/node",
    }
    for command in ("dockerd", "containerd", "docker-proxy", "traefik", "netbird", "wireguard-ui"):
        resolved = shutil.which(command)
        if resolved:
            optional_paths.add(resolved)
    installed = {path for path in optional_paths if os.path.exists(path)}

    selected = []
    for entry, label in rules:
        if entry.startswith("exe:"):
            if entry[4:] in installed:
                selected.append({"entry": entry, "label": label})
        elif entry.startswith("pexe:"):
            prefix = entry[5:].split(".*", 1)[0]
            if any(path.startswith(prefix) for path in installed):
                selected.append({"entry": entry, "label": label})
        elif entry.startswith("user:"):
            try:
                pwd.getpwnam(entry[5:])
            except KeyError:
                continue
            selected.append({"entry": entry, "label": label})

    selected.extend([
        {"entry": "pexe:/usr/lib/postgresql/.*/bin/postgres", "label": "PostgreSQL containers"},
        {"entry": "exe:/usr/sbin/nginx", "label": "Nginx containers"},
    ])
    return selected


def apply_supported_process_ignores():
    """Idempotently add supported workload rules to csf.pignore."""
    existing = set(get_csf_pignore_entries())
    added = []
    for proc in get_supported_process_ignores():
        entry = proc["entry"]
        if entry in existing:
            continue
        result = add_to_csf_pignore(entry, f"CSF-EUI: {proc['label']}")
        if result.get("success"):
            existing.add(entry)
            added.append(entry)
    return {"success": True, "added": added, "message": f"Applied {len(added)} supported-service process exemptions."}


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

    common_processes = [dict(proc, ignored=False) for proc in get_supported_process_ignores()]
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
    from csf_backend import csf_wrapper as csf

    results = []
    detected = detect_all_services()
    ignored = get_csf_ignore_entries()
    for svc in detected:
        if svc["subnet"] not in ignored:
            r = add_to_csf_ignore(svc["subnet"], f"{svc['type']}: {svc['name']}")
            results.append({"subnet": svc["subnet"], "name": svc["name"], "result": r})

    # CSF's stock 1800-second threshold creates noise from normal daemons.
    # Only change that known stock value; preserve deliberate custom tuning.
    conf = csf.load_csf_conf()
    if conf.get("PT_USERTIME") == "1800":
        r = csf.save_csf_conf({"PT_USERTIME": "0"})
        results.append({
            "setting": "PT_USERTIME",
            "name": "Disable noisy 30-minute process-runtime alerts",
            "result": r,
        })

    pignored = get_csf_pignore_entries()
    for proc in get_supported_process_ignores():
        entry = proc["entry"]
        comment = proc["label"]
        if entry not in pignored:
            r = add_to_csf_pignore(entry, comment)
            results.append({"entry": entry, "name": comment, "result": r})

    return {"success": True, "fixes": results, "message": f"Applied {len(results)} fixes. Restart LFD to take effect."}
