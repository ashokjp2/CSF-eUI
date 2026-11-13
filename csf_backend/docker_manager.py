import subprocess
import json
import re
import os


def run_cmd(cmd, timeout=30):
    if not isinstance(cmd, (list, tuple)):
        return {"success": False, "stdout": "", "stderr": "Command must be an argument list"}
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=False,
        )
        return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"success": False, "stdout": "", "stderr": str(e)}


def valid_id(value):
    """Container/network name or ID: never empty, never an option flag."""
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value))


def is_docker_installed():
    r = run_cmd(["docker", "--version"])
    return r["success"]


def is_docker_running():
    r = run_cmd(["docker", "info"])
    return r["success"]


def get_docker_version():
    r = run_cmd(["docker", "--version"])
    return r["stdout"].strip() if r["success"] else "Not installed"


def container_action(container_id, action):
    if not valid_id(container_id):
        return {"success": False, "stdout": "", "stderr": "Invalid container ID"}
    if action not in ("start", "stop", "restart"):
        return {"success": False, "stdout": "", "stderr": "Invalid action"}
    return run_cmd(["docker", action, container_id])


def list_containers(all_containers=False):
    cmd = ["docker", "ps", "--format", "json", "--no-trunc"]
    if all_containers:
        cmd.append("-a")
    r = run_cmd(cmd)
    if not r["success"]:
        return []
    containers = []
    for line in r["stdout"].strip().split("\n"):
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return containers


def get_container_details(container_id):
    if not valid_id(container_id):
        return None
    r = run_cmd(["docker", "inspect", container_id])
    if not r["success"]:
        return None
    try:
        data = json.loads(r["stdout"])
        return data[0] if data else None
    except json.JSONDecodeError:
        return None


def list_networks():
    r = run_cmd(["docker", "network", "ls", "--format", "json"])
    if not r["success"]:
        return []
    networks = []
    for line in r["stdout"].strip().split("\n"):
        if not line:
            continue
        try:
            networks.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return networks


def get_network_details(network_id):
    if not valid_id(network_id):
        return None
    r = run_cmd(["docker", "network", "inspect", network_id])
    if not r["success"]:
        return None
    try:
        data = json.loads(r["stdout"])
        return data[0] if data else None
    except json.JSONDecodeError:
        return None


def get_docker_ports():
    containers = list_containers()
    port_mappings = []
    for c in containers:
        ports_str = c.get("Ports", "")
        name = c.get("Names", "")
        cid = c.get("ID", "")[:12]
        if ports_str:
            for mapping in ports_str.split(", "):
                port_mappings.append({
                    "container": name,
                    "container_id": cid,
                    "mapping": mapping,
                })
    return port_mappings


def get_docker_interfaces():
    r = run_cmd(["ip", "-j", "link", "show"])
    if not r["success"]:
        return []
    try:
        interfaces = json.loads(r["stdout"])
        docker_ifaces = [
            iface for iface in interfaces
            if any(
                iface.get("ifname", "").startswith(prefix)
                for prefix in ("docker", "br-", "veth")
            )
        ]
        return docker_ifaces
    except json.JSONDecodeError:
        return []


def get_docker_iptables_rules():
    r = run_cmd(["iptables", "-L", "DOCKER", "-n", "--line-numbers", "-v"])
    if not r["success"]:
        return r["stderr"]
    return r["stdout"]


def get_docker_nat_rules():
    r = run_cmd(["iptables", "-t", "nat", "-L", "DOCKER", "-n", "--line-numbers", "-v"])
    if not r["success"]:
        return r["stderr"]
    return r["stdout"]


# Coolify detection
def is_coolify_installed():
    checks = [
        os.path.exists("/data/coolify"),
        os.path.exists("/etc/coolify"),
    ]
    if any(checks):
        return True
    r = run_cmd(["docker", "ps", "--filter", "name=coolify", "--format", "{{.Names}}"])
    return r["success"] and "coolify" in r["stdout"]


def get_coolify_containers():
    r = run_cmd(["docker", "ps", "--filter", "label=coolify.managed=true", "--format", "json"])
    if not r["success"]:
        r = run_cmd(["docker", "ps", "--filter", "name=coolify", "--format", "json"])
    if not r["success"]:
        return []
    containers = []
    for line in r["stdout"].strip().split("\n"):
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return containers


def get_coolify_ports():
    containers = get_coolify_containers()
    ports = set()
    for c in containers:
        ports_str = c.get("Ports", "")
        for part in ports_str.split(", "):
            match = re.search(r':(\d+)->', part)
            if match:
                ports.add(int(match.group(1)))
    defaults = {8000, 6001, 6002, 3000}
    ports.update(defaults)
    return sorted(ports)


# ---------------------------------------------------------------------------
# Exposure map: which published container ports the internet can reach.
# Docker publishes ports through its own NAT/FORWARD chains, bypassing CSF's INPUT
# rules, so a port can be open even when it is not in TCP_IN.  Restrictions are
# written to csfpost.sh (so they survive csf restarts) and applied immediately.
# ---------------------------------------------------------------------------
CSFPOST_PATH = "/etc/csf/csfpost.sh"
_PRIVATE_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
_PROXY_HINTS = ("coolify-proxy", "traefik", "caddy", "nginx-proxy", "npm", "haproxy")


def _restriction_rules(port, proto):
    """iptables lines, in insert order, that drop external traffic to a published port while
    keeping container-to-container (private) and localhost access."""
    base = f"-p {proto} -m conntrack --ctorigdstport {port} --ctdir ORIGINAL"
    rules = [f"iptables -I DOCKER-USER {base} -j DROP"]
    for net in _PRIVATE_NETS:
        rules.append(f"iptables -I DOCKER-USER {base} -s {net} -j RETURN")
    return rules


def _marker(port, proto):
    return f"# csfv2-exposure:{port}/{proto}"


def get_restricted_ports():
    try:
        with open(CSFPOST_PATH) as f:
            content = f.read()
    except OSError:
        return set()
    return set(re.findall(r"# csfv2-exposure:(\d+/(?:tcp|udp)) begin", content))


def set_port_restriction(port, proto, enable=True):
    key = f"{port}/{proto}"
    try:
        with open(CSFPOST_PATH) as f:
            content = f.read()
    except OSError:
        content = "#!/bin/sh\n"
    begin, end = f"{_marker(port, proto)} begin", f"{_marker(port, proto)} end"
    block_re = re.compile(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", re.S)
    rules = _restriction_rules(port, proto)
    content = block_re.sub("", content)
    if enable:
        content = content.rstrip("\n") + "\n" + begin + "\n" + "\n".join(rules) + "\n" + end + "\n"
    try:
        with open(CSFPOST_PATH, "w") as f:
            f.write(content)
        os.chmod(CSFPOST_PATH, 0o700)
    except OSError as e:
        return {"success": False, "error": f"Could not write csfpost.sh: {e}"}
    # Apply now: remove any existing copies first, then insert in order
    errors = []
    for rule in rules:
        run_cmd(rule.replace("iptables -I DOCKER-USER", "iptables -D DOCKER-USER").split())
    if enable:
        for rule in rules:
            r = run_cmd(rule.split())
            if not r["success"]:
                errors.append(r.get("stderr", "")[:120])
    return {"success": not errors, "error": "; ".join(errors) if errors else "", "port": key, "restricted": enable}


def _csf_setting(key):
    try:
        with open("/etc/csf/csf.conf") as f:
            for line in f:
                m = re.match(r'^%s\s*=\s*"(.*)"' % re.escape(key), line.strip())
                if m:
                    return m.group(1)
    except OSError:
        pass
    return ""


def get_exposure_map():
    containers = list_containers()
    restricted = get_restricted_ports()
    tcp_in = {p.strip() for p in _csf_setting("TCP_IN").split(",") if p.strip()}
    docker_mode = _csf_setting("DOCKER")
    rows = []
    proxies = []
    for c in containers:
        name = c.get("Names", "")
        labels = c.get("Labels", "") or ""
        is_proxy = any(h in name.lower() for h in _PROXY_HINTS)
        if is_proxy:
            proxies.append(name)
        behind_proxy = "traefik.enable=true" in labels or "caddy=" in labels or "coolify.managed=true" in labels
        published = []
        for mapping in (c.get("Ports") or "").split(", "):
            m = re.match(r"^(?:(\[?[0-9a-f.:]+\]?):)?(\d+)(?:-\d+)?->(\d+)(?:-\d+)?/(tcp|udp)$", mapping.strip())
            if not m:
                continue
            bind, host_port, cport, proto = m.group(1) or "", m.group(2), m.group(3), m.group(4)
            if bind in ("::", "[::]"):
                continue  # IPv6 twin of the 0.0.0.0 mapping
            published.append((bind, host_port, cport, proto))
        if not published:
            rows.append({"container": name, "id": c.get("ID", "")[:12], "port": "", "proto": "", "bind": "",
                         "reach": "internal", "behind_proxy": behind_proxy, "is_proxy": is_proxy,
                         "in_tcp_in": False, "restricted": False})
            continue
        for bind, host_port, cport, proto in published:
            key = f"{host_port}/{proto}"
            local = bind.startswith("127.") or bind == "localhost"
            if key in restricted:
                reach = "restricted"
            elif local:
                reach = "localhost"
            else:
                reach = "internet"
            rows.append({"container": name, "id": c.get("ID", "")[:12], "port": int(host_port), "cport": int(cport),
                         "proto": proto, "bind": bind or "0.0.0.0", "reach": reach, "behind_proxy": behind_proxy,
                         "is_proxy": is_proxy, "in_tcp_in": host_port in tcp_in, "restricted": key in restricted})
    order = {"internet": 0, "restricted": 1, "localhost": 2, "internal": 3}
    rows.sort(key=lambda r: (order.get(r["reach"], 9), r["port"] or 0, r["container"]))
    return {"rows": rows, "docker_mode": docker_mode, "proxies": proxies,
            "open_count": sum(1 for r in rows if r["reach"] == "internet" and not r["is_proxy"]),
            "tcp_in": sorted(tcp_in, key=lambda p: int(p) if p.isdigit() else 0)}


def generate_docker_csf_rules():
    rules = []
    rules.append("# Docker/Coolify firewall integration rules")
    rules.append("# Generated by CSFv2")
    rules.append("")

    port_mappings = get_docker_ports()
    seen_ports = set()
    for pm in port_mappings:
        mapping = pm["mapping"]
        match = re.search(r'0\.0\.0\.0:(\d+)', mapping)
        if match:
            port = match.group(1)
            if port not in seen_ports:
                rules.append(
                    f"# Docker container: {pm['container']} ({pm['container_id']})"
                )
                rules.append(f"tcp|in|d={port}|s=0/0")
                seen_ports.add(port)

    if is_coolify_installed():
        rules.append("")
        rules.append("# Coolify management ports")
        for port in get_coolify_ports():
            if str(port) not in seen_ports:
                rules.append(f"tcp|in|d={port}|s=0/0")

    return "\n".join(rules)


def get_docker_compose_services():
    compose_files = [
        "/data/coolify/source/docker-compose.yml",
        "/data/coolify/docker-compose.yml",
    ]
    for cf in compose_files:
        if os.path.exists(cf):
            r = run_cmd(["docker", "compose", "-f", cf, "ps", "--format", "json"])
            if r["success"]:
                services = []
                for line in r["stdout"].strip().split("\n"):
                    if not line:
                        continue
                    try:
                        services.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
                return services
    return []
