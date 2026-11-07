import subprocess
import json
import re
import os


def run_cmd(cmd, timeout=30):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=isinstance(cmd, str),
        )
        return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"success": False, "stdout": "", "stderr": str(e)}


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
