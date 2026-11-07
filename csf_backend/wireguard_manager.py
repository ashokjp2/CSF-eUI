import subprocess
import json
import os
import re
import ipaddress
from pathlib import Path

WG_CONF_DIR = "/etc/wireguard"
WG_BIN = "/usr/bin/wg"


def run_cmd(cmd, timeout=15):
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=isinstance(cmd, str),
        )
        return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return {"success": False, "stdout": "", "stderr": str(e)}


def is_installed():
    return os.path.exists(WG_BIN)


def get_version():
    r = run_cmd([WG_BIN, "--version"])
    return r["stdout"].strip() if r["success"] else "Not installed"


def list_interfaces():
    r = run_cmd([WG_BIN, "show", "interfaces"])
    if not r["success"]:
        return []
    return r["stdout"].strip().split()


def get_interface_status(iface="wg0"):
    r = run_cmd([WG_BIN, "show", iface])
    if not r["success"]:
        return None
    return parse_wg_show(r["stdout"])


def get_all_status():
    r = run_cmd([WG_BIN, "show", "all"])
    if not r["success"]:
        return {}
    return r["stdout"]


def parse_wg_show(output):
    result = {"interface": {}, "peers": []}
    current_peer = None
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith("interface:"):
            result["interface"]["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("peer:"):
            if current_peer:
                result["peers"].append(current_peer)
            current_peer = {"public_key": line.split(":", 1)[1].strip()}
        elif ":" in line:
            key, val = line.split(":", 1)
            key = key.strip().replace(" ", "_")
            val = val.strip()
            if current_peer is not None:
                current_peer[key] = val
            else:
                result["interface"][key] = val
    if current_peer:
        result["peers"].append(current_peer)
    return result


def list_configs():
    configs = []
    if not os.path.isdir(WG_CONF_DIR):
        return configs
    for f in sorted(os.listdir(WG_CONF_DIR)):
        if f.endswith(".conf"):
            iface = f[:-5]
            configs.append({
                "interface": iface,
                "path": os.path.join(WG_CONF_DIR, f),
                "active": is_interface_up(iface),
            })
    return configs


def is_interface_up(iface):
    r = run_cmd(["ip", "link", "show", iface])
    return r["success"] and "UP" in r["stdout"]


def read_config(iface):
    conf_path = os.path.join(WG_CONF_DIR, f"{iface}.conf")
    if not os.path.exists(conf_path):
        return None
    return Path(conf_path).read_text()


def parse_config(content):
    result = {"interface": {}, "peers": []}
    current = None
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[Interface]":
            current = result["interface"]
            continue
        if line == "[Peer]":
            peer = {}
            result["peers"].append(peer)
            current = peer
            continue
        if current is not None and "=" in line:
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()
            if key in current:
                if isinstance(current[key], list):
                    current[key].append(val)
                else:
                    current[key] = [current[key], val]
            else:
                current[key] = val
    return result


def save_config(iface, content):
    safe_iface = re.sub(r'[^\w]', '', iface)
    conf_path = os.path.join(WG_CONF_DIR, f"{safe_iface}.conf")
    try:
        Path(conf_path).write_text(content)
        os.chmod(conf_path, 0o600)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}


def interface_up(iface):
    safe = re.sub(r'[^\w]', '', iface)
    return run_cmd(["wg-quick", "up", safe])


def interface_down(iface):
    safe = re.sub(r'[^\w]', '', iface)
    return run_cmd(["wg-quick", "down", safe])


def interface_restart(iface):
    safe = re.sub(r'[^\w]', '', iface)
    interface_down(safe)
    return interface_up(safe)


def generate_keypair():
    priv = run_cmd(f"{WG_BIN} genkey", timeout=5)
    if not priv["success"]:
        return None
    private_key = priv["stdout"].strip()
    pub = run_cmd(f"echo '{private_key}' | {WG_BIN} pubkey", timeout=5)
    if not pub["success"]:
        return None
    return {
        "private_key": private_key,
        "public_key": pub["stdout"].strip(),
    }


def generate_preshared_key():
    r = run_cmd(f"{WG_BIN} genpsk", timeout=5)
    return r["stdout"].strip() if r["success"] else None


def add_peer(iface, public_key, allowed_ips, endpoint=None, preshared_key=None,
             persistent_keepalive=None):
    conf_path = os.path.join(WG_CONF_DIR, f"{iface}.conf")
    if not os.path.exists(conf_path):
        return {"success": False, "error": "Config not found"}

    peer_block = f"\n[Peer]\nPublicKey = {public_key}\nAllowedIPs = {allowed_ips}\n"
    if endpoint:
        peer_block += f"Endpoint = {endpoint}\n"
    if preshared_key:
        peer_block += f"PresharedKey = {preshared_key}\n"
    if persistent_keepalive:
        peer_block += f"PersistentKeepalive = {persistent_keepalive}\n"

    with open(conf_path, "a") as f:
        f.write(peer_block)

    if is_interface_up(iface):
        cmd_args = [WG_BIN, "set", iface, "peer", public_key, "allowed-ips", allowed_ips]
        if endpoint:
            cmd_args.extend(["endpoint", endpoint])
        if preshared_key:
            cmd_args.extend(["preshared-key", "/dev/stdin"])
        if persistent_keepalive:
            cmd_args.extend(["persistent-keepalive", str(persistent_keepalive)])
        run_cmd(cmd_args)

    return {"success": True}


def remove_peer(iface, public_key):
    conf_path = os.path.join(WG_CONF_DIR, f"{iface}.conf")
    if not os.path.exists(conf_path):
        return {"success": False, "error": "Config not found"}

    content = Path(conf_path).read_text()
    lines = content.split("\n")
    new_lines = []
    skip = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[Peer]":
            skip = False
            peek_idx = lines.index(line) + 1
            while peek_idx < len(lines):
                peek = lines[peek_idx].strip()
                if peek.startswith("PublicKey") and public_key in peek:
                    skip = True
                    break
                if peek.startswith("["):
                    break
                peek_idx += 1
        if not skip:
            new_lines.append(line)
        elif stripped.startswith("[") and stripped != "[Peer]":
            skip = False
            new_lines.append(line)

    Path(conf_path).write_text("\n".join(new_lines))
    os.chmod(conf_path, 0o600)

    if is_interface_up(iface):
        run_cmd([WG_BIN, "set", iface, "peer", public_key, "remove"])

    return {"success": True}


def get_transfer_stats(iface="wg0"):
    r = run_cmd([WG_BIN, "show", iface, "transfer"])
    if not r["success"]:
        return {}
    stats = {}
    for line in r["stdout"].strip().split("\n"):
        parts = line.split("\t")
        if len(parts) >= 3:
            stats[parts[0]] = {
                "rx": int(parts[1]),
                "tx": int(parts[2]),
            }
    return stats


def generate_client_config(server_iface, client_ip, server_endpoint,
                           server_public_key, dns="1.1.1.1"):
    keys = generate_keypair()
    if not keys:
        return None
    config = f"""[Interface]
PrivateKey = {keys['private_key']}
Address = {client_ip}
DNS = {dns}

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_endpoint}
PersistentKeepalive = 25
"""
    return {
        "config": config,
        "private_key": keys["private_key"],
        "public_key": keys["public_key"],
    }


def get_wg_csf_ports():
    ports = set()
    for conf in list_configs():
        content = read_config(conf["interface"])
        if content:
            for line in content.split("\n"):
                if line.strip().startswith("ListenPort"):
                    match = re.search(r'=\s*(\d+)', line)
                    if match:
                        ports.add(int(match.group(1)))
    if not ports:
        ports.add(51820)
    return sorted(ports)
