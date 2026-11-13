import subprocess
import json
import os
import re
import ipaddress
from pathlib import Path

WG_CONF_DIR = "/etc/wireguard"
WG_BIN = "/usr/bin/wg"


def run_cmd(cmd, timeout=15, input_text=None):
    if not isinstance(cmd, (list, tuple)):
        return {"success": False, "stdout": "", "stderr": "Command must be an argument list"}
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=False, input=input_text,
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
    priv = run_cmd([WG_BIN, "genkey"], timeout=5)
    if not priv["success"]:
        return None
    private_key = priv["stdout"].strip()
    pub = run_cmd([WG_BIN, "pubkey"], timeout=5, input_text=private_key + "\n")
    if not pub["success"]:
        return None
    return {
        "private_key": private_key,
        "public_key": pub["stdout"].strip(),
    }


def generate_preshared_key():
    r = run_cmd([WG_BIN, "genpsk"], timeout=5)
    return r["stdout"].strip() if r["success"] else None


# Peer fields are written verbatim into wg<N>.conf, which wg-quick executes as
# root (PostUp/PreDown). Reject anything that is not a single well-formed value.
_KEY_RE = re.compile(r"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=")


def valid_key(value):
    return isinstance(value, str) and bool(_KEY_RE.fullmatch(value))


def valid_cidr_list(value):
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        for part in value.split(","):
            ipaddress.ip_network(part.strip(), strict=False)
        return True
    except ValueError:
        return False


def valid_endpoint(value):
    if not isinstance(value, str) or len(value) > 259:
        return False
    host, sep, port = value.rpartition(":")
    if not sep:
        return False
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return False
    elif not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return False
    return port.isdigit() and 0 < int(port) < 65536


def valid_keepalive(value):
    return isinstance(value, (int, str)) and str(value).isdigit() and 0 <= int(value) <= 65535


def add_peer(iface, public_key, allowed_ips, endpoint=None, preshared_key=None,
             persistent_keepalive=None):
    conf_path = os.path.join(WG_CONF_DIR, f"{iface}.conf")
    if not os.path.exists(conf_path):
        return {"success": False, "error": "Config not found"}
    if not valid_key(public_key):
        return {"success": False, "error": "Invalid public key"}
    if not valid_cidr_list(allowed_ips):
        return {"success": False, "error": "Allowed IPs must be a comma-separated list of IPs or CIDRs"}
    if endpoint and not valid_endpoint(endpoint):
        return {"success": False, "error": "Endpoint must be host:port"}
    if preshared_key and not valid_key(preshared_key):
        return {"success": False, "error": "Invalid preshared key"}
    if persistent_keepalive and not valid_keepalive(persistent_keepalive):
        return {"success": False, "error": "Keepalive must be a number of seconds"}
    allowed_ips = ", ".join(p.strip() for p in allowed_ips.split(","))

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
        run_cmd(cmd_args, input_text=(preshared_key + "\n") if preshared_key else None)

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
    if (not valid_cidr_list(client_ip) or not valid_endpoint(server_endpoint)
            or not valid_key(server_public_key) or not valid_cidr_list(dns)):
        return None
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
