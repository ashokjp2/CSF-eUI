import subprocess
import re


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "", "Command failed"


def get_iptables_traffic():
    """Get per-rule packet/byte counters from iptables."""
    entries = []
    for chain in ["INPUT", "OUTPUT"]:
        code, out, _ = _run(["iptables", "-L", chain, "-n", "-v", "--line-numbers"])
        if code != 0:
            continue
        for line in out.splitlines()[2:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            try:
                entries.append({
                    "chain": chain,
                    "packets": parts[1],
                    "bytes": parts[2],
                    "target": parts[3],
                    "source": parts[8],
                    "destination": parts[9],
                })
            except (IndexError, ValueError):
                pass
    return entries


def get_interface_stats():
    """Get network interface byte counters from /proc/net/dev."""
    interfaces = []
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                name = name.strip()
                if name == "lo":
                    continue
                parts = data.split()
                if len(parts) >= 11:
                    interfaces.append({
                        "name": name,
                        "rx_bytes": int(parts[0]),
                        "rx_packets": int(parts[1]),
                        "rx_errors": int(parts[2]),
                        "tx_bytes": int(parts[8]),
                        "tx_packets": int(parts[9]),
                        "tx_errors": int(parts[10]),
                    })
    except OSError:
        pass
    return interfaces


def get_top_connections():
    """Get IPs with most active connections and their bandwidth."""
    code, out, _ = _run(["ss", "-tnp"])
    if code != 0:
        return []
    ip_counts = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            peer = parts[4]
            ip = peer.rsplit(":", 1)[0].strip("[]")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top = sorted(ip_counts.items(), key=lambda x: -x[1])[:20]
    return [{"ip": ip, "count": count} for ip, count in top]


def _human_bytes(b):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def get_bandwidth_summary():
    """Overall bandwidth summary."""
    return {
        "interfaces": get_interface_stats(),
        "top_connections": get_top_connections(),
    }
