import subprocess
import re
from collections import Counter


def get_connections():
    try:
        r = subprocess.run(
            ["ss", "-tun", "state", "established"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return {"connections": [], "error": "Failed to get connections"}

    conns = []
    ip_counter = Counter()

    for line in r.stdout.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[3]
        remote = parts[4]

        # Parse local
        local_match = re.match(r'(.+):(\d+)$', local)
        local_ip = local_match.group(1) if local_match else local
        local_port = int(local_match.group(2)) if local_match else 0

        # Parse remote
        remote_match = re.match(r'(.+):(\d+)$', remote)
        remote_ip = remote_match.group(1) if remote_match else remote
        remote_port = int(remote_match.group(2)) if remote_match else 0

        # Skip loopback
        if remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
            continue

        ip_counter[remote_ip] += 1

        conns.append({
            "proto": proto,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
        })

    # Top remote IPs
    top_ips = [{"ip": ip, "count": c} for ip, c in ip_counter.most_common(20)]

    # Port distribution
    port_counter = Counter(c["local_port"] for c in conns)
    port_dist = [{"port": p, "count": c} for p, c in port_counter.most_common(10)]

    return {
        "connections": conns[:200],
        "total": len(conns),
        "unique_ips": len(ip_counter),
        "top_ips": top_ips,
        "port_distribution": port_dist,
    }
