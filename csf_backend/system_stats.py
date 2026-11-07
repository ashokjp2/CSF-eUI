import os
import time
import subprocess
import re
from pathlib import Path


def get_uptime():
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        days = int(secs // 86400)
        hours = int((secs % 86400) // 3600)
        mins = int((secs % 3600) // 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        parts.append(f"{mins}m")
        return {"seconds": secs, "formatted": " ".join(parts)}
    except OSError:
        return {"seconds": 0, "formatted": "N/A"}


def get_load_average():
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        return {
            "1min": float(parts[0]),
            "5min": float(parts[1]),
            "15min": float(parts[2]),
            "processes": parts[3],
        }
    except OSError:
        return {"1min": 0, "5min": 0, "15min": 0, "processes": "0/0"}


def get_cpu_info():
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        fields = line.split()[1:]
        total = sum(int(x) for x in fields)
        idle = int(fields[3])
        return {
            "total": total,
            "idle": idle,
            "cores": os.cpu_count() or 1,
        }
    except OSError:
        return {"total": 0, "idle": 0, "cores": 1}


def get_cpu_usage():
    s1 = get_cpu_info()
    time.sleep(0.1)
    s2 = get_cpu_info()
    total_diff = s2["total"] - s1["total"]
    idle_diff = s2["idle"] - s1["idle"]
    if total_diff == 0:
        return 0.0
    return round((1 - idle_diff / total_diff) * 100, 1)


def get_memory():
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                key = parts[0].rstrip(":")
                info[key] = int(parts[1])
        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable", 0)
        used = total - available
        swap_total = info.get("SwapTotal", 0)
        swap_free = info.get("SwapFree", 0)
        swap_used = swap_total - swap_free
        return {
            "total_kb": total,
            "used_kb": used,
            "available_kb": available,
            "total_mb": round(total / 1024),
            "used_mb": round(used / 1024),
            "available_mb": round(available / 1024),
            "percent": round(used / total * 100, 1) if total else 0,
            "swap_total_mb": round(swap_total / 1024),
            "swap_used_mb": round(swap_used / 1024),
            "swap_percent": round(swap_used / swap_total * 100, 1) if swap_total else 0,
        }
    except OSError:
        return {
            "total_kb": 0, "used_kb": 0, "available_kb": 0,
            "total_mb": 0, "used_mb": 0, "available_mb": 0,
            "percent": 0, "swap_total_mb": 0, "swap_used_mb": 0, "swap_percent": 0,
        }


def get_disk_usage():
    disks = []
    try:
        result = subprocess.run(
            ["df", "-h", "--output=source,size,used,avail,pcent,target", "-x", "tmpfs",
             "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 6 and not parts[0].startswith("none"):
                    disks.append({
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2],
                        "available": parts[3],
                        "percent": int(parts[4].rstrip("%")),
                        "mount": parts[5],
                    })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return disks


def get_network_stats():
    stats = []
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()[2:]
        for line in lines:
            parts = line.split()
            iface = parts[0].rstrip(":")
            if iface == "lo":
                continue
            rx_bytes = int(parts[1])
            tx_bytes = int(parts[9])
            stats.append({
                "interface": iface,
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "rx_mb": round(rx_bytes / 1024 / 1024, 1),
                "tx_mb": round(tx_bytes / 1024 / 1024, 1),
                "rx_formatted": format_bytes(rx_bytes),
                "tx_formatted": format_bytes(tx_bytes),
            })
    except OSError:
        pass
    return stats


def format_bytes(b):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def get_hostname():
    try:
        return os.uname().nodename
    except AttributeError:
        import socket
        return socket.gethostname()


def get_kernel():
    try:
        return os.uname().release
    except AttributeError:
        return "Unknown"


def get_connections_count():
    try:
        result = subprocess.run(
            ["ss", "-s"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            tcp_match = re.search(r'TCP:\s+(\d+)', result.stdout)
            estab_match = re.search(r'estab\s+(\d+)', result.stdout)
            return {
                "tcp_total": int(tcp_match.group(1)) if tcp_match else 0,
                "established": int(estab_match.group(1)) if estab_match else 0,
            }
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return {"tcp_total": 0, "established": 0}


def get_blocked_ips_count():
    count = 0
    for fpath in ("/etc/csf/csf.deny", "/var/lib/csf/csf.tempban"):
        try:
            with open(fpath) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        count += 1
        except OSError:
            pass
    return count


def get_system_overview():
    return {
        "hostname": get_hostname(),
        "kernel": get_kernel(),
        "uptime": get_uptime(),
        "load": get_load_average(),
        "cpu_usage": get_cpu_usage(),
        "cpu_cores": os.cpu_count() or 1,
        "memory": get_memory(),
        "disks": get_disk_usage(),
        "network": get_network_stats(),
        "connections": get_connections_count(),
        "blocked_ips": get_blocked_ips_count(),
    }
