import subprocess
import re


def get_processes(sort_by="cpu", limit=50):
    try:
        r = subprocess.run(
            ["ps", "aux", f"--sort=-{sort_by}"],
            capture_output=True, text=True, timeout=5,
        )
        lines = r.stdout.strip().split("\n")
    except Exception:
        return {"processes": [], "error": "Failed to list processes"}

    header = lines[0] if lines else ""
    processes = []
    for line in lines[1:limit + 1]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        processes.append({
            "user": parts[0],
            "pid": int(parts[1]),
            "cpu": float(parts[2]),
            "mem": float(parts[3]),
            "vsz": parts[4],
            "rss": parts[5],
            "stat": parts[7],
            "start": parts[8],
            "time": parts[9],
            "command": parts[10][:120],
        })

    return {"processes": processes}


def get_listening_ports():
    try:
        r = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        return []

    ports = []
    for line in r.stdout.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        local = parts[3]
        # Extract port
        port_match = re.search(r':(\d+)$', local)
        if not port_match:
            continue
        port = int(port_match.group(1))
        bind = local[:local.rfind(":")]

        # Extract process name
        proc = ""
        proc_match = re.search(r'users:\(\("([^"]+)"', line)
        if proc_match:
            proc = proc_match.group(1)

        ports.append({
            "port": port,
            "bind": bind,
            "process": proc,
            "state": parts[1],
        })

    ports.sort(key=lambda x: x["port"])
    return ports


def kill_process(pid):
    pid = int(pid)
    # Safety: never kill PID 1 or very low PIDs
    if pid < 10:
        return {"success": False, "error": "Cannot kill system processes"}

    try:
        r = subprocess.run(
            ["kill", str(pid)],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            return {"success": True, "message": f"Signal sent to PID {pid}"}
        return {"success": False, "error": r.stderr.strip() or "Failed"}
    except Exception as e:
        return {"success": False, "error": str(e)}
