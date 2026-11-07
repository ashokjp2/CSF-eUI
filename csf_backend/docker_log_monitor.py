import subprocess
import re
import json
import os
import time

MONITOR_CONF = "/etc/csfv2/docker_monitors.json"

DEFAULT_MONITORS = {
    "dokploy": {
        "enabled": True,
        "container_pattern": "dokploy",
        "fail_regex": [
            r"Failed login.*from\s+(\d+\.\d+\.\d+\.\d+)",
            r"Invalid credentials.*?(\d+\.\d+\.\d+\.\d+)",
            r"401.*?(\d+\.\d+\.\d+\.\d+)",
            r"Unauthorized.*?(\d+\.\d+\.\d+\.\d+)",
        ],
        "log_lines": 200,
        "description": "Dokploy panel login failures",
    },
    "coolify": {
        "enabled": True,
        "container_pattern": "coolify",
        "fail_regex": [
            r"Failed login.*from\s+(\d+\.\d+\.\d+\.\d+)",
            r"Invalid credentials.*?(\d+\.\d+\.\d+\.\d+)",
            r"authentication failed.*?(\d+\.\d+\.\d+\.\d+)",
        ],
        "log_lines": 200,
        "description": "Coolify panel login failures",
    },
    "wireguard-ui": {
        "enabled": True,
        "container_pattern": "wg-easy|wireguard-ui|wg-dash|wg-portal",
        "fail_regex": [
            r"Failed login.*?(\d+\.\d+\.\d+\.\d+)",
            r"Invalid password.*?(\d+\.\d+\.\d+\.\d+)",
            r"authentication.*fail.*?(\d+\.\d+\.\d+\.\d+)",
            r"401.*?(\d+\.\d+\.\d+\.\d+)",
        ],
        "log_lines": 200,
        "description": "WireGuard UI login failures",
    },
    "netbird": {
        "enabled": True,
        "container_pattern": "netbird",
        "fail_regex": [
            r"Failed login.*?(\d+\.\d+\.\d+\.\d+)",
            r"unauthorized.*?(\d+\.\d+\.\d+\.\d+)",
            r"invalid token.*?(\d+\.\d+\.\d+\.\d+)",
        ],
        "log_lines": 200,
        "description": "Netbird login/auth failures",
    },
    "traefik": {
        "enabled": True,
        "container_pattern": "traefik",
        "fail_regex": [
            r"(\d+\.\d+\.\d+\.\d+).*\" 401 ",
            r"(\d+\.\d+\.\d+\.\d+).*\" 403 ",
        ],
        "log_lines": 500,
        "description": "Traefik 401/403 responses (brute-force indicators)",
    },
    "authentik": {
        "enabled": True,
        "container_pattern": "authentik.*server",
        "fail_regex": [
            r"Login failed.*?(\d+\.\d+\.\d+\.\d+)",
            r"AuthenticationFailed.*?(\d+\.\d+\.\d+\.\d+)",
            r"invalid_grant.*?(\d+\.\d+\.\d+\.\d+)",
        ],
        "log_lines": 200,
        "description": "Authentik SSO login failures",
    },
}


def load_monitors():
    if os.path.exists(MONITOR_CONF):
        try:
            with open(MONITOR_CONF) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return DEFAULT_MONITORS


def save_monitors(monitors):
    os.makedirs(os.path.dirname(MONITOR_CONF), exist_ok=True)
    with open(MONITOR_CONF, "w") as f:
        json.dump(monitors, f, indent=2)


def get_matching_containers(pattern):
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
        return [
            name.strip() for name in result.stdout.strip().split("\n")
            if name.strip() and re.search(pattern, name.strip(), re.IGNORECASE)
        ]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def scan_container_logs(container_name, fail_patterns, log_lines=200):
    failures = []
    try:
        result = subprocess.run(
            ["docker", "logs", "--tail", str(log_lines), container_name],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
        for line in output.split("\n"):
            for pattern in fail_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    ip = match.group(1)
                    failures.append({
                        "ip": ip,
                        "container": container_name,
                        "line": line.strip()[:200],
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return failures


def scan_all_monitors():
    monitors = load_monitors()
    results = {}
    for name, cfg in monitors.items():
        if not cfg.get("enabled", True):
            continue
        pattern = cfg.get("container_pattern", "")
        containers = get_matching_containers(pattern)
        results[name] = {
            "description": cfg.get("description", name),
            "containers_found": containers,
            "failures": [],
        }
        for container in containers:
            failures = scan_container_logs(
                container,
                cfg.get("fail_regex", []),
                cfg.get("log_lines", 200),
            )
            results[name]["failures"].extend(failures)
    return results


def get_monitor_status():
    monitors = load_monitors()
    status = {}
    for name, cfg in monitors.items():
        containers = get_matching_containers(cfg.get("container_pattern", ""))
        status[name] = {
            "enabled": cfg.get("enabled", True),
            "description": cfg.get("description", name),
            "installed": len(containers) > 0,
            "containers": containers,
        }
    return status
