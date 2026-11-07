import socket
import subprocess
import re


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "Submission", 993: "IMAPS", 995: "POP3S", 2222: "SSH Alt",
    3000: "Dev Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP Alt", 8443: "HTTPS Alt",
    8750: "CSFv2", 9090: "Cockpit", 10000: "Webmin", 27017: "MongoDB",
    51820: "WireGuard",
}


def scan_self(ports=None):
    """Scan this server's own ports to verify what's exposed."""
    if ports is None:
        ports = sorted(COMMON_PORTS.keys())

    # Get TCP_IN from csf.conf for comparison
    tcp_in = set()
    try:
        with open("/etc/csf/csf.conf") as f:
            for line in f:
                m = re.match(r'^TCP_IN\s*=\s*"(.+)"', line.strip())
                if m:
                    for p in m.group(1).split(","):
                        p = p.strip()
                        if p.isdigit():
                            tcp_in.add(int(p))
    except OSError:
        pass

    # Get listening ports
    listening = set()
    try:
        r = subprocess.run(["ss", "-tlnH"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.strip().split("\n"):
            pm = re.search(r':(\d+)\s', line)
            if pm:
                listening.add(int(pm.group(1)))
    except Exception:
        pass

    results = []
    for port in ports:
        service = COMMON_PORTS.get(port, "Unknown")
        is_listening = port in listening
        is_allowed = port in tcp_in

        if is_listening and is_allowed:
            status = "open"
            severity = "success"
            note = "Listening and allowed by firewall"
        elif is_listening and not is_allowed:
            status = "filtered"
            severity = "warning"
            note = "Listening but NOT in TCP_IN — blocked by firewall"
        elif not is_listening and is_allowed:
            status = "allowed_unused"
            severity = "info"
            note = "In TCP_IN but nothing listening — consider removing from firewall"
        else:
            status = "closed"
            severity = "default"
            note = "Closed and blocked"

        results.append({
            "port": port,
            "service": service,
            "status": status,
            "severity": severity,
            "listening": is_listening,
            "firewall_allowed": is_allowed,
            "note": note,
        })

    # Warnings
    warnings = []
    for r in results:
        if r["status"] == "allowed_unused":
            warnings.append(f"Port {r['port']} ({r['service']}) is allowed in firewall but nothing is listening — remove it to reduce attack surface")
        if r["port"] == 23 and r["listening"]:
            warnings.append("Telnet (port 23) is running! This is insecure — use SSH instead")
        if r["port"] == 3306 and r["status"] == "open":
            warnings.append("MySQL (port 3306) is exposed to the internet — consider restricting access")
        if r["port"] == 6379 and r["status"] == "open":
            warnings.append("Redis (port 6379) is exposed — Redis should never be public-facing")

    open_count = sum(1 for r in results if r["status"] == "open")
    filtered_count = sum(1 for r in results if r["status"] == "filtered")

    return {
        "results": results,
        "warnings": warnings,
        "open_count": open_count,
        "filtered_count": filtered_count,
        "total_scanned": len(results),
        "tcp_in_ports": sorted(tcp_in),
    }
