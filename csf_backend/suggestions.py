"""Block suggestions: group recent attackers by /24 network and by provider (ASN)."""
import ipaddress
import re
from collections import Counter, defaultdict

from csf_backend import lfd_blocks, ip_utils, csf_wrapper as csf


def _allowed_ips():
    out = []
    try:
        with open("/etc/csf/csf.allow") as f:
            for line in f:
                s = line.strip().split("#")[0].strip()
                if s and not s.startswith("tcp") and not s.startswith("udp"):
                    out.append(s.split("|")[0])
    except OSError:
        pass
    return out


def attackers(hours=168, limit=400):
    """Distinct attacker IPs from LFD blocks with counts (most recent log only)."""
    counts = Counter()
    for b in lfd_blocks.get_lfd_blocks(3000):
        if b.get("type") == "block" and b.get("ip"):
            counts[b["ip"]] += 1
    return counts.most_common(limit)


def suggest(min_ips=2, lookup_asn=True):
    att = attackers()
    allowed = _allowed_ips()
    nets = defaultdict(list)
    for ip, n in att:
        try:
            net = ipaddress.ip_network(ip + "/24", strict=False)
        except ValueError:
            continue
        nets[str(net)].append((ip, n))
    cidr_rows = []
    for net, members in nets.items():
        if len(members) < min_ips:
            continue
        clash = [a for a in allowed if _in(a, net)]
        cidr_rows.append({"target": net, "ips": len(members), "blocks": sum(n for _, n in members),
                          "examples": [ip for ip, _ in members[:3]], "allowed_clash": clash, "kind": "cidr"})
    cidr_rows.sort(key=lambda r: (-r["ips"], -r["blocks"]))

    asn_rows = []
    if lookup_asn and att:
        top = [ip for ip, _ in att[:60]]
        geo = {}
        try:
            geo = ip_utils.geolocate_batch(top) or {}
        except Exception:
            geo = {}
        by_as = defaultdict(list)
        for ip, n in att[:60]:
            g = geo.get(ip) if isinstance(geo, dict) else None
            as_name = (g or {}).get("as") or ""
            if as_name:
                by_as[as_name].append((ip, n))
        for as_name, members in by_as.items():
            if len(members) < min_ips:
                continue
            m = re.match(r"(AS\d+)\s*(.*)", as_name)
            asn_rows.append({"target": m.group(1) if m else as_name, "name": (m.group(2) if m else "")[:60], "ips": len(members),
                             "blocks": sum(n for _, n in members), "examples": [ip for ip, _ in members[:3]], "kind": "asn",
                             "countries": sorted({(geo.get(ip) or {}).get("country_code", "") for ip, _ in members} - {""})})
        asn_rows.sort(key=lambda r: (-r["ips"], -r["blocks"]))
    return {"cidr": cidr_rows[:15], "asn": asn_rows[:10], "attackers": len(att), "allowed": len(allowed)}


def for_ip(ip):
    """/24 suggestion for one IP: how many recent attackers share its network."""
    try:
        net = str(ipaddress.ip_network(ip + "/24", strict=False))
    except ValueError:
        return None
    members = [(a, n) for a, n in attackers() if _in(a, net)]
    return {"target": net, "ips": len(members), "blocks": sum(n for _, n in members),
            "allowed_clash": [a for a in _allowed_ips() if _in(a, net)]}


def _in(ip, net):
    try:
        return ipaddress.ip_address(ip.split("/")[0]) in ipaddress.ip_network(net, strict=False)
    except ValueError:
        return False


def block_cidr(target, comment=""):
    try:
        ipaddress.ip_network(target, strict=False)
    except ValueError:
        return {"success": False, "error": "Not a valid network"}
    return csf.deny_ip(target, comment or "Suggested block: repeated attacks from this network")
