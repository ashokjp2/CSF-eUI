"""Impact preview: what a block or port change would affect before it is applied."""
import ipaddress

from csf_backend import suggestions, lfd_blocks, port_defaults


def block(target):
    """Impact of blocking an IP or network."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return {"error": "Not a valid IP or network"}
    allowed = [a for a in suggestions._allowed_ips() if suggestions._in(a, str(net))]
    attackers = [(ip, n) for ip, n in suggestions.attackers() if suggestions._in(ip, str(net))]
    return {"target": str(net), "addresses": net.num_addresses, "allowed_clash": allowed,
            "attackers_covered": len(attackers), "blocks_covered": sum(n for _, n in attackers),
            "warning": "This range contains addresses in your allow list" if allowed else ""}


def port(port_no):
    """Impact of closing a port: what listens on it."""
    try:
        p = int(port_no)
    except (TypeError, ValueError):
        return {"error": "Bad port"}
    listening = []
    try:
        for proto, lp in port_defaults._get_listening_ports():
            if str(lp) == str(p):
                listening.append(proto)
    except Exception:
        pass
    containers = []
    try:
        from csf_backend import docker_manager
        for r in docker_manager.get_exposure_map().get("rows", []):
            if r.get("port") == p:
                containers.append(r["container"])
    except Exception:
        pass
    return {"port": p, "listening": listening, "containers": containers,
            "warning": "Something is listening on this port; closing it will cut that service off" if listening or containers else ""}
