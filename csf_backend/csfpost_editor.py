"""File handling and UI helpers for the csfpost.sh / csfpre.sh editor.

Parsing, structural editing and portable bundles all live in
``csfpost_model``; this module owns reading and writing the files on disk,
syntax checking, backups and the rule-builder presets.
"""

import json
import os
import socket
import subprocess
import tempfile
import time

from csf_backend import csfpost_model as model
from csf_backend.csfpost_model import EditError  # re-exported for the routes

CSFPOST_PATH = "/etc/csf/csfpost.sh"
CSFPRE_PATH = "/etc/csf/csfpre.sh"
BACKUP_DIR = "/var/lib/csfv2/script-backups"
MAX_BACKUPS = 20

SCRIPTS = {
    "csfpost": {
        "path": CSFPOST_PATH,
        "title": "csfpost.sh",
        "description": (
            "Runs AFTER CSF loads all of its rules. Use it for custom iptables "
            "rules, to accept traffic CSF would otherwise block, or to drop "
            "traffic CSF misses."
        ),
    },
    "csfpre": {
        "path": CSFPRE_PATH,
        "title": "csfpre.sh",
        "description": (
            "Runs BEFORE CSF loads its main rules. Use it to create custom "
            "chains or set up pre-conditions the main rules depend on."
        ),
    },
}

DEFAULT_SHEBANG = "#!/bin/sh"


def _script(name):
    return SCRIPTS.get(name) or SCRIPTS["csfpost"]


def script_path(name):
    return _script(name)["path"]


def read_script(name="csfpost"):
    try:
        with open(script_path(name)) as f:
            return f.read()
    except OSError:
        return ""


def _write_file(path, content):
    try:
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        # newline="\n": a shell script must never pick up CRLF line endings.
        with open(path, "w", newline="\n") as f:
            f.write(content)
        os.chmod(path, 0o700)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Backups - every write keeps the previous version so a bad edit is undoable
# ---------------------------------------------------------------------------

def _backup(name, content):
    if content == "":
        return
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = os.path.join(BACKUP_DIR, "%s.%s.sh" % (name, stamp))
        with open(path, "w", newline="\n") as f:
            f.write(content)
        os.chmod(path, 0o600)
        keep = sorted(f for f in os.listdir(BACKUP_DIR) if f.startswith(name + "."))
        for stale in keep[:-MAX_BACKUPS]:
            try:
                os.unlink(os.path.join(BACKUP_DIR, stale))
            except OSError:
                pass
    except OSError:
        pass


def list_backups(name="csfpost"):
    out = []
    try:
        for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if not fname.startswith(name + ".") or not fname.endswith(".sh"):
                continue
            path = os.path.join(BACKUP_DIR, fname)
            try:
                stat = os.stat(path)
            except OSError:
                continue
            out.append({
                "file": fname,
                "when": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
                "size": stat.st_size,
            })
    except OSError:
        pass
    return out


def read_backup(name, fname):
    if "/" in fname or "\\" in fname or ".." in fname:
        return None
    if not fname.startswith(name + ".") or not fname.endswith(".sh"):
        return None
    try:
        with open(os.path.join(BACKUP_DIR, fname)) as f:
            return f.read()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Page data
# ---------------------------------------------------------------------------

def get_script_info(script="csfpost"):
    meta = _script(script)
    content = read_script(script)
    doc = model.parse(content)
    return {
        "path": meta["path"],
        "title": meta["title"],
        "description": meta["description"],
        "script": script,
        "content": content,
        "exists": os.path.exists(meta["path"]),
        "nodes": model.doc_to_ui(doc),
        "summary": model.summarize(doc),
        "backups": list_backups(script),
    }


def get_tree(script="csfpost"):
    """The node tree plus summary, for AJAX refreshes."""
    content = read_script(script)
    doc = model.parse(content)
    return {
        "script": script,
        "content": content,
        "nodes": model.doc_to_ui(doc),
        "summary": model.summarize(doc),
    }


def save_script(content, script="csfpost"):
    """Write the script, prepending a shebang when one is missing.

    A save that would introduce a shell syntax error is refused.  If the file
    on disk is *already* broken the save goes through with a warning instead,
    so a bad script can still be repaired from the UI.
    """
    lines = content.splitlines()
    if not lines or not lines[0].startswith("#!"):
        content = DEFAULT_SHEBANG + "\n" + content
    if content and not content.endswith("\n"):
        content += "\n"

    previous = read_script(script)
    warning = ""
    check = check_syntax(content)
    if not check.get("valid"):
        errors = "; ".join(check.get("errors", [])[:3])
        if check_syntax(previous).get("valid"):
            return {"success": False,
                    "error": "Not saved - that would leave a shell syntax error: " + errors}
        warning = "Saved, but the script still has a syntax error: " + errors

    _backup(script, previous)
    result = _write_file(script_path(script), content)
    if result.get("success") and warning:
        result["warning"] = warning
    return result


def apply_edit(script, op, payload):
    """Run one structural edit against the file on disk."""
    content = read_script(script)
    try:
        new_content = model.apply_op(content, op, payload)
    except EditError as e:
        return {"success": False, "error": str(e)}
    except (ValueError, KeyError, IndexError, TypeError) as e:
        return {"success": False, "error": "Could not apply that change: %s" % e}
    if new_content == content:
        return {"success": True, "unchanged": True, **get_tree(script)}
    result = save_script(new_content, script)
    if not result.get("success"):
        return result
    out = {"success": True}
    out.update(get_tree(script))
    return out


def restore_backup(script, fname):
    content = read_backup(script, fname)
    if content is None:
        return {"success": False, "error": "Backup not found."}
    result = save_script(content, script)
    if result.get("success"):
        result.update(get_tree(script))
    return result


# ---------------------------------------------------------------------------
# Syntax check
# ---------------------------------------------------------------------------

def check_syntax(content):
    """Run ``sh -n`` over the script and return any errors."""
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        result = subprocess.run(["bash", "-n", tmp_path], capture_output=True,
                                text=True, timeout=10)
        if result.returncode == 0:
            return {"valid": True, "errors": []}
        errors = [e.replace(tmp_path, "<script>")
                  for e in result.stderr.strip().splitlines()]
        return {"valid": False, "errors": errors}
    except FileNotFoundError:
        return {"valid": True, "errors": [],
                "note": "Syntax check unavailable (bash not found on this host)."}
    except subprocess.TimeoutExpired:
        return {"valid": False, "errors": ["Syntax check timed out."]}
    except OSError as e:
        return {"valid": False, "errors": [str(e)]}
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def dry_run(content):
    """Report which rules the script would run, without running anything."""
    doc = model.parse(content)
    out = []
    for node, parked in model.walk_ctx(doc["nodes"]):
        # Parked = inside a heredoc comment block, so the shell never runs it.
        if node.get("kind") != "rule" or node.get("disabled") or parked:
            continue
        out.append({
            "line": node["lineno"],
            "command": " ".join(node["text"].split()),
            "description": node["description"],
            "dynamic": node["dynamic"],
        })
    return {"rules": out, "summary": model.summarize(doc)}


# ---------------------------------------------------------------------------
# Portable bundles
# ---------------------------------------------------------------------------

def export_bundle(script="csfpost"):
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    return model.export_bundle(read_script(script), script, hostname)


def import_bundle(script, bundle, mode="append", items=None):
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except ValueError:
            return {"success": False, "error": "That is not valid JSON."}
    try:
        new_content = model.import_bundle(read_script(script), bundle, mode,
                                          items, bundle.get("script", ""))
    except EditError as e:
        return {"success": False, "error": str(e)}
    result = save_script(new_content, script)
    if result.get("success"):
        result.update(get_tree(script))
        result["message"] = "Imported. Restart CSF+LFD to apply the new rules."
    return result


def import_raw(script, text, mode="append"):
    """Import a plain shell snippet pasted or uploaded by the user."""
    text = (text or "").strip("\n")
    if not text.strip():
        return {"success": False, "error": "Nothing to import."}
    bundle = model.export_bundle(text if text.endswith("\n") else text + "\n", script, "")
    return import_bundle(script, bundle, mode)


# ---------------------------------------------------------------------------
# Rule builder presets - each one prefills the generic rule form
# ---------------------------------------------------------------------------

RULE_TEMPLATES = [
    {
        "id": "allow_port_in",
        "label": "Allow inbound port",
        "description": "Accept incoming connections on a TCP/UDP port.",
        "fields": ["proto", "dport", "src", "in_iface"],
        "spec": {"op": "insert", "chain": "INPUT", "position": "1",
                 "target": "ACCEPT", "table": "filter",
                 "fields": {"proto": "tcp"}},
    },
    {
        "id": "block_ip",
        "label": "Block an IP or range",
        "description": "Drop every packet from an address or CIDR block.",
        "fields": ["src"],
        "spec": {"op": "insert", "chain": "INPUT", "position": "1",
                 "target": "DROP", "table": "filter", "fields": {}},
    },
    {
        "id": "allow_ip",
        "label": "Allow an IP or range",
        "description": "Accept everything from a trusted address or CIDR block.",
        "fields": ["src"],
        "spec": {"op": "insert", "chain": "INPUT", "position": "1",
                 "target": "ACCEPT", "table": "filter", "fields": {}},
    },
    {
        "id": "vpn_forward_in",
        "label": "Allow VPN / tunnel forwarding (inbound)",
        "description": "Let traffic arriving on a tunnel interface be forwarded "
                       "(WireGuard wg0, NetBird wt0, OpenVPN tun0).",
        "fields": ["in_iface"],
        "spec": {"op": "insert", "chain": "FORWARD", "position": "1",
                 "target": "ACCEPT", "table": "filter",
                 "fields": {"in_iface": "wt0"}},
    },
    {
        "id": "vpn_forward_back",
        "label": "Allow VPN / tunnel return traffic",
        "description": "Let established and related replies back out of a tunnel "
                       "interface.",
        "fields": ["out_iface", "state"],
        "spec": {"op": "insert", "chain": "FORWARD", "position": "1",
                 "target": "ACCEPT", "table": "filter",
                 "fields": {"out_iface": "wt0", "state": "ESTABLISHED,RELATED"}},
    },
    {
        "id": "nat_masquerade",
        "label": "NAT a subnet out of an interface",
        "description": "Masquerade a VPN or container subnet behind the host's "
                       "public address.",
        "fields": ["src", "out_iface"],
        "spec": {"op": "append", "chain": "POSTROUTING", "table": "nat",
                 "target": "MASQUERADE",
                 "fields": {"src": "100.0.0.0/8", "out_iface": "eth0"}},
    },
    {
        "id": "port_forward",
        "label": "Port forward to an internal host (DNAT)",
        "description": "Send an inbound port on to a machine behind this server.",
        "fields": ["in_iface", "proto", "dport", "to_destination"],
        "spec": {"op": "append", "chain": "PREROUTING", "table": "nat",
                 "target": "DNAT", "fields": {"proto": "tcp"}},
    },
    {
        "id": "forward_to_host",
        "label": "Allow forwarded traffic to an internal host",
        "description": "The FORWARD rule a port forward needs so the packets "
                       "actually reach the target host.",
        "fields": ["in_iface", "out_iface", "proto", "dst", "dport", "state"],
        "spec": {"op": "append", "chain": "FORWARD", "table": "filter",
                 "target": "ACCEPT",
                 "fields": {"proto": "tcp", "state": "NEW,ESTABLISHED,RELATED"}},
    },
    {
        "id": "docker_restrict",
        "label": "Restrict a published Docker port",
        "description": "Drop internet traffic to a published container port while "
                       "keeping container-to-container access.",
        "fields": ["proto", "ctorigdstport", "src"],
        "spec": {"op": "insert", "chain": "DOCKER-USER", "table": "filter",
                 "target": "DROP",
                 "fields": {"proto": "tcp", "ctdir": "ORIGINAL"}},
    },
    {
        "id": "log_then_drop",
        "label": "Log traffic",
        "description": "Write matching packets to syslog with a prefix. Add a "
                       "matching DROP rule after it.",
        "fields": ["proto", "dport", "src", "log_prefix", "log_level"],
        "spec": {"op": "insert", "chain": "INPUT", "position": "1",
                 "target": "LOG", "table": "filter",
                 "fields": {"proto": "tcp", "log_prefix": "CSF-DROP: ",
                            "log_level": "4"}},
    },
    {
        "id": "new_chain",
        "label": "Create a custom chain",
        "description": "Make a named chain, flushing it first if it already "
                       "exists, so the script is safe to re-run.",
        "fields": ["chain"],
        "spec": {"op": "new-chain", "chain": "MYCHAIN", "table": "filter",
                 "guard": "create-or-flush", "fields": {}},
    },
    {
        "id": "jump_to_chain",
        "label": "Send a chain's traffic to a custom chain",
        "description": "Hook a custom chain into INPUT, OUTPUT or FORWARD.",
        "fields": ["chain", "target"],
        "spec": {"op": "insert", "chain": "FORWARD", "position": "1",
                 "target": "MYCHAIN", "table": "filter", "fields": {}},
    },
    {
        "id": "multiport",
        "label": "Allow several ports at once",
        "description": "One rule covering a comma-separated list of ports.",
        "fields": ["proto", "dports", "src", "in_iface"],
        "spec": {"op": "append", "chain": "INPUT", "table": "filter",
                 "target": "ACCEPT",
                 "fields": {"proto": "tcp", "dports": "80,443"}},
    },
    {
        "id": "icmp",
        "label": "Allow ping / ICMP",
        "description": "Accept ICMP (IPv4) or ICMPv6 echo traffic.",
        "fields": ["proto", "in_iface", "src"],
        "spec": {"op": "insert", "chain": "INPUT", "position": "1",
                 "target": "ACCEPT", "table": "filter",
                 "fields": {"proto": "icmp"}},
    },
    {
        "id": "rate_limit",
        "label": "Rate limit a port",
        "description": "Accept only so many new connections per minute.",
        "fields": ["proto", "dport", "limit", "limit_burst"],
        "spec": {"op": "insert", "chain": "INPUT", "position": "1",
                 "target": "ACCEPT", "table": "filter",
                 "fields": {"proto": "tcp", "limit": "10/min",
                            "limit_burst": "20"}},
    },
    {
        "id": "guarded",
        "label": "Add a rule only once (check first)",
        "description": "Uses the -C ... || -I ... idiom so re-running the script "
                       "does not stack duplicates.",
        "fields": ["in_iface", "proto", "dport"],
        "spec": {"op": "insert", "chain": "FORWARD", "position": "1",
                 "target": "ACCEPT", "table": "filter",
                 "guard": "check-then-add", "fields": {}},
    },
]


# Choices the builder form offers.  Exposed so the template does not hard-code
# them in two places.
FORM_CHOICES = {
    "family": [("ipv4", "IPv4 (iptables)"), ("ipv6", "IPv6 (ip6tables)")],
    "table": [(t, t) for t in model.TABLES],
    "op": [("insert", "Insert at top (-I)"), ("append", "Append at end (-A)"),
           ("new-chain", "Create chain (-N)"), ("delete-chain", "Delete chain (-X)"),
           ("flush", "Flush chain (-F)"), ("policy", "Set chain policy (-P)")],
    "proto": [("", "any"), ("tcp", "TCP"), ("udp", "UDP"), ("icmp", "ICMP"),
              ("ipv6-icmp", "ICMPv6"), ("sctp", "SCTP"), ("esp", "ESP"),
              ("ah", "AH"), ("gre", "GRE"), ("all", "all")],
    "target": [("ACCEPT", "ACCEPT - allow"), ("DROP", "DROP - silently discard"),
               ("REJECT", "REJECT - refuse with an error"),
               ("RETURN", "RETURN - fall back to the calling chain"),
               ("LOG", "LOG - write to syslog"),
               ("MASQUERADE", "MASQUERADE - NAT behind this host"),
               ("DNAT", "DNAT - forward to another host"),
               ("SNAT", "SNAT - rewrite the source address"),
               ("REDIRECT", "REDIRECT - send to a local port"),
               ("MARK", "MARK - tag the packet")],
    "chains": model.BUILTIN_CHAINS,
    "guard": [("", "Plain rule"),
              ("check-then-add", "Only add if missing (-C ... || -I ...)"),
              ("create-or-flush", "Create or flush (-N ... || -F ...)")],
}


def build_rule(template_id, params):
    """Legacy helper: render a line from a preset id plus loose params."""
    preset = next((t for t in RULE_TEMPLATES if t["id"] == template_id), None)
    if not preset:
        return {"success": False, "error": "Unknown template"}
    spec = json.loads(json.dumps(preset["spec"]))
    spec.setdefault("fields", {})
    for key, value in (params or {}).items():
        value = (value or "").strip() if isinstance(value, str) else value
        if value in ("", None):
            continue
        if key in ("family", "table", "op", "chain", "position", "target",
                   "policy", "guard"):
            spec[key] = value
        else:
            spec["fields"][key] = value
    error = model.validate_spec(spec)
    if error:
        return {"success": False, "error": error}
    return {"success": True, "line": model.render_rule(spec), "spec": spec}


def preview_rule(spec):
    """Render and validate a spec straight from the rule form."""
    spec = spec or {}
    spec.setdefault("fields", {})
    error = model.validate_spec(spec)
    if error:
        return {"success": False, "error": error}
    line = model.render_rule(spec)
    doc = model.parse(line + "\n")
    rules = [n for n in model._walk(doc["nodes"]) if n.get("kind") == "rule"]
    return {
        "success": True,
        "line": line,
        "description": rules[0]["description"] if rules else "",
        "unknown": rules[0]["unknown"] if rules else [],
    }


def parse_rules(content):
    """Flat rule list in the old shape, for the legacy /api/csfpost/parse route."""
    doc = model.parse(content)
    out = []
    for node in model._walk(doc["nodes"]):
        if node.get("kind") != "rule":
            continue
        spec = node["spec"]
        out.append({
            "lineno": node["lineno"], "raw": node["text"], "cmd": spec["cmd"],
            "description": node["description"], "badge": node["badge"],
            "jump": spec["target"], "chain": spec["chain"],
            "proto": spec["fields"].get("proto", ""),
            "port": spec["fields"].get("dport", "") or spec["fields"].get("dports", ""),
            "src": spec["fields"].get("src", ""),
            "dst": spec["fields"].get("dst", ""),
            "disabled": node["disabled"],
        })
    return out
