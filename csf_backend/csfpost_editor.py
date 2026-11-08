import os
import re
import subprocess
import tempfile

CSFPOST_PATH = "/etc/csf/csfpost.sh"
CSFPRE_PATH = "/etc/csf/csfpre.sh"


def _read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _write_file(path, content):
    try:
        with open(path, "w") as f:
            f.write(content)
        # Ensure the file is executable
        os.chmod(path, 0o700)
        return {"success": True}
    except OSError as e:
        return {"success": False, "error": str(e)}


def get_script_info(script="csfpost"):
    path = CSFPRE_PATH if script == "csfpre" else CSFPOST_PATH
    content = _read_file(path)
    rules = parse_rules(content)
    return {
        "path": path,
        "content": content,
        "rules": rules,
        "script": script,
        "title": "csfpre.sh" if script == "csfpre" else "csfpost.sh",
        "description": (
            "Runs BEFORE CSF loads its main rules. Use to set up custom chains or "
            "pre-conditions."
            if script == "csfpre"
            else "Runs AFTER CSF loads all its rules. Use to add custom iptables rules, "
            "accept traffic CSF would otherwise block, or drop traffic CSF misses."
        ),
    }


def save_script(content, script="csfpost"):
    path = CSFPRE_PATH if script == "csfpre" else CSFPOST_PATH
    # Ensure shebang
    lines = content.splitlines()
    if not lines or not lines[0].startswith("#!"):
        content = "#!/bin/sh\n" + content
    return _write_file(path, content)


def check_syntax(content):
    """Run bash -n on the script content and return any errors."""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        result = subprocess.run(
            ["bash", "-n", tmp_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        os.unlink(tmp_path)

        if result.returncode == 0:
            return {"valid": True, "errors": []}
        else:
            errors = result.stderr.strip().splitlines()
            # Strip the temp path from error messages
            clean = [e.replace(tmp_path, "<script>") for e in errors]
            return {"valid": False, "errors": clean}
    except FileNotFoundError:
        # bash not available on this system (Windows dev environment)
        return {"valid": True, "errors": [], "note": "Syntax check unavailable (bash not found)"}
    except Exception as e:
        return {"valid": False, "errors": [str(e)]}


# ---------------------------------------------------------------------------
# Rule parsing: identify common iptables patterns in the script
# ---------------------------------------------------------------------------

# Map of iptables chain names → human-readable actions
_CHAIN_LABELS = {
    "ACCEPT": ("success", "Allow traffic"),
    "DROP": ("danger", "Drop traffic"),
    "REJECT": ("danger", "Reject traffic"),
    "LOG": ("info", "Log traffic"),
    "RETURN": ("default", "Return to caller"),
    "DOCKER-USER": ("warning", "DOCKER-USER chain"),
    "MASQUERADE": ("info", "Masquerade (NAT)"),
    "DNAT": ("info", "DNAT (port forward)"),
    "SNAT": ("info", "SNAT"),
}

_IPTABLES_RE = re.compile(
    r"""
    ^[ \t]*
    (?P<cmd>ip6?tables(?:-legacy)?(?:\s+-t\s+\S+)?)   # command + optional table
    \s+
    (?P<rest>.+)$
    """,
    re.VERBOSE | re.MULTILINE,
)

_CHAIN_FLAG_RE = re.compile(r"-(?:A|I|D|R|N|X|P)\s+(\S+)")
_PORT_RE = re.compile(r"--(?:dport|sport|destination-port|source-port)\s+([\d:]+)")
_IP_SRC_RE = re.compile(r"-s\s+([\d./a-fA-F:]+)")
_IP_DST_RE = re.compile(r"-d\s+([\d./a-fA-F:]+)")
_PROTO_RE = re.compile(r"-p\s+(\w+)")
_IN_RE = re.compile(r"-i\s+(\S+)")
_OUT_RE = re.compile(r"-o\s+(\S+)")
_JUMP_RE = re.compile(r"-j\s+(\S+)")
_STATE_RE = re.compile(r"--state\s+([\w,]+)|--ctstate\s+([\w,]+)")

# Shell heredocs are commonly used as multiline comments in csfpost.sh.  Keep
# the marker flexible enough for the usual forms: ``: <<COMMENT``,
# ``: <<'COMMENT'`` and the shorthand ``<<COMMENT`` used by some scripts.
_COMMENT_HEREDOC_RE = re.compile(
    r"^[ \t]*(?::[ \t]*)?<<-?[ \t]*(?P<quote>['\"]?)(?P<marker>[A-Za-z_][A-Za-z0-9_]*)\1[ \t]*$"
)


def _comment_heredoc_marker(line):
    """Return a heredoc comment marker, or None when *line* is not one."""
    match = _COMMENT_HEREDOC_RE.match(line)
    return match.group("marker") if match else None


def _is_full_line_comment(line):
    """Whether a physical shell line is a comment or blank line."""
    return not line.strip() or line.lstrip().startswith("#")


def _has_line_continuation(line):
    """Whether a shell line ends with an active line-continuation slash."""
    stripped = line.rstrip()
    if not stripped.endswith("\\"):
        return False

    # An even number of trailing slashes means the final slash is escaped and
    # therefore is a literal character, not a shell line continuation.
    slash_count = len(stripped) - len(stripped.rstrip("\\"))
    return slash_count % 2 == 1


def _join_continued_lines(lines, start):
    """Join a shell command beginning at *start* and return its end index."""
    logical = []
    index = start
    while index < len(lines):
        part = lines[index].rstrip()
        continued = _has_line_continuation(part)
        if continued:
            part = part[:-1].rstrip()
        logical.append(part.strip())
        if not continued:
            break
        index += 1

    return " ".join(part for part in logical if part), index


def _describe_rule(rest_line):
    """Turn an iptables argument string into a plain-English description."""
    parts = []

    chain_m = _CHAIN_FLAG_RE.search(rest_line)
    jump_m = _JUMP_RE.search(rest_line)
    proto_m = _PROTO_RE.search(rest_line)
    port_m = _PORT_RE.search(rest_line)
    src_m = _IP_SRC_RE.search(rest_line)
    dst_m = _IP_DST_RE.search(rest_line)
    in_m = _IN_RE.search(rest_line)
    out_m = _OUT_RE.search(rest_line)
    state_m = _STATE_RE.search(rest_line)

    jump = jump_m.group(1).upper() if jump_m else None
    chain = chain_m.group(1) if chain_m else None
    action_label = _CHAIN_LABELS.get(jump, ("default", jump))[1] if jump else "Unknown action"
    badge = _CHAIN_LABELS.get(jump, ("default", jump))[0] if jump else "default"

    # Build a human description
    proto = proto_m.group(1).upper() if proto_m else None
    port = port_m.group(1) if port_m else None
    src = src_m.group(1) if src_m else None
    dst = dst_m.group(1) if dst_m else None
    iface_in = in_m.group(1) if in_m else None
    iface_out = out_m.group(1) if out_m else None
    state = (state_m.group(1) or state_m.group(2)) if state_m else None

    desc_parts = [action_label]
    if proto and port:
        desc_parts.append(f"{proto} port {port}")
    elif proto:
        desc_parts.append(proto)
    if src:
        desc_parts.append(f"from {src}")
    if dst:
        desc_parts.append(f"to {dst}")
    if iface_in:
        desc_parts.append(f"in:{iface_in}")
    if iface_out:
        desc_parts.append(f"out:{iface_out}")
    if state:
        desc_parts.append(f"state {state}")
    if chain:
        desc_parts.append(f"[chain: {chain}]")

    return {
        "description": " ".join(desc_parts),
        "badge": badge,
        "jump": jump or "",
        "chain": chain or "",
        "proto": proto or "",
        "port": port or "",
        "src": src or "",
        "dst": dst or "",
    }


def parse_rules(content):
    """Parse active iptables commands from the script and explain them.

    The editor displays shell scripts, so a single firewall command may span
    several physical lines using a trailing ``\\``.  Parse that command as one
    logical rule.  Full-line comments and heredoc-style comment blocks are
    deliberately ignored, including any iptables-looking text inside them.
    """
    rules = []
    lines = content.splitlines()
    lineno = 0
    heredoc_marker = None

    while lineno < len(lines):
        line = lines[lineno]

        if heredoc_marker is not None:
            if line.strip() == heredoc_marker:
                heredoc_marker = None
            lineno += 1
            continue

        marker = _comment_heredoc_marker(line)
        if marker:
            heredoc_marker = marker
            lineno += 1
            continue

        if _is_full_line_comment(line):
            lineno += 1
            continue

        m = _IPTABLES_RE.match(line)
        if not m:
            lineno += 1
            continue

        start_lineno = lineno + 1
        logical_line, end_lineno = _join_continued_lines(lines, lineno)
        m = _IPTABLES_RE.match(logical_line)
        if not m:
            lineno += 1
            continue

        cmd = m.group("cmd").strip()
        rest = m.group("rest").strip()
        info = _describe_rule(rest)
        rules.append({
            "lineno": start_lineno,
            "raw": logical_line,
            "cmd": cmd,
            **info,
        })

        # The first line is already consumed; skip all physical continuation
        # lines so they cannot be mistaken for separate rules.
        lineno = end_lineno + 1

    return rules


# ---------------------------------------------------------------------------
# Rule builder helpers
# ---------------------------------------------------------------------------

RULE_TEMPLATES = [
    {
        "id": "allow_port_in",
        "label": "Allow inbound port (TCP/UDP)",
        "description": "Accept incoming connections on a specific port.",
        "fields": ["proto", "port", "src"],
        "template": "iptables -I INPUT -p {proto} --dport {port}{src_part} -j ACCEPT",
    },
    {
        "id": "block_ip",
        "label": "Block IP address",
        "description": "Drop all traffic from a specific IP or CIDR.",
        "fields": ["src"],
        "template": "iptables -I INPUT -s {src} -j DROP",
    },
    {
        "id": "allow_ip",
        "label": "Allow IP address (all traffic)",
        "description": "Accept all traffic from a trusted IP or CIDR.",
        "fields": ["src"],
        "template": "iptables -I INPUT -s {src} -j ACCEPT",
    },
    {
        "id": "docker_allow_port",
        "label": "Expose Docker container port",
        "description": "Allow external traffic through DOCKER-USER chain (bypasses Docker's own rules).",
        "fields": ["proto", "port", "dst"],
        "template": "iptables -I DOCKER-USER -p {proto} --dport {port}{dst_part} -j ACCEPT",
    },
    {
        "id": "log_drop",
        "label": "Log then drop traffic",
        "description": "Log matching traffic with a prefix label, then drop it.",
        "fields": ["proto", "port", "src", "log_prefix"],
        "template": (
            "iptables -I INPUT -p {proto} --dport {port}{src_part} -j LOG --log-prefix \"{log_prefix}\" --log-level 4\n"
            "iptables -I INPUT -p {proto} --dport {port}{src_part} -j DROP"
        ),
    },
    {
        "id": "nat_forward",
        "label": "NAT / Port forward",
        "description": "Forward an external port to an internal IP:port (DNAT).",
        "fields": ["proto", "port", "dst", "dst_port"],
        "template": "iptables -t nat -A PREROUTING -p {proto} --dport {port} -j DNAT --to-destination {dst}:{dst_port}",
    },
]


def build_rule(template_id, params):
    """Build an iptables line from a template_id and params dict."""
    tmpl = next((t for t in RULE_TEMPLATES if t["id"] == template_id), None)
    if not tmpl:
        return {"success": False, "error": "Unknown template"}

    try:
        src = params.get("src", "").strip()
        dst = params.get("dst", "").strip()
        src_part = f" -s {src}" if src else ""
        dst_part = f" -d {dst}" if dst else ""

        line = tmpl["template"].format(
            proto=params.get("proto", "tcp").strip(),
            port=params.get("port", "").strip(),
            src=src,
            dst=dst,
            src_part=src_part,
            dst_part=dst_part,
            dst_port=params.get("dst_port", "").strip(),
            log_prefix=params.get("log_prefix", "CSF-DROP: ").strip(),
        )
        return {"success": True, "line": line}
    except KeyError as e:
        return {"success": False, "error": f"Missing field: {e}"}
