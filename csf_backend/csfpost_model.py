"""Structure-preserving model for csfpost.sh / csfpre.sh.

The firewall scripts people actually keep in ``/etc/csf/csfpost.sh`` are real
shell scripts, not a flat list of iptables lines.  They contain section
banners, explanatory comments, rules commented out with one, two or three
hashes, heredoc blocks used as multi-line comments, shell variables,
``if``/``for`` blocks, ``iptables -N X 2>/dev/null || iptables -F X`` idioms,
commands split across lines with a trailing backslash, and ordinary shell
commands mixed in.

This module parses all of that into a node tree that renders back to
*byte-identical* text, so the UI can add, edit, reorder, enable or disable a
single rule without disturbing anything else in the file.

Design notes
------------
* Every node keeps ``raw`` - the exact source lines it came from.  Serialising
  an unedited document therefore always reproduces the original file.
* Rules keep their tokens together with the exact whitespace that preceded
  each one (``sep``).  Editing one field rewrites one token and leaves the
  rest of the line - odd alignment and unknown flags included - alone.
* Anything that cannot be understood is still represented (as a ``shell`` or
  ``block`` node) rather than dropped.
"""

import re
import time

# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

_QUOTES = "'" + '"'


def tokenize(text):
    """Split a shell command into tokens, preserving the exact separators.

    Returns ``(tokens, trailing)`` where *tokens* is a list of
    ``{"sep": <whitespace before>, "text": <token as written>}``.  Joining
    ``sep + text`` for every token and appending *trailing* reproduces *text*
    exactly, including backslash-newline continuations and quoting.
    """
    tokens = []
    i = 0
    n = len(text)
    sep_start = 0
    while i < n:
        ch = text[i]
        if ch in " \t\n":
            i += 1
            continue
        if ch == "\\" and i + 1 < n and text[i + 1] == "\n":
            i += 2
            continue
        sep = text[sep_start:i]
        start = i
        quote = None
        while i < n:
            c = text[i]
            if quote:
                if c == "\\" and quote == '"' and i + 1 < n:
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in _QUOTES:
                quote = c
                i += 1
                continue
            if c == "\\" and i + 1 < n:
                if text[i + 1] == "\n":
                    break
                i += 2
                continue
            if c in " \t\n":
                break
            i += 1
        tokens.append({"sep": sep, "text": text[start:i]})
        sep_start = i
    return tokens, text[sep_start:]


def render_tokens(tokens, trailing=""):
    return "".join(t["sep"] + t["text"] for t in tokens) + trailing


def unquote(value):
    """Strip one layer of matching shell quotes from a token."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in _QUOTES:
        return value[1:-1]
    return value


def shquote(value):
    """Quote a value for the shell only when it needs it."""
    value = str(value)
    if value == "":
        return '""'
    if value[0] in _QUOTES and value[-1] == value[0] and len(value) >= 2:
        return value  # already quoted by the caller
    if re.search(r"""[\s"'`;&|<>()*?\[\]{}#~!]""", value):
        if "'" not in value:
            return "'" + value + "'"
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


# ---------------------------------------------------------------------------
# iptables flag knowledge
# ---------------------------------------------------------------------------

FIREWALL_CMDS = ("iptables", "ip6tables", "iptables-legacy", "ip6tables-legacy",
                 "iptables-nft", "ip6tables-nft", "arptables", "ebtables")

_CMD_RE = re.compile(r"^(?:/(?:usr/)?s?bin/)?(" + "|".join(FIREWALL_CMDS) + r")$")

# Operation flag -> (canonical name, number of positional arguments)
OPS = {
    "-A": ("append", 1), "--append": ("append", 1),
    "-I": ("insert", 1), "--insert": ("insert", 1),
    "-D": ("delete", 1), "--delete": ("delete", 1),
    "-R": ("replace", 1), "--replace": ("replace", 1),
    "-C": ("check", 1), "--check": ("check", 1),
    "-N": ("new-chain", 1), "--new-chain": ("new-chain", 1), "--new": ("new-chain", 1),
    "-X": ("delete-chain", 1), "--delete-chain": ("delete-chain", 1),
    "-F": ("flush", 1), "--flush": ("flush", 1),
    "-P": ("policy", 2), "--policy": ("policy", 2),
    "-Z": ("zero", 1), "--zero": ("zero", 1),
    "-E": ("rename-chain", 2), "--rename-chain": ("rename-chain", 2),
    "-L": ("list", 1), "--list": ("list", 1),
    "-S": ("list-rules", 1), "--list-rules": ("list-rules", 1),
}

OP_FLAG_FOR = {
    "append": "-A", "insert": "-I", "delete": "-D", "replace": "-R",
    "check": "-C", "new-chain": "-N", "delete-chain": "-X", "flush": "-F",
    "policy": "-P", "zero": "-Z", "rename-chain": "-E",
}

OP_LABELS = {
    "append": "Append", "insert": "Insert", "delete": "Delete",
    "replace": "Replace", "check": "Check", "new-chain": "Create chain",
    "delete-chain": "Delete chain", "flush": "Flush chain",
    "policy": "Set policy", "zero": "Zero counters",
    "rename-chain": "Rename chain", "list": "List", "list-rules": "List rules",
}

# Flags that consume exactly one value.
VALUE_FLAGS = {
    "-t", "--table", "-s", "--source", "--src", "-d", "--destination", "--dst",
    "-p", "--protocol", "-i", "--in-interface", "-o", "--out-interface",
    "-j", "--jump", "-g", "--goto", "-m", "--match",
    "--dport", "--destination-port", "--sport", "--source-port",
    "--dports", "--destination-ports", "--sports", "--source-ports", "--ports",
    "--state", "--ctstate", "--ctdir", "--ctproto", "--ctstatus", "--ctexpire",
    "--ctorigdstport", "--ctorigsrcport", "--ctrepldstport", "--ctreplsrcport",
    "--ctorigsrc", "--ctorigdst", "--ctreplsrc", "--ctrepldst",
    "--icmp-type", "--icmpv6-type", "--log-prefix", "--log-level",
    "--to-destination", "--to-source", "--to-ports", "--to", "--on-port", "--on-ip",
    "--reject-with", "--set-mark", "--set-xmark", "--and-mark", "--or-mark",
    "--xor-mark", "--mark", "--comment",
    "--limit", "--limit-burst", "--mac-source", "--uid-owner", "--gid-owner",
    "--src-range", "--dst-range", "--pkt-type",
    "--hashlimit", "--hashlimit-upto", "--hashlimit-above", "--hashlimit-burst",
    "--hashlimit-mode", "--hashlimit-name", "--hashlimit-htable-expire",
    "--hashlimit-htable-max", "--hashlimit-htable-size", "--hashlimit-srcmask",
    "--hashlimit-dstmask", "--seconds", "--hitcount", "--name", "--mask",
    "--connlimit-above", "--connlimit-mask", "--connlimit-upto",
    "--string", "--hex-string", "--algo", "--from", "--to-offset",
    "--nflog-prefix", "--nflog-group", "--nflog-range", "--nflog-threshold",
    "--set-dscp", "--set-dscp-class", "--set-tos", "--set-mss", "--mss",
    "--physdev-in", "--physdev-out", "--rt-type",
    "--hl-eq", "--hl-lt", "--hl-gt", "--hl-set", "--hl-dec", "--hl-inc",
    "--ttl-eq", "--ttl-lt", "--ttl-gt", "--ttl-set", "--ttl-dec", "--ttl-inc",
    "--length", "--every", "--packet", "--queue-num", "--queue-balance",
    "--match-set", "--src-type", "--dst-type", "--rateest", "--helper",
    "--gateway", "--tos", "--label", "--timeout", "--dccp-types", "--dccp-option",
    "--sctp-chunk-types", "--chunk-types", "--ah-spi", "--esp-spi",
    "--rt-segsleft", "--src-cc", "--dst-cc", "--addrtype", "--set-class",
    "--nfmask", "--ctmask", "--cluster-total-nodes", "--cluster-local-node",
    "--cluster-hash-seed",
}

# Standalone switches.
BOOL_FLAGS = {
    "--syn", "--rsource", "--rdest", "--rcheck", "--update", "--set", "--remove",
    "--reap", "--rttl", "--random", "--random-fully", "--persistent", "--nodst",
    "--log-tcp-sequence", "--log-tcp-options", "--log-ip-options", "--log-uid",
    "--clamp-mss-to-pmtu", "--physdev-is-in", "--physdev-is-out",
    "--physdev-is-bridged", "--save-mark", "--restore-mark",
    "-f", "--fragment", "--numeric", "--line-numbers", "--exact", "--verbose",
}

TWO_VALUE_FLAGS = {"--tcp-flags"}

TABLES = ("filter", "nat", "mangle", "raw", "security")

BUILTIN_CHAINS = {
    "filter": ("INPUT", "FORWARD", "OUTPUT"),
    "nat": ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"),
    "mangle": ("PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"),
    "raw": ("PREROUTING", "OUTPUT"),
    "security": ("INPUT", "FORWARD", "OUTPUT"),
}

TARGET_LABELS = {
    "ACCEPT": ("success", "Allow"),
    "DROP": ("danger", "Drop"),
    "REJECT": ("danger", "Reject"),
    "LOG": ("info", "Log"),
    "NFLOG": ("info", "Log (nflog)"),
    "ULOG": ("info", "Log (ulog)"),
    "RETURN": ("default", "Return"),
    "MASQUERADE": ("warning", "Masquerade"),
    "DNAT": ("warning", "Port forward"),
    "SNAT": ("warning", "Source NAT"),
    "REDIRECT": ("warning", "Redirect"),
    "MARK": ("info", "Mark"),
    "TCPMSS": ("info", "Clamp MSS"),
    "TPROXY": ("info", "Transparent proxy"),
    "NOTRACK": ("default", "No conntrack"),
    "CT": ("default", "Conntrack"),
}

PROTO_LABELS = {
    "tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "icmpv6": "ICMPv6",
    "ipv6-icmp": "ICMPv6", "all": "all", "esp": "ESP", "ah": "AH",
    "gre": "GRE", "sctp": "SCTP", "dccp": "DCCP", "udplite": "UDPLite",
}

# Fields the UI form exposes, in the order they are emitted when a rule is
# generated from scratch.  ``flag`` is the iptables flag, ``multi`` means the
# field may appear more than once in a rule.
FORM_FIELDS = [
    {"key": "table", "flag": "-t", "label": "Table"},
    {"key": "in_iface", "flag": "-i", "label": "In interface"},
    {"key": "out_iface", "flag": "-o", "label": "Out interface"},
    {"key": "proto", "flag": "-p", "label": "Protocol"},
    {"key": "src", "flag": "-s", "label": "Source"},
    {"key": "dst", "flag": "-d", "label": "Destination"},
    {"key": "sport", "flag": "--sport", "label": "Source port"},
    {"key": "dport", "flag": "--dport", "label": "Destination port"},
    {"key": "sports", "flag": "--sports", "label": "Source ports (multiport)"},
    {"key": "dports", "flag": "--dports", "label": "Destination ports (multiport)"},
    {"key": "state", "flag": "--state", "label": "Connection state"},
    {"key": "ctstate", "flag": "--ctstate", "label": "Conntrack state"},
    {"key": "ctorigdstport", "flag": "--ctorigdstport", "label": "Original dest port"},
    {"key": "ctdir", "flag": "--ctdir", "label": "Conntrack direction"},
    {"key": "icmp_type", "flag": "--icmp-type", "label": "ICMP type"},
    {"key": "icmpv6_type", "flag": "--icmpv6-type", "label": "ICMPv6 type"},
    {"key": "mac_source", "flag": "--mac-source", "label": "Source MAC"},
    {"key": "src_range", "flag": "--src-range", "label": "Source range"},
    {"key": "dst_range", "flag": "--dst-range", "label": "Destination range"},
    {"key": "limit", "flag": "--limit", "label": "Rate limit"},
    {"key": "limit_burst", "flag": "--limit-burst", "label": "Limit burst"},
    {"key": "comment", "flag": "--comment", "label": "Rule comment"},
]

TARGET_OPT_FIELDS = [
    {"key": "to_destination", "flag": "--to-destination", "targets": ["DNAT"]},
    {"key": "to_source", "flag": "--to-source", "targets": ["SNAT"]},
    {"key": "to_ports", "flag": "--to-ports", "targets": ["REDIRECT", "MASQUERADE"]},
    {"key": "reject_with", "flag": "--reject-with", "targets": ["REJECT"]},
    {"key": "log_prefix", "flag": "--log-prefix", "targets": ["LOG"]},
    {"key": "log_level", "flag": "--log-level", "targets": ["LOG"]},
    {"key": "set_mark", "flag": "--set-mark", "targets": ["MARK"]},
    {"key": "set_mss", "flag": "--set-mss", "targets": ["TCPMSS"]},
]

_FLAG_BY_KEY = {f["key"]: f["flag"] for f in FORM_FIELDS}
_FLAG_BY_KEY.update({f["key"]: f["flag"] for f in TARGET_OPT_FIELDS})
_KEY_BY_FLAG = {}
for _k, _f in _FLAG_BY_KEY.items():
    _KEY_BY_FLAG.setdefault(_f, _k)
_KEY_BY_FLAG["--destination-port"] = "dport"
_KEY_BY_FLAG["--source-port"] = "sport"
_KEY_BY_FLAG["--destination-ports"] = "dports"
_KEY_BY_FLAG["--source-ports"] = "sports"
_KEY_BY_FLAG["--source"] = "src"
_KEY_BY_FLAG["--src"] = "src"
_KEY_BY_FLAG["--destination"] = "dst"
_KEY_BY_FLAG["--dst"] = "dst"
_KEY_BY_FLAG["--protocol"] = "proto"
_KEY_BY_FLAG["--in-interface"] = "in_iface"
_KEY_BY_FLAG["--out-interface"] = "out_iface"
_KEY_BY_FLAG["--table"] = "table"

# Match modules implied by a flag, so a generated rule loads the right -m.
_MODULE_FOR_FLAG = {
    "--state": "state",
    "--ctstate": "conntrack", "--ctdir": "conntrack",
    "--ctorigdstport": "conntrack", "--ctorigsrcport": "conntrack",
    "--ctrepldstport": "conntrack", "--ctreplsrcport": "conntrack",
    "--dports": "multiport", "--sports": "multiport", "--ports": "multiport",
    "--mac-source": "mac",
    "--src-range": "iprange", "--dst-range": "iprange",
    "--limit": "limit", "--limit-burst": "limit",
    "--comment": "comment",
}

# Reverse map, used to drop a now-pointless ``-m <module>`` when the last
# option belonging to it is cleared from a rule.
_FLAGS_FOR_MODULE = {}
for _flag, _mod in _MODULE_FOR_FLAG.items():
    _FLAGS_FOR_MODULE.setdefault(_mod, set()).add(_flag)
_FLAGS_FOR_MODULE["conntrack"].update({"--ctproto", "--ctstatus", "--ctexpire",
                                       "--ctorigsrc", "--ctorigdst",
                                       "--ctreplsrc", "--ctrepldst"})
_FLAGS_FOR_MODULE["multiport"].add("--ports")
_FLAGS_FOR_MODULE["limit"].add("--limit-burst")

# Values whose trailing space is meaningful - a log prefix without one runs
# straight into the kernel's own fields ("CSF-DROP:IN=eth0").
_KEEP_SPACES = {"log_prefix", "nflog_prefix"}


def _clean(key, value):
    value = "" if value is None else str(value)
    return value if key in _KEEP_SPACES else value.strip()


# ---------------------------------------------------------------------------
# Section markers
# ---------------------------------------------------------------------------

_MANAGED_PREFIXES = ("CSFV2-", "csfv2-")

_BEGIN_PATTERNS = [
    re.compile(r"^BEGIN\s+(?P<label>.+?)\s*$", re.I),
    re.compile(r"^(?P<label>\S.*?)\s+begin\s*$", re.I),
    re.compile(r"^-{2,}\s*(?P<label>.+?)\s*-{2,}$"),
    re.compile(r"^(?P<label>CSFV2-[A-Z0-9_-]+)\s*$"),
]
_END_PATTERNS = [
    re.compile(r"^END\s+(?P<label>.+?)\s*$", re.I),
    re.compile(r"^(?P<label>\S.*?)\s+end\s*$", re.I),
]


def _marker_kind(body):
    """Classify a comment body as a section begin/end marker, or None."""
    body = body.strip()
    if not body:
        return None
    for pat in _END_PATTERNS:
        m = pat.match(body)
        if m:
            return ("end", m.group("label").strip())
    for pat in _BEGIN_PATTERNS:
        m = pat.match(body)
        if m:
            return ("begin", m.group("label").strip())
    return None


def _label_key(label):
    """Normalise a section label so BEGIN/END pairs match loosely."""
    label = re.sub(r"\(.*?\)", " ", label)
    label = re.sub(r"[^A-Za-z0-9]+", " ", label).strip().lower()
    return label


def _labels_match(begin, end):
    a, b = _label_key(begin), _label_key(end)
    if not a or not b:
        return False
    return a == b or a.startswith(b) or b.startswith(a)


def _is_managed(label):
    return any(label.startswith(p) for p in _MANAGED_PREFIXES)


# ---------------------------------------------------------------------------
# Line classification helpers
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<hashes>#+)(?P<space>[ \t]*)(?P<body>.*)$")
_HEREDOC_RE = re.compile(r"<<-?\s*(?P<q>['\"]?)(?P<marker>[A-Za-z_][A-Za-z0-9_]*)(?P=q)")
_VAR_RE = re.compile(r"^[ \t]*(?:export[ \t]+|local[ \t]+|declare[ \t]+)?"
                     r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$")
_BLOCK_OPEN_RE = re.compile(r"^[ \t]*(?P<kw>if|for|while|until|case|select)\b")
_FUNC_RE = re.compile(r"^[ \t]*(?:function[ \t]+)?(?P<name>[A-Za-z_][A-Za-z0-9_-]*)[ \t]*\([ \t]*\)[ \t]*\{?[ \t]*$")
_BLOCK_CLOSE = {"if": "fi", "for": "done", "while": "done", "until": "done",
                "case": "esac", "select": "done"}


def _continues(line):
    """True when *line* ends with an active backslash continuation."""
    stripped = line.rstrip()
    if not stripped.endswith("\\"):
        return False
    trailing = len(stripped) - len(stripped.rstrip("\\"))
    return trailing % 2 == 1


def _first_word(text):
    m = re.match(r"^[ \t]*([^\s;|&]+)", text)
    return m.group(1) if m else ""


def _is_firewall_cmd(text):
    word = _first_word(text)
    if word.endswith(";"):
        word = word[:-1]
    return bool(_CMD_RE.match(word))


def _strip_comment_prefix(line):
    """Split a comment line into (indent, hashes, space, body) or None."""
    m = _COMMENT_RE.match(line)
    if not m:
        return None
    return m.group("indent"), m.group("hashes"), m.group("space"), m.group("body")


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def _split_on_or(tokens):
    """Split a token list on a top-level ``||``.  Returns (left, right)."""
    for idx, tok in enumerate(tokens):
        if tok["text"] == "||":
            return tokens[:idx], tokens[idx + 1:]
    return tokens, None


def _parse_command_tokens(tokens):
    """Parse one iptables invocation's tokens into a spec dict."""
    spec = {
        "cmd": "", "family": "ipv4", "table": "", "op": "", "chain": "",
        "position": "", "policy": "", "newname": "", "target": "", "goto": "",
        "modules": [], "fields": {}, "bools": [], "negated": {},
        "extra": [], "redirects": [], "terminator": "",
    }
    index = {}  # key -> token index of the value (or flag for bools)
    i = 0
    n = len(tokens)
    if not n:
        return spec, index

    cmd_token = tokens[0]["text"]
    term = ""
    if cmd_token.endswith(";"):
        cmd_token, term = cmd_token[:-1], ";"
    spec["cmd"] = cmd_token
    spec["family"] = "ipv6" if "ip6tables" in cmd_token else "ipv4"
    spec["terminator"] = term
    index["cmd"] = 0
    i = 1

    negate_next = False
    while i < n:
        raw = tokens[i]["text"]
        if raw.endswith(";") and len(raw) > 1 and not raw.startswith("-"):
            raw, spec["terminator"] = raw[:-1], ";"
        if raw == "!":
            negate_next = True
            i += 1
            continue
        if re.match(r"^\d*[<>]", raw) or raw.startswith("&>"):
            spec["redirects"].append({"i": i, "text": raw})
            i += 1
            continue
        if raw in OPS:
            name, argc = OPS[raw]
            spec["op"] = name
            index["op"] = i
            if argc >= 1 and i + 1 < n:
                spec["chain"] = unquote(tokens[i + 1]["text"])
                index["chain"] = i + 1
                i += 2
            else:
                i += 1
            if name == "policy" and i < n:
                spec["policy"] = unquote(tokens[i]["text"])
                index["policy"] = i
                i += 1
            elif name == "rename-chain" and i < n:
                spec["newname"] = unquote(tokens[i]["text"])
                index["newname"] = i
                i += 1
            elif name in ("insert", "replace") and i < n and re.match(r"^\d+$", tokens[i]["text"]):
                spec["position"] = tokens[i]["text"]
                index["position"] = i
                i += 1
            continue
        if raw in ("-m", "--match"):
            if i + 1 < n:
                mod = unquote(tokens[i + 1]["text"])
                spec["modules"].append({"name": mod, "i": i, "vi": i + 1})
                i += 2
            else:
                i += 1
            continue
        if raw in ("-j", "--jump"):
            if i + 1 < n:
                spec["target"] = unquote(tokens[i + 1]["text"])
                index["target"] = i + 1
                index["target_flag"] = i
                i += 2
            else:
                i += 1
            continue
        if raw in ("-g", "--goto"):
            if i + 1 < n:
                spec["goto"] = unquote(tokens[i + 1]["text"])
                index["goto"] = i + 1
                i += 2
            else:
                i += 1
            continue
        if raw in TWO_VALUE_FLAGS:
            vals = [unquote(t["text"]) for t in tokens[i + 1:i + 3]]
            key = raw.lstrip("-").replace("-", "_")
            spec["fields"][key] = " ".join(vals)
            if negate_next:
                spec["negated"][key] = True
            index[key] = i + 1
            index[key + "__flag"] = i
            negate_next = False
            i += 3
            continue
        if raw in VALUE_FLAGS:
            key = _KEY_BY_FLAG.get(raw) or raw.lstrip("-").replace("-", "_")
            value = unquote(tokens[i + 1]["text"]) if i + 1 < n else ""
            spec["fields"][key] = value
            if negate_next:
                spec["negated"][key] = True
            index[key] = i + 1
            index[key + "__flag"] = i
            negate_next = False
            i += 2
            continue
        if raw in BOOL_FLAGS:
            key = raw.lstrip("-").replace("-", "_")
            spec["bools"].append(key)
            if negate_next:
                spec["negated"][key] = True
            index[key + "__flag"] = i
            negate_next = False
            i += 1
            continue
        spec["extra"].append({"i": i, "text": raw})
        negate_next = False
        i += 1

    if "table" not in spec["fields"]:
        spec["table"] = "filter"
    else:
        spec["table"] = spec["fields"].pop("table")
        index["table"] = index.get("table")
    return spec, index


def _describe(spec):
    """Plain-English summary of a rule spec."""
    f = spec["fields"]
    target = spec.get("target") or spec.get("goto") or ""
    verb = TARGET_LABELS.get(target.upper(), ("default", target or "Rule"))[1]
    bits = []
    op = spec.get("op")
    if op == "new-chain":
        return "Create chain %s" % (spec.get("chain") or "?")
    if op == "flush":
        return "Flush chain %s" % (spec.get("chain") or "?")
    if op == "delete-chain":
        return "Delete chain %s" % (spec.get("chain") or "?")
    if op == "policy":
        return "Default policy of %s is %s" % (spec.get("chain") or "?", spec.get("policy") or "?")
    if op == "rename-chain":
        return "Rename chain %s to %s" % (spec.get("chain"), spec.get("newname"))

    if target and target.upper() not in TARGET_LABELS:
        verb = "Send to chain %s" % target
    bits.append(verb)

    neg = spec.get("negated") or {}

    def mark(key, text):
        return ("not " + text) if neg.get(key) else text

    proto = f.get("proto")
    if proto:
        bits.append(mark("proto", PROTO_LABELS.get(proto.lower(), proto.upper())))
    port = f.get("dport") or f.get("dports")
    if port:
        bits.append("port %s" % port if ":" not in port and "," not in port else "ports %s" % port)
    sport = f.get("sport") or f.get("sports")
    if sport:
        bits.append("from port %s" % sport)
    if f.get("src"):
        bits.append(mark("src", "from %s" % f["src"]))
    if f.get("dst"):
        bits.append(mark("dst", "to %s" % f["dst"]))
    if f.get("in_iface"):
        bits.append(mark("in_iface", "arriving on %s" % f["in_iface"]))
    if f.get("out_iface"):
        bits.append(mark("out_iface", "leaving via %s" % f["out_iface"]))
    state = f.get("state") or f.get("ctstate")
    if state:
        bits.append("when %s" % state.lower())
    if f.get("ctorigdstport"):
        bits.append("originally to port %s" % f["ctorigdstport"])
    if f.get("to_destination"):
        bits.append("-> %s" % f["to_destination"])
    if f.get("to_source"):
        bits.append("as %s" % f["to_source"])
    if f.get("to_ports"):
        bits.append("-> port %s" % f["to_ports"])
    if f.get("icmp_type") or f.get("icmpv6_type"):
        bits.append("icmp type %s" % (f.get("icmp_type") or f.get("icmpv6_type")))
    if f.get("log_prefix"):
        bits.append("tagged %s" % f["log_prefix"])
    if f.get("limit"):
        bits.append("limited to %s" % f["limit"])
    if f.get("comment"):
        bits.append("(%s)" % f["comment"])

    chain = spec.get("chain")
    if chain:
        where = {"append": "at the end of", "insert": "at the top of",
                 "delete": "removed from", "check": "checked in",
                 "replace": "replacing in"}.get(op, "in")
        pos = spec.get("position")
        bits.append("%s %s%s" % (where, chain, " position %s" % pos if pos and pos != "1" else ""))
    if spec.get("table") and spec["table"] != "filter":
        bits.append("[%s table]" % spec["table"])
    if spec.get("family") == "ipv6":
        bits.append("(IPv6)")
    return " ".join(bits)


def _rule_node(raw_lines, lineno, text, disabled=False, prefixes=None):
    """Build a rule node from the (uncommented) command *text*."""
    tokens, trailing = tokenize(text)
    left, right = _split_on_or(tokens)
    spec, index = _parse_command_tokens(left)
    guard = None
    if right is not None:
        gspec, gindex = _parse_command_tokens(right)
        if spec.get("op") == "check" and gspec.get("op") in ("insert", "append"):
            guard = "check-then-add"
            spec, index = gspec, gindex       # the real rule is the fallback
        elif spec.get("op") == "new-chain" and gspec.get("op") == "flush":
            guard = "create-or-flush"
        else:
            guard = "custom"

    target = (spec.get("target") or spec.get("goto") or "").upper()
    badge = TARGET_LABELS.get(target, ("default", target))[0]
    dynamic = bool(re.search(r"[$`]", text))
    editable = guard in (None, "check-then-add", "create-or-flush")
    node = {
        "kind": "rule",
        "lineno": lineno,
        "raw": list(raw_lines),
        "text": text,
        "tokens": tokens,
        "trailing": trailing,
        "spec": spec,
        "index": index,
        "guard": guard,
        "disabled": disabled,
        "prefixes": prefixes or [],
        "badge": badge,
        "dynamic": dynamic,
        "editable": editable,
        "multiline": len(raw_lines) > 1,
        "description": _describe(spec),
        "unknown": [e["text"] for e in spec["extra"]],
    }
    return node


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse(content):
    """Parse script *content* into a document dict."""
    ends_nl = content.endswith("\n")
    body = content[:-1] if ends_nl else content
    lines = body.split("\n") if body != "" else ([] if not ends_nl else [""])
    nodes = _parse_lines(lines, 1)
    nodes = _fold_sections(nodes)
    _assign_ids(nodes, [0])
    return {"nodes": nodes, "ends_nl": ends_nl, "line_count": len(lines)}


def _parse_lines(lines, base_lineno):
    nodes = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        lineno = base_lineno + i

        # 1. shebang
        if lineno == 1 and line.startswith("#!"):
            nodes.append({"kind": "shebang", "lineno": lineno, "raw": [line],
                          "text": line})
            i += 1
            continue

        # 2. blank run
        if line.strip() == "":
            start = i
            while i < n and lines[i].strip() == "":
                i += 1
            nodes.append({"kind": "blank", "lineno": lineno,
                          "raw": lines[start:i], "count": i - start})
            continue

        # 3. comment (plain, marker or disabled rule)
        parts = _strip_comment_prefix(line)
        if parts is not None:
            indent, hashes, space, cbody = parts
            if _is_firewall_cmd(cbody):
                raw, texts, prefixes, i = _consume_commented_command(lines, i)
                nodes.append(_rule_node(raw, lineno, "\n".join(texts),
                                        disabled=True, prefixes=prefixes))
                continue
            marker = _marker_kind(cbody)
            if marker:
                nodes.append({"kind": "comment", "lineno": lineno, "raw": [line],
                              "text": cbody, "indent": indent, "hashes": hashes,
                              "space": space, "marker": marker[0],
                              "label": marker[1]})
                i += 1
                continue
            # group consecutive plain comment lines
            start = i
            texts = []
            while i < n:
                p = _strip_comment_prefix(lines[i])
                if p is None:
                    break
                if _is_firewall_cmd(p[3]) or _marker_kind(p[3]):
                    break
                texts.append(p[3])
                i += 1
            nodes.append({"kind": "comment", "lineno": lineno,
                          "raw": lines[start:i], "text": "\n".join(texts),
                          "indent": indent, "hashes": hashes, "space": space,
                          "marker": None, "label": ""})
            continue

        # 4. heredoc
        hd = _HEREDOC_RE.search(line)
        if hd and not line.lstrip().startswith("#"):
            marker = hd.group("marker")
            start = i
            i += 1
            while i < n and lines[i].strip() != marker:
                i += 1
            if i < n:
                i += 1
                raw = lines[start:i]
                head = line[:hd.start()].strip()
                inner = raw[1:-1]
                nodes.append({
                    "kind": "heredoc", "lineno": lineno, "raw": raw,
                    "head_raw": raw[:1], "foot_raw": raw[-1:],
                    "marker": marker, "head": head,
                    "comment_block": head in ("", ":"),
                    "children": _fold_sections(_parse_lines(inner, lineno + 1)),
                })
                continue
            i = start  # no terminator: fall through and treat as shell

        # 5. compound block
        bm = _BLOCK_OPEN_RE.match(line)
        fm = _FUNC_RE.match(line)
        if bm or fm:
            raw, inner, i = _consume_block(lines, i, bm.group("kw") if bm else None)
            closed = len(raw) >= 2
            nodes.append({
                "kind": "block", "lineno": lineno, "raw": raw,
                "head_raw": raw[:1] if closed else list(raw),
                "foot_raw": raw[-1:] if closed else [],
                "block_type": bm.group("kw") if bm else "function",
                "name": fm.group("name") if fm else "",
                "head": raw[0].strip(),
                "children": _fold_sections(_parse_lines(inner, lineno + 1)) if closed else [],
            })
            continue

        # 6. firewall rule
        if _is_firewall_cmd(line):
            raw, i = _consume_continued(lines, i)
            nodes.append(_rule_node(raw, lineno, "\n".join(raw)))
            continue

        # 7. variable assignment
        vm = _VAR_RE.match(line)
        if vm and not _continues(line):
            nodes.append({"kind": "var", "lineno": lineno, "raw": [line],
                          "name": vm.group("name"),
                          "value": unquote(vm.group("value").strip()),
                          "text": line.strip()})
            i += 1
            continue

        # 8. anything else
        raw, i = _consume_continued(lines, i)
        nodes.append({"kind": "shell", "lineno": lineno, "raw": raw,
                      "text": "\n".join(raw).strip()})
    return nodes


def _consume_continued(lines, i):
    """Consume a command and its backslash continuations."""
    start = i
    while i < len(lines) and _continues(lines[i]):
        i += 1
    i = min(i + 1, len(lines))
    return lines[start:i], i


def _consume_commented_command(lines, i):
    """Consume a commented-out command, including continuation lines."""
    start = i
    texts, prefixes = [], []
    while i < len(lines):
        p = _strip_comment_prefix(lines[i])
        if p is None:
            break
        indent, hashes, space, cbody = p
        prefixes.append(indent + hashes + space)
        texts.append(cbody)
        if not _continues(cbody):
            i += 1
            break
        i += 1
    return lines[start:i], texts, prefixes, i


def _consume_block(lines, i, keyword):
    """Consume a compound block, tracking nesting. Returns (raw, inner, next)."""
    closer = _BLOCK_CLOSE.get(keyword or "", "}")
    start = i
    depth = 0
    i_end = len(lines)
    j = i
    while j < len(lines):
        stripped = lines[j].strip()
        head = _BLOCK_OPEN_RE.match(lines[j])
        if head and _BLOCK_CLOSE[head.group("kw")] == closer:
            depth += 1
        elif closer == "}" and stripped.endswith("{"):
            depth += 1
        if stripped == closer or stripped.startswith(closer + " ") or stripped == closer + ";":
            depth -= 1
            if depth <= 0:
                i_end = j + 1
                break
        j += 1
    raw = lines[start:i_end]
    inner = raw[1:-1] if len(raw) > 2 else []
    return raw, inner, i_end


def _fold_sections(nodes):
    """Fold ``# BEGIN x`` ... ``# END x`` comment pairs into section nodes."""
    out = []
    i = 0
    while i < len(nodes):
        node = nodes[i]
        if node.get("kind") == "comment" and node.get("marker") == "begin":
            label = node["label"]
            depth = 0
            end_at = None
            for j in range(i + 1, len(nodes)):
                other = nodes[j]
                if other.get("kind") != "comment":
                    continue
                if other.get("marker") == "begin" and _labels_match(label, other["label"]):
                    depth += 1
                elif other.get("marker") == "end" and _labels_match(label, other["label"]):
                    if depth == 0:
                        end_at = j
                        break
                    depth -= 1
            if end_at is not None:
                children = _fold_sections(nodes[i + 1:end_at])
                out.append({
                    "kind": "section", "lineno": node["lineno"],
                    "label": label, "managed": _is_managed(label),
                    "begin": node, "end": nodes[end_at], "children": children,
                })
                i = end_at + 1
                continue
        out.append(node)
        i += 1
    return out


def _assign_ids(nodes, counter):
    for node in nodes:
        counter[0] += 1
        node["id"] = "n%d" % counter[0]
        if node.get("children"):
            _assign_ids(node["children"], counter)


# ---------------------------------------------------------------------------
# Serialiser
# ---------------------------------------------------------------------------

def serialize(doc):
    lines = []
    _emit(doc["nodes"], lines)
    text = "\n".join(lines)
    if doc.get("ends_nl"):
        text += "\n"
    return text


def _emit(nodes, out):
    """Render nodes back to lines.

    Containers (sections, heredocs, ``if``/``for`` blocks) are rendered from
    their own children so that an edit to a rule nested inside one actually
    reaches the file.  Leaf nodes emit the exact lines they were parsed from.
    """
    for node in nodes:
        kind = node.get("kind")
        if kind == "section":
            _emit([node["begin"]], out)
            _emit(node["children"], out)
            _emit([node["end"]], out)
        elif kind in ("heredoc", "block"):
            out.extend(node.get("head_raw") or [])
            _emit(node.get("children") or [], out)
            out.extend(node.get("foot_raw") or [])
        else:
            out.extend(node.get("raw", []))


def _walk(nodes):
    for node in nodes:
        yield node
        if node.get("kind") == "section":
            for sub in _walk(node["children"]):
                yield sub
        elif node.get("children"):
            for sub in _walk(node["children"]):
                yield sub


def walk_ctx(nodes, parked=False):
    """Walk the tree yielding ``(node, parked)``.

    *parked* is True for anything sitting inside a heredoc used as a comment
    block: it is real, parseable script that the shell never executes, so it
    must not be counted among the rules this file applies.
    """
    for node in nodes:
        yield node, parked
        children = node.get("children")
        if not children:
            continue
        inner = parked or (node.get("kind") == "heredoc" and node.get("comment_block"))
        for sub in walk_ctx(children, inner):
            yield sub


def find_node(doc, node_id):
    """Return (node, parent_list, index) for *node_id*, or (None, None, -1)."""
    def search(nodes):
        for idx, node in enumerate(nodes):
            if node.get("id") == node_id:
                return node, nodes, idx
            if node.get("kind") == "section":
                found = search(node["children"])
                if found[0]:
                    return found
            elif node.get("children"):
                found = search(node["children"])
                if found[0]:
                    return found
        return None, None, -1
    return search(doc["nodes"])


# ---------------------------------------------------------------------------
# Rule rendering from a spec (used by the builder and by imports)
# ---------------------------------------------------------------------------

def render_rule(spec):
    """Render a fresh iptables command line from a form spec dict."""
    family = spec.get("family", "ipv4")
    cmd = spec.get("cmd") or ("ip6tables" if family == "ipv6" else "iptables")
    parts = [cmd]

    table = (spec.get("table") or "filter").strip()
    if table and table != "filter":
        parts += ["-t", table]

    op = spec.get("op") or "append"
    chain = (spec.get("chain") or "").strip()
    op_flag = OP_FLAG_FOR.get(op, "-A")
    if chain:
        parts += [op_flag, chain]
    if op == "insert" and str(spec.get("position") or "").strip():
        parts.append(str(spec["position"]).strip())
    if op == "policy" and spec.get("policy"):
        parts.append(spec["policy"])
    if op == "rename-chain" and spec.get("newname"):
        parts.append(spec["newname"])
    if op in ("new-chain", "delete-chain", "flush", "policy", "rename-chain", "zero"):
        line = " ".join(parts)
        if op == "new-chain" and spec.get("guard") == "create-or-flush":
            line = "%s 2>/dev/null || %s -F %s" % (line, cmd, chain)
        return line

    fields = dict(spec.get("fields") or {})
    negated = spec.get("negated") or {}
    modules = []

    def add(key):
        value = _clean(key, fields.get(key, ""))
        if not value.strip():
            return
        flag = _FLAG_BY_KEY.get(key)
        if not flag:
            return
        module = _MODULE_FOR_FLAG.get(flag)
        if module and module not in modules:
            modules.append(module)
            parts.extend(["-m", module])
        if negated.get(key):
            parts.append("!")
        parts.append(flag)
        parts.append(shquote(value))

    # interfaces / protocol / addresses first, then match-module options
    for key in ("in_iface", "out_iface", "proto", "src", "dst"):
        add(key)
    if fields.get("sport") or fields.get("dport"):
        proto = (fields.get("proto") or "").lower()
        if proto in ("tcp", "udp", "sctp", "dccp", "udplite") and "p_module" not in modules:
            modules.append("p_module")
            parts.extend(["-m", proto])
        add("sport")
        add("dport")
    for key in ("sports", "dports", "state", "ctstate", "ctorigdstport", "ctdir",
                "icmp_type", "icmpv6_type", "mac_source", "src_range", "dst_range",
                "limit", "limit_burst"):
        add(key)

    for extra in spec.get("extra_args") or []:
        extra = str(extra).strip()
        if extra:
            parts.append(extra)

    target = (spec.get("target") or "").strip()
    if target:
        parts += ["-g" if spec.get("use_goto") else "-j", target]
        for opt in TARGET_OPT_FIELDS:
            if target.upper() in opt["targets"]:
                value = _clean(opt["key"], fields.get(opt["key"], ""))
                if value.strip():
                    parts += [opt["flag"], shquote(value)]

    if fields.get("comment"):
        parts += ["-m", "comment", "--comment", shquote(fields["comment"])]

    line = " ".join(p for p in parts if p != "")
    if spec.get("guard") == "check-then-add":
        check = line.replace(" %s %s" % (op_flag, chain), " -C %s" % chain, 1)
        check = re.sub(r"(-C %s) \d+\b" % re.escape(chain), r"\1", check, count=1)
        line = "%s 2>/dev/null || %s" % (check, line)
    return line


# ---------------------------------------------------------------------------
# Token-level editing (keeps unknown flags and odd spacing intact)
# ---------------------------------------------------------------------------

def apply_field_edits(node, updates):
    """Rewrite individual fields of a parsed rule at the token level.

    *updates* maps form keys (``src``, ``dport``, ``target`` ...) to new
    values.  An empty value removes the flag.  Tokens that are not touched -
    including flags this module does not recognise - keep their original text
    and spacing.

    For the ``-C ... || -I ...`` and ``-N ... || -F ...`` idioms the same edit
    is applied to both halves, so the guard never drifts from the rule it
    guards.
    """
    all_tokens = [dict(t) for t in node["tokens"]]
    left, right = _split_on_or(all_tokens)
    if right is None:
        edited = _edit_tokens(left, updates)
    else:
        # The ``||`` token keeps its own separator; splice the halves back.
        or_token = all_tokens[len(left)]
        skip_left = {"position"} if node.get("guard") == "check-then-add" else set()
        left_updates = {k: v for k, v in updates.items() if k not in skip_left}
        edited = _edit_tokens(left, left_updates) + [or_token] + _edit_tokens(right, updates)
    return render_tokens(edited, node.get("trailing", ""))


def _edit_tokens(tokens, updates):
    """Apply field updates to one command's token list.

    Nothing is spliced while indices are still being resolved: tokens are
    marked for removal, replacement or prefixing, and the list is rebuilt once
    at the end.  Untouched tokens keep their original text and separator.
    """
    tokens = [dict(t) for t in tokens]
    first_sep = tokens[0]["sep"] if tokens else ""
    _, index = _parse_command_tokens(tokens)

    drop = set()           # token indices to delete
    negate = set()         # flag indices that need a leading "!"
    before = {}            # index -> tokens inserted in front of it
    additions = []         # (flag, value) appended before -j

    def tok(text):
        return {"sep": " ", "text": text}

    for key, value in updates.items():
        if key.startswith("neg_"):
            field = key[4:]
            fi = index.get(field + "__flag")
            if fi is None:
                continue
            has_neg = fi > 0 and tokens[fi - 1]["text"] == "!"
            if value and not has_neg:
                negate.add(fi)
            elif not value and has_neg:
                drop.add(fi - 1)
            continue

        value = _clean(key, value)

        if key == "family":
            ci = index.get("cmd", 0)
            current = tokens[ci]["text"]
            is_v6 = "ip6tables" in current
            if value == "ipv6" and not is_v6:
                tokens[ci]["text"] = current.replace("iptables", "ip6tables")
            elif value == "ipv4" and is_v6:
                tokens[ci]["text"] = current.replace("ip6tables", "iptables")
            continue

        if key == "op":
            oi = index.get("op")
            if oi is not None and value in OP_FLAG_FOR:
                tokens[oi]["text"] = OP_FLAG_FOR[value]
                if value != "insert" and index.get("position") is not None:
                    drop.add(index["position"])
            continue

        if key == "target":
            ti, fi = index.get("target"), index.get("target_flag")
            if ti is not None and value:
                tokens[ti]["text"] = shquote(value)
            elif ti is not None and not value:
                drop.update({fi, ti})
            elif value:
                additions.append(("-j", value))
            continue

        if key in ("chain", "policy", "newname"):
            ti = index.get(key)
            if ti is not None and value:
                tokens[ti]["text"] = value
            continue

        if key == "position":
            ti, ci = index.get("position"), index.get("chain")
            if ti is not None and value:
                tokens[ti]["text"] = value
            elif ti is not None and not value:
                drop.add(ti)
            elif value and ci is not None:
                before.setdefault(ci + 1, []).append(tok(value))
            continue

        if key == "table":
            ti = index.get("table")
            fi = index.get("table__flag", (ti - 1) if ti is not None else None)
            wanted = value and value != "filter"
            if ti is not None and wanted:
                tokens[ti]["text"] = value
            elif ti is not None and not wanted:
                drop.update({fi, ti})
            elif wanted:
                before.setdefault(1, []).extend([tok("-t"), tok(value)])
            continue

        flag = _FLAG_BY_KEY.get(key)
        if not flag:
            continue
        ti, fi = index.get(key), index.get(key + "__flag")
        if ti is not None and value:
            tokens[ti]["text"] = shquote(value)
        elif ti is not None and not value:
            drop.update({fi, ti})
            if fi is not None and fi > 0 and tokens[fi - 1]["text"] == "!":
                drop.add(fi - 1)
        elif value:
            additions.append((flag, value))

    rebuilt = []
    for i, token in enumerate(tokens):
        for extra in before.get(i, []):
            rebuilt.append(dict(extra))
        if i in drop:
            continue
        if i in negate:
            rebuilt.append(tok("!"))
        rebuilt.append(token)
    for extra in before.get(len(tokens), []):
        rebuilt.append(dict(extra))

    if additions:
        insert_at = len(rebuilt)
        for pos, token in enumerate(rebuilt):
            if token["text"] in ("-j", "--jump", "-g", "--goto"):
                insert_at = pos
                break
        present = {t["text"] for t in rebuilt}
        proto = ""
        for pos, token in enumerate(rebuilt):
            if token["text"] in ("-p", "--protocol") and pos + 1 < len(rebuilt):
                proto = unquote(rebuilt[pos + 1]["text"]).lower()
        for flag, value in additions:
            if flag in ("-p", "--protocol"):
                proto = value.lower()
        new_tokens = []
        for flag, value in additions:
            module = _MODULE_FOR_FLAG.get(flag)
            if module and module not in present:
                present.add(module)
                new_tokens += [tok("-m"), tok(module)]
            elif flag in ("--dport", "--sport") and proto in (
                    "tcp", "udp", "sctp", "dccp", "udplite") and proto not in present:
                present.add(proto)
                new_tokens += [tok("-m"), tok(proto)]
            new_tokens += [tok(flag), tok(shquote(value))]
        rebuilt[insert_at:insert_at] = new_tokens

    rebuilt = _drop_orphan_modules(rebuilt)
    if rebuilt:
        rebuilt[0]["sep"] = first_sep
    return rebuilt


def _drop_orphan_modules(tokens):
    """Remove ``-m <module>`` once the last option it loaded has gone."""
    flags_present = {t["text"] for t in tokens}
    drop = set()
    for i, token in enumerate(tokens):
        if token["text"] not in ("-m", "--match") or i + 1 >= len(tokens):
            continue
        module = unquote(tokens[i + 1]["text"])
        wanted = _FLAGS_FOR_MODULE.get(module)
        if wanted and not (wanted & flags_present):
            drop.update({i, i + 1})
    if not drop:
        return tokens
    return [t for i, t in enumerate(tokens) if i not in drop]


# ---------------------------------------------------------------------------
# Projection for the UI / API (JSON-safe, no internal token bookkeeping)
# ---------------------------------------------------------------------------

def node_to_ui(node):
    kind = node.get("kind")
    out = {"id": node.get("id"), "kind": kind, "lineno": node.get("lineno", 0),
           "raw": "\n".join(node.get("raw", []))}
    if kind == "rule":
        spec = node["spec"]
        out.update({
            "cmd": spec["cmd"], "family": spec["family"], "table": spec["table"],
            "op": spec["op"], "op_label": OP_LABELS.get(spec["op"], spec["op"]),
            "chain": spec["chain"], "position": spec["position"],
            "policy": spec["policy"], "newname": spec["newname"],
            "target": spec["target"] or spec["goto"],
            "use_goto": bool(spec["goto"]),
            "fields": spec["fields"], "negated": spec["negated"],
            "bools": spec["bools"],
            "modules": [m["name"] for m in spec["modules"]],
            "badge": node["badge"], "description": node["description"],
            "disabled": node["disabled"], "dynamic": node["dynamic"],
            "editable": node["editable"], "multiline": node["multiline"],
            "guard": node["guard"], "unknown": node["unknown"],
            "signature": rule_signature(node),
        })
    elif kind == "section":
        out.update({
            "label": node["label"], "managed": node["managed"],
            "begin": "\n".join(node["begin"]["raw"]),
            "end": "\n".join(node["end"]["raw"]),
            "children": [node_to_ui(c) for c in node["children"]],
            "rule_count": sum(1 for n in _walk(node["children"]) if n.get("kind") == "rule"),
        })
    elif kind == "heredoc":
        out.update({
            "marker": node["marker"], "head": node["head"],
            "comment_block": node["comment_block"],
            "children": [node_to_ui(c) for c in node.get("children", [])],
        })
    elif kind == "block":
        out.update({
            "block_type": node["block_type"], "name": node.get("name", ""),
            "head": node["head"],
            "children": [node_to_ui(c) for c in node.get("children", [])],
        })
    elif kind == "comment":
        out.update({"text": node["text"], "marker": node.get("marker")})
    elif kind == "blank":
        out.update({"count": node["count"]})
    elif kind == "var":
        out.update({"name": node["name"], "value": node["value"], "text": node["text"]})
    else:
        out.update({"text": node.get("text", "")})
    return out


def doc_to_ui(doc):
    return [node_to_ui(n) for n in doc["nodes"]]


def rule_signature(node):
    """Normalised form of a rule, used to spot duplicates across servers."""
    spec = node.get("spec") or {}
    parts = [spec.get("cmd", ""), spec.get("table", "filter"), spec.get("op", ""),
             spec.get("chain", ""), spec.get("target", "") or spec.get("goto", "")]
    for key in sorted((spec.get("fields") or {}).keys()):
        parts.append("%s=%s" % (key, spec["fields"][key]))
    for flag in sorted(spec.get("bools") or []):
        parts.append(flag)
    return "|".join(parts)


def summarize(doc):
    """Counts and inventories shown at the top of the editor page."""
    rules = active = disabled = parked_count = 0
    chains, custom_chains, ifaces, tables, targets = set(), set(), set(), set(), set()
    sections, unknown_flags = [], set()
    for node, parked in walk_ctx(doc["nodes"]):
        kind = node.get("kind")
        if kind == "section":
            sections.append({"id": node["id"], "label": node["label"],
                             "managed": node["managed"]})
            continue
        if kind != "rule":
            continue
        rules += 1
        if parked:
            parked_count += 1
        elif node["disabled"]:
            disabled += 1
        else:
            active += 1
        spec = node["spec"]
        if spec.get("chain"):
            chains.add(spec["chain"])
            if spec["op"] == "new-chain":
                custom_chains.add(spec["chain"])
        if spec.get("table"):
            tables.add(spec["table"])
        if spec.get("target"):
            targets.add(spec["target"])
        for key in ("in_iface", "out_iface"):
            value = spec["fields"].get(key)
            if value:
                ifaces.add(value)
        unknown_flags.update(node["unknown"])
    builtin = set()
    for names in BUILTIN_CHAINS.values():
        builtin.update(names)
    custom_chains.update(c for c in chains if c not in builtin)
    return {
        "rules": rules, "active": active, "disabled": disabled,
        "parked": parked_count,
        "chains": sorted(chains), "custom_chains": sorted(custom_chains),
        "interfaces": sorted(ifaces), "tables": sorted(tables),
        "targets": sorted(targets), "sections": sections,
        "unknown_flags": sorted(unknown_flags),
        "lines": doc.get("line_count", 0),
    }


# ---------------------------------------------------------------------------
# Structural edits.  Each returns the new script text.
# ---------------------------------------------------------------------------

class EditError(Exception):
    pass


def _lines_of(text):
    return text.split("\n")


def _disable_lines(raw):
    out = []
    for line in raw:
        m = re.match(r"^([ \t]*)(.*)$", line)
        out.append(m.group(1) + "# " + m.group(2) if m.group(2) else line)
    return out


def _enable_lines(raw):
    """Uncomment a rule, keeping the indentation of continuation lines.

    ``#  -o wt0 \\`` must come back as ``  -o wt0 \\`` (the hash was added in
    column 0), while ``# iptables ...`` must come back without the single
    separating space.  So one space is dropped only when *every* line of the
    rule has one.
    """
    matches = [_COMMENT_RE.match(line) for line in raw]
    if not all(matches):
        return list(raw)
    drop_space = all(m.group("space")[:1] in (" ", "\t") for m in matches)
    out = []
    for m in matches:
        space = m.group("space")[1:] if drop_space else m.group("space")
        out.append(m.group("indent") + space + m.group("body"))
    return out


def _insert_point(doc, after_id, inside_id=None):
    """Return (list, index) where new nodes should go."""
    if inside_id:
        node, _, _ = find_node(doc, inside_id)
        if node and node.get("kind") == "section":
            return node["children"], len(node["children"])
    if after_id:
        node, parent, idx = find_node(doc, after_id)
        if node is None:
            raise EditError("Target block no longer exists - reload the page.")
        return parent, idx + 1
    return doc["nodes"], len(doc["nodes"])


def _new_nodes(text):
    """Wrap literal text as raw nodes ready to splice into a document."""
    return [{"kind": "raw", "raw": _lines_of(text), "lineno": 0}]


def apply_op(content, op, payload):
    """Apply one structural edit to *content* and return the new text."""
    doc = parse(content)
    payload = payload or {}
    node_id = payload.get("id") or ""

    if op == "update_rule":
        node, _, _ = find_node(doc, node_id)
        if not node or node.get("kind") != "rule":
            raise EditError("Rule not found - reload the page.")
        if not node["editable"]:
            raise EditError("This rule uses shell syntax the form cannot rewrite safely. "
                            "Edit it as raw text instead.")
        updates = payload.get("updates") or {}
        new_text = apply_field_edits(node, updates)
        lines = _lines_of(new_text)
        node["raw"] = _disable_lines(lines) if node["disabled"] else lines

    elif op == "replace_raw":
        node, _, _ = find_node(doc, node_id)
        if not node:
            raise EditError("Block not found - reload the page.")
        if node.get("kind") == "section":
            raise EditError("Edit the lines inside the section, not the section itself.")
        node["raw"] = _lines_of(payload.get("text", ""))

    elif op == "toggle":
        node, _, _ = find_node(doc, node_id)
        if not node or node.get("kind") != "rule":
            raise EditError("Rule not found - reload the page.")
        node["raw"] = _enable_lines(node["raw"]) if node["disabled"] else _disable_lines(node["raw"])

    elif op == "delete":
        node, parent, idx = find_node(doc, node_id)
        if node is None:
            raise EditError("Block not found - reload the page.")
        if node.get("kind") == "section" and node.get("managed"):
            raise EditError("This section is maintained by CSF-eUI and cannot be deleted here.")
        parent.pop(idx)

    elif op == "move":
        node, parent, idx = find_node(doc, node_id)
        if node is None:
            raise EditError("Block not found - reload the page.")
        step = -1 if payload.get("direction") == "up" else 1
        target = idx + step
        # Hop over blank runs so moving feels natural.
        while 0 <= target < len(parent) and parent[target].get("kind") == "blank":
            target += step
        if not (0 <= target < len(parent)):
            raise EditError("Already at the %s." % ("top" if step < 0 else "bottom"))
        parent[idx], parent[target] = parent[target], parent[idx]

    elif op == "unwrap":
        node, parent, idx = find_node(doc, node_id)
        if not node or node.get("kind") != "heredoc":
            raise EditError("Only a heredoc block can be activated this way.")
        children = node.get("children") or []
        if not children:
            raise EditError("That block is empty.")
        parent[idx:idx + 1] = children

    elif op == "duplicate":
        node, parent, idx = find_node(doc, node_id)
        if node is None:
            raise EditError("Block not found - reload the page.")
        parent.insert(idx + 1, {"kind": "raw", "raw": list(node["raw"]), "lineno": 0})

    elif op == "add_rule":
        spec = payload.get("spec") or {}
        error = validate_spec(spec)
        if error:
            raise EditError(error)
        line = render_rule(spec)
        chunk = []
        comment = (payload.get("comment") or "").strip()
        if comment:
            chunk += ["# " + c for c in comment.split("\n")]
        chunk.append(line)
        if payload.get("disabled"):
            chunk = _disable_lines(chunk)
        parent, at = _insert_point(doc, payload.get("after_id"), payload.get("section_id"))
        parent.insert(at, {"kind": "raw", "raw": chunk, "lineno": 0})

    elif op == "add_comment":
        text = (payload.get("text") or "").strip()
        if not text:
            raise EditError("Comment text is required.")
        parent, at = _insert_point(doc, payload.get("after_id"), payload.get("section_id"))
        parent.insert(at, {"kind": "raw", "lineno": 0,
                           "raw": ["# " + c for c in text.split("\n")]})

    elif op == "add_raw":
        text = payload.get("text", "")
        if not text.strip():
            raise EditError("Nothing to insert.")
        parent, at = _insert_point(doc, payload.get("after_id"), payload.get("section_id"))
        parent.insert(at, {"kind": "raw", "raw": _lines_of(text), "lineno": 0})

    elif op == "add_section":
        label = (payload.get("label") or "").strip()
        if not label:
            raise EditError("Section name is required.")
        if _is_managed(label):
            raise EditError("That name is reserved for sections CSF-eUI maintains.")
        body = payload.get("text", "")
        chunk = ["", "# BEGIN " + label]
        if body.strip():
            chunk += _lines_of(body)
        chunk += ["# END " + label]
        parent, at = _insert_point(doc, payload.get("after_id"))
        parent.insert(at, {"kind": "raw", "raw": chunk, "lineno": 0})

    elif op == "rename_section":
        node, _, _ = find_node(doc, node_id)
        if not node or node.get("kind") != "section":
            raise EditError("Section not found - reload the page.")
        if node.get("managed"):
            raise EditError("This section is maintained by CSF-eUI and cannot be renamed.")
        label = (payload.get("label") or "").strip()
        if not label:
            raise EditError("Section name is required.")
        node["begin"]["raw"] = ["# BEGIN " + label]
        node["end"]["raw"] = ["# END " + label]

    elif op == "set_blank":
        node, _, _ = find_node(doc, node_id)
        if not node or node.get("kind") != "blank":
            raise EditError("Spacer not found - reload the page.")
        count = max(0, min(10, int(payload.get("count", 1) or 0)))
        node["raw"] = [""] * count

    else:
        raise EditError("Unknown action: %s" % op)

    return serialize(doc)


def validate_spec(spec):
    """Check a builder spec before rendering it. Returns an error string or ''."""
    op = spec.get("op") or "append"
    if op not in OP_FLAG_FOR:
        return "Unsupported operation: %s" % op
    chain = (spec.get("chain") or "").strip()
    if not chain:
        return "A chain is required (for example INPUT, FORWARD or a custom chain)."
    if not re.match(r"^[A-Za-z0-9_.\-]+$", chain):
        return "Chain names may only contain letters, digits, dot, dash and underscore."
    table = (spec.get("table") or "filter").strip()
    if table and table not in TABLES:
        return "Unknown table: %s" % table
    if op == "insert":
        pos = str(spec.get("position") or "").strip()
        if pos and not pos.isdigit():
            return "Insert position must be a number."
    if op == "policy" and not (spec.get("policy") or "").strip():
        return "A policy target (ACCEPT or DROP) is required."
    if op in ("append", "insert", "replace", "check", "delete"):
        if not (spec.get("target") or "").strip():
            return "A target is required (ACCEPT, DROP, a custom chain, and so on)."
    fields = spec.get("fields") or {}
    for key in ("dport", "sport"):
        value = str(fields.get(key, "")).strip()
        if value and not re.match(r"^\$?[\w:]+$", value):
            return "%s must be a port or a range like 5060:5062." % key
    for key in ("dports", "sports"):
        value = str(fields.get(key, "")).strip()
        if value and not re.match(r"^[\w,:$]+$", value):
            return "%s must be a comma-separated list of ports." % key
    if (fields.get("dport") or fields.get("sport") or fields.get("dports")
            or fields.get("sports")):
        proto = (fields.get("proto") or "").lower()
        if proto not in ("tcp", "udp", "sctp", "dccp", "udplite"):
            return "Port matches need a protocol of tcp, udp, sctp, dccp or udplite."
    target = (spec.get("target") or "").upper()
    if target == "DNAT" and not (fields.get("to_destination") or "").strip():
        return "DNAT needs a destination such as 10.0.0.5:8096."
    if target == "SNAT" and not (fields.get("to_source") or "").strip():
        return "SNAT needs a source address."
    if target in ("DNAT", "SNAT", "MASQUERADE", "REDIRECT") and table != "nat":
        return "%s only works in the nat table." % target
    return ""


# ---------------------------------------------------------------------------
# Portable bundles: recreate a script on another server from the UI alone
# ---------------------------------------------------------------------------

BUNDLE_FORMAT = "csfv2-firewall-script"
BUNDLE_VERSION = 1


def _item_from_node(node):
    kind = node.get("kind")
    raw = "\n".join(node.get("raw", []))
    if kind == "rule":
        return {"type": "rule", "text": raw, "disabled": node["disabled"],
                "description": node["description"],
                "signature": rule_signature(node),
                "family": node["spec"]["family"], "table": node["spec"]["table"],
                "chain": node["spec"]["chain"], "target": node["spec"]["target"]}
    if kind == "section":
        return {"type": "section", "label": node["label"], "managed": node["managed"],
                "begin": "\n".join(node["begin"]["raw"]),
                "end": "\n".join(node["end"]["raw"]),
                "items": [_item_from_node(c) for c in node["children"]]}
    if kind == "blank":
        return {"type": "blank", "count": node["count"]}
    if kind == "comment":
        return {"type": "comment", "text": raw}
    if kind == "shebang":
        return {"type": "shebang", "text": raw}
    return {"type": kind or "raw", "text": raw}


def export_bundle(content, script="csfpost", hostname=""):
    doc = parse(content)
    return {
        "format": BUNDLE_FORMAT,
        "version": BUNDLE_VERSION,
        "script": script,
        "exported": int(time.time()),
        "hostname": hostname,
        "summary": summarize(doc),
        "content": content,
        "items": [_item_from_node(n) for n in doc["nodes"]],
    }


def _render_items(items, skip_managed=True):
    out = []
    for item in items or []:
        itype = item.get("type")
        if itype == "section":
            if skip_managed and item.get("managed"):
                continue
            out.append(item.get("begin") or ("# BEGIN " + item.get("label", "section")))
            out.extend(_render_items(item.get("items"), skip_managed))
            out.append(item.get("end") or ("# END " + item.get("label", "section")))
        elif itype == "blank":
            out.extend([""] * max(1, int(item.get("count", 1) or 1)))
        elif itype == "shebang":
            continue
        else:
            text = item.get("text", "")
            if text != "" or itype == "comment":
                out.extend(text.split("\n"))
    return out


def _existing_signatures(content):
    """Signatures of the rules this server actually applies today."""
    doc = parse(content)
    return {rule_signature(n) for n, parked in walk_ctx(doc["nodes"])
            if n.get("kind") == "rule" and not n.get("disabled") and not parked}


def import_bundle(current, bundle, mode="append", items=None, script_label=""):
    """Bring a bundle (or a selection from one) into *current*.

    ``replace`` swaps the whole script, ``append`` adds everything selected,
    ``merge`` adds only the rules this server does not already have.
    Sections CSF-eUI maintains itself are never imported.
    """
    if not isinstance(bundle, dict) or bundle.get("format") != BUNDLE_FORMAT:
        raise EditError("That is not a CSF-eUI firewall script bundle.")
    chosen = items if items is not None else bundle.get("items") or []

    if mode == "replace":
        text = bundle.get("content")
        if items is not None or not text:
            text = "#!/bin/sh\n" + "\n".join(_render_items(chosen)).lstrip("\n") + "\n"
        return text if text.endswith("\n") else text + "\n"

    if mode == "merge":
        have = _existing_signatures(current)
        chosen = _filter_new(chosen, have)

    lines = _render_items(chosen)
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        if mode == "merge":
            raise EditError("Nothing new to import - this server already has these rules.")
        raise EditError("Nothing to import - the bundle only holds sections that "
                        "CSF-eUI rebuilds on each server by itself.")

    banner = "# BEGIN imported%s" % ((" from " + bundle.get("hostname")) if bundle.get("hostname") else "")
    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime())
    block = ["", banner, "# imported %s%s" % (stamp, (" (" + script_label + ")") if script_label else "")]
    block += lines
    block += ["# END imported%s" % ((" from " + bundle.get("hostname")) if bundle.get("hostname") else "")]

    base = current if current.endswith("\n") or current == "" else current + "\n"
    return base + "\n".join(block) + "\n"


def _filter_new(items, have):
    """Keep only what the target server is missing.

    Comments and blank lines are held back until something they introduce
    survives the filter, so a skipped duplicate does not leave its heading
    stranded on the other server.
    """
    out = []
    pending = []
    for item in items:
        itype = item.get("type")

        if itype in ("comment", "blank"):
            pending.append(item)
            continue

        if itype == "shebang":
            continue

        if itype == "rule":
            if item.get("disabled") or item.get("signature") not in have:
                out.extend(pending)
                out.append(item)
            # A duplicate takes its own heading with it.
            pending = []
            continue

        if itype == "section":
            if item.get("managed"):
                pending = []
                continue
            kids = _filter_new(item.get("items") or [], have)
            if any(k.get("type") == "rule" for k in kids):
                clone = dict(item)
                clone["items"] = kids
                out.extend(pending)
                out.append(clone)
            pending = []
            continue

        # vars, shell lines and heredocs come across as they are
        out.extend(pending)
        out.append(item)
        pending = []

    return out
