"""Rate-limit presets: one click sets CT_LIMIT / PORTFLOOD / CONNLIMIT / SYNFLOOD for a kind of server."""
from csf_backend import csf_wrapper as csf

PRESETS = {
    "docker_paas": {
        "title": "Docker / Coolify / Dokploy host",
        "blurb": "Apps behind a reverse proxy. Moderate connection limits so the proxy is never throttled; strict login protection.",
        "values": {"CT_LIMIT": "300", "CT_INTERVAL": "30", "CT_BLOCK_TIME": "1800", "CONNLIMIT": "22;20,80;300,443;300",
                   "PORTFLOOD": "22;tcp;10;300,80;tcp;300;5,443;tcp;300;5", "SYNFLOOD": "0", "LF_SSHD": "5", "LF_SSHD_PERM": "1", "PS_LIMIT": "10"},
    },
    "web_cms": {
        "title": "WordPress / Nextcloud / web app",
        "blurb": "Many short HTTP connections per visitor. Looser web limits, protection for wp-login style brute force via LF_HTACCESS and 404 floods.",
        "values": {"CT_LIMIT": "200", "CT_INTERVAL": "30", "CT_BLOCK_TIME": "1800", "CONNLIMIT": "80;200,443;200",
                   "PORTFLOOD": "80;tcp;200;5,443;tcp;200;5", "LF_APACHE_404": "100", "LF_APACHE_403": "50", "LF_HTACCESS": "10", "SYNFLOOD": "0"},
    },
    "mail": {
        "title": "Mail server",
        "blurb": "Tight limits on SMTP/IMAP/POP3 password guessing; connection tracking that does not break mail clients.",
        "values": {"CT_LIMIT": "150", "CT_INTERVAL": "30", "CT_BLOCK_TIME": "3600", "LF_SMTPAUTH": "5", "LF_IMAPD": "10", "LF_POP3D": "10",
                   "LF_DISTSMTP": "5", "SMTP_BLOCK": "1", "PORTFLOOD": "25;tcp;20;300,587;tcp;20;300,993;tcp;30;300"},
    },
    "ssh_only": {
        "title": "SSH-only / private server",
        "blurb": "Nothing public but SSH. Very strict: few login attempts, port-scan detection, low connection ceiling.",
        "values": {"CT_LIMIT": "50", "CT_INTERVAL": "30", "CT_BLOCK_TIME": "3600", "LF_SSHD": "3", "LF_SSHD_PERM": "1",
                   "PS_LIMIT": "5", "PS_INTERVAL": "300", "PORTFLOOD": "22;tcp;5;300", "SYNFLOOD": "1", "SYNFLOOD_RATE": "100/s", "SYNFLOOD_BURST": "150"},
    },
    "under_attack": {
        "title": "Under attack right now",
        "blurb": "Temporary emergency settings: aggressive connection limits and SYN-flood protection. Switch back when it calms down.",
        "values": {"CT_LIMIT": "60", "CT_INTERVAL": "15", "CT_BLOCK_TIME": "7200", "SYNFLOOD": "1", "SYNFLOOD_RATE": "50/s", "SYNFLOOD_BURST": "80",
                   "PORTFLOOD": "22;tcp;3;300,80;tcp;60;5,443;tcp;60;5", "PS_LIMIT": "5", "LF_SSHD": "3"},
    },
}


def list_presets():
    current = csf.load_csf_conf()
    out = []
    for key, p in PRESETS.items():
        diff = {k: (current.get(k, ""), v) for k, v in p["values"].items() if str(current.get(k, "")) != v}
        out.append({"key": key, "title": p["title"], "blurb": p["blurb"], "values": p["values"], "changes": diff, "applied": not diff})
    return out


def apply(key):
    p = PRESETS.get(key)
    if not p:
        return {"success": False, "error": "Unknown preset"}
    current = csf.load_csf_conf()
    changes = [{"key": k, "old": current.get(k, ""), "new": v} for k, v in p["values"].items() if str(current.get(k, "")) != v]
    res = csf.save_csf_conf(p["values"])
    res["changes"] = changes
    return res
