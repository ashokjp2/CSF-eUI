"""Plain-English explanations for LFD trigger codes and block reasons."""
import re

CODES = {
    "LF_SSHD": "Tried the wrong SSH password too many times",
    "LF_FTPD": "Tried the wrong FTP password too many times",
    "LF_SMTPAUTH": "Tried the wrong email (SMTP) password too many times",
    "LF_POP3D": "Tried the wrong POP3 mailbox password too many times",
    "LF_IMAPD": "Tried the wrong IMAP mailbox password too many times",
    "LF_HTACCESS": "Tried the wrong web-page password too many times",
    "LF_MODSEC": "Triggered the web application firewall (ModSecurity) repeatedly",
    "LF_CPANEL": "Tried the wrong control-panel password too many times",
    "LF_WEBMIN": "Tried the wrong Webmin password too many times",
    "LF_DIRECTADMIN": "Tried the wrong DirectAdmin password too many times",
    "LF_BIND": "Hammered the DNS server",
    "LF_SUHOSIN": "Triggered PHP security (Suhosin) alerts",
    "LF_EXIMSYNTAX": "Sent malformed email commands repeatedly",
    "LF_APACHE_404": "Requested many missing web pages (scanning for vulnerabilities)",
    "LF_APACHE_403": "Hit many forbidden web pages (probing)",
    "LF_DISTATTACK": "Part of a distributed attack: many IPs trying the same account",
    "LF_DISTFTP": "Part of a distributed FTP attack",
    "LF_DISTSMTP": "Part of a distributed email attack",
    "LF_PERMBLOCK": "Was temporarily blocked so often it is now blocked permanently",
    "LF_NETBLOCK": "So many IPs from this network attacked that the whole range was blocked",
    "LF_CUSTOMTRIGGER": "Matched a custom log pattern you configured",
    "LF_LOOKUPS": "Blocked after a reputation lookup",
    "LF_EXPLOIT": "Exploit attempt detected",
    "PS_LIMIT": "Scanned many ports looking for something open",
    "CT_LIMIT": "Opened far too many connections at once (flood)",
    "CONNLIMIT": "Exceeded the per-port connection limit",
    "PORTFLOOD": "Hit one port too many times in a short burst",
    "SYNFLOOD": "Sent a flood of connection requests (SYN flood)",
    "UI": "Tried the wrong CSF UI password too many times",
    "LF_SSH_EMAIL_ALERT": "Logged in over SSH (alert, not a block)",
    "LF_SU_EMAIL_ALERT": "Switched to root with su (alert, not a block)",
    "BLOCKLIST": "Listed on a public blocklist you subscribe to",
    "CC_DENY": "Comes from a country you have blocked",
    "RBL": "Listed on a DNS blocklist",
    "LF_INTEGRITY": "System file changed (alert, not a block)",
    "LF_DIRWATCH": "A watched directory changed (alert, not a block)",
    "PT_LIMIT": "A process ran for too long (alert, not a block)",
}

_PATTERNS = [
    (re.compile(r"Failed SSH login|sshd", re.I), "LF_SSHD"),
    (re.compile(r"Port Scan|PS_LIMIT", re.I), "PS_LIMIT"),
    (re.compile(r"CT_LIMIT|Connection Tracking", re.I), "CT_LIMIT"),
    (re.compile(r"SYN flood", re.I), "SYNFLOOD"),
    (re.compile(r"distributed", re.I), "LF_DISTATTACK"),
    (re.compile(r"smtpauth|exim|postfix", re.I), "LF_SMTPAUTH"),
    (re.compile(r"ftp", re.I), "LF_FTPD"),
    (re.compile(r"imap|dovecot", re.I), "LF_IMAPD"),
    (re.compile(r"pop3", re.I), "LF_POP3D"),
    (re.compile(r"mod_security|modsec", re.I), "LF_MODSEC"),
    (re.compile(r"htpasswd|htaccess", re.I), "LF_HTACCESS"),
    (re.compile(r"blocklist", re.I), "BLOCKLIST"),
    (re.compile(r"PERMBLOCK|permanently", re.I), "LF_PERMBLOCK"),
    (re.compile(r"NETBLOCK", re.I), "LF_NETBLOCK"),
]


def code_of(text):
    """Find the LFD trigger code in a log line / reason string."""
    m = re.search(r"\[(LF_[A-Z0-9_]+|PS_LIMIT|CT_LIMIT|CONNLIMIT|PORTFLOOD|SYNFLOOD|UI|BLOCKLIST|CC_DENY|RBL)[^\]]*\]", text or "")
    if m:
        return m.group(1)
    for pat, code in _PATTERNS:
        if pat.search(text or ""):
            return code
    return ""


def explain(text):
    """Return (code, sentence) for a block reason or log line."""
    code = code_of(text)
    return code, CODES.get(code, "Blocked by a firewall rule" if text else "")
