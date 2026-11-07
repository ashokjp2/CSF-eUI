SETTING_HELP = {
    "TESTING": {
        "plain": "Safety mode that clears firewall rules every 5 minutes. Turn this OFF once you're sure you won't lock yourself out.",
        "risk": "high",
        "tip": "Always test your SSH access works before disabling this.",
    },
    "TCP_IN": {
        "plain": "Ports that can receive incoming TCP connections from the internet. Only open what your services actually need.",
        "risk": "high",
        "tip": "Common: 22 (SSH), 80 (HTTP), 443 (HTTPS). Use Quick Config for easier editing.",
    },
    "TCP_OUT": {
        "plain": "Ports your server can connect to on other servers. Needed for updates, DNS, sending email, etc.",
        "risk": "medium",
        "tip": "Keep 53 (DNS), 80 (HTTP), 443 (HTTPS) at minimum for system updates.",
    },
    "UDP_IN": {
        "plain": "UDP ports that can receive incoming traffic. Usually only DNS (53) and VPN (e.g. 51820 for WireGuard).",
        "risk": "medium",
    },
    "UDP_OUT": {
        "plain": "UDP ports your server can send to. DNS (53) and NTP (123) are essential.",
        "risk": "low",
    },
    "TCP6_IN": {
        "plain": "Same as TCP_IN but for IPv6 traffic. Usually mirrors TCP_IN.",
        "risk": "high",
    },
    "TCP6_OUT": {
        "plain": "Same as TCP_OUT but for IPv6 traffic. Usually mirrors TCP_OUT.",
        "risk": "medium",
    },
    "UDP6_IN": {
        "plain": "Same as UDP_IN but for IPv6 traffic.",
        "risk": "medium",
    },
    "UDP6_OUT": {
        "plain": "Same as UDP_OUT but for IPv6 traffic.",
        "risk": "low",
    },
    "SYSLOG_CHECK": {
        "plain": "How often (in seconds) LFD checks the system logs for suspicious activity.",
        "risk": "low",
    },
    "LF_SSHD": {
        "plain": "Block an IP after this many failed SSH login attempts. Set to 0 to disable (not recommended).",
        "risk": "high",
        "tip": "Recommended: 5. Lower = stricter, but may block legitimate users who mistype passwords.",
    },
    "LF_SSHD_PERM": {
        "plain": "How long to block IPs that fail SSH logins. 1=permanent, 0=use LF_TRIGGER timer.",
        "risk": "medium",
    },
    "LF_FTPD": {
        "plain": "Block an IP after this many failed FTP login attempts. Set to 0 to disable.",
        "risk": "medium",
    },
    "LF_SMTPAUTH": {
        "plain": "Block an IP after this many failed SMTP authentication attempts.",
        "risk": "medium",
    },
    "LF_POP3D": {
        "plain": "Block an IP after this many failed POP3 login attempts.",
        "risk": "medium",
    },
    "LF_IMAPD": {
        "plain": "Block an IP after this many failed IMAP login attempts.",
        "risk": "medium",
    },
    "LF_HTACCESS": {
        "plain": "Block an IP after this many failed .htaccess password attempts (Apache).",
        "risk": "medium",
    },
    "LF_MODSEC": {
        "plain": "Block an IP after this many ModSecurity rule triggers.",
        "risk": "medium",
    },
    "LF_TRIGGER": {
        "plain": "Default block duration in seconds for temporary blocks. 0 = permanent block.",
        "risk": "medium",
        "tip": "3600 = 1 hour, 86400 = 1 day. Start with temporary blocks until you trust the rules.",
    },
    "LF_PERMBLOCK": {
        "plain": "Permanently block IPs that get temporarily blocked this many times. Catches repeat offenders.",
        "risk": "medium",
        "tip": "Recommended: 1 (enable). Keeps persistent attackers from coming back.",
    },
    "LF_PERMBLOCK_COUNT": {
        "plain": "Number of temporary blocks before an IP gets permanently blocked.",
        "risk": "low",
    },
    "LF_PERMBLOCK_INTERVAL": {
        "plain": "Time window (seconds) in which temporary blocks must occur to trigger a permanent block.",
        "risk": "low",
    },
    "LF_NETBLOCK": {
        "plain": "Block entire IP ranges (/24 networks) that have too many individual blocked IPs.",
        "risk": "medium",
        "tip": "Be careful — this blocks 256 IPs at once and could affect legitimate users.",
    },
    "LF_ALERT_TO": {
        "plain": "Email address to receive alerts when IPs are blocked. Leave empty to disable email alerts.",
        "risk": "low",
        "tip": "Set this to stay informed about attacks on your server.",
    },
    "LF_ALERT_FROM": {
        "plain": "Sender email address for firewall alert emails.",
        "risk": "low",
    },
    "CT_LIMIT": {
        "plain": "Maximum number of connections from a single IP. Blocks IPs exceeding this. 0 = disabled.",
        "risk": "medium",
        "tip": "Recommended: 300. Protects against DDoS and connection flooding.",
    },
    "CT_INTERVAL": {
        "plain": "How often (seconds) to check connection counts.",
        "risk": "low",
    },
    "CT_PORTS": {
        "plain": "Only count connections on these ports for connection tracking. Empty = all ports.",
        "risk": "low",
    },
    "PS_LIMIT": {
        "plain": "Block IPs that connect to this many different ports within PS_INTERVAL. Detects port scanners.",
        "risk": "medium",
        "tip": "Recommended: 10. Catches attackers probing for open services.",
    },
    "PS_INTERVAL": {
        "plain": "Time window (seconds) for port scan detection.",
        "risk": "low",
    },
    "PORTFLOOD": {
        "plain": "Rate-limit connections per port. Format: port;protocol;hits;interval. Blocks flood attacks.",
        "risk": "medium",
        "tip": "Example: '80;tcp;20;5' = max 20 connections to port 80 in 5 seconds per IP.",
    },
    "SYNFLOOD": {
        "plain": "Enable SYN flood protection. Helps against a common DDoS attack type.",
        "risk": "medium",
    },
    "SYNFLOOD_RATE": {
        "plain": "Maximum SYN packets per second before triggering flood protection.",
        "risk": "low",
    },
    "SYNFLOOD_BURST": {
        "plain": "Maximum SYN packet burst before triggering flood protection.",
        "risk": "low",
    },
    "CONNLIMIT": {
        "plain": "Limit concurrent connections per IP on specific ports. Format: port;limit.",
        "risk": "medium",
        "tip": "Example: '22;3' = max 3 simultaneous SSH connections per IP.",
    },
    "CC_DENY": {
        "plain": "Block ALL traffic from these countries (comma-separated 2-letter codes like CN,RU).",
        "risk": "high",
        "tip": "Use Quick Config > Country Block for a friendlier interface.",
    },
    "CC_ALLOW": {
        "plain": "If set, ONLY these countries can connect. Everything else is blocked. Very restrictive!",
        "risk": "high",
        "tip": "Be very careful — this blocks everyone not in the list, including you if your country isn't listed.",
    },
    "CC_ALLOW_FILTER": {
        "plain": "Countries that bypass CC_DENY but still respect your TCP_IN port rules. Safer than CC_ALLOW (which bypasses all port rules).",
        "risk": "medium",
        "tip": "Use this to whitelist countries without opening all ports to them. E.g. IN,US,UK,SG",
    },
    "CC_ALLOW_PORTS": {
        "plain": "COUNTRY CODES (not ports!) allowed to access the closed ports in CC_ALLOW_PORTS_TCP/UDP. The ports must be REMOVED from TCP_IN first — this opens otherwise-closed ports only for these countries.",
        "risk": "high",
        "tip": "Workflow: remove the port from TCP_IN → add country codes here → add port numbers to CC_ALLOW_PORTS_TCP or CC_ALLOW_PORTS_UDP.",
    },
    "CC_DENY_PORTS": {
        "plain": "COUNTRY CODES (not ports!) to block on the specific ports in CC_DENY_PORTS_TCP/UDP. The ports stay open in TCP_IN for everyone else.",
        "risk": "medium",
        "tip": "Workflow: keep the port in TCP_IN → add country codes here → add port numbers to CC_DENY_PORTS_TCP or CC_DENY_PORTS_UDP.",
    },
    "DOCKER": {
        "plain": "Enable Docker compatibility mode. MUST be ON if you run Docker containers, or CSF will break container networking.",
        "risk": "high",
        "tip": "If docker is installed, turn this ON immediately.",
    },
    "RESTRICT_SYSLOG": {
        "plain": "Restrict syslog/rsyslog access to prevent log spoofing attacks. 0=off, 3=strict.",
        "risk": "medium",
        "tip": "Recommended: 3 (strict). Prevents attackers from injecting fake log entries.",
    },
    "IPV6": {
        "plain": "Enable IPv6 firewall rules. Turn ON if your server has IPv6 addresses.",
        "risk": "medium",
        "tip": "If your server has IPv6, leaving this OFF means IPv6 traffic is completely unfiltered!",
    },
    "LF_DIRWATCH": {
        "plain": "Monitor specific directories for changes. Alerts you to unauthorized file modifications.",
        "risk": "low",
    },
    "LF_INTEGRITY": {
        "plain": "Check system binary integrity periodically (seconds). Detects rootkits and trojan replacements.",
        "risk": "low",
    },
    "PT_LIMIT": {
        "plain": "Process tracking: alert on processes using more than this amount of memory (MB).",
        "risk": "low",
    },
    "CLUSTER_SENDTO": {
        "plain": "IP addresses of other servers in your CSF cluster. They share allow/deny lists automatically.",
        "risk": "low",
    },
    "CLUSTER_RECVFROM": {
        "plain": "IP addresses of cluster members you accept updates from.",
        "risk": "low",
    },
}


def get_help(setting):
    return SETTING_HELP.get(setting)


def get_all_help():
    return SETTING_HELP
