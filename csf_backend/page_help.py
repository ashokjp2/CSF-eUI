"""In-context help shown in the side drawer (the '?' on panel headings and the topbar)."""

README = "https://download.configserver.com/csf/readme.txt"

HELP = {
    "/": {"title": "Dashboard", "body": [
        "The banner at the top tells you whether the firewall and attack detection (LFD) are running. Green is good.",
        "The IP action box is the quickest way to allow, block or look up an address. Use Temp block for a nuisance you want gone for a few hours.",
        "Blocked IPs counts addresses currently in the deny list; the small text under it counts blocks LFD made in the last 24 hours.",
        "If a bar appears saying \"Unapplied firewall changes\", click Apply safely: it restarts the firewall and undoes the change by itself if you lose access."],
        "readme": "#SECTION:1"},
    "/qconfig": {"title": "Quick Config", "body": [
        "Ports: only ports listed in TCP_IN can receive connections. Add the port an app listens on; remove ports you no longer use.",
        "Country block: deny or allow whole countries. Blocking everything except your own country is a strong, simple protection for a private server.",
        "Connection limits: how many connections one address may open. The presets at the top set sensible values for common setups.",
        "Changes are written to csf.conf and need a restart to take effect; the bar at the top of the page offers a safe restart."],
        "readme": "#SECTION:2"},
    "/config": {"title": "Configuration", "body": [
        "This is every CSF setting. Each row shows what the setting does in plain words, a safe value, and how risky it is to change.",
        "Tick \"Show only settings changed from CSF defaults\" to see what makes this server different.",
        "Saving shows you a review of exactly what will change first. Recent changes can be reverted one by one."],
        "readme": "#SECTION:3"},
    "/ip-lists": {"title": "Allow / Deny lists", "body": [
        "csf.allow is your whitelist: addresses that are never blocked. Put your own office or home IP here.",
        "csf.deny is your blacklist: addresses that can never connect.",
        "Tick several rows and use the bulk bar to allow, block or unblock many at once. An entry like 1.2.3.0/24 covers 256 addresses."],
        "readme": "#SECTION:5"},
    "/temp": {"title": "Temporary blocks", "body": [
        "Addresses LFD blocked for a limited time after an attack. They are released automatically when the timer runs out.",
        "If a real user got caught (wrong password a few times), remove the block here or add them to csf.allow."],
        "readme": "#SECTION:4"},
    "/countries": {"title": "Country blocks", "body": [
        "Uses two-letter country codes (GB, IN, US…). CC_DENY blocks a country completely; CC_ALLOW lets a country through even if everything else is blocked.",
        "Country data comes from a GeoIP database; keep MM_LICENSE_KEY set so it stays up to date."],
        "readme": "#SECTION:7"},
    "/logs": {"title": "Log viewer", "body": [
        "lfd.log is the attack-detection diary: every block, and why. Search for an IP to see what it did.",
        "Smart view groups the raw lines into readable events; Raw shows the file as is."]},
    "/analytics": {"title": "Attack analytics", "body": [
        "Counts attack attempts (failed logins, scans, floods) from all logs, not just blocks. Use it to spot where attacks come from.",
        "Suggested blocks groups attackers by network (/24) and provider (ASN) so you can shut a whole source down in one click."]},
    "/health": {"title": "Health check", "body": [
        "A score from 0 to 100 built from checks on your firewall, SSH, Docker, accounts, this panel and the system. Items are weighted: a public database or a Docker socket mount costs far more than a cosmetic warning.",
        "Each check with a Fix button applies the recommended value through safe apply. If a finding is intentional (say, FTP really is needed), use Accept and give a reason: it stays visible but stops counting against the score.",
        "New or worsened findings since the last run are marked, so a fresh red item stands out."]},
    "/docker": {"title": "Docker", "body": [
        "Docker opens ports on its own, bypassing the firewall's normal rules. The Exposure tab shows which container ports the internet can reach, and Restrict closes them to the outside while keeping them reachable from other containers."],
        "readme": "#SECTION:27"},
    "/notifications": {"title": "Notifications", "body": [
        "Get a Telegram, Slack, Discord or webhook message when something happens. Blocks are grouped so you are not flooded.",
        "The weekly digest summarises blocks, changes, open ports and certificate status in one message."]},
    "/servers": {"title": "Servers", "body": [
        "Add other servers running CSF-eUI to watch them all here and push an allow or block to every one at once.",
        "Each remote server needs an API token created on that server under Settings → API tokens."]},
    "/settings": {"title": "Settings", "body": [
        "Turn on two-factor authentication: the UI controls your firewall, so a password alone is not enough.",
        "Viewer accounts can look but not change. API tokens let scripts talk to the firewall without a login."]},
    "/backup-restore": {"title": "Backups", "body": [
        "A backup is an archive of every CSF configuration file. Take one before big changes; restore puts the files back (then restart the firewall).",
        "Off-server copies can be sent by SFTP, WebDAV or rclone so a lost server does not mean a lost configuration."]},
    "/scheduled-rules": {"title": "Scheduled rules", "body": [
        "Allow or deny an address only between two dates — for a contractor, a migration, or a maintenance window. The rule is added at the start time and removed at the end automatically."]},
    "/blocklist-feeds": {"title": "Blocklist feeds", "body": [
        "Public lists of known-bad addresses that CSF downloads on a schedule. Enable the well-known free ones; the table shows whether each feed is actually being fetched and how many addresses it contributes."],
        "readme": "#SECTION:7"},
    "/tasks": {"title": "Guided tasks", "body": [
        "Each task walks you through a common job in two or three steps and ends with a safe apply, so a mistake cannot lock you out."]},
    "/activity": {"title": "Activity", "body": [
        "One chronological list of everything that changed: UI actions, configuration edits, safe-apply events and notifications. Export it as CSV for records."]},
}


def get(path):
    """Best match for a request path (exact, then longest prefix)."""
    if path in HELP:
        h = dict(HELP[path])
    else:
        best = ""
        for key in HELP:
            if key != "/" and path.startswith(key) and len(key) > len(best):
                best = key
        if not best:
            return {"title": "Help", "body": ["No page-specific help yet. The CSF readme covers every setting in depth."], "readme": README}
        h = dict(HELP[best])
    h["readme"] = README + (h.get("readme") or "")
    return h
