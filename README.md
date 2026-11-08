# CSF-eUI

**A modern web UI for ConfigServer Security & Firewall (CSF/LFD)**

CSF-eUI replaces the old, dated CSF web interface with a clean, responsive dashboard that makes managing your Linux server firewall straightforward — even if you're not a command-line expert.

---

## What is CSF-eUI?

[ConfigServer Security & Firewall (CSF)](https://configserver.com/cp/csf.html) is one of the most widely used firewall solutions for Linux servers. It's powerful, but its built-in control panel is clunky and hard to navigate.

CSF-eUI is a self-hosted Flask application that gives you:
- A polished, mobile-friendly dashboard
- Real-time firewall status and event monitoring
- Safe, guided configuration editing (with validation and inline help)
- One-click actions for the most common tasks

---

## Features

### Dashboard & Monitoring
- **Live status banner** — instantly see if CSF is active, in test mode, or if LFD is down (with a prominent alert)
- **System stats** — CPU, memory, uptime, active connections, and blocked IP count in live tiles
- **Recent firewall events** — auto-refreshing LFD event feed with IP lookup links
- **GeoIP map** — visualise where attacks are coming from

### Configuration
- **Full csf.conf editor** — every setting editable from the browser, with:
  - Dropdown menus for fixed-option fields (no wrong values)
  - Country multi-select pickers (Select2) for all CC_ fields
  - Descriptive labels on 0/1 toggles (e.g. "Permanent block / Temp block")
  - Placeholder text showing expected format for every plain-text field
  - Inline field validation on blur — catches bad values before you save
  - Pre-save validation that blocks the form if any field is invalid
  - Inline warnings for dangerous combos (e.g. CC_ALLOW_PORTS set without CC_ALLOW_PORTS_TCP)
- **Quick Config** — guided forms for the most common settings (ports, country blocking, connection limits, DynDNS)
- **Configuration backup & restore**

### Firewall Management
- Quick Allow / Deny / Ignore / Unblock from the dashboard
- Temporary block/allow with timeout
- Permanent and temporary block lists with search and unblock
- Country block management
- IP lookup with geo and reputation data
- Port scanner
- Plain rules editor (csf.allow, csf.deny)

### Security Monitoring
- LFD block log with filtering
- Attack analytics with charts
- Firewall timeline
- Login history
- Process monitor
- Active connections viewer
- Bandwidth monitor
- Audit log of all actions taken in the UI

### System
- **SSL certificate management** — Let's Encrypt, ZeroSSL, self-signed, or upload your own
- **HTTP → HTTPS redirect** — port 8080 redirects to 8750 HTTPS (enabled by default)
- Security health score
- Email alert configuration
- Docker and WireGuard integration
- Cluster support
- Scheduled tasks
- Setup wizard for first-time configuration

### Updates
- Version badge in the sidebar footer
- Automatic version check every 12 hours (checks only, never auto-installs)
- In-app notification when a new release is available
- One-click update from the UI with a live streaming log

---

## Requirements

- **OS:** Debian 11+ or Ubuntu 20.04+ (amd64)
- **CSF/LFD:** must be [installed](https://configserver.com/cp/csf.html) before running the installer
- **Python:** 3.9+ (usually pre-installed on modern Ubuntu/Debian)
- **Root access** (CSF requires root to manage iptables)

The installer handles everything else: Python venv, WHOIS and DNS utilities, SSL certificate, systemd service, and firewall port.

---

## Installation

### Step 1 — Install CSF (skip if already installed)

```bash
cd /tmp
wget https://download.configserver.com/csf.tgz
tar -xzf csf.tgz && cd csf && sh install.sh
```

### Step 2 — Clone and install CSF-eUI

```bash
git clone https://github.com/ashokjp2/CSF-eUI.git /opt/csfv2
cd /opt/csfv2
bash install.sh
```

The installer will:

1. Install Python dependencies and the `whois`/`dnsutils` system utilities
2. Generate an SSL certificate (self-signed by default; prompts for a domain if `certbot` is detected)
3. Create `/etc/csfv2/csfv2.conf` with a random secret key and SSL paths
4. Prompt you to create an admin username and password
5. Install and start three systemd units:
   - `csfv2` — the main app on port **8750** (HTTPS)
   - `csfv2-redirect` — HTTP→HTTPS redirect on port **8080**
   - `csfv2-update-check.timer` — version check every 12 h (checks only, never auto-installs)
6. Add port 8750 to CSF's `TCP_IN` and reload the firewall

### Step 3 — Open the UI

```
https://your-server-ip:8750
```

If you used a self-signed certificate, your browser will show a security warning — click through it. To get a trusted certificate, use the **SSL** page inside the UI or run:

```bash
certbot certonly --standalone -d your.domain.com
# then update SSL_CERT/SSL_KEY in /etc/csfv2/csfv2.conf and restart
systemctl restart csfv2
```

---

## Upgrading

**From the UI:** go to **System → Updates** and click **Update now**.

**From the command line:**

```bash
cd /opt/csfv2
git pull origin main
venv/bin/pip install -q -r requirements.txt
systemctl restart csfv2
```

---

## Configuration

All CSF-eUI settings live in `/etc/csfv2/` (created by the installer). CSF's own rules stay in `/etc/csf/` and are never modified directly by the UI.

| Path | Purpose |
|---|---|
| `/etc/csfv2/csfv2.conf` | App config: port, SSL paths, secret key, SMTP |
| `/etc/csfv2/auth.json` | UI login credentials (PBKDF2-hashed) |
| `/etc/csfv2/ssl/` | Self-signed certificate (if no domain cert) |
| `/opt/csfv2/` | Application code |

### SMTP for email alerts

By default, CSF-eUI sends alert emails via the system `mail` command. To use a dedicated SMTP account (Gmail, Mailgun, etc.) instead, go to **Email Alerts → SMTP Configuration** in the UI and fill in your SMTP settings. Credentials are stored in `/etc/csfv2/csfv2.conf`.

### Ports

| Port | Purpose |
|---|---|
| `8750/tcp` | CSF-eUI HTTPS — open this in your firewall |
| `8080/tcp` | HTTP→HTTPS redirect (optional, redirects to 8750) |

---

## Managing the service

```bash
systemctl status csfv2         # check status
systemctl restart csfv2        # restart after a config change
systemctl stop csfv2           # stop
journalctl -u csfv2 -f         # follow live logs
```

> **Note on the service file:** `/etc/systemd/system/csfv2.service` is created by `install.sh` and lives only on the server — it is not tracked in git. App code updates (`git pull`) do not touch it. If a future release changes gunicorn arguments, the release notes will say so and you can update it with:
> ```bash
> cd /opt/csfv2 && bash install.sh   # safe to re-run; skips existing config and certs
> ```

---

## Security notes

- CSF-eUI runs as root (required to manage iptables and restart CSF). Keep the port (8750) restricted — use `CC_ALLOW_PORTS` to allow only your country, or restrict access via csf.allow.
- Use a Let's Encrypt certificate (available in the SSL page) to avoid browser warnings.
- Enable two-factor authentication in Settings.

---

## License

MIT — see [LICENSE](LICENSE).
