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
- **HTTP → HTTPS redirect** — one click to enable via nginx
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

- Linux server (Debian/Ubuntu or RHEL/CentOS based)
- [CSF/LFD](https://configserver.com/cp/csf.html) already installed
- Python 3.9+
- nginx (recommended, for HTTPS and HTTP redirect)
- Root or sudo access

---

## Installation

### 1. Install CSF (if not already installed)

```bash
cd /tmp && wget https://download.configserver.com/csf.tgz
tar -xzf csf.tgz && cd csf && sh install.sh
```

### 2. Clone CSF-eUI

```bash
git clone https://github.com/ashokjp2/CSF-eUI.git /opt/csfv2
cd /opt/csfv2
```

### 3. Run the installer

```bash
bash install.sh
```

The installer will:
- Create a Python virtual environment
- Install dependencies
- Generate a random secret key
- Create and enable the systemd service on port **8750**
- Set up the automatic update-check timer (every 12 h)

### 4. Open the UI

Navigate to `https://your-server-ip:8750` in your browser.

Default login is configured during the first run — the installer prints the credentials.

---

## Upgrading

**From the UI:** go to **System → Updates** and click **Update**.

**From the command line:**

```bash
cd /opt/csfv2
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
systemctl restart csfv2
```

---

## Configuration

The application stores its own settings in `/etc/csfv2/` (created by the installer). CSF's firewall rules remain in `/etc/csf/` and are never touched by the UI directly.

| Path | Purpose |
|---|---|
| `/etc/csfv2/secret_key` | Flask session secret |
| `/etc/csfv2/users.json` | UI login credentials |
| `/etc/csfv2/https_redirect` | Enables nginx HTTP redirect (managed via UI) |
| `/opt/csfv2/` | Application code |

---

## Running as a systemd service

The installer creates `/etc/systemd/system/csfv2.service`. To manage it:

```bash
systemctl status csfv2      # check status
systemctl restart csfv2     # restart
systemctl stop csfv2        # stop
journalctl -u csfv2 -f      # follow logs
```

---

## Security notes

- CSF-eUI runs as root (required to manage iptables and restart CSF). Keep the port (8750) restricted — use `CC_ALLOW_PORTS` to allow only your country, or restrict access via csf.allow.
- Use a Let's Encrypt certificate (available in the SSL page) to avoid browser warnings.
- Enable two-factor authentication in Settings.

---

## License

MIT — see [LICENSE](LICENSE).
