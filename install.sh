#!/usr/bin/env bash
# CSF-eUI installer for Debian/Ubuntu
# Usage: bash install.sh
set -euo pipefail

INSTALL_DIR="/opt/csfv2"
CONF_DIR="/etc/csfv2"
SSL_DIR="/etc/csfv2/ssl"
SESSION_DIR="/var/lib/csfv2/sessions"
SERVICE_NAME="csfv2"
PORT=8750
PYTHON="${PYTHON:-python3}"
LOG_FILE="/var/log/csfv2-install.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[x]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}=== $* ===${NC}"; }

# Tee all output (stdout + stderr) to install log
exec > >(tee -a "$LOG_FILE") 2>&1
echo "=== CSF-eUI install started at $(date) ==="

# ── Preflight ────────────────────────────────────────────────────────────────

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

section "Checking requirements"

# Python 3.9+
$PYTHON -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" \
    || error "Python 3.9+ required. Install with: apt-get install python3"

# CSF must already be installed
[[ -x /usr/sbin/csf ]] || error "CSF is not installed. Install it first:
  cd /tmp && wget https://download.configserver.com/csf.tgz
  tar -xzf csf.tgz && cd csf && sh install.sh"

info "Requirements met."

# ── App directory ─────────────────────────────────────────────────────────────

section "Setting up application"

if [[ ! -f "$INSTALL_DIR/app.py" ]]; then
    info "Cloning CSF-eUI to $INSTALL_DIR..."
    apt-get install -y --quiet git
    git clone https://github.com/ashokjp2/CSF-eUI.git "$INSTALL_DIR"
else
    info "Using existing installation at $INSTALL_DIR"
    info "Keeping existing application files; continuing with dependency and service setup."
fi

cd "$INSTALL_DIR"

# ── Python environment ────────────────────────────────────────────────────────

section "Installing application dependencies"
apt-get install -y --quiet python3-venv python3-pip whois dnsutils curl wget perl perl6 libwww-perl ipset sendmail unzip
$PYTHON -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
info "Python environment ready."

# Ubuntu 26.04 ships postfix-mta-sts-resolver 1.5.0 with a Python 3.14
# incompatibility: it calls asyncio.get_event_loop() before creating a loop.
# Keep the distro package, but launch it through a small compatibility wrapper
# so the service remains functional on both old and new Ubuntu releases.
if command -v mta-sts-daemon >/dev/null 2>&1; then
    MTA_STS_WRAPPER="/usr/local/sbin/csfv2-mta-sts-daemon"
    cat > "$MTA_STS_WRAPPER" <<'PY'
#!/usr/bin/python3
import asyncio
import runpy

_get_event_loop = asyncio.get_event_loop


def _get_event_loop_compat():
    try:
        return _get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


asyncio.get_event_loop = _get_event_loop_compat
runpy.run_path("/usr/bin/mta-sts-daemon", run_name="__main__")
PY
    chmod 755 "$MTA_STS_WRAPPER"
    mkdir -p /etc/systemd/system/postfix-mta-sts-resolver.service.d
    cat > /etc/systemd/system/postfix-mta-sts-resolver.service.d/csfv2-compat.conf <<EOF
[Service]
ExecStart=
ExecStart=$MTA_STS_WRAPPER --config /etc/mta-sts-daemon.yml
EOF
    systemctl daemon-reload
    if systemctl is-active --quiet postfix-mta-sts-resolver.service; then
        systemctl try-restart postfix-mta-sts-resolver.service || \
            warn "Could not restart postfix-mta-sts-resolver after applying the Python compatibility wrapper."
    fi
    info "Applied MTA-STS Python event-loop compatibility wrapper."
fi

# ── CSF-eUI LFD defaults and supported-service exemptions ────────────────────

section "Configuring LFD for supported services"

# CSF's stock 1800-second user-process runtime threshold flags normal daemons
# such as rsyslogd and systemd-networkd. Preserve explicit custom values, but
# remove the known noisy stock default on new/stock CSF configurations.
if grep -qE '^PT_USERTIME[[:space:]]*=[[:space:]]*"?1800"?[[:space:]]*$' /etc/csf/csf.conf 2>/dev/null; then
    sed -i 's/^PT_USERTIME[[:space:]]*=.*/PT_USERTIME = "0"/' /etc/csf/csf.conf
    info "Disabled the noisy stock PT_USERTIME=1800 process-alert default."
fi

# Keep this list in the application so install-time and UI auto-fix behavior
# cannot drift apart as Docker/WireGuard/NetBird support grows.
"$INSTALL_DIR/venv/bin/python3" -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
from csf_backend.service_integration import apply_supported_process_ignores
result = apply_supported_process_ignores()
print(result.get('message', 'Supported-service process exemptions applied.'))
" || warn "Could not apply supported-service process exemptions; use Quick Config > Services to retry."

# ── Directories ───────────────────────────────────────────────────────────────

mkdir -p "$CONF_DIR" "$SSL_DIR" "$SESSION_DIR"
chmod 700 "$CONF_DIR" "$SSL_DIR" "$SESSION_DIR"

# ── SSL certificate ───────────────────────────────────────────────────────────

section "SSL certificate"

CERT_FILE="$SSL_DIR/cert.pem"
KEY_FILE="$SSL_DIR/key.pem"
DOMAIN=""

# 1. Check if csfv2.conf already points to valid cert files
if [[ -f "$CONF_DIR/csfv2.conf" ]]; then
    _conf_cert=$(grep -E '^SSL_CERT=' "$CONF_DIR/csfv2.conf" | head -1 | cut -d= -f2- | tr -d '"')
    _conf_key=$(grep -E '^SSL_KEY=' "$CONF_DIR/csfv2.conf" | head -1 | cut -d= -f2- | tr -d '"')
    if [[ -f "$_conf_cert" && -f "$_conf_key" ]]; then
        CERT_FILE="$_conf_cert"
        KEY_FILE="$_conf_key"
        info "SSL already configured in csfv2.conf and cert files exist — skipping."
        info "  CERT: $CERT_FILE"
        info "  KEY:  $KEY_FILE"
    fi
fi

if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
    # 2. Auto-detect existing Let's Encrypt certs on this server
    LE_DOMAINS=()
    if [[ -d /etc/letsencrypt/live ]]; then
        while IFS= read -r -d '' d; do
            dom=$(basename "$d")
            [[ -f "$d/fullchain.pem" && -f "$d/privkey.pem" ]] && LE_DOMAINS+=("$dom")
        done < <(find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
    fi

    if [[ ${#LE_DOMAINS[@]} -gt 0 ]]; then
        echo ""
        echo "  Existing Let's Encrypt certificates found on this server:"
        for i in "${!LE_DOMAINS[@]}"; do
            echo "    [$((i+1))] ${LE_DOMAINS[$i]}"
        done
        echo "    [n] Request a new Let's Encrypt certificate for a different domain"
        echo "    [s] Generate a self-signed certificate"
        echo "    [x] Skip — I will configure SSL manually"
        echo ""
        read -r -p "  Choose [1-${#LE_DOMAINS[@]}/n/s/x]: " SSL_CHOICE

        if [[ "$SSL_CHOICE" =~ ^[0-9]+$ ]] && (( SSL_CHOICE >= 1 && SSL_CHOICE <= ${#LE_DOMAINS[@]} )); then
            DOMAIN="${LE_DOMAINS[$((SSL_CHOICE-1))]}"
            CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
            KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
            info "Using existing Let's Encrypt certificate for $DOMAIN."
        elif [[ "${SSL_CHOICE,,}" == "n" ]]; then
            SSL_CHOICE="new_le"
        elif [[ "${SSL_CHOICE,,}" == "s" ]]; then
            SSL_CHOICE="self"
        elif [[ "${SSL_CHOICE,,}" == "x" ]]; then
            SSL_CHOICE="skip"
        else
            warn "Invalid choice — defaulting to self-signed."
            SSL_CHOICE="self"
        fi
    else
        echo ""
        echo "  No existing certificates detected. How would you like to handle SSL?"
        echo "    [1] Request a Let's Encrypt certificate (needs a domain pointing to this server)"
        echo "    [2] Generate a self-signed certificate (browser will show a warning)"
        echo "    [3] Skip — I will configure SSL manually"
        echo ""
        read -r -p "  Choose [1/2/3]: " SSL_CHOICE
        case "$SSL_CHOICE" in
            1) SSL_CHOICE="new_le" ;;
            3) SSL_CHOICE="skip" ;;
            *) SSL_CHOICE="self" ;;
        esac
    fi

    # Handle new LE request
    if [[ "${SSL_CHOICE}" == "new_le" ]]; then
        read -r -p "  Enter your domain name: " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            warn "No domain entered — falling back to self-signed."
            SSL_CHOICE="self"
        else
            info "Requesting Let's Encrypt certificate for $DOMAIN..."
            apt-get install -y --quiet certbot
            certbot certonly --standalone --non-interactive --agree-tos \
                --register-unsafely-without-email -d "$DOMAIN" \
                --preferred-challenges http \
                || error "Let's Encrypt failed. Run certbot manually or use a self-signed cert."
            CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
            KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
            info "Let's Encrypt certificate installed for $DOMAIN."
        fi
    fi

    if [[ "${SSL_CHOICE}" == "self" ]]; then
        info "Generating self-signed SSL certificate (browser will show a warning)..."
        SERVER_IP=$(hostname -I | awk '{print $1}')
        openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
            -keyout "$KEY_FILE" -out "$CERT_FILE" \
            -subj "/CN=$SERVER_IP/O=CSFv2/C=US" \
            -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null
        chmod 600 "$KEY_FILE"
        info "Self-signed certificate generated."
        warn "To replace later: certbot certonly --standalone -d your.domain.com"
        warn "Then update SSL_CERT/SSL_KEY in $CONF_DIR/csfv2.conf and restart: systemctl restart $SERVICE_NAME"
    fi

    if [[ "${SSL_CHOICE}" == "skip" ]]; then
        warn "SSL setup skipped. You must set SSL_CERT and SSL_KEY in $CONF_DIR/csfv2.conf before the service will start."
        CERT_FILE="<path-to-cert.pem>"
        KEY_FILE="<path-to-key.pem>"
    fi
fi

# ── App config ────────────────────────────────────────────────────────────────

section "Creating app configuration"

if [[ ! -f "$CONF_DIR/csfv2.conf" ]]; then
    SECRET_KEY=$($PYTHON -c "import secrets; print(secrets.token_hex(32))")
    cat > "$CONF_DIR/csfv2.conf" <<EOF
# CSFv2 Configuration
HOST=0.0.0.0
PORT=$PORT
SSL=1
SSL_CERT="$CERT_FILE"
SSL_KEY="$KEY_FILE"
SECRET_KEY=$SECRET_KEY
DEBUG=0
EOF
    chmod 600 "$CONF_DIR/csfv2.conf"
    info "Configuration written to $CONF_DIR/csfv2.conf"
else
    info "Config already exists at $CONF_DIR/csfv2.conf — skipping."
fi

# ── Admin user ────────────────────────────────────────────────────────────────

section "Admin account"

AUTH_FILE="$CONF_DIR/auth.json"
if [[ -f "$AUTH_FILE" ]]; then
    info "Auth file already exists — skipping user creation."
else
    echo ""
    echo "Create the admin login for CSF-eUI."
    read -r -p "  Username [admin]: " ADMIN_USER
    ADMIN_USER="${ADMIN_USER:-admin}"

    while true; do
        read -r -s -p "  Password: " ADMIN_PASS; echo
        read -r -s -p "  Confirm password: " ADMIN_PASS2; echo
        [[ "$ADMIN_PASS" == "$ADMIN_PASS2" ]] && break
        warn "Passwords do not match, try again."
    done

    "$INSTALL_DIR/venv/bin/python3" -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
from csf_backend.auth import create_user
create_user('$ADMIN_USER', '$ADMIN_PASS')
print('User created.')
"
    info "Admin user '$ADMIN_USER' created."
fi

# ── systemd service ───────────────────────────────────────────────────────────

section "Installing systemd service"

cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=CSF-eUI - ConfigServer Security & Firewall Web UI
After=network.target csf.service lfd.service
Wants=csf.service lfd.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONF_DIR/csfv2.conf
ExecStart=$INSTALL_DIR/venv/bin/gunicorn \
    --bind \${HOST}:\${PORT} \
    --workers 2 \
    --timeout 120 \
    --keyfile \${SSL_KEY} \
    --certfile \${SSL_CERT} \
    --access-logfile /var/log/csfv2-access.log \
    --error-logfile /var/log/csfv2-error.log \
    app:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Version-check timer (checks GitHub every 12 h, never auto-installs)
cat > /etc/systemd/system/${SERVICE_NAME}-update-check.service <<EOF
[Unit]
Description=CSF-eUI version check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/csf_backend/_version_check_runner.py
EOF

cat > /etc/systemd/system/${SERVICE_NAME}-update-check.timer <<EOF
[Unit]
Description=CSF-eUI update check every 12 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}" || true
systemctl disable --now "${SERVICE_NAME}-redirect" >/dev/null 2>&1 || true
if systemctl enable --now "${SERVICE_NAME}-update-check.timer"; then
    if systemctl is-active --quiet "${SERVICE_NAME}-update-check.timer"; then
        info "Update-check timer is active."
    else
        warn "Update-check timer was enabled but is not active. Check: systemctl status ${SERVICE_NAME}-update-check.timer"
    fi
else
    warn "Could not enable the update-check timer. Check: systemctl status ${SERVICE_NAME}-update-check.timer"
fi

# Give gunicorn a moment to bind, then check
sleep 2
SERVICE_OK=0
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    info "Service ${SERVICE_NAME} is running."
    SERVICE_OK=1
else
    echo -e "\n${RED}[x] Service ${SERVICE_NAME} failed to start. Last journal entries:${NC}"
    journalctl -u "${SERVICE_NAME}" -n 40 --no-pager
    echo -e "\n${YELLOW}[!] Fix the error above, then run: systemctl restart ${SERVICE_NAME}${NC}"
    echo -e "${YELLOW}[!] Full install log saved to: $LOG_FILE${NC}\n"
fi

# ── CSF firewall: open port 8750 ──────────────────────────────────────────────

section "Opening firewall port"

if grep -q "^TCP_IN" /etc/csf/csf.conf 2>/dev/null; then
    if ! grep "^TCP_IN" /etc/csf/csf.conf | grep -q "$PORT"; then
        sed -i "s/^TCP_IN = \"\(.*\)\"/TCP_IN = \"\1,$PORT\"/" /etc/csf/csf.conf
        csf -r
        info "Port $PORT added to CSF TCP_IN and firewall reloaded."
    else
        info "Port $PORT already in CSF TCP_IN."
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────

SERVER_IP=$(hostname -I | awk '{print $1}')
DISPLAY_HOST="${DOMAIN:-$SERVER_IP}"

echo ""
if [[ $SERVICE_OK -eq 1 ]]; then
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  CSF-eUI installation complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════${NC}"
else
    echo -e "${YELLOW}════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  CSF-eUI installed — but service did not start${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════${NC}"
fi
echo ""
echo -e "  UI:         ${CYAN}https://$DISPLAY_HOST:$PORT${NC}"
echo ""
echo -e "  Service:    systemctl status $SERVICE_NAME"
echo -e "  Logs:       journalctl -u $SERVICE_NAME -f"
echo -e "  Restart:    systemctl restart $SERVICE_NAME"
echo -e "  Install log: $LOG_FILE"
echo ""
if [[ -z "${DOMAIN:-}" ]]; then
    echo -e "${YELLOW}  Note: Self-signed certificate — your browser will show a security warning.${NC}"
    echo -e "${YELLOW}  To get a trusted cert: certbot certonly --standalone -d your.domain.com${NC}"
    echo -e "${YELLOW}  Then update SSL_CERT/SSL_KEY in $CONF_DIR/csfv2.conf${NC}"
fi
echo "=== CSF-eUI install finished at $(date) ===" >> "$LOG_FILE"
echo ""
