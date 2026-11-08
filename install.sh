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

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[x]${NC} $*"; exit 1; }
section() { echo -e "\n${CYAN}=== $* ===${NC}"; }

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
    cd "$INSTALL_DIR"
    git pull origin main
fi

cd "$INSTALL_DIR"

# ── Python environment ────────────────────────────────────────────────────────

section "Installing Python dependencies"
apt-get install -y --quiet python3-venv python3-pip
$PYTHON -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
info "Python environment ready."

# ── Directories ───────────────────────────────────────────────────────────────

mkdir -p "$CONF_DIR" "$SSL_DIR" "$SESSION_DIR"
chmod 700 "$CONF_DIR" "$SSL_DIR" "$SESSION_DIR"

# ── SSL certificate ───────────────────────────────────────────────────────────

section "SSL certificate"

CERT_FILE="$SSL_DIR/cert.pem"
KEY_FILE="$SSL_DIR/key.pem"

if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
    info "Existing SSL certificate found — skipping generation."
else
    # Check for Let's Encrypt cert
    DOMAIN=""
    if command -v certbot &>/dev/null; then
        read -r -p "Enter your domain name for Let's Encrypt (or press Enter to use a self-signed cert): " DOMAIN
    fi

    if [[ -n "$DOMAIN" ]]; then
        info "Requesting Let's Encrypt certificate for $DOMAIN..."
        apt-get install -y --quiet certbot
        certbot certonly --standalone --non-interactive --agree-tos \
            --register-unsafely-without-email -d "$DOMAIN" \
            --preferred-challenges http \
            || error "Let's Encrypt failed. Run certbot manually or use a self-signed cert."
        CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        info "Let's Encrypt certificate installed for $DOMAIN."
    else
        info "Generating self-signed SSL certificate (browser will show a warning)..."
        SERVER_IP=$(hostname -I | awk '{print $1}')
        openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
            -keyout "$KEY_FILE" -out "$CERT_FILE" \
            -subj "/CN=$SERVER_IP/O=CSFv2/C=US" \
            -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null
        chmod 600 "$KEY_FILE"
        info "Self-signed certificate generated."
        warn "To replace with a real certificate, run: certbot certonly --standalone -d your.domain.com"
        warn "Then update SSL_CERT/SSL_KEY in $CONF_DIR/csfv2.conf and restart: systemctl restart $SERVICE_NAME"
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
ExecStart=$INSTALL_DIR/venv/bin/gunicorn \\
    --bind \${HOST:-0.0.0.0}:\${PORT:-8750} \\
    --workers 2 \\
    --timeout 120 \\
    --keyfile \${SSL_KEY} \\
    --certfile \${SSL_CERT} \\
    --access-logfile /var/log/csfv2-access.log \\
    --error-logfile /var/log/csfv2-error.log \\
    app:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# HTTP→HTTPS redirect service (port 8080 → 8750)
cat > /etc/systemd/system/${SERVICE_NAME}-redirect.service <<EOF
[Unit]
Description=CSF-eUI HTTP redirect (8080 -> 8750)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $INSTALL_DIR/http_redirect.py
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
ExecStart=$INSTALL_DIR/venv/bin/python3 -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
from csf_backend import updater
info = updater.get_version_info(force=True)
if info.get('update_available'):
    print(f'CSF-eUI update available: {info[\"current\"]} -> {info[\"latest\"]}')
"
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
systemctl enable --now "${SERVICE_NAME}"
systemctl enable --now "${SERVICE_NAME}-redirect"
systemctl enable --now "${SERVICE_NAME}-update-check.timer"

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
echo ""
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  CSF-eUI installation complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  UI:         ${CYAN}https://$SERVER_IP:$PORT${NC}"
echo -e "  HTTP redir: http://$SERVER_IP:8080  →  https://$SERVER_IP:$PORT"
echo ""
echo -e "  Logs:       journalctl -u $SERVICE_NAME -f"
echo -e "  Restart:    systemctl restart $SERVICE_NAME"
echo ""
if [[ -z "${DOMAIN:-}" ]]; then
    echo -e "${YELLOW}  Note: Self-signed certificate — your browser will show a security warning.${NC}"
    echo -e "${YELLOW}  To get a trusted cert: certbot certonly --standalone -d your.domain.com${NC}"
    echo -e "${YELLOW}  Then update SSL_CERT/SSL_KEY in $CONF_DIR/csfv2.conf${NC}"
fi
echo ""
