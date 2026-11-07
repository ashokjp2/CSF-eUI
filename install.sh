#!/usr/bin/env bash
# CSF-eUI installer
set -euo pipefail

INSTALL_DIR="/opt/csfv2"
SERVICE_NAME="csfv2"
PORT=8750
PYTHON="${PYTHON:-python3}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

info "CSF-eUI installer starting..."

# --- Python venv + deps ---
info "Creating Python virtual environment..."
$PYTHON -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
info "Dependencies installed."

# --- Config directory ---
mkdir -p /etc/csfv2
if [[ ! -f /etc/csfv2/secret_key ]]; then
    $PYTHON -c "import secrets; print(secrets.token_hex(48))" > /etc/csfv2/secret_key
    chmod 600 /etc/csfv2/secret_key
    info "Secret key generated at /etc/csfv2/secret_key"
fi

# --- Git remote (for future updates) ---
if ! git -C "$INSTALL_DIR" remote get-url origin &>/dev/null; then
    git -C "$INSTALL_DIR" remote add origin https://github.com/ashokjp2/CSF-eUI.git 2>/dev/null || true
fi

# --- systemd service ---
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=CSF-eUI - ConfigServer Security & Firewall Web UI
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
Environment=CSFV2_SECRET_KEY_FILE=/etc/csfv2/secret_key
ExecStartPre=/bin/bash -c 'export CSFV2_SECRET_KEY=\$(cat /etc/csfv2/secret_key)'
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn \\
    --bind 0.0.0.0:${PORT} \\
    --workers 2 \\
    --timeout 120 \\
    --access-logfile /var/log/csfv2-access.log \\
    --error-logfile /var/log/csfv2-error.log \\
    app:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# --- systemd update-check timer (checks GitHub every 12 h, never auto-installs) ---
cat > /etc/systemd/system/csfv2-update-check.service <<'EOF'
[Unit]
Description=CSF-eUI version check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -c "
import sys; sys.path.insert(0, '/opt/csfv2')
from csf_backend import updater
info = updater.get_version_info(force=True)
if info['update_available']:
    print(f'CSF-eUI update available: {info[\"current\"]} -> {info[\"latest\"]}')
"
EOF

cat > /etc/systemd/system/csfv2-update-check.timer <<EOF
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
systemctl enable --now ${SERVICE_NAME}
systemctl enable --now csfv2-update-check.timer

info "Service ${SERVICE_NAME} started on port ${PORT}."
info "Update-check timer enabled (runs every 12 h)."
echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo "  UI:      https://$(hostname -I | awk '{print $1}'):${PORT}"
echo "  Logs:    journalctl -u ${SERVICE_NAME} -f"
echo "  Restart: systemctl restart ${SERVICE_NAME}"
