#!/bin/bash
# Deploy CSFv2 to remote server
# Usage: bash deploy.sh

set -e

SERVER="66.96.83.33"
HOSTNAME="fw.app.ajhome.in"
SSH_KEY="$HOME/Documents/Mobile & Home Tech/SSDNodes/keys for ssh/openssh_key"
REMOTE_USER="root"
REMOTE_DIR="/tmp/csfv2-deploy"

echo "========================================="
echo "  CSFv2 - Deploy to $HOSTNAME"
echo "  Server: $SERVER"
echo "========================================="
echo ""

# Verify SSH key exists
if [ ! -f "$SSH_KEY" ]; then
    echo "ERROR: SSH key not found: $SSH_KEY"
    exit 1
fi

# Check known ports on the server before deploying
echo "Checking for port conflicts on $SERVER..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "$REMOTE_USER@$SERVER" '
    echo "== Active listeners =="
    ss -tlnp 2>/dev/null | head -30
    echo ""
    echo "== Common services =="
    echo -n "Dokploy:     "; (ss -tlnp | grep -oP ":\K(3000|443|80) " || echo "not detected")
    echo -n "WireGuard:   "; (ss -ulnp | grep -oP ":\K51820 " || echo "not detected")
    echo -n "WG-UI:       "; (ss -tlnp | grep -oP ":\K(5000|51821) " || echo "not detected")
    echo -n "Port 8750:   "; (ss -tlnp | grep ":8750 " >/dev/null && echo "IN USE" || echo "available")
'

echo ""
read -p "Continue with deployment? (y/N): " PROCEED
if [ "$PROCEED" != "y" ] && [ "$PROCEED" != "Y" ]; then
    echo "Aborted."
    exit 0
fi

# Upload files
echo ""
echo "Uploading CSFv2 files..."
ssh -i "$SSH_KEY" "$REMOTE_USER@$SERVER" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"

scp -i "$SSH_KEY" -r \
    app.py \
    requirements.txt \
    install.sh \
    uninstall.sh \
    csf_backend \
    templates \
    static \
    "$REMOTE_USER@$SERVER:$REMOTE_DIR/"

# Run installer
echo ""
echo "Running installer on $SERVER..."
ssh -i "$SSH_KEY" -t "$REMOTE_USER@$SERVER" "cd $REMOTE_DIR && bash install.sh"

echo ""
echo "========================================="
echo "  Deployment complete!"
echo "========================================="
echo ""
echo "  Access CSFv2 at:"
echo "    https://$HOSTNAME:8750"
echo "    https://$SERVER:8750"
echo ""
echo "  Default login: admin / admin"
echo "  Change the password immediately!"
echo ""
