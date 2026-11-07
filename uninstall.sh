#!/bin/bash
set -e

echo "========================================="
echo "  CSFv2 - Uninstaller"
echo "========================================="

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Must be run as root."
    exit 1
fi

echo "This will remove CSFv2 (the GUI only, not CSF itself)."
read -p "Continue? (y/N): " CONFIRM
if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    exit 0
fi

echo "Stopping service..."
systemctl stop csfv2.service 2>/dev/null || true
systemctl disable csfv2.service 2>/dev/null || true
rm -f /etc/systemd/system/csfv2.service
systemctl daemon-reload

echo "Removing application files..."
rm -rf /opt/csfv2

read -p "Remove configuration and data? (y/N): " RMDATA
if [ "$RMDATA" = "y" ] || [ "$RMDATA" = "Y" ]; then
    rm -rf /etc/csfv2
    rm -rf /var/lib/csfv2
    rm -f /var/log/csfv2.log
    rm -f /var/log/csfv2-access.log
    rm -f /var/log/csfv2-error.log
fi

echo "CSFv2 has been removed."
