#!/usr/bin/env bash
# AUNIX Agent Uninstaller
# Usage: sudo ./uninstall.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Error: run as root: sudo ./uninstall.sh" >&2
  exit 1
fi

echo "Uninstalling AUNIX agent..."

systemctl stop aunix-agent.timer 2>/dev/null || true
systemctl stop aunix-agent.service 2>/dev/null || true
systemctl disable aunix-agent.timer 2>/dev/null || true

rm -f /etc/systemd/system/aunix-agent.service
rm -f /etc/systemd/system/aunix-agent.timer
systemctl daemon-reload

rm -rf /opt/aunix

echo "✓ AUNIX agent removed"
