#!/usr/bin/env bash
# AUNIX Agent Installer for Ubuntu/Linux
# Usage: sudo ./install.sh
# The agent will scan every 2 minutes and send results to your dashboard

set -euo pipefail

# ── Checks ───────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  echo "Error: run this installer as root: sudo ./install.sh" >&2
  exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Error: this installer is for Linux only."
  echo "On macOS, test manually with: sudo python3 aunix_scan.py"
  exit 1
fi

if ! command -v systemctl &>/dev/null; then
  echo "Error: systemd not found."
  echo "Run the agent manually instead: sudo python3 aunix_scan.py"
  exit 1
fi

if [[ ! -f config.json ]]; then
  echo "Error: config.json not found." >&2
  echo "Download your agent package from the AUNIX dashboard first." >&2
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo "Python3 not found. Installing..."
  apt-get update -qq && apt-get install -y python3 python3-pip
fi

# ── Install files ─────────────────────────────────────────────────────────────

INSTALL_DIR="/opt/aunix"
echo ""
echo "Installing AUNIX agent to ${INSTALL_DIR}..."

mkdir -p "${INSTALL_DIR}"
cp aunix_scan.py "${INSTALL_DIR}/"
cp config.json   "${INSTALL_DIR}/"
cp run.sh        "${INSTALL_DIR}/"
chmod +x "${INSTALL_DIR}/run.sh"

# Install Python dependencies if requirements.txt exists
if [[ -f requirements.txt ]]; then
  echo "Installing Python dependencies..."
  pip3 install -q -r requirements.txt
fi

# ── systemd service ───────────────────────────────────────────────────────────

cat > /etc/systemd/system/aunix-agent.service << EOF
[Unit]
Description=AUNIX SSH Key Audit Agent
After=network.target
Documentation=https://github.com/jkr1963/aunix

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/aunix_scan.py
WorkingDirectory=${INSTALL_DIR}
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# ── systemd timer (every 2 minutes for testing) ───────────────────────────────

cat > /etc/systemd/system/aunix-agent.timer << EOF
[Unit]
Description=AUNIX agent — run every 2 minutes
Requires=aunix-agent.service

[Timer]
OnBootSec=30sec
OnUnitActiveSec=2min
Unit=aunix-agent.service
AccuracySec=10sec

[Install]
WantedBy=timers.target
EOF

# ── Enable and start ──────────────────────────────────────────────────────────

systemctl daemon-reload
systemctl enable aunix-agent.timer
systemctl start aunix-agent.timer

# Run once immediately so user sees results right away
echo ""
echo "Running initial scan..."
python3 "${INSTALL_DIR}/aunix_scan.py" && echo "✓ Initial scan complete" || echo "⚠ Initial scan failed — check logs"

echo ""
echo "✓ AUNIX agent installed successfully"
echo ""
echo "  Scan interval : every 2 minutes"
echo "  Install dir   : ${INSTALL_DIR}"
echo ""
echo "  Useful commands:"
echo "  Check timer status : systemctl status aunix-agent.timer"
echo "  View live logs     : journalctl -u aunix-agent -f"
echo "  Run scan now       : systemctl start aunix-agent.service"
echo "  Stop agent         : systemctl disable aunix-agent.timer && systemctl stop aunix-agent.timer"
echo "  Uninstall          : systemctl disable aunix-agent.timer && rm -rf ${INSTALL_DIR} && rm /etc/systemd/system/aunix-agent.*"
echo ""
