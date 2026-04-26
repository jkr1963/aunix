#!/usr/bin/env bash
#
# AUNIX agent entry point.
#
# Usage:
#   sudo ./run.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "$SCRIPT_DIR/config.json" ]; then
  echo "Error: config.json not found alongside run.sh"
  echo "       Did you extract the full tarball?"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "This scan needs root to read SSH keys in /etc/ssh, /root/.ssh, etc."
  echo "Re-running with sudo..."
  exec sudo "$0" "$@"
fi

PYTHON_BIN=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PYTHON_BIN="$candidate"
    break
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  echo "Error: Python 3 is required but not found in PATH."
  exit 1
fi

if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "Warning: ssh-keygen not found. Install OpenSSH client tools for accurate"
  echo "         fingerprints. Continuing anyway..."
fi

echo "==========================================="
echo "AUNIX SSH key scanner"
echo "Working directory: $SCRIPT_DIR"
echo "Using Python: $(command -v "$PYTHON_BIN")"
echo "==========================================="

"$PYTHON_BIN" "$SCRIPT_DIR/aunix_scan.py" --config "$SCRIPT_DIR/config.json" "$@"
