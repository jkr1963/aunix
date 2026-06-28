#!/usr/bin/env bash
# AUNIX Agent — single run
# Used for manual testing or called by systemd service

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "Error: must be run as root (sudo ./run.sh)" >&2
  exit 1
fi

python3 "${SCRIPT_DIR}/aunix_scan.py" "$@"
