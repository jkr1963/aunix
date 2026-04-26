AUNIX Agent
===========

This package scans the local machine for SSH keys and uploads the
results to your AUNIX dashboard.

Requirements:
  - Linux or macOS
  - Python 3.7+
  - OpenSSH client tools (for `ssh-keygen`)
  - sudo access

Usage:
  sudo ./run.sh

That's it. The scanner will:
  1. Walk known SSH key locations (/etc/ssh, /root/.ssh, /home/*/.ssh)
  2. Compute SHA256 fingerprints with ssh-keygen
  3. Upload the inventory to the dashboard

To preview the scan without uploading:
  sudo ./run.sh --no-upload

To save a copy of the upload payload locally:
  sudo ./run.sh --output /tmp/scan_payload.json

Files in this package:
  run.sh         - entry point
  aunix_scan.py  - the scanner
  config.json    - your target ID, agent token, and API URL
  README.txt     - this file

The agent token in config.json is what authenticates this scanner to
your dashboard. Treat it like a password - if it leaks, anyone can
upload fake scan data for this target. To revoke it, download a fresh
agent package from the dashboard (the old token is invalidated).
