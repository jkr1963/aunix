#!/usr/bin/env bash
#
# AUNIX dev helper: generate a mix of SSH keys for testing the dashboard.
#
# Creates ~13 keys across multiple algorithms, sizes, locations, and ages
# so every chart and finding type has something to display.
#
# Safe by default: refuses to run if it would touch your real ~/.ssh keys.
# All generated keys live in $AUNIX_DEMO_DIR (default: ~/.aunix_demo).
#
# Usage:
#   ./generate_demo_keys.sh           # create demo keys
#   ./generate_demo_keys.sh --clean   # remove demo keys (calls cleanup_demo_keys.sh)
#
# After running, run the AUNIX scanner with:
#   sudo ./run.sh
# All demo keys live under your home directory, so a non-root scan would
# also find them — but we run with sudo to match how a real audit works.

set -euo pipefail

DEMO_DIR="${AUNIX_DEMO_DIR:-$HOME/.aunix_demo}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "${1:-}" = "--clean" ]; then
  exec "$SCRIPT_DIR/cleanup_demo_keys.sh"
fi

# --- Sanity checks ---

if [ -d "$DEMO_DIR" ]; then
  echo "Demo directory already exists: $DEMO_DIR"
  echo "Run with --clean first if you want a fresh set."
  exit 1
fi

if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "Error: ssh-keygen not found. Install OpenSSH client tools."
  exit 1
fi

echo "================================================"
echo "AUNIX demo key generator"
echo "Creating keys in: $DEMO_DIR"
echo "================================================"
echo

mkdir -p "$DEMO_DIR"

# Helper: silent ssh-keygen, no passphrase, no comment prompts.
gen() {
  local algo="$1"; local bits="$2"; local out="$3"; local comment="$4"
  if [ -z "$bits" ]; then
    ssh-keygen -t "$algo" -f "$out" -N "" -C "$comment" -q
  else
    ssh-keygen -t "$algo" -b "$bits" -f "$out" -N "" -C "$comment" -q
  fi
}

# Helper: backdate file timestamps to simulate old keys.
# $1 = path, $2 = days ago for both mtime and atime
backdate() {
  local path="$1"
  local days="$2"
  # Cross-platform date math: BSD date (macOS) vs GNU date (Linux).
  local stamp
  if date -v-1d >/dev/null 2>&1; then
    # BSD date (macOS)
    stamp=$(date -v-"${days}d" +%Y%m%d%H%M)
  else
    # GNU date
    stamp=$(date -d "${days} days ago" +%Y%m%d%H%M)
  fi
  touch -t "$stamp" "$path"
}

# ============================================================
# 1. STRONG, MODERN, CLEAN — the "good citizens"
# ============================================================
echo "[1/8] Modern ED25519 key in standard location, recent..."
mkdir -p "$DEMO_DIR/.ssh"
chmod 700 "$DEMO_DIR/.ssh"
gen ed25519 "" "$DEMO_DIR/.ssh/id_ed25519" "demo-modern@aunix"
chmod 600 "$DEMO_DIR/.ssh/id_ed25519"
chmod 644 "$DEMO_DIR/.ssh/id_ed25519.pub"

# ============================================================
# 2. STRONG RSA — also fine
# ============================================================
echo "[2/8] RSA-4096 key, properly stored..."
gen rsa 4096 "$DEMO_DIR/.ssh/id_rsa_4096" "demo-rsa4096@aunix"
chmod 600 "$DEMO_DIR/.ssh/id_rsa_4096"
chmod 644 "$DEMO_DIR/.ssh/id_rsa_4096.pub"

# ============================================================
# 3. ECDSA 521 — modern and strong
# ============================================================
echo "[3/8] ECDSA-521 key..."
gen ecdsa 521 "$DEMO_DIR/.ssh/id_ecdsa" "demo-ecdsa@aunix"
chmod 600 "$DEMO_DIR/.ssh/id_ecdsa"
chmod 644 "$DEMO_DIR/.ssh/id_ecdsa.pub"

# ============================================================
# 4. WEAK CRYPTO — RSA-1024 (CRITICAL finding)
# ============================================================
echo "[4/8] RSA-1024 (intentionally weak — should flag CRITICAL)..."
gen rsa 1024 "$DEMO_DIR/.ssh/id_rsa_1024" "demo-rsa1024-WEAK@aunix"
chmod 600 "$DEMO_DIR/.ssh/id_rsa_1024"
chmod 644 "$DEMO_DIR/.ssh/id_rsa_1024.pub"

# ============================================================
# 5. DEPRECATED ALGO — DSA (CRITICAL finding)
#    Some newer ssh-keygen builds refuse to make DSA. Try, fall back.
# ============================================================
echo "[5/8] DSA-1024 (deprecated — should flag CRITICAL)..."
if gen dsa 1024 "$DEMO_DIR/.ssh/id_dsa" "demo-dsa-DEPRECATED@aunix" 2>/dev/null; then
  chmod 600 "$DEMO_DIR/.ssh/id_dsa"
  chmod 644 "$DEMO_DIR/.ssh/id_dsa.pub"
else
  echo "       (your ssh-keygen refused to make DSA — skipping; that's fine)"
fi

# ============================================================
# 6. WEAK PERMISSIONS — RSA-2048 with world-readable private key (CRITICAL)
# ============================================================
echo "[6/8] RSA-2048 with permissions 644 (CRITICAL: should be 600)..."
gen rsa 2048 "$DEMO_DIR/.ssh/id_rsa_loose" "demo-loose-perms@aunix"
chmod 644 "$DEMO_DIR/.ssh/id_rsa_loose"   # Wrong on purpose
chmod 644 "$DEMO_DIR/.ssh/id_rsa_loose.pub"

# ============================================================
# 7. STALE KEY — modern algo, but not "accessed" in over a year (HIGH)
# ============================================================
echo "[7/8] Old ED25519 not accessed for 400 days (HIGH: stale)..."
gen ed25519 "" "$DEMO_DIR/.ssh/id_ed25519_stale" "demo-stale@aunix"
chmod 600 "$DEMO_DIR/.ssh/id_ed25519_stale"
chmod 644 "$DEMO_DIR/.ssh/id_ed25519_stale.pub"
backdate "$DEMO_DIR/.ssh/id_ed25519_stale" 400
backdate "$DEMO_DIR/.ssh/id_ed25519_stale.pub" 400

# Aging key — 100 days ago (MEDIUM)
echo "       Plus another ED25519 last accessed 100 days ago (MEDIUM)..."
gen ed25519 "" "$DEMO_DIR/.ssh/id_ed25519_aging" "demo-aging@aunix"
chmod 600 "$DEMO_DIR/.ssh/id_ed25519_aging"
chmod 644 "$DEMO_DIR/.ssh/id_ed25519_aging.pub"
backdate "$DEMO_DIR/.ssh/id_ed25519_aging" 100
backdate "$DEMO_DIR/.ssh/id_ed25519_aging.pub" 100

# ============================================================
# 8. NON-STANDARD LOCATION — key outside ~/.ssh (HIGH for private)
# ============================================================
echo "[8/8] Private key in a non-standard location (HIGH: wrong location)..."
mkdir -p "$DEMO_DIR/Documents"
gen rsa 2048 "$DEMO_DIR/Documents/leaked_backup_key" "demo-misplaced@aunix"
chmod 600 "$DEMO_DIR/Documents/leaked_backup_key"
chmod 644 "$DEMO_DIR/Documents/leaked_backup_key.pub"

# Orphan public key — public_only pairing status
echo "       Plus an orphan public key (no matching private)..."
gen ed25519 "" "$DEMO_DIR/.ssh/id_ed25519_orphan_src" "demo-orphan@aunix"
mv "$DEMO_DIR/.ssh/id_ed25519_orphan_src.pub" "$DEMO_DIR/.ssh/orphan_authorized_key.pub"
rm "$DEMO_DIR/.ssh/id_ed25519_orphan_src"   # delete the private half
chmod 644 "$DEMO_DIR/.ssh/orphan_authorized_key.pub"

# Orphan private key — private_only pairing status
echo "       Plus an orphan private key (no matching public)..."
gen rsa 2048 "$DEMO_DIR/.ssh/id_rsa_lonely" "demo-lonely@aunix"
rm "$DEMO_DIR/.ssh/id_rsa_lonely.pub"
chmod 600 "$DEMO_DIR/.ssh/id_rsa_lonely"

# ============================================================
# Summary
# ============================================================
echo
echo "================================================"
echo "Done."
echo
echo "Generated files:"
find "$DEMO_DIR" -type f | sort | sed 's/^/  /'
echo
echo "Counts:"
echo "  Private keys: $(find "$DEMO_DIR" -type f ! -name '*.pub' | wc -l | tr -d ' ')"
echo "  Public keys:  $(find "$DEMO_DIR" -type f -name '*.pub' | wc -l | tr -d ' ')"
echo
echo "Expected dashboard findings:"
echo "  CRITICAL:"
echo "    - RSA-1024 (private + public)        weak algorithm"
echo "    - DSA-1024 (if generated)            deprecated algorithm"
echo "    - RSA-2048 with 644 perms            loose permissions"
echo "  HIGH:"
echo "    - Stale ED25519 (~400d)              not used in 6+ months"
echo "    - Private key in ~/Documents/        non-standard location"
echo "    - Orphan private key                 private_only pair status"
echo "  MEDIUM:"
echo "    - Aging ED25519 (~100d)              not used in 3+ months"
echo "    - Public key in Documents            non-standard location"
echo "  INFO:"
echo "    - Several modern, clean keys"
echo
echo "Next: re-run the scanner so it picks these up."
echo "  cd ~/Downloads/aunix-agent-1   # or wherever you extracted it"
echo "  sudo ./run.sh"
echo
echo "When done testing, clean up with:"
echo "  $SCRIPT_DIR/cleanup_demo_keys.sh"
echo "================================================"
