#!/usr/bin/env bash
#
# AUNIX dev helper: remove the demo SSH keys created by generate_demo_keys.sh.
#
# Refuses to touch anything outside the demo directory, even if you set
# AUNIX_DEMO_DIR to something risky.

set -euo pipefail

DEMO_DIR="${AUNIX_DEMO_DIR:-$HOME/.aunix_demo}"

# Hard refuse a few obviously unsafe targets.
case "$DEMO_DIR" in
  "" | "/" | "$HOME" | "$HOME/" | "$HOME/.ssh" | "$HOME/.ssh/")
    echo "Refusing to delete: $DEMO_DIR (looks like a real directory)."
    exit 1
    ;;
esac

if [ ! -d "$DEMO_DIR" ]; then
  echo "Nothing to clean — $DEMO_DIR doesn't exist."
  exit 0
fi

# Only proceed if the directory's name looks like ours.
case "$DEMO_DIR" in
  *aunix_demo* | *aunix-demo* )
    : ;;  # OK
  *)
    echo "Refusing: $DEMO_DIR doesn't have 'aunix_demo' or 'aunix-demo' in its path."
    echo "If this really is the demo dir, rename it to ~/.aunix_demo and try again."
    exit 1
    ;;
esac

echo "About to remove: $DEMO_DIR"
echo "Contents:"
find "$DEMO_DIR" -type f 2>/dev/null | sed 's/^/  /'
echo

read -r -p "Proceed? [y/N] " ans
case "$ans" in
  [yY] | [yY][eE][sS]) ;;
  *) echo "Aborted."; exit 0 ;;
esac

rm -rf "$DEMO_DIR"
echo "Removed $DEMO_DIR"
echo
echo "The keys are gone from disk, but they're still in the AUNIX dashboard"
echo "until you re-run the scanner. Re-scan to refresh:"
echo "  cd ~/Downloads/aunix-agent-1"
echo "  sudo ./run.sh"
