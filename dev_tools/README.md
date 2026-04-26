# Dev Tools — Demo Key Generator

These scripts populate your machine with a varied set of SSH keys so the
AUNIX dashboard has interesting data to display.

**Use these in development only.** They create real SSH keys; treat them
the same way you'd treat any cryptographic material.

## What's here

- `generate_demo_keys.sh` — creates ~13 keys across multiple algorithms,
  permissions, ages, and locations under `~/.aunix_demo/`. None of them
  ever touch your real `~/.ssh/`.
- `cleanup_demo_keys.sh` — removes everything the generator created.
  Refuses to operate on anything outside an `aunix_demo` directory.

## Quick usage

From the project root:

```bash
cd dev_tools
chmod +x generate_demo_keys.sh cleanup_demo_keys.sh   # one-time
./generate_demo_keys.sh
```

Then run the AUNIX scanner from wherever you extracted the agent:

```bash
cd ~/Downloads/aunix-agent-1
sudo ./run.sh
```

Refresh the dashboard. You should see roughly:

- **5 CRITICAL** findings (weak crypto, loose perms)
- **3 HIGH** findings (stale, misplaced, orphan private)
- **2 MEDIUM** findings (aging, public-side misplacement)
- **10 INFO** entries (modern keys + the orphan public)

## What gets generated

| Key | Location | Algo | Perms | Age | Expected severity |
|---|---|---|---|---|---|
| id_ed25519 | `.aunix_demo/.ssh/` | ED25519 | 600 | new | info |
| id_rsa_4096 | `.aunix_demo/.ssh/` | RSA-4096 | 600 | new | info |
| id_ecdsa | `.aunix_demo/.ssh/` | ECDSA-521 | 600 | new | info |
| id_rsa_1024 | `.aunix_demo/.ssh/` | RSA-1024 | 600 | new | **CRITICAL** (weak algo) |
| id_dsa | `.aunix_demo/.ssh/` | DSA-1024 | 600 | new | **CRITICAL** (deprecated)\* |
| id_rsa_loose | `.aunix_demo/.ssh/` | RSA-2048 | 644 | new | **CRITICAL** (loose perms) |
| id_ed25519_stale | `.aunix_demo/.ssh/` | ED25519 | 600 | 400d | **HIGH** (stale) |
| id_ed25519_aging | `.aunix_demo/.ssh/` | ED25519 | 600 | 100d | **MEDIUM** (aging) |
| leaked_backup_key | `.aunix_demo/Documents/` | RSA-2048 | 600 | new | **HIGH** (non-standard location) |
| orphan_authorized_key.pub | `.aunix_demo/.ssh/` | ED25519 (.pub only) | 644 | new | info |
| id_rsa_lonely | `.aunix_demo/.ssh/` | RSA-2048 (private only) | 600 | new | **HIGH** (private_only) |

\*The DSA row may not appear if your build of `ssh-keygen` refuses to create
DSA keys (modern OpenSSH builds increasingly do). The script handles this
gracefully — it skips that one and continues.

## How to verify the demo dir won't conflict

```bash
ls -la ~/.aunix_demo 2>/dev/null && echo "exists — clean first" || echo "not present, safe to generate"
```

## Custom location

Both scripts honor `AUNIX_DEMO_DIR`:

```bash
AUNIX_DEMO_DIR=/tmp/my-aunix-test ./generate_demo_keys.sh
AUNIX_DEMO_DIR=/tmp/my-aunix-test ./cleanup_demo_keys.sh
```

The cleanup script refuses to operate on a path that doesn't have
`aunix_demo` or `aunix-demo` somewhere in it, so even with a typo'd
env var it won't blow away `/etc` or your home.
