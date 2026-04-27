#!/usr/bin/env python3
"""
AUNIX scanner agent.

Scans the local machine for SSH keys, pairs public/private by fingerprint,
and uploads results to the AUNIX backend.

Reads config from ./config.json next to this script:
    {
        "target_id": <int>,
        "agent_token": "<opaque>",
        "api_url": "https://.../api"
    }
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import pwd
import shutil
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

# --- Where to look ---

KNOWN_DIRS = [
    Path("/etc/ssh"),
    Path("/root/.ssh"),
]

SKIP_PREFIXES = (
    "/proc", "/sys", "/dev", "/run", "/snap", "/tmp",
    "/var/lib/docker", "/var/lib/containerd",
    # macOS user-data folders that won't have SSH keys but are huge:
    "/Users/Shared",
    "/System", "/Library", "/Applications",
)

# Per-user dirs we want to skip inside any home (Linux or Mac).
# We match against path *components* anywhere in the path.
SKIP_HOME_COMPONENTS = {
    "Library", "Pictures", "Music", "Movies", "Photos",
    "Caches", ".cache", "node_modules", ".git",
    ".npm", ".gem", ".cargo", ".rustup", ".m2",
    "Trash", ".Trash",
}

COMMON_PRIVATE_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity"}
COMMON_PUBLIC_NAMES = {"authorized_keys", "known_hosts"}


# --- Helpers ---

def iso_time(epoch: float) -> Optional[str]:
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except Exception:
        return None


def owner_name(file_path: Path) -> Optional[str]:
    try:
        return pwd.getpwuid(file_path.stat().st_uid).pw_name
    except Exception:
        return None


def permission_octal(file_path: Path) -> Optional[str]:
    try:
        return oct(file_path.stat().st_mode & 0o777)[2:]
    except Exception:
        return None


def file_type_label(file_path: Path) -> str:
    """Best-effort file type. Uses `file` if available, else falls back."""
    try:
        result = subprocess.run(
            ["file", "-b", str(file_path)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    name = file_path.name
    if name.endswith(".pub"):
        return "OpenSSH public key"
    return "ASCII text"


def detect_username(path: Path) -> Optional[str]:
    parts = path.parts
    if len(parts) >= 3 and parts[1] == "home":
        return parts[2]
    if len(parts) >= 2 and parts[1] == "root":
        return "root"
    return owner_name(path)


# --- Fingerprinting (uses ssh-keygen, not file hashing) ---

def _has_ssh_keygen() -> bool:
    return shutil.which("ssh-keygen") is not None


def _parse_keygen_lf(stdout: str) -> Optional[dict]:
    """Parse `ssh-keygen -lf` output.

    Format: "<bits> SHA256:<fp> <comment...> (<algo>)"
    Returns {fingerprint, algorithm, bits} or None.
    """
    parts = stdout.split()
    if len(parts) < 2 or not parts[1].startswith("SHA256:"):
        return None

    bits = None
    try:
        bits = int(parts[0])
    except (ValueError, IndexError):
        pass

    algorithm = None
    if stdout.rstrip().endswith(")"):
        end = stdout.rstrip().rfind("(")
        if end != -1:
            algorithm = stdout.rstrip()[end + 1:-1]

    return {"fingerprint": parts[1], "algorithm": algorithm, "bits": bits}


def fingerprint_public(file_path: Path) -> Optional[dict]:
    """Run `ssh-keygen -lf <pub>` and return {fingerprint, algorithm, bits}."""
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", str(file_path)],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return _parse_keygen_lf(result.stdout)
    except Exception:
        pass
    return None


def fingerprint_private(file_path: Path) -> Optional[dict]:
    """Derive public key from private, then fingerprint it.

    Special case: if ssh-keygen refuses due to overly-open permissions,
    we still want to surface this key in the audit — that's exactly the
    thing we want to flag. Return a path-derived placeholder fingerprint
    and let the classifier catch the permissions issue downstream.
    """
    try:
        derive = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(file_path)],
            capture_output=True, text=True, timeout=5
        )
        if derive.returncode == 0 and derive.stdout.strip():
            fp = subprocess.run(
                ["ssh-keygen", "-lf", "-"],
                input=derive.stdout,
                capture_output=True, text=True, timeout=5
            )
            if fp.returncode == 0:
                return _parse_keygen_lf(fp.stdout)

        # ssh-keygen refused. If the reason is permissions, we still want to
        # record the key — that's an auditable finding. Detect that case.
        stderr = (derive.stderr or "").lower()
        if "bad permissions" in stderr or "are too open" in stderr:
            import hashlib
            digest = hashlib.sha256(str(file_path).encode("utf-8")).hexdigest()[:32]
            return {
                "fingerprint": f"unreadable-perms:{digest}",
                "algorithm": None,
                "bits": None,
            }
    except Exception:
        pass
    return None


# --- Classification ---

def looks_like_private_key(file_path: Path) -> bool:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(200)
        return "PRIVATE KEY" in head
    except Exception:
        return False


def looks_like_public_key(file_path: Path) -> bool:
    if file_path.suffix == ".pub":
        return True
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.readline().strip()
        return head.startswith(("ssh-rsa", "ssh-ed25519", "ssh-dss", "ecdsa-"))
    except Exception:
        return False


KEY_EXTENSIONS = {".pem", ".key", ".priv", ".rsa", ".dsa", ".ecdsa", ".ed25519"}


def is_candidate(file_path: Path) -> bool:
    if not file_path.is_file():
        return False
    name = file_path.name
    if name in COMMON_PRIVATE_NAMES or name in COMMON_PUBLIC_NAMES:
        return True
    if name.endswith(".pub"):
        return True
    if file_path.suffix.lower() in KEY_EXTENSIONS:
        return looks_like_private_key(file_path) or looks_like_public_key(file_path)
    if "ssh" in str(file_path).lower() or name.startswith("id_"):
        return looks_like_private_key(file_path) or looks_like_public_key(file_path)
    # Last-resort content sniff for small files with no extension at all,
    # since SSH keys often have no extension. We bound this so we don't
    # read every file in $HOME.
    if not file_path.suffix:
        try:
            if file_path.stat().st_size <= 16 * 1024:
                return looks_like_private_key(file_path) or looks_like_public_key(file_path)
        except (OSError, PermissionError):
            return False
    return False


# --- Walking ---

def collect_dirs() -> list[Path]:
    dirs: list[Path] = []
    for d in KNOWN_DIRS:
        if d.is_dir():
            dirs.append(d)

    home_root = Path("/home")
    if home_root.is_dir():
        try:
            for child in home_root.iterdir():
                ssh_dir = child / ".ssh"
                if ssh_dir.is_dir():
                    dirs.append(ssh_dir)
                # Also include home itself shallowly so misplaced keys get found
                if child.is_dir():
                    dirs.append(child)
        except PermissionError:
            pass

    # macOS: user homes live under /Users, not /home
    users_root = Path("/Users")
    if users_root.is_dir():
        try:
            for child in users_root.iterdir():
                if child.name in ("Shared", "Guest"):
                    continue
                ssh_dir = child / ".ssh"
                if ssh_dir.is_dir():
                    dirs.append(ssh_dir)
                if child.is_dir():
                    dirs.append(child)
        except PermissionError:
            pass

    # Always include the invoking user's home and ~/.ssh as a final safety net
    user_ssh = Path.home() / ".ssh"
    if user_ssh.is_dir():
        dirs.append(user_ssh)
    if Path.home().is_dir():
        dirs.append(Path.home())

    return sorted(set(dirs), key=str)


def should_skip(path_str: str) -> bool:
    if any(path_str.startswith(p) for p in SKIP_PREFIXES):
        return True
    parts = set(Path(path_str).parts)
    if parts & SKIP_HOME_COMPONENTS:
        return True
    return False


def walk_for_keys() -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()

    for base in collect_dirs():
        for root, subdirs, files in os.walk(base, onerror=lambda e: None):
            if should_skip(root):
                subdirs[:] = []
                continue
            for fname in files:
                full = Path(root) / fname
                full_str = str(full)
                if full_str in seen or should_skip(full_str):
                    continue
                seen.add(full_str)
                try:
                    if is_candidate(full):
                        found.append(full)
                except (PermissionError, OSError):
                    continue
    return found


# --- Building records ---

def build_record(file_path: Path) -> Optional[dict]:
    try:
        st = file_path.stat()
    except (PermissionError, OSError):
        return None

    is_pub = looks_like_public_key(file_path)
    is_priv = looks_like_private_key(file_path)
    if not (is_pub or is_priv):
        return None

    if is_pub:
        kind = "public"
        fp_info = fingerprint_public(file_path)
    else:
        kind = "private"
        fp_info = fingerprint_private(file_path)

    if not fp_info or not fp_info.get("fingerprint"):
        return None  # Skip things we couldn't fingerprint

    return {
        "username": detect_username(file_path),
        "file_path": str(file_path),
        "fingerprint": fp_info["fingerprint"],
        "key_algorithm": fp_info.get("algorithm"),
        "key_bits": fp_info.get("bits"),
        "last_modified": iso_time(st.st_mtime),
        "last_accessed": iso_time(st.st_atime),
        "owner": owner_name(file_path),
        "permissions": permission_octal(file_path),
        "file_type": file_type_label(file_path),
        "key_kind": kind,
        # paired_key_status filled in after we collect everything
        "paired_key_status": None,
    }


def assign_pairing(records: list[dict]) -> None:
    """Mark each record as 'paired', 'public_only', or 'private_only'
    based on whether the same fingerprint appears as both kinds."""
    by_fp: dict[str, set[str]] = {}
    for r in records:
        by_fp.setdefault(r["fingerprint"], set()).add(r["key_kind"])

    for r in records:
        kinds = by_fp[r["fingerprint"]]
        if "public" in kinds and "private" in kinds:
            r["paired_key_status"] = "paired"
        elif r["key_kind"] == "public":
            r["paired_key_status"] = "public_only"
        else:
            r["paired_key_status"] = "private_only"


# --- Upload ---

def upload(api_url: str, token: str, payload: dict) -> dict:
    """POST scan results, return parsed JSON response."""
    endpoint = f"{api_url.rstrip('/')}/scan-results"
    body = json.dumps(payload).encode("utf-8")

    req = urllib_request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib_request.urlopen(req, timeout=60) as response:
        text = response.read().decode("utf-8")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}


def save_rotated_token(config_path: Path, cfg: dict, new_token: str) -> None:
    """Rewrite config.json with the rotated agent token."""
    cfg["agent_token"] = new_token
    tmp = config_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    tmp.replace(config_path)
    try:
        config_path.chmod(0o600)
    except Exception:
        pass


# --- Main ---

def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        sys.exit(f"Config file not found: {config_path}")
    with open(config_path) as f:
        cfg = json.load(f)
    for key in ("target_id", "agent_token", "api_url"):
        if not cfg.get(key):
            sys.exit(f"Config missing required field: {key}")
    return cfg


# ============================================================================
# POLICY AUDIT
# ============================================================================
# 11 rules across 4 files:
#   sshd_config: PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords,
#                MaxAuthTries, weak ciphers/MACs/KEX, no AllowUsers, X11Forwarding
#   passwd:      non-root UID 0, service accounts with login shells, duplicate UIDs
#   shadow:      empty passwords, weak hash algorithms (DES/MD5)
#   sudoers:     NOPASSWD ALL, long timestamp_timeout
#
# Each check produces zero or more findings. A finding is a dict with:
#   rule_id, category, severity, title, description, file_path, evidence, recommendation


WEAK_SSH_ALGOS = {
    # Substrings that indicate weakness when present in a Ciphers/MACs/KexAlgorithms list
    "arcfour", "3des", "des-cbc", "rc4",
    "-cbc",          # any CBC-mode cipher
    "md5",
    "sha1",          # legacy hash
    "diffie-hellman-group1",
    "diffie-hellman-group14-sha1",
}


def _resolve_sshd_config() -> Optional[str]:
    """Return resolved sshd_config text. Prefer `sshd -T` for drop-in/default support."""
    sshd_paths = ["/usr/sbin/sshd", "/sbin/sshd", "/usr/local/sbin/sshd"]
    sshd_bin = next((p for p in sshd_paths if Path(p).exists()), None)
    if sshd_bin:
        try:
            res = subprocess.run(
                [sshd_bin, "-T"],
                capture_output=True, text=True, timeout=10
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout
        except Exception:
            pass

    # Fall back to reading the file directly
    cfg_path = Path("/etc/ssh/sshd_config")
    if cfg_path.exists():
        try:
            return cfg_path.read_text(errors="ignore")
        except Exception:
            return None
    return None


def _sshd_directive(text: str, name: str) -> Optional[str]:
    """Get last value of `name` directive from sshd config text. Case-insensitive."""
    name_l = name.lower()
    found = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) >= 2 and parts[0].lower() == name_l:
            found = parts[1].strip()
    return found


def audit_sshd() -> list[dict]:
    findings = []
    text = _resolve_sshd_config()
    if not text:
        return findings  # No sshd config; not all systems have one

    file_path = "/etc/ssh/sshd_config"

    # --- PermitRootLogin ---
    val = _sshd_directive(text, "PermitRootLogin")
    if val and val.lower() == "yes":
        findings.append({
            "rule_id": "sshd.permit_root_login",
            "category": "sshd",
            "severity": "critical",
            "title": "Root login enabled over SSH",
            "description": "PermitRootLogin is set to 'yes', allowing direct "
                           "root authentication over SSH.",
            "file_path": file_path,
            "evidence": f"PermitRootLogin {val}",
            "recommendation": "Set PermitRootLogin to 'no' or 'prohibit-password'.",
        })

    # --- PasswordAuthentication ---
    val = _sshd_directive(text, "PasswordAuthentication")
    if val and val.lower() == "yes":
        findings.append({
            "rule_id": "sshd.password_auth",
            "category": "sshd",
            "severity": "critical",
            "title": "Password authentication enabled for SSH",
            "description": "PasswordAuthentication is enabled. Passwords are "
                           "brute-forceable; key-based authentication is recommended.",
            "file_path": file_path,
            "evidence": f"PasswordAuthentication {val}",
            "recommendation": "Set PasswordAuthentication to 'no' and require keys.",
        })

    # --- PermitEmptyPasswords ---
    val = _sshd_directive(text, "PermitEmptyPasswords")
    if val and val.lower() == "yes":
        findings.append({
            "rule_id": "sshd.empty_passwords",
            "category": "sshd",
            "severity": "critical",
            "title": "Empty passwords permitted on SSH",
            "description": "PermitEmptyPasswords is 'yes' - any account with a "
                           "blank password can log in via SSH.",
            "file_path": file_path,
            "evidence": f"PermitEmptyPasswords {val}",
            "recommendation": "Set PermitEmptyPasswords to 'no'.",
        })

    # --- MaxAuthTries ---
    val = _sshd_directive(text, "MaxAuthTries")
    try:
        if val and int(val) > 6:
            findings.append({
                "rule_id": "sshd.max_auth_tries",
                "category": "sshd",
                "severity": "high",
                "title": "MaxAuthTries permits many login attempts",
                "description": f"MaxAuthTries is set to {val}. High values let "
                               "attackers brute-force credentials per connection.",
                "file_path": file_path,
                "evidence": f"MaxAuthTries {val}",
                "recommendation": "Set MaxAuthTries to 4 or lower.",
            })
    except (TypeError, ValueError):
        pass

    # --- Weak Ciphers / MACs / KexAlgorithms ---
    for directive in ("Ciphers", "MACs", "KexAlgorithms"):
        val = _sshd_directive(text, directive)
        if not val:
            continue
        algos = [a.strip().lower() for a in val.split(",") if a.strip()]
        weak_hits = []
        for a in algos:
            for w in WEAK_SSH_ALGOS:
                if w in a:
                    weak_hits.append(a)
                    break
        if weak_hits:
            findings.append({
                "rule_id": f"sshd.weak_{directive.lower()}",
                "category": "sshd",
                "severity": "high",
                "title": f"Weak {directive} allowed in SSH config",
                "description": f"The {directive} directive includes algorithms "
                               f"considered weak: {', '.join(sorted(set(weak_hits)))}.",
                "file_path": file_path,
                "evidence": f"{directive} {val}",
                "recommendation": f"Remove weak entries from {directive}; use "
                                  "modern algorithms only (e.g. aes256-gcm@openssh.com, "
                                  "hmac-sha2-512-etm@openssh.com, curve25519-sha256).",
            })

    # --- X11Forwarding (info only - downgrade to surface in the table only) ---
    val = _sshd_directive(text, "X11Forwarding")
    if val and val.lower() == "yes":
        findings.append({
            "rule_id": "sshd.x11_forwarding",
            "category": "sshd",
            "severity": "info",
            "title": "X11 forwarding enabled on SSH",
            "description": "X11Forwarding is enabled. Unnecessary attack surface "
                           "if X11 forwarding is not actively used.",
            "file_path": file_path,
            "evidence": f"X11Forwarding {val}",
            "recommendation": "Set X11Forwarding to 'no' unless required.",
        })

    return findings


def audit_passwd() -> list[dict]:
    findings = []
    pw_path = Path("/etc/passwd")
    if not pw_path.exists():
        return findings

    file_path = "/etc/passwd"
    try:
        lines = pw_path.read_text(errors="ignore").splitlines()
    except Exception:
        return findings

    uid_count = {}
    real_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/zsh",
                   "/usr/bin/bash", "/bin/dash", "/bin/ksh", "/bin/csh", "/bin/tcsh"}
    service_account_names = {
        "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
        "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody",
        "systemd-network", "systemd-resolve", "systemd-timesync",
        "messagebus", "syslog", "_apt", "tss", "uuidd", "tcpdump",
        "nginx", "apache", "postgres", "mysql", "redis", "mongodb",
    }

    for lineno, raw in enumerate(lines, start=1):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        username, _pwd, uid_s, _gid, _gecos, _home, shell = parts[:7]

        try:
            uid = int(uid_s)
        except ValueError:
            continue

        # Non-root UID 0
        if uid == 0 and username != "root":
            findings.append({
                "rule_id": "passwd.non_root_uid_zero",
                "category": "passwd",
                "severity": "critical",
                "title": f"Non-root account '{username}' has UID 0",
                "description": f"Account '{username}' has UID 0, granting it full "
                               "root privileges. This is a backdoor pattern.",
                "file_path": file_path,
                "evidence": f"line {lineno}: {raw}",
                "recommendation": f"Remove or change UID for account '{username}'. "
                                  "Only 'root' should have UID 0.",
            })

        # Track UIDs to flag duplicates
        uid_count.setdefault(uid, []).append((username, lineno, raw))

        # Service account with a real shell
        if username.lower() in service_account_names and shell in real_shells:
            findings.append({
                "rule_id": "passwd.service_account_login_shell",
                "category": "passwd",
                "severity": "medium",
                "title": f"Service account '{username}' has a login shell",
                "description": f"Service account '{username}' is configured with "
                               f"login shell {shell}. Service accounts should not "
                               "be able to log in interactively.",
                "file_path": file_path,
                "evidence": f"line {lineno}: {raw}",
                "recommendation": f"Set shell to /usr/sbin/nologin for '{username}'.",
            })

    # Duplicate UIDs
    for uid, entries in uid_count.items():
        if len(entries) > 1:
            users = ", ".join(e[0] for e in entries)
            findings.append({
                "rule_id": f"passwd.duplicate_uid_{uid}",
                "category": "passwd",
                "severity": "high",
                "title": f"Duplicate UID {uid} shared by multiple accounts",
                "description": f"UID {uid} is shared by {len(entries)} accounts: "
                               f"{users}. This breaks ownership tracking and audit "
                               "logging.",
                "file_path": file_path,
                "evidence": "; ".join(f"line {e[1]}" for e in entries),
                "recommendation": "Assign each account a unique UID.",
            })

    return findings


def audit_shadow() -> list[dict]:
    findings = []
    sh_path = Path("/etc/shadow")
    if not sh_path.exists():
        return findings  # macOS, etc.

    file_path = "/etc/shadow"
    try:
        lines = sh_path.read_text(errors="ignore").splitlines()
    except (PermissionError, OSError):
        return findings  # Need root

    for lineno, raw in enumerate(lines, start=1):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 2:
            continue
        username, hash_field = parts[0], parts[1]

        # Empty password = passwordless login allowed
        if hash_field == "":
            findings.append({
                "rule_id": "shadow.empty_password",
                "category": "shadow",
                "severity": "critical",
                "title": f"Account '{username}' has empty password",
                "description": f"Account '{username}' has an empty password hash "
                               "field. Anyone can log in as this user.",
                "file_path": file_path,
                "evidence": f"line {lineno}",
                "recommendation": f"Lock the account ('passwd -l {username}') or "
                                  "set a strong password.",
            })
            continue

        # Locked accounts: ! or *
        if hash_field in {"!", "*", "!!"} or hash_field.startswith("!"):
            continue

        # DES (13 chars, no $) or MD5 ($1$) - weak hash algorithms
        if hash_field.startswith("$1$"):
            findings.append({
                "rule_id": "shadow.md5_hash",
                "category": "shadow",
                "severity": "high",
                "title": f"Account '{username}' uses MD5 password hash",
                "description": f"Account '{username}' password is hashed with MD5 "
                               "($1$), which is broken for password hashing.",
                "file_path": file_path,
                "evidence": f"line {lineno}: {hash_field[:8]}...",
                "recommendation": "Force a password reset; ensure ENCRYPT_METHOD "
                                  "is SHA512 or yescrypt in /etc/login.defs.",
            })
        elif not hash_field.startswith("$") and len(hash_field) == 13:
            findings.append({
                "rule_id": "shadow.des_hash",
                "category": "shadow",
                "severity": "high",
                "title": f"Account '{username}' uses DES-crypt password hash",
                "description": f"Account '{username}' uses legacy DES-crypt, which "
                               "limits passwords to 8 chars and is trivially crackable.",
                "file_path": file_path,
                "evidence": f"line {lineno}",
                "recommendation": "Force a password reset; configure SHA512 or "
                                  "yescrypt as the system default.",
            })

    return findings


def audit_sudoers() -> list[dict]:
    findings = []
    sudoers_files = []

    main_path = Path("/etc/sudoers")
    if main_path.exists():
        sudoers_files.append(main_path)

    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.is_dir():
        try:
            for child in sudoers_d.iterdir():
                if child.is_file() and not child.name.startswith("."):
                    sudoers_files.append(child)
        except (PermissionError, OSError):
            pass

    for path in sudoers_files:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (PermissionError, OSError):
            continue

        file_path = str(path)
        for lineno, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # NOPASSWD: ALL - password-less full root
            if "NOPASSWD" in stripped.upper() and "ALL" in stripped.upper():
                # Extract the first token (user/group)
                first_tok = stripped.split()[0] if stripped.split() else "?"
                findings.append({
                    "rule_id": f"sudoers.nopasswd_all.{path.name}.{lineno}",
                    "category": "sudoers",
                    "severity": "critical",
                    "title": f"Sudoers grants password-less root to {first_tok}",
                    "description": f"{first_tok} can run any command as root "
                                   "without entering a password. Stolen credentials "
                                   "or a compromised shell becomes instant root.",
                    "file_path": file_path,
                    "evidence": f"line {lineno}: {stripped}",
                    "recommendation": f"Remove NOPASSWD from this rule, or restrict "
                                      "it to specific commands instead of ALL.",
                })

            # Long timestamp_timeout
            stripped_l = stripped.lower()
            if stripped_l.startswith("defaults") and "timestamp_timeout" in stripped_l:
                # e.g. "Defaults timestamp_timeout=60"
                try:
                    val = stripped_l.split("timestamp_timeout", 1)[1]
                    val = val.strip().lstrip("=").strip()
                    # Take leading number, ignore trailing comma/text
                    num_str = ""
                    for c in val:
                        if c.isdigit() or c == "-":
                            num_str += c
                        else:
                            break
                    if num_str:
                        timeout = int(num_str)
                        if timeout > 15 or timeout < 0:  # negative = never expires
                            findings.append({
                                "rule_id": f"sudoers.long_timeout.{path.name}.{lineno}",
                                "category": "sudoers",
                                "severity": "medium",
                                "title": "Sudo timestamp timeout is unusually long",
                                "description": f"timestamp_timeout = {timeout} "
                                               "minutes. After authenticating once, "
                                               "a stolen terminal stays root for that "
                                               "long. -1 means never expires.",
                                "file_path": file_path,
                                "evidence": f"line {lineno}: {stripped}",
                                "recommendation": "Set timestamp_timeout to 5-15.",
                            })
                except (ValueError, IndexError):
                    pass

    return findings


def run_policy_audit() -> list[dict]:
    """Run all policy auditors. Returns a list of finding dicts."""
    findings = []
    try:
        findings.extend(audit_sshd())
    except Exception as e:
        print(f"  sshd audit failed: {e}", file=sys.stderr)
    try:
        findings.extend(audit_passwd())
    except Exception as e:
        print(f"  passwd audit failed: {e}", file=sys.stderr)
    try:
        findings.extend(audit_shadow())
    except Exception as e:
        print(f"  shadow audit failed: {e}", file=sys.stderr)
    try:
        findings.extend(audit_sudoers())
    except Exception as e:
        print(f"  sudoers audit failed: {e}", file=sys.stderr)
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="AUNIX SSH key scanner")
    parser.add_argument(
        "--config", default=str(Path(__file__).resolve().parent / "config.json"),
        help="Path to config.json (default: alongside this script)",
    )
    parser.add_argument(
        "--no-upload", action="store_true",
        help="Scan only, print results to stdout, don't upload.",
    )
    parser.add_argument(
        "--output", default=None,
        help="Also write the JSON payload to this file.",
    )
    args = parser.parse_args()

    if not _has_ssh_keygen():
        print("WARNING: ssh-keygen not found in PATH. Fingerprints will be empty "
              "and most keys will be skipped.", file=sys.stderr)

    if os.geteuid() != 0:
        print("WARNING: not running as root. Many SSH key locations will be "
              "unreadable. Re-run with sudo for a complete scan.", file=sys.stderr)

    print("Scanning for SSH keys...")
    candidate_paths = walk_for_keys()
    print(f"  candidate files: {len(candidate_paths)}")

    records = []
    for p in candidate_paths:
        rec = build_record(p)
        if rec is not None:
            records.append(rec)

    assign_pairing(records)
    print(f"  fingerprinted keys: {len(records)}")

    print("Running policy audit...")
    policy_findings = run_policy_audit()
    print(f"  policy findings: {len(policy_findings)}")

    payload = {
        "scan_type": "agent",
        "hostname": socket.gethostname(),
        "operating_system": f"{platform.system()} {platform.release()}",
        "keys": records,
        "policy_findings": policy_findings,
    }

    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2))
        print(f"Wrote payload to {args.output}")

    if args.no_upload:
        print(json.dumps(payload, indent=2))
        return 0

    cfg = load_config(Path(args.config))
    print(f"Uploading to {cfg['api_url']} (target_id={cfg['target_id']})...")
    try:
        resp = upload(cfg["api_url"], cfg["agent_token"], payload)
        print("Upload OK:")
        print(json.dumps({k: v for k, v in resp.items() if k != "rotated_agent_token"}, indent=2))

        # Rotate the agent token. Backend already invalidated the old one.
        rotated = resp.get("rotated_agent_token")
        if rotated:
            save_rotated_token(Path(args.config), cfg, rotated)
            print("Agent token rotated. Old token is no longer valid.")
        return 0
    except HTTPError as e:
        print(f"Upload failed (HTTP {e.code}): {e.read().decode('utf-8', 'ignore')}",
              file=sys.stderr)
        return 1
    except URLError as e:
        print(f"Network error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
