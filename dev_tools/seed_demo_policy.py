#!/usr/bin/env python3
"""
seed_demo_policy.py — Inject realistic demo policy findings into the AUNIX
database for one of your registered targets.

This is a developer/demo tool. It bypasses the agent and writes findings
directly to Postgres so you can see the Configuration Policy panel
populated on machines (like Mac) where the real Linux audits don't
fire much.

Usage:
    cd ~/Desktop/aunix-project
    source venv/bin/activate
    set -a; source .env; set +a
    python dev_tools/seed_demo_policy.py             # interactive picker
    python dev_tools/seed_demo_policy.py --target-id 1
    python dev_tools/seed_demo_policy.py --target-id 1 --clear   # remove demo findings
"""

import argparse
import os
import sys
from pathlib import Path

# Make backend imports resolvable regardless of where the script is run from.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from models import Base, TargetMachine, PolicyFinding, UserAccount
except ImportError as e:
    print(f"ERROR: could not import backend modules: {e}")
    print("Make sure your virtualenv is activated and you're in the project root.")
    sys.exit(1)


# ---- The demo dataset ---------------------------------------------------
# A realistic mix of findings spread across all four categories so every
# part of the panel renders. Severity distribution chosen to drop the
# posture score noticeably without bottoming out: 4 critical, 4 high,
# 2 medium, 1 info.

DEMO_FINDINGS = [
    # --- sshd: 3 critical + 1 high + 1 info ---
    {
        "rule_id": "sshd.permit_root_login",
        "category": "sshd",
        "severity": "critical",
        "title": "Root login enabled over SSH",
        "description": "PermitRootLogin is set to 'yes', allowing direct "
                       "root authentication over SSH.",
        "file_path": "/etc/ssh/sshd_config",
        "evidence": "PermitRootLogin yes",
        "recommendation": "Set PermitRootLogin to 'no' or 'prohibit-password'.",
    },
    {
        "rule_id": "sshd.password_auth",
        "category": "sshd",
        "severity": "critical",
        "title": "Password authentication enabled for SSH",
        "description": "PasswordAuthentication is enabled. Passwords are "
                       "brute-forceable; key-based authentication is recommended.",
        "file_path": "/etc/ssh/sshd_config",
        "evidence": "PasswordAuthentication yes",
        "recommendation": "Set PasswordAuthentication to 'no' and require keys.",
    },
    {
        "rule_id": "sshd.permit_empty_passwords",
        "category": "sshd",
        "severity": "critical",
        "title": "Empty passwords permitted on SSH",
        "description": "PermitEmptyPasswords is 'yes' - any account with a "
                       "blank password can log in via SSH.",
        "file_path": "/etc/ssh/sshd_config",
        "evidence": "PermitEmptyPasswords yes",
        "recommendation": "Set PermitEmptyPasswords to 'no'.",
    },
    {
        "rule_id": "sshd.weak_ciphers",
        "category": "sshd",
        "severity": "high",
        "title": "Weak Ciphers allowed in SSH config",
        "description": "The Ciphers directive includes algorithms considered "
                       "weak: 3des-cbc, arcfour.",
        "file_path": "/etc/ssh/sshd_config",
        "evidence": "Ciphers aes256-ctr,3des-cbc,arcfour",
        "recommendation": "Remove weak entries from Ciphers; use modern "
                          "algorithms only (e.g. aes256-gcm@openssh.com).",
    },
    {
        "rule_id": "sshd.x11_forwarding",
        "category": "sshd",
        "severity": "info",
        "title": "X11 forwarding enabled on SSH",
        "description": "X11Forwarding is enabled. Unnecessary attack surface "
                       "if X11 forwarding is not actively used.",
        "file_path": "/etc/ssh/sshd_config",
        "evidence": "X11Forwarding yes",
        "recommendation": "Set X11Forwarding to 'no' unless required.",
    },

    # --- passwd: 1 critical + 1 high + 1 medium ---
    {
        "rule_id": "passwd.non_root_uid_zero",
        "category": "passwd",
        "severity": "critical",
        "title": "Non-root account 'backdoor' has UID 0",
        "description": "Account 'backdoor' has UID 0, granting it full root "
                       "privileges. This is a backdoor pattern.",
        "file_path": "/etc/passwd",
        "evidence": "line 24: backdoor:x:0:0:Hidden Admin:/home/backdoor:/bin/bash",
        "recommendation": "Remove or change UID for account 'backdoor'. "
                          "Only 'root' should have UID 0.",
    },
    {
        "rule_id": "passwd.duplicate_uid_1001",
        "category": "passwd",
        "severity": "high",
        "title": "Duplicate UID 1001 shared by multiple accounts",
        "description": "UID 1001 is shared by 2 accounts: alice, bob. This "
                       "breaks ownership tracking and audit logging.",
        "file_path": "/etc/passwd",
        "evidence": "line 41; line 42",
        "recommendation": "Assign each account a unique UID.",
    },
    {
        "rule_id": "passwd.service_account_login_shell",
        "category": "passwd",
        "severity": "medium",
        "title": "Service account 'postgres' has a login shell",
        "description": "Service account 'postgres' is configured with login "
                       "shell /bin/bash. Service accounts should not be able "
                       "to log in interactively.",
        "file_path": "/etc/passwd",
        "evidence": "line 33: postgres:x:104:110::/var/lib/postgresql:/bin/bash",
        "recommendation": "Set shell to /usr/sbin/nologin for 'postgres'.",
    },

    # --- shadow: 1 high ---
    {
        "rule_id": "shadow.md5_hash",
        "category": "shadow",
        "severity": "high",
        "title": "Account 'legacy_admin' uses MD5 password hash",
        "description": "Account 'legacy_admin' password is hashed with MD5 "
                       "($1$), which is broken for password hashing.",
        "file_path": "/etc/shadow",
        "evidence": "line 18: $1$abc12...",
        "recommendation": "Force a password reset; ensure ENCRYPT_METHOD is "
                          "SHA512 or yescrypt in /etc/login.defs.",
    },

    # --- sudoers: 1 high + 1 medium ---
    {
        "rule_id": "sudoers.nopasswd_all.devs.1",
        "category": "sudoers",
        "severity": "high",
        "title": "Sudoers grants password-less root to %developers",
        "description": "%developers can run any command as root without "
                       "entering a password. Stolen credentials or a "
                       "compromised shell becomes instant root.",
        "file_path": "/etc/sudoers.d/devs",
        "evidence": "line 1: %developers ALL=(ALL) NOPASSWD: ALL",
        "recommendation": "Remove NOPASSWD from this rule, or restrict it "
                          "to specific commands instead of ALL.",
    },
    {
        "rule_id": "sudoers.long_timeout.sudoers.5",
        "category": "sudoers",
        "severity": "medium",
        "title": "Sudo timestamp timeout is unusually long",
        "description": "timestamp_timeout = 60 minutes. After authenticating "
                       "once, a stolen terminal stays root for that long.",
        "file_path": "/etc/sudoers",
        "evidence": "line 5: Defaults timestamp_timeout=60",
        "recommendation": "Set timestamp_timeout to 5-15.",
    },
]


def get_db_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        sys.exit(
            "ERROR: DATABASE_URL is not set.\n"
            "Run: set -a; source .env; set +a"
        )
    # SQLAlchemy needs the dialect prefix; the env file may use either form.
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def pick_target_interactive(session) -> int:
    targets = session.query(TargetMachine).all()
    if not targets:
        sys.exit(
            "No target machines registered yet. Register one in the dashboard "
            "first, then re-run this script."
        )

    print("\nRegistered machines:")
    print(f"  {'ID':<6} {'Hostname':<30} {'Owner':<25} Last Scan")
    print("  " + "-" * 80)
    for t in targets:
        owner = (
            session.query(UserAccount).filter(UserAccount.id == t.user_id).first()
        )
        owner_email = owner.email if owner else "?"
        last = t.last_scan_at.strftime("%Y-%m-%d %H:%M") if t.last_scan_at else "never"
        print(f"  {t.id:<6} {t.hostname:<30} {owner_email:<25} {last}")

    while True:
        raw = input("\nEnter target ID to seed (or 'q' to quit): ").strip()
        if raw.lower() in {"q", "quit", "exit"}:
            sys.exit("Cancelled.")
        try:
            tid = int(raw)
        except ValueError:
            print("  Not a number, try again.")
            continue
        if not session.query(TargetMachine).filter(TargetMachine.id == tid).first():
            print("  No target with that ID, try again.")
            continue
        return tid


def main():
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target-id", type=int,
                        help="Target machine ID to seed (skips picker).")
    parser.add_argument("--clear", action="store_true",
                        help="Remove all demo policy findings for the target "
                             "instead of inserting.")
    args = parser.parse_args()

    engine = create_engine(get_db_url())
    Base.metadata.create_all(bind=engine)  # safe no-op if tables exist
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        if args.target_id is not None:
            target = session.query(TargetMachine).filter(
                TargetMachine.id == args.target_id
            ).first()
            if not target:
                sys.exit(f"No target with ID {args.target_id}.")
            target_id = target.id
        else:
            target_id = pick_target_interactive(session)

        target = session.query(TargetMachine).filter(
            TargetMachine.id == target_id
        ).first()

        if args.clear:
            deleted = session.query(PolicyFinding).filter(
                PolicyFinding.target_id == target_id
            ).delete(synchronize_session=False)
            session.commit()
            print(f"\nRemoved {deleted} policy findings from "
                  f"'{target.hostname}' (target {target_id}).")
            return

        # Wipe existing findings so we don't pile duplicates on repeat runs.
        existing = session.query(PolicyFinding).filter(
            PolicyFinding.target_id == target_id
        ).delete(synchronize_session=False)

        for f in DEMO_FINDINGS:
            session.add(PolicyFinding(target_id=target_id, **f))

        session.commit()

        print(f"\nSeeded {len(DEMO_FINDINGS)} demo policy findings on "
              f"'{target.hostname}' (target {target_id}).")
        if existing:
            print(f"(replaced {existing} existing findings)")

        sev_counts = {}
        for f in DEMO_FINDINGS:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        summary = ", ".join(f"{n} {s}" for s, n in sorted(sev_counts.items()))
        print(f"Distribution: {summary}")
        print("\nReload the dashboard to see them.")
        print("To remove later:  python dev_tools/seed_demo_policy.py "
              f"--target-id {target_id} --clear")

    finally:
        session.close()


if __name__ == "__main__":
    main()
