"""
Risk classification for SSH keys.

Single source of truth — used by both the per-target keys endpoint
(to attach severity, findings, and fix recommendations to each row) and
the fleet summary endpoint (to aggregate counts).

Classification rules are deliberately conservative — we want true positives
worth showing to an auditor, not noise.
"""

from datetime import datetime, timezone
from typing import Optional, Tuple, List


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        # Tolerate trailing 'Z' and missing tz
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def days_since(ts: Optional[str]) -> Optional[int]:
    dt = _parse_iso(ts)
    if dt is None:
        return None
    delta = datetime.now(timezone.utc) - dt
    return max(delta.days, 0)


def _is_standard_location(file_path: Optional[str]) -> bool:
    if not file_path:
        return False
    return (
        file_path.startswith("/etc/ssh/")
        or file_path.startswith("/root/.ssh/")
        or "/.ssh/" in file_path
    )


def _algo_label(algo: Optional[str], bits: Optional[int]) -> str:
    """e.g. 'RSA-2048', 'ED25519', 'unknown'."""
    if not algo:
        return "unknown"
    if bits and algo.upper() in {"RSA", "DSA", "ECDSA"}:
        return f"{algo.upper()}-{bits}"
    return algo.upper()


def classify(key) -> Tuple[str, List[str], List[str]]:
    """
    Returns (severity, findings, recommendations) for a single key.

    severity: 'critical' | 'high' | 'medium' | 'info'
    findings: list of human-readable strings describing the issues.
    recommendations: parallel list - recommendations[i] is the fix advice
                     for findings[i]. Always the same length as findings.
    """
    findings: List[str] = []
    recommendations: List[str] = []
    severity = "info"

    kind = (key.key_kind or "").lower()
    perms = (key.permissions or "").strip()
    algo = (key.key_algorithm or "").upper()
    bits = key.key_bits or 0

    def add(finding: str, rec: str):
        findings.append(finding)
        recommendations.append(rec)

    # ---- CRITICAL ----

    if kind == "private" and perms and perms != "600":
        add(
            f"Private key has permissions {perms} (should be 600).",
            f"Run 'chmod 600 {key.file_path}'. SSH refuses to use a private "
            "key with permissions any other user can read."
        )
        severity = "critical"

    if algo == "DSA":
        add(
            "DSA is deprecated and considered insecure.",
            "Generate a replacement key with 'ssh-keygen -t ed25519', "
            "deploy the new public key to anywhere this DSA key was "
            "authorized, then delete the DSA keypair."
        )
        severity = "critical"

    if algo == "RSA" and bits and bits < 2048:
        add(
            f"RSA-{bits} is below the recommended 2048-bit minimum.",
            "Generate a replacement with 'ssh-keygen -t ed25519' (preferred) "
            "or 'ssh-keygen -t rsa -b 4096', deploy the new public key, "
            "then remove the weak key."
        )
        severity = "critical"

    # ---- HIGH ----

    if severity != "critical":
        access_age = days_since(key.last_accessed)
        modified_age = days_since(key.last_modified)

        # atime-based staleness (unreliable on relatime/noatime, but useful when present)
        if kind == "private" and access_age is not None and access_age >= 180:
            add(
                f"Private key not accessed in {access_age} days "
                "(may be stale or forgotten).",
                "If this key is no longer needed, remove it from "
                "~/.ssh/ and from any authorized_keys files where it "
                "is listed. If it's still needed, document its purpose."
            )
            severity = "high"

        # mtime-based age — reliable, signals rotation hygiene
        if kind == "private" and modified_age is not None and modified_age >= 180:
            add(
                f"Private key has not been rotated in {modified_age} days.",
                "Rotate the key: generate a new keypair, deploy the new "
                "public key everywhere the old one is authorized, then "
                "delete the old keypair. Aim for a 180-day rotation cadence."
            )
            severity = "high"

        if kind == "private" and not _is_standard_location(key.file_path):
            add(
                "Private key stored outside standard SSH directories.",
                "Move the key to ~/.ssh/ (with permissions 700 on the "
                "directory, 600 on the key file). Keys in unusual paths "
                "often escape backups, audits, and access controls."
            )
            severity = "high"

        if (key.paired_key_status or "") == "private_only":
            # private with no matching public on the same machine — unusual
            add(
                "Private key has no matching public key on this machine.",
                "Restore the matching public key with 'ssh-keygen -y -f "
                f"{key.file_path} > {key.file_path}.pub' (you'll need the "
                "passphrase). Without the public key it's hard to identify "
                "what this key is authorized for."
            )
            if severity != "high":
                severity = "high"

    # ---- MEDIUM ----

    if severity == "info":
        access_age = days_since(key.last_accessed)
        modified_age = days_since(key.last_modified)

        if kind == "private" and access_age is not None and 90 <= access_age < 180:
            add(
                f"Private key not accessed in {access_age} days.",
                "If you're not using this key, plan to remove it. Otherwise "
                "no action needed yet — flagged so it doesn't drift past "
                "180 days unnoticed."
            )
            severity = "medium"

        if kind == "private" and modified_age is not None and 90 <= modified_age < 180:
            add(
                f"Private key has not been rotated in {modified_age} days.",
                "Plan a rotation soon. Generate a fresh keypair, push the "
                "new public key to authorized_keys files, then retire this one."
            )
            severity = "medium"

        if kind == "public" and not _is_standard_location(key.file_path):
            add(
                "Public key stored outside standard SSH directories.",
                "Either move the public key to ~/.ssh/ alongside its "
                "private counterpart, or document why it lives where it does."
            )
            severity = "medium"

    return severity, findings, recommendations


def algorithm_label(key) -> str:
    return _algo_label(key.key_algorithm, key.key_bits)


def is_standard_location(file_path: Optional[str]) -> bool:
    return _is_standard_location(file_path)


def posture_score(severity_counts: dict) -> int:
    """
    Compute a 0-100 fleet posture score from severity counts.

    Starts at 100 and deducts based on findings:
      - Each critical finding: -8
      - Each high finding:     -3
      - Each medium finding:   -1

    Floored at 0. Higher is better.

    The deductions are gentle on purpose - even a fleet with several
    criticals shouldn't drop instantly to 0. The intent is a usable
    spectrum, not a binary pass/fail.
    """
    score = 100
    score -= 8 * severity_counts.get("critical", 0)
    score -= 3 * severity_counts.get("high", 0)
    score -= 1 * severity_counts.get("medium", 0)
    return max(score, 0)


def posture_band(score: int) -> str:
    """Map a posture score to a label for dashboard display."""
    if score >= 90:
        return "good"
    if score >= 70:
        return "fair"
    if score >= 50:
        return "poor"
    return "critical"
