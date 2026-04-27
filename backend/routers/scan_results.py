"""
/api/scan-results

Called by the scanner agent to upload findings. Authenticated via
Bearer agent token.

After each successful upload, we ROTATE the agent token. The new token
is returned in the response body, and the agent persists it to its
config.json. This means:

  - A captured-but-unused tarball remains valid until its first scan,
    then becomes useless.
  - Replaying a captured scan upload (with the just-used token) fails
    because the token is already rotated.
  - If an attacker steals an agent token mid-flight, they have a one-
    time use; the legitimate agent will fail its NEXT scan, which
    surfaces tampering.

This is real defense-in-depth, but the threat model is bounded: a
sophisticated attacker with persistent root on the target can always
read the new token from disk and stay synchronized. See SECURITY_NOTES.md.
"""

from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_target
from models import TargetMachine, SSHKeyInventory, PolicyFinding
from schemas import ScanUploadRequest
from security import generate_agent_token, hash_agent_token

router = APIRouter(tags=["scan"])


@router.post("/scan-results")
def upload_scan_results(
    payload: ScanUploadRequest,
    db: Session = Depends(get_db),
    target: TargetMachine = Depends(get_current_target),
):
    """Called by the scanner agent. Auth = bearer agent token."""

    # Wipe and replace the inventory + policy findings for this target.
    db.query(SSHKeyInventory).filter(
        SSHKeyInventory.target_id == target.id
    ).delete(synchronize_session=False)

    db.query(PolicyFinding).filter(
        PolicyFinding.target_id == target.id
    ).delete(synchronize_session=False)

    keys_inserted = 0
    for item in payload.keys:
        if not item.file_path or not item.fingerprint:
            continue
        db.add(SSHKeyInventory(
            target_id=target.id,
            username=item.username,
            file_path=item.file_path,
            fingerprint=item.fingerprint,
            key_algorithm=item.key_algorithm,
            key_bits=item.key_bits,
            last_modified=item.last_modified,
            last_accessed=item.last_accessed,
            owner=item.owner,
            permissions=item.permissions,
            file_type=item.file_type,
            key_kind=item.key_kind,
            paired_key_status=item.paired_key_status,
        ))
        keys_inserted += 1

    findings_inserted = 0
    for f in payload.policy_findings:
        if not f.rule_id or not f.severity:
            continue
        db.add(PolicyFinding(
            target_id=target.id,
            rule_id=f.rule_id,
            category=f.category,
            severity=f.severity,
            title=f.title,
            description=f.description,
            file_path=f.file_path,
            evidence=f.evidence,
            recommendation=f.recommendation,
        ))
        findings_inserted += 1

    target.status = "active"
    target.last_scan_at = datetime.utcnow()
    if payload.hostname and not target.hostname.strip():
        target.hostname = payload.hostname
    if payload.operating_system and not (target.operating_system or "").strip():
        target.operating_system = payload.operating_system

    # Rotate the agent token. Old token becomes invalid the moment we commit.
    new_token = generate_agent_token()
    target.agent_token_hash = hash_agent_token(new_token)

    db.commit()

    return {
        "message": "Scan results uploaded successfully",
        "target_id": target.id,
        "scan_type": payload.scan_type,
        "keys_inserted": keys_inserted,
        "policy_findings_inserted": findings_inserted,
        # The agent reads this and writes it back to its config.json.
        "rotated_agent_token": new_token,
    }
