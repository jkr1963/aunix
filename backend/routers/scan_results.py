from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_target
from models import TargetMachine, SSHKeyInventory, PolicyFinding
from schemas import ScanUploadRequest

router = APIRouter(tags=["scan"])


@router.post("/scan-results")
def upload_scan_results(
    payload: ScanUploadRequest,
    db: Session = Depends(get_db),
    target: TargetMachine = Depends(get_current_target),
):
    """Called by the scanner agent. Auth = bearer agent token."""

    # Replace this target's inventory with the latest scan.
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

    db.commit()

    return {
        "message": "Scan results uploaded successfully",
        "target_id": target.id,
        "scan_type": payload.scan_type,
        "keys_inserted": keys_inserted,
        "policy_findings_inserted": findings_inserted,
    }
