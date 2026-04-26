from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user
from models import UserAccount, TargetMachine, SSHKeyInventory
from schemas import SSHKeyResponse
from risk import classify

router = APIRouter(prefix="/keys", tags=["keys"])


def _to_response(key: SSHKeyInventory) -> SSHKeyResponse:
    severity, findings, recommendations = classify(key)
    return SSHKeyResponse(
        id=key.id,
        target_id=key.target_id,
        username=key.username,
        file_path=key.file_path,
        fingerprint=key.fingerprint,
        key_algorithm=key.key_algorithm,
        key_bits=key.key_bits,
        last_modified=key.last_modified,
        last_accessed=key.last_accessed,
        owner=key.owner,
        permissions=key.permissions,
        file_type=key.file_type,
        key_kind=key.key_kind,
        paired_key_status=key.paired_key_status,
        severity=severity,
        findings=findings,
        recommendations=recommendations,
    )


@router.get("", response_model=List[SSHKeyResponse])
def list_keys(
    target_id: Optional[int] = Query(default=None),
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    user_target_ids = [
        t.id for t in db.query(TargetMachine.id).filter(
            TargetMachine.user_id == user.id
        ).all()
    ]
    if not user_target_ids:
        return []

    query = db.query(SSHKeyInventory).filter(
        SSHKeyInventory.target_id.in_(user_target_ids)
    )

    if target_id is not None:
        if target_id not in user_target_ids:
            raise HTTPException(status_code=404, detail="Target not found")
        query = query.filter(SSHKeyInventory.target_id == target_id)

    return [_to_response(k) for k in query.all()]
