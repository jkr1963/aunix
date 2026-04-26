from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user
from models import UserAccount, TargetMachine, PolicyFinding
from schemas import PolicyFindingResponse

router = APIRouter(prefix="/policy", tags=["policy"])

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


@router.get("/findings/{target_id}", response_model=List[PolicyFindingResponse])
def list_findings(
    target_id: int,
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    """All policy findings for one target the user owns, sorted critical-first."""
    target = db.query(TargetMachine).filter(
        TargetMachine.id == target_id,
        TargetMachine.user_id == user.id,
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    findings = db.query(PolicyFinding).filter(
        PolicyFinding.target_id == target_id
    ).all()

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.category, f.title))
    return findings
