import os
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user
from models import UserAccount, TargetMachine
from schemas import TargetCreate, TargetResponse, TargetCreateResponse
from security import generate_agent_token, hash_agent_token

router = APIRouter(prefix="/targets", tags=["targets"])


def _public_api_url() -> str:
    return os.getenv("PUBLIC_API_URL", "http://127.0.0.1:8000/api")


@router.post("", response_model=TargetCreateResponse)
def register_target(
    payload: TargetCreate,
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    agent_token = generate_agent_token()

    target = TargetMachine(
        user_id=user.id,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        operating_system=payload.operating_system,
        status="pending",
        agent_token_hash=hash_agent_token(agent_token),
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    install_command = (
        f"tar -xzf aunix-agent-{target.id}.tar.gz && "
        f"cd aunix-agent-{target.id} && sudo ./run.sh"
    )

    return TargetCreateResponse(
        id=target.id,
        hostname=target.hostname,
        ip_address=target.ip_address,
        operating_system=target.operating_system,
        status=target.status,
        last_scan_at=target.last_scan_at,
        created_at=target.created_at,
        agent_token=agent_token,
        install_command=install_command,
    )


@router.get("", response_model=List[TargetResponse])
def list_targets(
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    return db.query(TargetMachine).filter(
        TargetMachine.user_id == user.id
    ).order_by(TargetMachine.created_at.desc()).all()


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: int,
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    target = db.query(TargetMachine).filter(
        TargetMachine.id == target_id,
        TargetMachine.user_id == user.id,
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/{target_id}")
def delete_target(
    target_id: int,
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    target = db.query(TargetMachine).filter(
        TargetMachine.id == target_id,
        TargetMachine.user_id == user.id,
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    db.delete(target)
    db.commit()
    return {"message": "Target deleted"}
