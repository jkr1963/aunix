import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user
from models import UserAccount, TargetMachine
from security import generate_agent_token, hash_agent_token
from agent_builder import build_agent_tarball

router = APIRouter(prefix="/installers", tags=["installers"])


def _public_api_url() -> str:
    return os.getenv("PUBLIC_API_URL", "http://127.0.0.1:8000/api")


@router.post("/agent/{target_id}")
def download_agent(
    target_id: int,
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    """
    Build a fresh agent tarball for this target.

    POST (not GET) because we issue a new agent token each time the package
    is downloaded - the old token is revoked. This avoids leaving an
    unrevocable credential lying around if a download is intercepted.
    """
    target = db.query(TargetMachine).filter(
        TargetMachine.id == target_id,
        TargetMachine.user_id == user.id,
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    new_token = generate_agent_token()
    target.agent_token_hash = hash_agent_token(new_token)
    db.commit()

    tarball_path = build_agent_tarball(
        target_id=target.id,
        agent_token=new_token,
        api_url=_public_api_url(),
    )

    return FileResponse(
        path=str(tarball_path),
        filename=f"aunix-agent-{target.id}.tar.gz",
        media_type="application/gzip",
    )
