"""
/api/installers/agent/{target_id}

Returns a one-line install command the user can copy into a Terminal on
the target machine. The command:

  1. Issues a fresh per-target agent token (invalidating any previous one).
  2. Returns JSON containing the token and a ready-to-copy curl command
     that fetches aunix_scan.py from GitHub and pipes it into Python with
     the required environment variables set.

This replaces the older tarball-based flow. Benefits:
  - No file download. No extracting. No "where did the tarball go?"
  - The scanner source lives in one place (GitHub) and is auditable.
  - Per-scan token rotation still works; the user just fetches a fresh
    command from the dashboard before each scan.
"""

import os

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from deps import get_current_user
from models import UserAccount, TargetMachine
from security import generate_agent_token, hash_agent_token

router = APIRouter(prefix="/installers", tags=["installers"])


def _public_api_url() -> str:
    return os.getenv("PUBLIC_API_URL", "http://127.0.0.1:8000/api")


def _scanner_url() -> str:
    """Raw URL of the scanner script on GitHub.

    Set AUNIX_SCANNER_URL in the backend environment to point at your
    repository's main branch raw URL, e.g.

        https://raw.githubusercontent.com/<org>/<repo>/main/agent/aunix_scan.py
    """
    return os.getenv(
        "AUNIX_SCANNER_URL",
        "https://raw.githubusercontent.com/jkr1963/aunix/main/agent/aunix_scan.py",
    )


def _build_install_command(target_id: int, agent_token: str, api_url: str) -> str:
    """Compose the one-liner the user pastes into their Terminal."""
    return (
        f"curl -fsSL {_scanner_url()} | "
        f"sudo AUNIX_TARGET_ID={target_id} "
        f"AUNIX_AGENT_TOKEN={agent_token} "
        f"AUNIX_API_URL={api_url} "
        f"python3 -"
    )


@router.post("/agent/{target_id}")
def issue_install_command(
    target_id: int,
    db: Session = Depends(get_db),
    user: UserAccount = Depends(get_current_user),
):
    """Issue a fresh install command for this target.

    POST (not GET) because we generate a new agent token each time and
    invalidate the previous one. This keeps the captured-command threat
    model identical to the old tarball model: a copied command works for
    one scan upload, after which it's dead.
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

    install_command = _build_install_command(
        target_id=target.id,
        agent_token=new_token,
        api_url=_public_api_url(),
    )

    return {
        "target_id": target.id,
        "hostname": target.hostname,
        "install_command": install_command,
    }
