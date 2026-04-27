"""
Authentication routes.

Registration flow with deferred persistence:

1. POST /auth/register
   - Validates the email isn't already registered.
   - Generates an MFA secret + QR code.
   - Stashes (email, name, password_hash, mfa_secret) in an in-memory
     pending registrations table keyed by email, with a 15-minute TTL.
   - Returns the QR code to the user.
   - NOTHING is written to the database yet.

2. POST /auth/verify-mfa
   - Looks up the pending registration by email.
   - Verifies the OTP code.
   - On success: creates the UserAccount in the database (mfa_enabled=True
     from the start), removes the pending entry.
   - On failure: pending entry stays so the user can retry.

This means closing the browser tab between step 1 and step 2 leaves no
trace in the database. After 15 minutes the in-memory entry expires and
the user must restart from /auth/register.

Caveats:
  * Pending registrations are lost on backend restart. For a production
    system you'd persist them in Redis with a TTL or in a dedicated
    'pending_users' table cleaned by a periodic job.
  * In-memory dict is per-process. Multi-worker deployments would need
    Redis for consistency.
"""

import base64
import time
from io import BytesIO
from threading import Lock
from typing import Dict

import qrcode
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import UserAccount
from schemas import (
    UserRegister, UserLogin, MFAVerifyRequest, LoginMFARequest,
    UserResponse, TokenResponse,
)
from security import (
    hash_password, verify_password,
    generate_mfa_secret, build_mfa_uri, verify_otp,
    create_access_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])

# ----- pending registrations -----
# Keyed by lowercase email. Value:
#   { name, email, password_hash, mfa_secret, expires_at (epoch seconds) }
_PENDING: Dict[str, dict] = {}
_PENDING_LOCK = Lock()
PENDING_TTL_SECONDS = 15 * 60  # 15 minutes


def _purge_expired():
    """Drop any pending registration past its TTL. Called opportunistically."""
    now = time.time()
    with _PENDING_LOCK:
        expired = [k for k, v in _PENDING.items() if v["expires_at"] < now]
        for k in expired:
            _PENDING.pop(k, None)


@router.post("/register")
def register_user(payload: UserRegister, db: Session = Depends(get_db)):
    """
    Step 1 of registration: validate inputs, generate MFA QR code,
    stash credentials in memory. NOTHING IS PERSISTED.
    """
    _purge_expired()

    email = payload.email.strip().lower()

    # Already in the database?
    existing = db.query(UserAccount).filter(UserAccount.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    secret = generate_mfa_secret()
    pending = {
        "name": payload.name,
        "email": email,
        "password_hash": hash_password(payload.password),
        "mfa_secret": secret,
        "expires_at": time.time() + PENDING_TTL_SECONDS,
    }
    with _PENDING_LOCK:
        _PENDING[email] = pending

    # Build the QR code right here so the frontend doesn't need a second call.
    uri = build_mfa_uri(secret, email)
    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {
        "message": "Scan the QR code with your authenticator app, "
                   "then submit a code to complete registration.",
        "email": email,
        "qr_code_base64": qr_b64,
        "expires_in_minutes": PENDING_TTL_SECONDS // 60,
    }


@router.post("/setup-mfa")
def setup_mfa_legacy(payload: UserLogin):
    """
    Legacy endpoint kept for backward compatibility with old frontends.
    The new flow puts the QR code directly in the /register response.
    """
    raise HTTPException(
        status_code=410,
        detail="This endpoint is no longer used. The /register response "
               "now includes the QR code directly."
    )


@router.post("/verify-mfa", response_model=UserResponse)
def verify_mfa_and_finalize(payload: MFAVerifyRequest, db: Session = Depends(get_db)):
    """
    Step 2 of registration: verify the OTP code and only THEN write
    the user to the database.
    """
    _purge_expired()
    email = payload.email.strip().lower()

    with _PENDING_LOCK:
        pending = _PENDING.get(email)

    if not pending:
        raise HTTPException(
            status_code=404,
            detail="No pending registration found for this email. "
                   "Either it expired (15 minute window), the email is wrong, "
                   "or you already completed registration. Try registering again.",
        )

    if pending["expires_at"] < time.time():
        with _PENDING_LOCK:
            _PENDING.pop(email, None)
        raise HTTPException(
            status_code=400,
            detail="Pending registration expired. Please register again.",
        )

    if not verify_otp(pending["mfa_secret"], payload.otp_code):
        raise HTTPException(status_code=400, detail="Invalid authenticator code")

    # Re-check the email isn't taken (could have been registered by someone
    # else in the time the user was scanning the QR).
    existing = db.query(UserAccount).filter(UserAccount.email == email).first()
    if existing:
        with _PENDING_LOCK:
            _PENDING.pop(email, None)
        raise HTTPException(status_code=400, detail="Email already registered")

    user = UserAccount(
        email=pending["email"],
        name=pending["name"],
        password_hash=pending["password_hash"],
        mfa_secret=pending["mfa_secret"],
        mfa_enabled=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    with _PENDING_LOCK:
        _PENDING.pop(email, None)

    return user


@router.post("/login")
def login_step_one(payload: UserLogin, db: Session = Depends(get_db)):
    """Verify password. Tells the frontend to collect an OTP next."""
    user = db.query(UserAccount).filter(UserAccount.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.mfa_enabled:
        # Should not happen in the new flow; user wouldn't exist without MFA.
        raise HTTPException(status_code=400, detail="MFA is not enabled for this account")
    return {"mfa_required": True, "message": "Credentials verified. Enter authenticator code."}


@router.post("/login-mfa", response_model=TokenResponse)
def login_step_two(payload: LoginMFARequest, db: Session = Depends(get_db)):
    """Verify password+OTP together and issue a JWT."""
    user = db.query(UserAccount).filter(UserAccount.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled for this account")
    if not user.mfa_secret or not verify_otp(user.mfa_secret, payload.otp_code):
        raise HTTPException(status_code=401, detail="Invalid authenticator code")

    token = create_access_token(user.id, user.email)
    return TokenResponse(access_token=token, user=user)
