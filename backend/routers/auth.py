import base64
from io import BytesIO

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


@router.post("/register", response_model=UserResponse)
def register_user(payload: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(UserAccount).filter(UserAccount.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = UserAccount(
        email=payload.email,
        name=payload.name,
        password_hash=hash_password(payload.password),
        mfa_secret=generate_mfa_secret(),
        mfa_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/setup-mfa")
def setup_mfa(payload: UserLogin, db: Session = Depends(get_db)):
    """Returns the QR code so a freshly registered user can enroll an authenticator."""
    user = db.query(UserAccount).filter(UserAccount.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.mfa_secret:
        user.mfa_secret = generate_mfa_secret()
        db.commit()
        db.refresh(user)

    uri = build_mfa_uri(user.mfa_secret, user.email)
    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return {
        "message": "Scan this QR code with Google Authenticator",
        "otpauth_uri": uri,
        "qr_code_base64": qr_b64,
    }


@router.post("/verify-mfa")
def verify_mfa(payload: MFAVerifyRequest, db: Session = Depends(get_db)):
    user = db.query(UserAccount).filter(UserAccount.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA secret is not set")
    if not verify_otp(user.mfa_secret, payload.otp_code):
        raise HTTPException(status_code=400, detail="Invalid OTP code")

    user.mfa_enabled = True
    db.commit()
    return {"message": "MFA enabled successfully"}


@router.post("/login")
def login_step_one(payload: UserLogin, db: Session = Depends(get_db)):
    """Verify password. Tells the frontend to collect an OTP next."""
    user = db.query(UserAccount).filter(UserAccount.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.mfa_enabled:
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
