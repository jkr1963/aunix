import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from passlib.context import CryptContext

# ---------------- Passwords ----------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ---------------- TOTP / MFA ----------------

def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def verify_otp(secret: str, otp_code: str) -> bool:
    return pyotp.TOTP(secret).verify(otp_code, valid_window=1)


def build_mfa_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="AUNIX")


# ---------------- JWT (user sessions) ----------------

JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))


def create_access_token(user_id: int, email: str) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


# ---------------- Agent tokens (per-target API keys) ----------------

def generate_agent_token() -> str:
    """Opaque, URL-safe token. ~256 bits of entropy."""
    return "aunix_" + secrets.token_urlsafe(32)


def hash_agent_token(token: str) -> str:
    """SHA-256 of the token. Stored in DB; the plaintext only goes to the agent."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
