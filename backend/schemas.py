from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


# ---------------- Auth ----------------

class UserRegister(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=8, max_length=200)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class MFAVerifyRequest(BaseModel):
    email: EmailStr
    otp_code: str


class LoginMFARequest(BaseModel):
    email: EmailStr
    password: str
    otp_code: str


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    name: str
    mfa_enabled: bool

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ---------------- Targets ----------------

class TargetCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None


class TargetResponse(BaseModel):
    id: int
    hostname: str
    ip_address: Optional[str]
    operating_system: Optional[str]
    status: str
    last_scan_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class TargetCreateResponse(TargetResponse):
    """Returned only at creation time. Agent token is shown once."""
    agent_token: str
    install_command: str


# ---------------- Keys ----------------

class SSHKeyResponse(BaseModel):
    id: int
    target_id: int
    username: Optional[str]
    file_path: str
    fingerprint: str
    key_algorithm: Optional[str]
    key_bits: Optional[int]
    last_modified: Optional[str]
    last_accessed: Optional[str]
    owner: Optional[str]
    permissions: Optional[str]
    file_type: Optional[str]
    key_kind: Optional[str]
    paired_key_status: Optional[str]

    # Computed fields, attached by the API:
    severity: Optional[str] = None       # "critical" | "high" | "medium" | "info"
    findings: List[str] = []             # human-readable issue descriptions
    recommendations: List[str] = []      # parallel list - fix advice per finding

    class Config:
        from_attributes = True


# ---------------- Scan upload (from agent) ----------------

class ScanResultItem(BaseModel):
    username: Optional[str] = None
    file_path: str
    fingerprint: str
    key_algorithm: Optional[str] = None
    key_bits: Optional[int] = None
    last_modified: Optional[str] = None
    last_accessed: Optional[str] = None
    owner: Optional[str] = None
    permissions: Optional[str] = None
    file_type: Optional[str] = None
    key_kind: Optional[str] = None
    paired_key_status: Optional[str] = None


class PolicyFindingItem(BaseModel):
    """One finding from the agent's policy audit."""
    rule_id: str
    category: str            # sshd | passwd | shadow | sudoers
    severity: str            # critical | high | medium | info
    title: str
    description: str
    file_path: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None


class ScanUploadRequest(BaseModel):
    scan_type: str = "quick"
    hostname: Optional[str] = None
    operating_system: Optional[str] = None
    keys: List[ScanResultItem]
    policy_findings: List[PolicyFindingItem] = []


class PolicyFindingResponse(BaseModel):
    id: int
    target_id: int
    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    file_path: Optional[str]
    evidence: Optional[str]
    recommendation: Optional[str]

    class Config:
        from_attributes = True


# ---------------- Dashboard summary ----------------

class FleetSummary(BaseModel):
    """Cross-machine view for the executive overview."""
    total_machines: int
    machines_reporting: int       # has scanned at least once
    machines_silent: int          # last_scan_at older than threshold
    machines_never_scanned: int   # registered but no data yet

    total_keys: int
    unique_fingerprints: int      # distinct keys across the estate
    private_keys: int
    public_keys: int

    findings_by_severity: dict    # {"critical": N, "high": N, "medium": N}
    posture_score: int            # 0-100 weighted by severity, higher is better

    algorithm_distribution: dict  # {"RSA-2048": N, "ED25519": N, ...}

    top_risk_machines: List[dict]  # [{id, hostname, critical, high, medium, key_count}, ...]
    shared_keys: List[dict]        # [{fingerprint, algorithm, bits, machine_count, hostnames}, ...]
