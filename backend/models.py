from datetime import datetime
from sqlalchemy import (
    Column, Integer, Text, Boolean, ForeignKey, DateTime, Index
)
from sqlalchemy.orm import relationship
from database import Base


class UserAccount(Base):
    __tablename__ = "user_accounts"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(Text, nullable=False, unique=True, index=True)
    name = Column(Text, nullable=False)
    password_hash = Column(Text, nullable=False)
    mfa_secret = Column(Text, nullable=True)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    targets = relationship("TargetMachine", back_populates="owner",
                           cascade="all, delete-orphan")


class TargetMachine(Base):
    __tablename__ = "target_machines"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("user_accounts.id", ondelete="CASCADE"),
                     nullable=False, index=True)

    hostname = Column(Text, nullable=False)
    ip_address = Column(Text, nullable=True)
    operating_system = Column(Text, nullable=True)
    status = Column(Text, default="pending", nullable=False)
    # status values: pending (no scan yet), active (has scan data), inactive

    # Agent auth: scanner sends bearer token, we look up by sha256 of it.
    # Storing only the hash means a DB leak doesn't leak agent credentials.
    agent_token_hash = Column(Text, nullable=False, unique=True, index=True)

    last_scan_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    owner = relationship("UserAccount", back_populates="targets")
    keys = relationship("SSHKeyInventory", back_populates="target",
                        cascade="all, delete-orphan")


class SSHKeyInventory(Base):
    __tablename__ = "ssh_key_inventory"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("target_machines.id", ondelete="CASCADE"),
                       nullable=False, index=True)

    username = Column(Text, nullable=True)
    file_path = Column(Text, nullable=False)
    fingerprint = Column(Text, nullable=False)
    key_algorithm = Column(Text, nullable=True)  # e.g. "RSA", "ED25519", "ECDSA", "DSA"
    key_bits = Column(Integer, nullable=True)    # e.g. 2048, 4096, 256, 521
    last_modified = Column(Text, nullable=True)
    last_accessed = Column(Text, nullable=True)
    owner = Column(Text, nullable=True)
    permissions = Column(Text, nullable=True)
    file_type = Column(Text, nullable=True)
    key_kind = Column(Text, nullable=True)
    paired_key_status = Column(Text, nullable=True)

    target = relationship("TargetMachine", back_populates="keys")


Index("ix_ssh_key_target_fp", SSHKeyInventory.target_id, SSHKeyInventory.fingerprint)


class PolicyFinding(Base):
    """A single policy/configuration finding from a target machine."""
    __tablename__ = "policy_findings"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("target_machines.id", ondelete="CASCADE"),
                       nullable=False, index=True)

    # Rule identifier, e.g. "sshd.permit_root_login", "passwd.uid_zero".
    # Stable across versions so the dashboard can group/filter on it.
    rule_id = Column(Text, nullable=False)

    # Category: "sshd" | "passwd" | "shadow" | "sudoers"
    category = Column(Text, nullable=False)

    # "critical" | "high" | "medium" | "info"
    severity = Column(Text, nullable=False, index=True)

    # Human title, e.g. "Root login enabled over SSH"
    title = Column(Text, nullable=False)

    # Full description of what was found.
    description = Column(Text, nullable=False)

    # The file path that triggered the finding (e.g. /etc/ssh/sshd_config).
    file_path = Column(Text, nullable=True)

    # The offending line/value extracted from the file. Free-form text.
    evidence = Column(Text, nullable=True)

    # What the user should change it to.
    recommendation = Column(Text, nullable=True)


Index("ix_policy_target_severity", PolicyFinding.target_id, PolicyFinding.severity)
