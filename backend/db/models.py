"""SQLAlchemy models for users, cases, and structured forensic evidence."""

from __future__ import annotations

from typing import List, Optional
from sqlalchemy import (
    Boolean,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


class User(Base):
    """User account model for investigators and platform administrators."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(50), nullable=False, default="investigator"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    created_at: Mapped[str] = mapped_column(String(50), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(50), nullable=False)
    last_login_at: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )

    cases: Mapped[List["Case"]] = relationship(
        "Case", back_populates="owner"
    )


class Case(Base):
    """Investigation case container model."""

    __tablename__ = "cases"

    case_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    owner_user_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("users.id"), index=True, nullable=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="open"
    )
    created_at: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    updated_at: Mapped[str] = mapped_column(String(50), nullable=False)
    original_filename: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    file_sha256: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )
    file_path: Mapped[Optional[str]] = mapped_column(
        String(1024), nullable=True
    )
    file_size_bytes: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    raw_eml_content: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    analysis_status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="pending", index=True
    )
    threat_label: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    threat_confidence: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )
    threat_confidence_metric: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    entity_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    relationship_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    hypothesis_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    owner: Mapped[Optional[User]] = relationship(
        "User", back_populates="cases"
    )
    evidence: Mapped[List["CaseEvidence"]] = relationship(
        "CaseEvidence", back_populates="case"
    )
    entities: Mapped[List["CaseEntity"]] = relationship(
        "CaseEntity", back_populates="case"
    )
    relationships: Mapped[List["CaseRelationship"]] = relationship(
        "CaseRelationship", back_populates="case"
    )
    hypotheses: Mapped[List["CaseHypothesis"]] = relationship(
        "CaseHypothesis", back_populates="case"
    )
    analysis_data: Mapped[Optional["CaseAnalysisData"]] = relationship(
        "CaseAnalysisData", back_populates="case", uselist=False
    )


class CaseEvidence(Base):
    """Normalized forensic evidence item model."""

    __tablename__ = "case_evidence"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    case_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("cases.case_id"), index=True, nullable=False
    )
    evidence_id: Mapped[str] = mapped_column(String(100), nullable=False)
    source_module: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    trust_state: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    entity_ids_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    timestamp: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    provenance_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    supporting_fields_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    case: Mapped[Case] = relationship("Case", back_populates="evidence")


class CaseEntity(Base):
    """Normalized investigative entity model."""

    __tablename__ = "case_entities"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    case_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("cases.case_id"), index=True, nullable=False
    )
    entity_id: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False)
    canonical_value: Mapped[str] = mapped_column(Text, nullable=False)
    source_modules_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    first_observed_timestamp: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    attributes_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    case: Mapped[Case] = relationship("Case", back_populates="entities")


class CaseRelationship(Base):
    """Extracted relationship between investigative entities."""

    __tablename__ = "case_relationships"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    case_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("cases.case_id"), index=True, nullable=False
    )
    relationship_id: Mapped[str] = mapped_column(String(100), nullable=False)
    source_entity_id: Mapped[str] = mapped_column(String(100), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(100), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_ids_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    source_modules_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    trust_state: Mapped[str] = mapped_column(String(50), nullable=False)
    timestamp: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    provenance_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    case: Mapped[Case] = relationship("Case", back_populates="relationships")


class CaseHypothesis(Base):
    """Forensic hypothesis with evidence linkage."""

    __tablename__ = "case_hypotheses"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    case_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("cases.case_id"), index=True, nullable=False
    )
    hypothesis_id: Mapped[str] = mapped_column(String(100), nullable=False)
    hypothesis_type: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_metric: Mapped[str] = mapped_column(String(100), nullable=False)
    supporting_evidence_ids_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    contradicting_evidence_ids_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    provenance_json: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    case: Mapped[Case] = relationship("Case", back_populates="hypotheses")


class CaseAnalysisData(Base):
    """Large structured analysis payloads (origin, summary, full case)."""

    __tablename__ = "case_analysis_data"

    case_id: Mapped[str] = mapped_column(
        String(100), ForeignKey("cases.case_id"), primary_key=True
    )
    origin_json: Mapped[str] = mapped_column(Text, nullable=False)
    summary_json: Mapped[str] = mapped_column(Text, nullable=False)
    full_case_json: Mapped[str] = mapped_column(Text, nullable=False)

    case: Mapped[Case] = relationship(
        "Case", back_populates="analysis_data"
    )
