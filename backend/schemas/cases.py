"""Pydantic schemas for case management and file operations."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class CaseCreateRequest(BaseModel):
    """Payload for creating a new investigation case."""

    title: str = Field(
        ...,
        min_length=1,
        max_length=200,
        description="Investigative case title",
    )


class CaseResponse(BaseModel):
    """Case summary model returned by case management endpoints."""

    case_id: str
    owner_user_id: Optional[str] = None
    title: str
    status: str
    created_at: str
    updated_at: str
    original_filename: Optional[str] = None
    file_sha256: Optional[str] = None
    file_size_bytes: Optional[int] = None
    analysis_status: str
    threat_label: Optional[str] = None
    threat_confidence: Optional[float] = None
    threat_confidence_metric: Optional[str] = None
    summary: Optional[str] = None
    evidence_count: int = 0
    entity_count: int = 0
    relationship_count: int = 0
    hypothesis_count: int = 0
    error_message: Optional[str] = None


class CaseListResponse(BaseModel):
    """Collection of case summaries."""

    total: int
    cases: List[CaseResponse]


class FileUploadResponse(BaseModel):
    """Response returned upon successful email upload."""

    case_id: str
    original_filename: str
    file_sha256: str
    file_size_bytes: int
    message: str


class AnalysisTriggerResponse(BaseModel):
    """Response returned when an analysis job is initiated or completed."""

    case_id: str
    analysis_status: str
    message: str
    threat_label: Optional[str] = None
    threat_confidence: Optional[float] = None
