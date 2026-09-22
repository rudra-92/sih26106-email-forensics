"""API router for forensic analysis and artifact retrieval."""

from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_owned_case
from ..db.session import get_db
from ..repositories.case_repository import (
    CaseRepository,
    ConcurrencyConflictError,
)
from ..schemas.analysis import (
    EntityListResponse,
    EvidenceListResponse,
    HypothesisListResponse,
    OriginResponse,
    RelationshipListResponse,
    SummaryResponse,
)
from ..schemas.cases import AnalysisTriggerResponse
from ..services.analysis_service import AnalysisService

router = APIRouter(prefix="/api/cases/{case_id}", tags=["Analysis"])


def get_analysis_service(db: Session = Depends(get_db)) -> AnalysisService:
    """Dependency provider for AnalysisService."""
    repo = CaseRepository(session=db)
    return AnalysisService(repository=repo)


@router.post(
    "/analyze",
    response_model=AnalysisTriggerResponse,
    summary="Trigger full forensic pipeline analysis",
)
def analyze_case(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
    service: AnalysisService = Depends(get_analysis_service),
) -> AnalysisTriggerResponse:
    """Run Modules 1-6, ML Fusion, and Enrichment on case email file."""
    try:
        res = service.run_case_analysis(case_id)
        summary = res.get("summary", {})
        return AnalysisTriggerResponse(
            case_id=case_id,
            analysis_status=res.get("status", "completed"),
            message=res.get("message", "Analysis completed."),
            threat_label=summary.get("threat_label"),
            threat_confidence=summary.get("threat_confidence"),
        )
    except ConcurrencyConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline execution failed: {str(exc)}",
        )


@router.get(
    "/evidence",
    response_model=EvidenceListResponse,
    summary="Get normalized forensic evidence",
)
def get_case_evidence(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
    service: AnalysisService = Depends(get_analysis_service),
) -> EvidenceListResponse:
    """Retrieve normalized forensic evidence items for the case."""
    try:
        res = service.get_evidence(case_id)
        evidence = res.get("evidence", [])
        return EvidenceListResponse(
            case_id=case_id,
            total=len(evidence),
            evidence=evidence,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@router.get(
    "/entities",
    response_model=EntityListResponse,
    summary="Get extracted forensic entities",
)
def get_case_entities(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
    service: AnalysisService = Depends(get_analysis_service),
) -> EntityListResponse:
    """Retrieve resolved entities for the case."""
    try:
        res = service.get_entities(case_id)
        entities = res.get("entities", [])
        return EntityListResponse(
            case_id=case_id,
            total=len(entities),
            entities=entities,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@router.get(
    "/relationships",
    response_model=RelationshipListResponse,
    summary="Get forensic graph relationships",
)
def get_case_relationships(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
    service: AnalysisService = Depends(get_analysis_service),
) -> RelationshipListResponse:
    """Retrieve graph relationships between entities for the case."""
    try:
        res = service.get_relationships(case_id)
        relationships = res.get("relationships", [])
        return RelationshipListResponse(
            case_id=case_id,
            total=len(relationships),
            relationships=relationships,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@router.get(
    "/hypotheses",
    response_model=HypothesisListResponse,
    summary="Get generated hypotheses",
)
def get_case_hypotheses(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
    service: AnalysisService = Depends(get_analysis_service),
) -> HypothesisListResponse:
    """Retrieve investigative hypotheses for the case."""
    try:
        res = service.get_hypotheses(case_id)
        hypotheses = res.get("hypotheses", [])
        return HypothesisListResponse(
            case_id=case_id,
            total=len(hypotheses),
            hypotheses=hypotheses,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@router.get(
    "/origin",
    response_model=OriginResponse,
    summary="Get origin and network infrastructure data",
)
def get_case_origin(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
    service: AnalysisService = Depends(get_analysis_service),
) -> OriginResponse:
    """Retrieve origin and hop reconstruction for the case email."""
    try:
        res = service.get_origin(case_id)
        origin_data = res.get("origin", {})
        origin_data["case_id"] = case_id
        return OriginResponse(**origin_data)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )


@router.get(
    "/summary",
    response_model=SummaryResponse,
    summary="Get executive dashboard summary",
)
def get_case_summary(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
    service: AnalysisService = Depends(get_analysis_service),
) -> SummaryResponse:
    """Retrieve executive investigation summary for the case."""
    try:
        res = service.get_summary(case_id)
        summary_data = res.get("summary", {})
        summary_data["case_id"] = case_id
        return SummaryResponse(**summary_data)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
