"""API router for case management and email artifact upload."""

from __future__ import annotations

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user, get_owned_case
from ..config import STORAGE_DIR
from ..db.models import User
from ..db.session import get_db
from ..repositories.case_repository import CaseRepository
from ..schemas.cases import (
    CaseCreateRequest,
    CaseListResponse,
    CaseResponse,
    FileUploadResponse,
)
from ..services.case_service import CaseService

router = APIRouter(prefix="/api/cases", tags=["Cases"])


def get_case_repository(db: Session = Depends(get_db)) -> CaseRepository:
    """Dependency provider for CaseRepository."""
    return CaseRepository(session=db)


def get_case_service(
    repo: CaseRepository = Depends(get_case_repository),
) -> CaseService:
    """Dependency provider for CaseService."""
    return CaseService(repository=repo, storage_dir=STORAGE_DIR)


@router.post(
    "",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new investigation case",
)
def create_case(
    payload: CaseCreateRequest,
    current_user: User = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseResponse:
    """Create a new investigative case container.

    Owned by the authenticated user.
    """
    try:
        case = service.create_case(
            title=payload.title,
            owner_user_id=current_user.id,
        )
        return CaseResponse(**case)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.get(
    "",
    response_model=CaseListResponse,
    summary="List investigation cases",
)
def list_cases(
    current_user: User = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseListResponse:
    """Retrieve investigation cases.

    Investigators see only cases they own; administrators see all cases.
    """
    if current_user.role == "admin":
        cases_raw: List[dict] = service.list_cases()
    else:
        cases_raw = service.list_cases(owner_user_id=current_user.id)

    cases = [CaseResponse(**c) for c in cases_raw]
    return CaseListResponse(total=len(cases), cases=cases)


@router.get(
    "/{case_id}",
    response_model=CaseResponse,
    summary="Get case details by ID",
)
def get_case(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
) -> CaseResponse:
    """Retrieve single case record by case_id with ownership authorization."""
    return CaseResponse(**case)


@router.post(
    "/{case_id}/email",
    response_model=FileUploadResponse,
    summary="Upload original .eml file to case",
)
async def upload_email(
    case_id: str,
    file: UploadFile = File(...),
    case: Dict[str, Any] = Depends(get_owned_case),
    service: CaseService = Depends(get_case_service),
) -> FileUploadResponse:
    """Upload and immutably preserve the original .eml file for this case."""
    try:
        content_bytes = await file.read()
        filename = file.filename or "message.eml"
        res = service.upload_email(
            case_id=case_id,
            filename=filename,
            content_bytes=content_bytes,
        )
        return FileUploadResponse(
            case_id=res["case_id"],
            original_filename=res["original_filename"],
            file_sha256=res["file_sha256"],
            file_size_bytes=res["file_size_bytes"],
            message=res["message"],
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


@router.delete(
    "/{case_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete an investigation case",
)
def delete_case(
    case_id: str,
    case: Dict[str, Any] = Depends(get_owned_case),
    service: CaseService = Depends(get_case_service),
) -> Dict[str, Any]:
    """Permanently delete a forensic case container, entities, and evidence."""
    success = service.delete_case(case_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )
    return {
        "status": "ok",
        "message": f"Case '{case_id}' deleted successfully.",
        "case_id": case_id,
    }

