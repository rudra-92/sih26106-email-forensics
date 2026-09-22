"""API router for administrative user management."""

from __future__ import annotations

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth.dependencies import require_admin
from ..db.models import User
from ..db.session import get_db
from ..repositories.user_repository import UserRepository
from ..schemas.auth import (
    UserListResponse,
    UserStatusUpdateRequest,
    UserSummaryResponse,
)

router = APIRouter(prefix="/api/admin", tags=["Administration"])


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List all registered users (Admin only)",
)
def list_all_users(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserListResponse:
    """Retrieve all users across the platform."""
    user_repo = UserRepository(session=db)
    users_raw = user_repo.list_users()
    users: List[UserSummaryResponse] = [
        UserSummaryResponse(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at,
            last_login_at=u.last_login_at,
        )
        for u in users_raw
    ]
    return UserListResponse(total=len(users), users=users)


@router.patch(
    "/users/{user_id}/status",
    response_model=UserSummaryResponse,
    summary="Activate or deactivate a user account (Admin only)",
)
def update_user_status(
    user_id: str,
    payload: UserStatusUpdateRequest,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> UserSummaryResponse:
    """Activate or deactivate a user.

    Deactivated users will be prevented from making subsequent authenticated
    calls. Existing forensic cases owned by the user are safely preserved.
    """
    user_repo = UserRepository(session=db)
    updated_user = user_repo.update_user_status(
        user_id=user_id, is_active=payload.is_active
    )
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' was not found.",
        )

    return UserSummaryResponse(
        id=updated_user.id,
        email=updated_user.email,
        full_name=updated_user.full_name,
        role=updated_user.role,
        is_active=updated_user.is_active,
        created_at=updated_user.created_at,
        last_login_at=updated_user.last_login_at,
    )
