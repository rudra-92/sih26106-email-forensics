"""FastAPI authentication and authorization dependencies supporting Supabase Auth."""

from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.orm import Session

from ..db.models import User
from ..db.session import get_db
from ..repositories.case_repository import CaseRepository
from ..repositories.user_repository import UserRepository
from .security import decode_access_token

security_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        security_scheme
    ),
    db: Session = Depends(get_db),
) -> User:
    """Validate Supabase JWT bearer token and retrieve or auto-provision active user.

    Raises:
        HTTPException (401): If token is missing, expired, invalid, or user inactive.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Missing authentication token. "
                "Please provide 'Authorization: Bearer <token>'"
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        payload = decode_access_token(token)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub") or payload.get("id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload: missing subject identifier.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = str(payload.get("email") or "").strip().lower()
    user_metadata = payload.get("user_metadata") if isinstance(payload.get("user_metadata"), dict) else {}
    app_metadata = payload.get("app_metadata") if isinstance(payload.get("app_metadata"), dict) else {}

    raw_role = (
        payload.get("role")
        or user_metadata.get("role")
        or app_metadata.get("role")
    )
    if raw_role in ["admin", "investigator"]:
        role = raw_role
    else:
        role = "admin" if email == "admin@forensics.local" else "investigator"

    full_name = (
        user_metadata.get("full_name")
        or user_metadata.get("name")
        or (email.split("@")[0].capitalize() if email else "Investigator")
    )

    user_repo = UserRepository(session=db)
    user = user_repo.get_user_by_id(str(user_id))

    if not user and email:
        # Check if matching user exists by email (e.g. from local bootstrap)
        user = user_repo.get_user_by_email(email)

    if not user:
        # Auto-provision Supabase user in local DB to satisfy relational foreign keys
        user = user_repo.create_user(
            user_id=str(user_id),
            email=email or f"{user_id}@supabase.local",
            password_hash="supabase_auth_managed",
            full_name=full_name,
            role=role,
            is_active=True,
        )
    else:
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is deactivated. Access denied.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Keep admin role in sync if admin email is matched
        if role == "admin" and user.role != "admin":
            user.role = "admin"
            db.commit()
            db.refresh(user)

    return user


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """Ensure authenticated user has administrative privileges.

    Raises:
        HTTPException (403): If user does not have admin role.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required to access this endpoint.",
        )
    return current_user


def get_owned_case(
    case_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve case record verifying ownership or admin access.

    Raises:
        HTTPException (404): If case does not exist.
        HTTPException (403): If investigator does not own the case.
    """
    repo = CaseRepository(session=db)
    case = repo.get_case(case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found.",
        )

    # Admins can access all cases; investigators can only access own cases
    is_owner = case.get("owner_user_id") == current_user.id
    if current_user.role != "admin" and not is_owner:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"You do not have permission to access case '{case_id}'.",
        )

    return case
