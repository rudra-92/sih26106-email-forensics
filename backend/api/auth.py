"""API router for user registration, authentication, and current profile."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth.dependencies import get_current_user
from ..auth.security import (
    create_access_token,
    hash_password,
    normalize_email,
    validate_password,
    verify_password,
)
from ..config import ACCESS_TOKEN_EXPIRE_MINUTES
from ..db.models import User
from ..db.session import get_db
from ..repositories.user_repository import UserRepository
from ..schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    UserSummaryResponse,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new investigator user",
)
def register_user(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
) -> RegisterResponse:
    """Create a new user account with investigator privileges."""
    try:
        clean_email = normalize_email(payload.email)
        validate_password(payload.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    clean_name = payload.full_name.strip()
    if not clean_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Full name cannot be blank.",
        )

    user_repo = UserRepository(session=db)
    existing_user = user_repo.get_user_by_email(clean_email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An account with email '{clean_email}' already exists.",
        )

    pw_hash = hash_password(payload.password)
    user_id = str(uuid.uuid4())

    # Self-registered users are strictly assigned role='investigator'
    user = user_repo.create_user(
        user_id=user_id,
        email=clean_email,
        password_hash=pw_hash,
        full_name=clean_name,
        role="investigator",
        is_active=True,
    )

    return RegisterResponse(
        id=user.id,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Authenticate and receive JWT bearer token",
)
def login_user(
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """Validate credentials and return a signed JWT access token."""
    clean_email = payload.email.strip().lower()
    user_repo = UserRepository(session=db)
    user = user_repo.get_user_by_email(clean_email)

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "User account is deactivated. "
                "Please contact an administrator."
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Record successful login timestamp
    user_repo.update_last_login(user.id)

    access_token = create_access_token(
        user_id=user.id,
        role=user.role,
    )

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserSummaryResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        ),
    )


@router.get(
    "/me",
    response_model=UserSummaryResponse,
    summary="Get current authenticated user profile",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> UserSummaryResponse:
    """Return profile attributes of the authenticated user."""
    return UserSummaryResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login_at=current_user.last_login_at,
    )
