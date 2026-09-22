"""Pydantic schemas for authentication, user management, and token exchange."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RegisterRequest(BaseModel):
    """Payload for new investigator user registration."""

    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Plaintext password")
    full_name: str = Field(
        ..., min_length=1, max_length=200, description="Full name"
    )

    model_config = ConfigDict(extra="ignore")


class RegisterResponse(BaseModel):
    """Response returned upon successful user registration."""

    id: str
    user_id: str
    email: str
    full_name: str
    role: str

    model_config = ConfigDict(from_attributes=True)


class LoginRequest(BaseModel):
    """Payload for user authentication."""

    email: str = Field(..., description="User email address")
    password: str = Field(..., description="Plaintext password")

    model_config = ConfigDict(extra="ignore")


class UserSummaryResponse(BaseModel):
    """User profile data excluding sensitive credentials."""

    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: str
    last_login_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class LoginResponse(BaseModel):
    """Response payload containing JWT bearer token and user summary."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserSummaryResponse


class UserStatusUpdateRequest(BaseModel):
    """Payload for administrative user status changes."""

    is_active: bool = Field(..., description="New active status")


class UserListResponse(BaseModel):
    """List of all registered user accounts for administration."""

    total: int
    users: List[UserSummaryResponse]
