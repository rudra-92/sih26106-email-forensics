"""Security utilities: Argon2 password hashing and PyJWT token management."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any, Dict, Optional
import argon2
from argon2.exceptions import VerifyMismatchError
import jwt

from ..config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
)

_hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)
MIN_PASSWORD_LENGTH = 8


def normalize_email(email: str) -> str:
    """Normalize and validate email format."""
    normalized = email.strip().lower()
    if not normalized or not EMAIL_REGEX.match(normalized):
        raise ValueError(f"Invalid email address format: '{email}'.")
    return normalized


def validate_password(password: str) -> None:
    """Enforce minimum password length and non-empty check."""
    if not password or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )


def hash_password(password: str) -> str:
    """Hash plaintext password with Argon2."""
    validate_password(password)
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against Argon2 hash."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, Exception):
        return False


def create_access_token(
    user_id: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generate signed JWT access token with minimal, non-sensitive claims."""
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "role": str(role),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate signed JWT token.

    Enforces explicit algorithm verification and required claims.

    Raises:
        ExpiredSignatureError: If token has expired.
        InvalidTokenError: If token is malformed, has invalid signature, etc.
    """
    return jwt.decode(
        token,
        JWT_SECRET_KEY,
        algorithms=[JWT_ALGORITHM],
        options={
            "require": ["exp", "sub", "iat"],
            "verify_signature": True,
            "verify_exp": True,
        },
    )
