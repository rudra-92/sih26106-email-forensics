"""Authentication package exposing security functions and dependencies."""

from .security import (
    create_access_token,
    decode_access_token,
    hash_password,
    normalize_email,
    validate_password,
    verify_password,
)

__all__ = [
    "hash_password",
    "verify_password",
    "validate_password",
    "normalize_email",
    "create_access_token",
    "decode_access_token",
]
