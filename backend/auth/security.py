"""Security utilities: Argon2 password hashing, PyJWT token management, and Supabase JWT verification."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
import re
from typing import Any, Dict, Optional
import urllib.request
import urllib.error

import argon2
from argon2.exceptions import VerifyMismatchError
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from ..config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    JWT_ALGORITHM,
    JWT_SECRET_KEY,
    SUPABASE_URL,
    SUPABASE_ANON_KEY,
    SUPABASE_JWT_SECRET,
)

logger = logging.getLogger(__name__)

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

_jwks_client: Optional[jwt.PyJWKClient] = None


def get_jwks_client() -> Optional[jwt.PyJWKClient]:
    """Lazy initialize and cache PyJWKClient for Supabase JWKS endpoint."""
    global _jwks_client
    if _jwks_client is None and SUPABASE_URL:
        jwks_url = f"{SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"
        try:
            _jwks_client = jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=3600)
        except Exception as exc:
            logger.warning("Failed to initialize Supabase PyJWKClient: %s", exc)
    return _jwks_client


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


def verify_token_with_supabase_api(token: str) -> Dict[str, Any]:
    """Verify access token directly with Supabase Auth API as authoritative fallback.

    GET /auth/v1/user
    """
    if not SUPABASE_URL or not SUPABASE_ANON_KEY:
        raise InvalidTokenError("Supabase configuration missing.")

    endpoint = f"{SUPABASE_URL.rstrip('/')}/auth/v1/user"
    req = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "apikey": SUPABASE_ANON_KEY,
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                return {
                    "sub": data.get("id"),
                    "id": data.get("id"),
                    "email": data.get("email"),
                    "user_metadata": data.get("user_metadata", {}),
                    "app_metadata": data.get("app_metadata", {}),
                    "role": data.get("user_metadata", {}).get("role") or data.get("app_metadata", {}).get("role"),
                }
    except urllib.error.HTTPError as err:
        if err.code == 401:
            raise InvalidTokenError("Supabase token rejected or expired.")
        raise InvalidTokenError(f"Supabase auth service returned HTTP {err.code}")
    except Exception as exc:
        raise InvalidTokenError(f"Unable to reach Supabase Auth API: {exc}")

    raise InvalidTokenError("Invalid token.")


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate signed JWT token (Supabase Auth or local).

    Supports:
    1. Supabase JWKS (ES256 / RS256)
    2. Supabase Secret Key (HS256)
    3. Supabase Auth API (/auth/v1/user) verification
    4. Local backend JWT secret fallback (for test isolation)

    Raises:
        ExpiredSignatureError: If token has expired.
        InvalidTokenError: If token is malformed, has invalid signature, etc.
    """
    if not token or not isinstance(token, str):
        raise InvalidTokenError("Invalid token format.")

    # 1. Try Supabase JWKS verification
    try:
        jwks_client = get_jwks_client()
        if jwks_client:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["ES256", "RS256", "HS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,
                },
            )
            return payload
    except ExpiredSignatureError:
        raise
    except Exception as exc:
        logger.debug("JWKS validation failed, trying alternate methods: %s", exc)

    # 2. Try Supabase JWT Secret (if configured)
    if SUPABASE_JWT_SECRET:
        try:
            return jwt.decode(
                token,
                SUPABASE_JWT_SECRET,
                algorithms=["HS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,
                },
            )
        except ExpiredSignatureError:
            raise
        except Exception:
            pass

    # 3. Try Supabase Auth API verification
    if SUPABASE_URL and SUPABASE_ANON_KEY:
        try:
            return verify_token_with_supabase_api(token)
        except ExpiredSignatureError:
            raise
        except Exception:
            pass

    # 4. Fallback to local JWT Secret (for local unit tests and legacy tokens)
    try:
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
    except ExpiredSignatureError:
        raise
    except Exception as exc:
        raise InvalidTokenError(f"Invalid or unauthorized token: {exc}")
