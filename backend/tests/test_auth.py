"""Unit and integration tests for auth and JWT handling."""

from __future__ import annotations

from datetime import timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.auth.security import create_access_token
from backend.repositories.user_repository import UserRepository


def test_01_registration_succeeds(unauthenticated_client: TestClient) -> None:
    """Ensure valid user registration succeeds with HTTP 201."""
    res = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "analyst1@forensics.local",
            "password": "StrongPassword123!",
            "full_name": "Forensic Analyst",
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert data["email"] == "analyst1@forensics.local"
    assert data["full_name"] == "Forensic Analyst"
    assert data["role"] == "investigator"
    assert "id" in data
    assert "password" not in data
    assert "password_hash" not in data


def test_02_duplicate_registration_returns_409(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure duplicate email registration returns HTTP 409 Conflict."""
    payload = {
        "email": "duplicate@forensics.local",
        "password": "Password123!",
        "full_name": "Duplicate User",
    }
    res1 = unauthenticated_client.post("/api/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = unauthenticated_client.post("/api/auth/register", json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"].lower()


def test_03_invalid_email_returns_422(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure malformed email returns HTTP 422."""
    res = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "not-an-email",
            "password": "ValidPassword123!",
            "full_name": "Invalid Email",
        },
    )
    assert res.status_code == 422


def test_04_short_password_returns_422(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure passwords shorter than 8 chars return HTTP 422."""
    res = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "shortpw@forensics.local",
            "password": "short",
            "full_name": "Short Pass",
        },
    )
    assert res.status_code == 422


def test_05_login_succeeds(unauthenticated_client: TestClient) -> None:
    """Ensure valid login returns bearer access token and user profile."""
    # Register first
    unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "loginuser@forensics.local",
            "password": "LoginPassword123!",
            "full_name": "Login User",
        },
    )

    res = unauthenticated_client.post(
        "/api/auth/login",
        json={
            "email": "LOGINUSER@forensics.local",  # Test case-insensitivity
            "password": "LoginPassword123!",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0
    assert data["user"]["email"] == "loginuser@forensics.local"
    assert data["user"]["role"] == "investigator"
    assert "password" not in data["user"]
    assert "password_hash" not in data["user"]


def test_06_wrong_password_returns_401(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure incorrect password returns HTTP 401."""
    res = unauthenticated_client.post(
        "/api/auth/login",
        json={
            "email": "investigator@forensics.local",
            "password": "WrongPassword!",
        },
    )
    assert res.status_code == 401
    assert "invalid email or password" in res.json()["detail"].lower()


def test_07_nonexistent_account_returns_401(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure login with nonexistent email returns generic HTTP 401."""
    res = unauthenticated_client.post(
        "/api/auth/login",
        json={
            "email": "nonexistent@forensics.local",
            "password": "AnyPassword123!",
        },
    )
    assert res.status_code == 401
    assert "invalid email or password" in res.json()["detail"].lower()


def test_08_get_me_succeeds(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure GET /api/auth/me returns the authenticated user profile."""
    res = client.get("/api/auth/me")
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "investigator@forensics.local"
    assert data["role"] == "investigator"
    assert data["is_active"] is True
    assert "password_hash" not in data


def test_09_invalid_jwt_returns_401(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure invalid or forged JWT returns HTTP 401."""
    res = unauthenticated_client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer forged.invalid.token"},
    )
    assert res.status_code == 401


def test_10_expired_jwt_returns_401(
    unauthenticated_client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure expired JWT returns HTTP 401."""
    investigator = temp_backend_env["investigator"]
    expired_token = create_access_token(
        user_id=investigator.id,
        role=investigator.role,
        expires_delta=timedelta(seconds=-10),  # expired in past
    )
    res = unauthenticated_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


def test_11_inactive_user_rejected_returns_401(
    unauthenticated_client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure deactivated user cannot use previously issued JWT."""
    investigator = temp_backend_env["investigator"]
    token = temp_backend_env["inv_token"]
    session: Session = temp_backend_env["session"]

    # Deactivate the user in database
    user_repo = UserRepository(session=session)
    user_repo.update_user_status(investigator.id, is_active=False)

    res = unauthenticated_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 401
    assert "deactivated" in res.json()["detail"].lower()


def test_12_password_hash_never_appears_in_responses(
    unauthenticated_client: TestClient,
) -> None:
    """Verify password and hash never leak through register or login."""
    reg = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "safety@forensics.local",
            "password": "SafetyPassword123!",
            "full_name": "Safety Officer",
        },
    )
    assert "password_hash" not in reg.text
    assert "SafetyPassword123!" not in reg.text

    login = unauthenticated_client.post(
        "/api/auth/login",
        json={
            "email": "safety@forensics.local",
            "password": "SafetyPassword123!",
        },
    )
    assert "password_hash" not in login.text
    assert "SafetyPassword123!" not in login.text


def test_13_new_account_defaults_to_investigator(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure newly registered users default to investigator role."""
    res = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "defaultrole@forensics.local",
            "password": "DefaultPassword123!",
            "full_name": "Role Test",
        },
    )
    assert res.status_code == 201
    assert res.json()["role"] == "investigator"


def test_14_self_registration_cannot_create_admin(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure clients cannot escalate to admin during registration."""
    res = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "hacker@forensics.local",
            "password": "HackerPassword123!",
            "full_name": "Evil Actor",
            "role": "admin",  # Attempt privilege escalation
        },
    )
    assert res.status_code == 201
    # Role must still be investigator
    assert res.json()["role"] == "investigator"
