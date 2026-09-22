"""Security regression tests: privilege escalation and secret safety."""

from __future__ import annotations

import io
from fastapi.testclient import TestClient

from backend.config import JWT_SECRET_KEY


def test_sec_01_password_and_hash_never_leaked_in_any_response(
    unauthenticated_client: TestClient, client: TestClient
) -> None:
    """Ensure password, hash, and secret key never appear in API responses."""
    # Register
    reg_res = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "leaktest@forensics.local",
            "password": "SuperSecretPassword123!",
            "full_name": "Leak Tester",
        },
    )
    assert reg_res.status_code == 201
    assert "SuperSecretPassword123!" not in reg_res.text
    assert "password_hash" not in reg_res.text

    # Login
    login_res = unauthenticated_client.post(
        "/api/auth/login",
        json={
            "email": "leaktest@forensics.local",
            "password": "SuperSecretPassword123!",
        },
    )
    assert login_res.status_code == 200
    assert "SuperSecretPassword123!" not in login_res.text
    assert "password_hash" not in login_res.text
    assert JWT_SECRET_KEY not in login_res.text

    # Get /me
    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert "password" not in me_res.text
    assert "password_hash" not in me_res.text
    assert JWT_SECRET_KEY not in me_res.text


def test_sec_02_role_cannot_be_escalated_via_json(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure attempts to register as admin default to investigator."""
    res = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "escalation@forensics.local",
            "password": "ValidPassword123!",
            "full_name": "Privilege Escalator",
            "role": "admin",
            "is_admin": True,
            "permissions": ["all"],
        },
    )
    assert res.status_code == 201
    assert res.json()["role"] == "investigator"


def test_sec_03_path_traversal_on_upload_blocked(
    client: TestClient,
) -> None:
    """Ensure filename path traversal attempts (../../) are neutralized."""
    # Create case
    case_res = client.post("/api/cases", json={"title": "Traversal Test"})
    case_id = case_res.json()["case_id"]

    # Upload with dangerous traversal filename
    upload_res = client.post(
        f"/api/cases/{case_id}/email",
        files={
            "file": (
                "../../../../etc/passwd.eml",
                io.BytesIO(b"From: safe@test.local\r\n\r\nHello"),
                "message/rfc822",
            )
        },
    )
    assert upload_res.status_code == 200
    upload_data = upload_res.json()
    stored_name = upload_data["original_filename"]
    # Sanitized or stripped of path separators
    assert ".." not in stored_name
    assert "/" not in stored_name
    assert "\\" not in stored_name


def test_sec_04_tampered_jwt_rejected(
    unauthenticated_client: TestClient, client: TestClient
) -> None:
    """Ensure JWTs with tampered signatures or headers are rejected."""
    # Tamper with the token
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l"
        "IiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    tampered_headers = {"Authorization": f"Bearer {token}"}
    res = unauthenticated_client.get("/api/auth/me", headers=tampered_headers)
    assert res.status_code == 401


def test_sec_05_algorithm_manipulation_blocked(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure tokens attempting algorithm confusion (alg: none) are blocked."""
    # Token forged with alg: none
    none_alg_token = (
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyMDAwMDAwMDAw"
        "LCJpYXQiOjE1MTYyMzkwMjJ9."
    )
    res = unauthenticated_client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {none_alg_token}"}
    )
    assert res.status_code == 401


def test_sec_06_db_connection_is_not_superuser(
    temp_backend_env: dict,
) -> None:
    """Ensure application database connection is not superuser."""
    from sqlalchemy import text

    session = temp_backend_env["session"]
    row = session.execute(
        text(
            "SELECT current_user, usesuper FROM pg_user "
            "WHERE usename = current_user;"
        )
    ).fetchone()
    assert row is not None
    current_user, is_superuser = row[0], row[1]
    assert current_user == "sih26106_app"
    assert is_superuser is False
