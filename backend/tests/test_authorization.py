"""Unit and integration tests for role-based authorization.

Verifies case isolation and privilege separation.
"""

from __future__ import annotations

import io
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.auth.security import hash_password
from backend.repositories.case_repository import CaseRepository
from backend.repositories.user_repository import UserRepository


def test_27_unauthenticated_cases_endpoint_returns_401(
    unauthenticated_client: TestClient,
) -> None:
    """Ensure accessing cases without credentials returns HTTP 401."""
    res_list = unauthenticated_client.get("/api/cases")
    assert res_list.status_code == 401

    res_get = unauthenticated_client.get("/api/cases/CASE-ANY")
    assert res_get.status_code == 401

    res_post = unauthenticated_client.post(
        "/api/cases", json={"title": "Unauthorized"}
    )
    assert res_post.status_code == 401


def test_28_investigator_sees_own_cases(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure investigator retrieves only their own cases on GET /api/cases."""
    # Create case as default investigator (authenticated in 'client')
    c1 = client.post("/api/cases", json={"title": "Investigator 1 Case"})
    assert c1.status_code == 201
    c1_id = c1.json()["case_id"]

    res = client.get("/api/cases")
    assert res.status_code == 200
    case_ids = [c["case_id"] for c in res.json()["cases"]]
    assert c1_id in case_ids


def test_29_investigator_cannot_see_another_users_case(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure investigator receives HTTP 403 on another user's case."""
    session: Session = temp_backend_env["session"]
    user_repo = UserRepository(session=session)
    inv2 = user_repo.create_user(
        user_id="user-inv-002",
        email="inv2@forensics.local",
        password_hash=hash_password("Pass12345!"),
        full_name="Second Investigator",
        role="investigator",
    )

    case_repo = CaseRepository(session=session)
    c2 = case_repo.create_case(
        case_id="CASE-INV2-SECRET",
        title="Secret Case of Inv2",
        owner_user_id=inv2.id,
    )

    # First investigator (client) attempts to read inv2's case
    res = client.get(f"/api/cases/{c2['case_id']}")
    assert res.status_code == 403
    assert "permission" in res.json()["detail"].lower()


def test_30_investigator_cannot_modify_another_users_case(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure investigator receives 403 when uploading to another's case."""
    session: Session = temp_backend_env["session"]
    user_repo = UserRepository(session=session)
    inv2 = user_repo.create_user(
        user_id="user-inv-002-mod",
        email="inv2mod@forensics.local",
        password_hash=hash_password("Pass12345!"),
        full_name="Second Investigator",
        role="investigator",
    )

    case_repo = CaseRepository(session=session)
    c2 = case_repo.create_case(
        case_id="CASE-INV2-UPLOAD",
        title="Inv2 Upload Case",
        owner_user_id=inv2.id,
    )

    # First investigator attempts upload
    res = client.post(
        f"/api/cases/{c2['case_id']}/email",
        files={
            "file": (
                "hack.eml",
                io.BytesIO(b"From: hacker@evil.com\r\n\r\nHello"),
                "message/rfc822",
            )
        },
    )
    assert res.status_code == 403


def test_31_investigator_cannot_analyze_another_users_case(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure investigator receives HTTP 403 when analyzing another's case."""
    session: Session = temp_backend_env["session"]
    user_repo = UserRepository(session=session)
    inv2 = user_repo.create_user(
        user_id="user-inv-002-ana",
        email="inv2ana@forensics.local",
        password_hash=hash_password("Pass12345!"),
        full_name="Second Investigator",
        role="investigator",
    )

    case_repo = CaseRepository(session=session)
    c2 = case_repo.create_case(
        case_id="CASE-INV2-ANA",
        title="Inv2 Ana Case",
        owner_user_id=inv2.id,
    )

    res = client.post(f"/api/cases/{c2['case_id']}/analyze")
    assert res.status_code == 403


def test_32_investigator_cannot_access_another_users_evidence(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure investigator receives HTTP 403 on another user's evidence."""
    session: Session = temp_backend_env["session"]
    user_repo = UserRepository(session=session)
    inv2 = user_repo.create_user(
        user_id="user-inv-002-evi",
        email="inv2evi@forensics.local",
        password_hash=hash_password("Pass12345!"),
        full_name="Second Investigator",
        role="investigator",
    )

    case_repo = CaseRepository(session=session)
    c2 = case_repo.create_case(
        case_id="CASE-INV2-EVI",
        title="Inv2 Evidence Case",
        owner_user_id=inv2.id,
    )

    endpoints = [
        "evidence",
        "entities",
        "relationships",
        "hypotheses",
        "origin",
        "summary",
    ]
    for ep in endpoints:
        res = client.get(f"/api/cases/{c2['case_id']}/{ep}")
        assert res.status_code == 403, f"Endpoint {ep} did not enforce 403"


def test_33_admin_sees_all_cases(
    admin_client: TestClient, client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure administrators can list and access all cases."""
    # Create case as investigator
    res = client.post(
        "/api/cases", json={"title": "Investigator Case For Admin"}
    )
    assert res.status_code == 201
    c_id = res.json()["case_id"]

    # Admin reads case list
    res_list = admin_client.get("/api/cases")
    assert res_list.status_code == 200
    case_ids = [c["case_id"] for c in res_list.json()["cases"]]
    assert c_id in case_ids

    # Admin reads case detail
    res_detail = admin_client.get(f"/api/cases/{c_id}")
    assert res_detail.status_code == 200
    assert res_detail.json()["case_id"] == c_id


def test_34_non_admin_cannot_access_admin_endpoints(
    client: TestClient,
) -> None:
    """Ensure normal investigators receive HTTP 403 on admin endpoints."""
    res_users = client.get("/api/admin/users")
    assert res_users.status_code == 403

    res_patch = client.patch(
        "/api/admin/users/any-id/status", json={"is_active": False}
    )
    assert res_patch.status_code == 403


def test_35_admin_can_deactivate_user(
    admin_client: TestClient,
    unauthenticated_client: TestClient,
    temp_backend_env: dict,
) -> None:
    """Ensure admin can toggle user active status, immediately revoking."""
    # Register a new investigator
    reg = unauthenticated_client.post(
        "/api/auth/register",
        json={
            "email": "targetuser@forensics.local",
            "password": "Password123!",
            "full_name": "Target User",
        },
    )
    target_id = reg.json()["id"]

    # Login to get token
    login = unauthenticated_client.post(
        "/api/auth/login",
        json={
            "email": "targetuser@forensics.local",
            "password": "Password123!",
        },
    )
    target_token = login.json()["access_token"]

    # Token works initially
    res_init = unauthenticated_client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {target_token}"}
    )
    assert res_init.status_code == 200

    # Admin deactivates target user
    res_deact = admin_client.patch(
        f"/api/admin/users/{target_id}/status",
        json={"is_active": False},
    )
    assert res_deact.status_code == 200
    assert res_deact.json()["is_active"] is False

    # Target user token is now rejected with 401
    res_blocked = unauthenticated_client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {target_token}"}
    )
    assert res_blocked.status_code == 401
    assert "deactivated" in res_blocked.json()["detail"].lower()
