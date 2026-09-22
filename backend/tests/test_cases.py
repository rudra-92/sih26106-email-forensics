"""Unit and integration tests for case lifecycle and ownership."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.auth.security import create_access_token, hash_password
from backend.repositories.user_repository import UserRepository


def test_36_case_creation_assigns_current_user(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure POST /api/cases assigns owner_user_id to current user."""
    investigator = temp_backend_env["investigator"]
    res = client.post(
        "/api/cases", json={"title": "Ownership Assignment Case"}
    )
    assert res.status_code == 201
    data = res.json()
    assert data["owner_user_id"] == investigator.id


def test_37_owner_user_id_cannot_be_injected_by_client(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure client cannot spoof or override owner_user_id in payload."""
    investigator = temp_backend_env["investigator"]
    res = client.post(
        "/api/cases",
        json={
            "title": "Injection Test Case",
            "owner_user_id": "spoofed-user-id-999",  # Attempt spoofing
        },
    )
    assert res.status_code == 201
    data = res.json()
    # The backend MUST overwrite/ignore spoofed owner
    assert data["owner_user_id"] == investigator.id
    assert data["owner_user_id"] != "spoofed-user-id-999"


def test_38_case_list_filters_correctly(
    client: TestClient,
    admin_client: TestClient,
    unauthenticated_client: TestClient,
    temp_backend_env: dict,
) -> None:
    """Ensure investigator sees only owned cases while admin sees all."""
    session: Session = temp_backend_env["session"]
    user_repo = UserRepository(session=session)
    other_user = user_repo.create_user(
        user_id="user-other-filter",
        email="other@forensics.local",
        password_hash=hash_password("Pass12345!"),
        full_name="Other User",
        role="investigator",
    )
    other_token = create_access_token(
        user_id=other_user.id, role=other_user.role
    )

    # 1. Investigator 1 creates a case
    c1 = client.post("/api/cases", json={"title": "User 1 Case"})
    assert c1.status_code == 201
    c1_id = c1.json()["case_id"]

    # 2. Investigator 2 creates a case
    c2 = unauthenticated_client.post(
        "/api/cases",
        json={"title": "User 2 Case"},
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert c2.status_code == 201
    c2_id = c2.json()["case_id"]

    # 3. Investigator 1 lists cases -> only sees c1
    list1 = client.get("/api/cases").json()["cases"]
    ids1 = [c["case_id"] for c in list1]
    assert c1_id in ids1
    assert c2_id not in ids1

    # 4. Investigator 2 lists cases -> only sees c2
    list2 = unauthenticated_client.get(
        "/api/cases", headers={"Authorization": f"Bearer {other_token}"}
    ).json()["cases"]
    ids2 = [c["case_id"] for c in list2]
    assert c2_id in ids2
    assert c1_id not in ids2

    # 5. Admin lists cases -> sees both c1 and c2
    list_admin = admin_client.get("/api/cases").json()["cases"]
    admin_ids = [c["case_id"] for c in list_admin]
    assert c1_id in admin_ids
    assert c2_id in admin_ids


def test_39_case_detail_authorization_works(
    client: TestClient,
    admin_client: TestClient,
    unauthenticated_client: TestClient,
    temp_backend_env: dict,
) -> None:
    """Verify detail authorization for owner, other user (403), admin (200)."""
    session: Session = temp_backend_env["session"]
    user_repo = UserRepository(session=session)
    other_user = user_repo.create_user(
        user_id="user-other-detail",
        email="otherdetail@forensics.local",
        password_hash=hash_password("Pass12345!"),
        full_name="Other Detail User",
        role="investigator",
    )
    other_token = create_access_token(
        user_id=other_user.id, role=other_user.role
    )

    # Investigator 1 creates case
    c = client.post("/api/cases", json={"title": "Detail Auth Case"})
    case_id = c.json()["case_id"]

    # Owner accesses -> 200
    res_owner = client.get(f"/api/cases/{case_id}")
    assert res_owner.status_code == 200

    # Non-owner investigator accesses -> 403
    res_stranger = unauthenticated_client.get(
        f"/api/cases/{case_id}",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert res_stranger.status_code == 403

    # Admin accesses -> 200
    res_admin = admin_client.get(f"/api/cases/{case_id}")
    assert res_admin.status_code == 200
    assert res_admin.json()["case_id"] == case_id
