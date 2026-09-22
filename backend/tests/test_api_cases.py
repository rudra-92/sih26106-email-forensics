"""Unit and integration tests for case management and email endpoints."""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from fastapi.testclient import TestClient


def test_health_and_root_endpoints(client: TestClient) -> None:
    """Ensure health and root discovery endpoints return expected status."""
    res_health = client.get("/health")
    assert res_health.status_code == 200
    data_health = res_health.json()
    assert data_health["status"] == "ok"
    assert "SIH26106" in data_health["service"]

    res_root = client.get("/")
    assert res_root.status_code == 200
    data_root = res_root.json()
    assert data_root["status"] == "active"
    assert "/docs" in data_root["docs_url"]


def test_case_crud_lifecycle(client: TestClient) -> None:
    """Test creating, fetching, and listing investigative cases."""
    # 1. Create a case
    res = client.post("/api/cases", json={"title": "Operation PhishShield"})
    assert res.status_code == 201
    case_data = res.json()
    case_id = case_data["case_id"]
    assert case_id.startswith("CASE-")
    assert case_data["title"] == "Operation PhishShield"
    assert case_data["analysis_status"] == "pending"

    # 2. Get the case by ID
    res_get = client.get(f"/api/cases/{case_id}")
    assert res_get.status_code == 200
    assert res_get.json()["case_id"] == case_id
    assert res_get.json()["title"] == "Operation PhishShield"

    # 3. Create a second case
    res2 = client.post("/api/cases", json={"title": "BEC Payroll Scam"})
    assert res2.status_code == 201

    # 4. List all cases
    res_list = client.get("/api/cases")
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["total"] >= 2
    case_ids = [c["case_id"] for c in list_data["cases"]]
    assert case_id in case_ids

    # 5. Nonexistent case
    res_not_found = client.get("/api/cases/CASE-DOESNOTEXIST")
    assert res_not_found.status_code == 404


def test_email_upload_and_exact_immutability(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Verify email bytes are saved immutably with exact SHA-256."""
    # Create case
    case_res = client.post("/api/cases", json={"title": "Immutability Test"})
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]

    raw_eml = (
        b"From: ceo@paypal-spoof.com\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: Immediate Wire Transfer\r\n\r\n"
        b"Please send $50,000 immediately.\r\n"
    )
    expected_sha256 = hashlib.sha256(raw_eml).hexdigest()

    file_obj = io.BytesIO(raw_eml)
    upload_res = client.post(
        f"/api/cases/{case_id}/email",
        files={"file": ("urgent_payment.eml", file_obj, "message/rfc822")},
    )
    assert upload_res.status_code == 200
    upload_data = upload_res.json()

    assert upload_data["case_id"] == case_id
    assert upload_data["original_filename"] == "urgent_payment.eml"
    assert upload_data["file_sha256"] == expected_sha256
    assert upload_data["file_size_bytes"] == len(raw_eml)

    # Verify preserved file on disk matches byte-for-byte
    case = client.get(f"/api/cases/{case_id}").json()
    assert case["file_sha256"] == expected_sha256

    repo = temp_backend_env["repo"]
    persisted_case = repo.get_case(case_id)
    assert persisted_case is not None
    stored_path = Path(persisted_case["file_path"])
    assert stored_path.is_file()

    with open(stored_path, "rb") as f:
        stored_bytes = f.read()

    assert stored_bytes == raw_eml
    assert hashlib.sha256(stored_bytes).hexdigest() == expected_sha256


def test_upload_validation_errors(client: TestClient) -> None:
    """Validate file extension, empty file, and missing case error handling."""
    # Create case
    case_res = client.post("/api/cases", json={"title": "Validation Test"})
    case_id = case_res.json()["case_id"]

    # 1. Invalid file extension (.exe)
    bad_file = io.BytesIO(b"MZ\x90\x00executable")
    res_bad_ext = client.post(
        f"/api/cases/{case_id}/email",
        files={"file": ("malware.exe", bad_file, "application/octet-stream")},
    )
    assert res_bad_ext.status_code == 400
    assert "Invalid file extension" in res_bad_ext.json()["detail"]

    # 2. Empty file
    empty_file = io.BytesIO(b"")
    res_empty = client.post(
        f"/api/cases/{case_id}/email",
        files={"file": ("empty.eml", empty_file, "message/rfc822")},
    )
    assert res_empty.status_code == 400
    assert "cannot be empty" in res_empty.json()["detail"]

    # 3. Upload to non-existent case
    some_file = io.BytesIO(b"From: test@test.com\n\nbody")
    res_no_case = client.post(
        "/api/cases/CASE-NOTFOUND/email",
        files={"file": ("test.eml", some_file, "message/rfc822")},
    )
    assert res_no_case.status_code == 404


def test_upload_filename_traversal_sanitization(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure traversal attacks in uploaded filenames are neutralized."""
    case_res = client.post("/api/cases", json={"title": "Traversal Test"})
    case_id = case_res.json()["case_id"]

    raw_eml = b"From: attacker@evil.com\r\n\r\nTraverse"
    file_obj = io.BytesIO(raw_eml)

    # Malicious traversal filename
    res = client.post(
        f"/api/cases/{case_id}/email",
        files={
            "file": (
                "../../../../etc/shadow.eml",
                file_obj,
                "message/rfc822",
            )
        },
    )
    assert res.status_code == 200

    repo = temp_backend_env["repo"]
    persisted_case = repo.get_case(case_id)
    assert persisted_case is not None
    stored_path = Path(persisted_case["file_path"])

    # File must reside strictly inside the case storage folder
    storage_dir = temp_backend_env["storage_dir"]
    assert str(stored_path).startswith(str(storage_dir))
    assert stored_path.is_file()
