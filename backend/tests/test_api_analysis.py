"""Unit and integration tests for forensic pipeline and artifact APIs."""

from __future__ import annotations

import io
from pathlib import Path
from fastapi.testclient import TestClient
import pytest

from backend.repositories.case_repository import (
    CaseRepository,
    ConcurrencyConflictError,
)

SAMPLE_EML_PATH = Path("ml/validation/forensic/reply_to_spoof.eml")


def test_analysis_requires_uploaded_file(client: TestClient) -> None:
    """Verify analysis request without an attached email returns 400."""
    case_res = client.post("/api/cases", json={"title": "Empty Case"})
    case_id = case_res.json()["case_id"]

    res = client.post(f"/api/cases/{case_id}/analyze")
    assert res.status_code == 400
    assert "no email file uploaded" in res.json()["detail"].lower()


def test_analysis_nonexistent_case(client: TestClient) -> None:
    """Verify analysis on non-existent case returns 404."""
    res = client.post("/api/cases/CASE-DOESNOTEXIST/analyze")
    assert res.status_code == 404


def test_analysis_concurrency_lock_returns_409(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Ensure simultaneous analysis requests on same case return 409."""
    repo: CaseRepository = temp_backend_env["repo"]

    # 1. Create case and upload a dummy email
    case_res = client.post("/api/cases", json={"title": "Concurrency Case"})
    case_id = case_res.json()["case_id"]

    raw_eml = b"From: attacker@evil.com\r\nSubject: Test\r\n\r\nBody"
    client.post(
        f"/api/cases/{case_id}/email",
        files={"file": ("test.eml", io.BytesIO(raw_eml), "message/rfc822")},
    )

    # 2. Acquire lock (sets status to 'running')
    repo.acquire_analysis_lock(case_id)
    case_info = repo.get_case(case_id)
    assert case_info is not None
    assert case_info["analysis_status"] == "running"

    # 3. Direct lock re-acquisition raises ConcurrencyConflictError
    with pytest.raises(ConcurrencyConflictError) as exc_info:
        repo.acquire_analysis_lock(case_id)
    assert "already running" in str(exc_info.value)

    # 4. Triggering via API endpoint while 'running' returns HTTP 409 Conflict
    res_conflict = client.post(f"/api/cases/{case_id}/analyze")
    assert res_conflict.status_code == 409
    assert "already running" in res_conflict.json()["detail"]


def test_sqlite_transaction_atomicity(temp_backend_env: dict) -> None:
    """Verify atomic rollback if analysis persistence fails midway."""
    repo: CaseRepository = temp_backend_env["repo"]

    case = repo.create_case("CASE-TX01", "Transaction Test Case")
    case_id = case["case_id"]

    # Provide entity with None entity_id to trigger SQLite NOT NULL failure
    # after evidence items have already been inserted in the same transaction
    bad_entity = {
        "entity_id": None,
        "entity_type": "domain",
        "canonical_value": "bad.com",
    }

    try:
        repo.save_analysis_results(
            case_id=case_id,
            threat_label="malicious",
            threat_confidence=0.85,
            threat_confidence_metric="ml_fusion",
            summary_text="Failed run",
            evidence_items=[
                {
                    "evidence_id": "EV-001",
                    "source_module": "m1",
                    "rule_id": "R1",
                    "trust_state": "observed",
                    "severity": "high",
                    "description": "Valid evidence before rollback",
                }
            ],
            entities=[bad_entity],
            relationships=[],
            hypotheses=[],
            origin_dict={},
            summary_dict={},
            full_case_dict={},
        )
    except Exception as exc:
        repo.mark_analysis_failed(case_id, str(exc))

    failed_case = repo.get_case(case_id)
    assert failed_case is not None
    assert failed_case["analysis_status"] == "failed"
    assert "constraint" in (failed_case["error_message"] or "").lower()

    # Verify that EV-001 was rolled back and NOT committed!
    evs = repo.get_case_evidence(case_id)
    ents = repo.get_case_entities(case_id)
    assert len(evs) == 0
    assert len(ents) == 0


def test_full_forensic_pipeline_and_artifact_apis(
    client: TestClient,
) -> None:
    """End-to-end test of forensic pipeline on reply_to_spoof.eml."""
    assert SAMPLE_EML_PATH.is_file(), f"Sample {SAMPLE_EML_PATH} missing"
    eml_bytes = SAMPLE_EML_PATH.read_bytes()

    # 1. Create case
    case_res = client.post(
        "/api/cases",
        json={"title": "Forensic Pipeline Integration Test"},
    )
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]

    # 2. Upload .eml file
    upload_res = client.post(
        f"/api/cases/{case_id}/email",
        files={
            "file": (
                "reply_to_spoof.eml",
                io.BytesIO(eml_bytes),
                "message/rfc822",
            )
        },
    )
    assert upload_res.status_code == 200

    # 3. Trigger analysis
    analyze_res = client.post(f"/api/cases/{case_id}/analyze")
    assert analyze_res.status_code == 200
    res_data = analyze_res.json()
    assert res_data["case_id"] == case_id
    assert res_data["analysis_status"] == "completed"
    assert res_data["threat_label"] is not None
    assert isinstance(res_data["threat_confidence"], float)

    # 4. Verify Evidence endpoint
    ev_res = client.get(f"/api/cases/{case_id}/evidence")
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert ev_data["case_id"] == case_id
    assert ev_data["total"] > 0
    assert len(ev_data["evidence"]) == ev_data["total"]
    first_ev = ev_data["evidence"][0]
    assert "evidence_id" in first_ev
    assert "source_module" in first_ev
    assert "trust_state" in first_ev

    # 5. Verify Entities endpoint
    ent_res = client.get(f"/api/cases/{case_id}/entities")
    assert ent_res.status_code == 200
    ent_data = ent_res.json()
    assert ent_data["total"] > 0
    first_ent = ent_data["entities"][0]
    assert "entity_id" in first_ent
    assert "entity_type" in first_ent
    assert "canonical_value" in first_ent

    # 6. Verify Relationships endpoint
    rel_res = client.get(f"/api/cases/{case_id}/relationships")
    assert rel_res.status_code == 200
    rel_data = rel_res.json()
    assert rel_data["total"] > 0
    first_rel = rel_data["relationships"][0]
    assert "relationship_type" in first_rel
    assert "source_entity_id" in first_rel
    assert "target_entity_id" in first_rel

    # 7. Verify Hypotheses endpoint
    hyp_res = client.get(f"/api/cases/{case_id}/hypotheses")
    assert hyp_res.status_code == 200
    hyp_data = hyp_res.json()
    assert hyp_data["total"] > 0
    first_hyp = hyp_data["hypotheses"][0]
    assert "hypothesis_type" in first_hyp
    assert first_hyp["confidence"] <= 0.94  # Bounded heuristic consensus

    # 8. Verify Origin endpoint
    org_res = client.get(f"/api/cases/{case_id}/origin")
    assert org_res.status_code == 200
    org_data = org_res.json()
    assert org_data["case_id"] == case_id
    assert len(org_data["hops"]) > 0
    assert "infrastructure" in org_data
    assert "semantic_note" in org_data

    # 9. Verify Summary endpoint
    sum_res = client.get(f"/api/cases/{case_id}/summary")
    assert sum_res.status_code == 200
    sum_data = sum_res.json()
    assert sum_data["case_id"] == case_id
    assert sum_data["threat_label"] == res_data["threat_label"]
    assert "evidence_counts" in sum_data
    assert "entity_counts" in sum_data

    # 10. Verify Case details endpoint reflect completed counts
    updated_case_res = client.get(f"/api/cases/{case_id}")
    assert updated_case_res.status_code == 200
    updated_case = updated_case_res.json()
    assert updated_case["analysis_status"] == "completed"
    assert updated_case["evidence_count"] == ev_data["total"]
    assert updated_case["entity_count"] == ent_data["total"]
    assert updated_case["threat_label"] == res_data["threat_label"]
