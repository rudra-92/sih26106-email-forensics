"""Forensic pipeline regression tests.

Verifies that forensic semantics are fully preserved across PostgreSQL.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from fastapi.testclient import TestClient

from backend.repositories.case_repository import CaseRepository
from backend.tests.conftest import TestSessionLocal

SAMPLE_EML_PATH = Path("ml/validation/forensic/reply_to_spoof.eml")


def test_40_to_50_forensic_regression_suite(
    client: TestClient, temp_backend_env: dict
) -> None:
    """Execute complete forensic pipeline on reply_to_spoof.eml.

    Tests criteria:
    40. authenticated user uploads .eml
    41. SHA-256 preserved
    42. authenticated user analyzes email
    43. threat label preserved
    44. threat confidence preserved
    45. evidence preserved
    46. entities preserved
    47. relationships preserved
    48. hypotheses preserved
    49. origin data preserved
    50. analysis survives application restart
    """
    assert SAMPLE_EML_PATH.is_file(), (
        f"Sample file {SAMPLE_EML_PATH} not found"
    )
    eml_bytes = SAMPLE_EML_PATH.read_bytes()
    expected_sha256 = hashlib.sha256(eml_bytes).hexdigest()

    # Step 1: Create case
    case_res = client.post(
        "/api/cases", json={"title": "Forensic Regression Verification"}
    )
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]

    # Criterion 40: Authenticated user uploads .eml
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
    upload_data = upload_res.json()

    # Criterion 41: SHA-256 preserved
    assert upload_data["file_sha256"] == expected_sha256
    case_after_upload = client.get(f"/api/cases/{case_id}").json()
    assert case_after_upload["file_sha256"] == expected_sha256

    # Criterion 42: Authenticated user analyzes email
    analyze_res = client.post(f"/api/cases/{case_id}/analyze")
    assert analyze_res.status_code == 200
    analyze_data = analyze_res.json()
    assert analyze_data["analysis_status"] == "completed"

    # Criterion 43: Threat label preserved
    threat_label = analyze_data["threat_label"]
    assert threat_label is not None
    assert threat_label in {"phishing", "fraud_related", "suspicious"}

    # Criterion 44: Threat confidence preserved
    threat_confidence = analyze_data["threat_confidence"]
    assert isinstance(threat_confidence, float)
    assert 0.0 <= threat_confidence <= 1.0

    # Criterion 45: Evidence preserved
    ev_res = client.get(f"/api/cases/{case_id}/evidence")
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert ev_data["total"] > 0
    assert len(ev_data["evidence"]) == ev_data["total"]

    # Criterion 46: Entities preserved
    ent_res = client.get(f"/api/cases/{case_id}/entities")
    assert ent_res.status_code == 200
    ent_data = ent_res.json()
    assert ent_data["total"] > 0
    assert len(ent_data["entities"]) == ent_data["total"]

    # Criterion 47: Relationships preserved
    rel_res = client.get(f"/api/cases/{case_id}/relationships")
    assert rel_res.status_code == 200
    rel_data = rel_res.json()
    assert rel_data["total"] > 0
    assert len(rel_data["relationships"]) == rel_data["total"]

    # Criterion 48: Hypotheses preserved
    hyp_res = client.get(f"/api/cases/{case_id}/hypotheses")
    assert hyp_res.status_code == 200
    hyp_data = hyp_res.json()
    assert hyp_data["total"] > 0
    assert len(hyp_data["hypotheses"]) == hyp_data["total"]

    # Criterion 49: Origin data preserved
    org_res = client.get(f"/api/cases/{case_id}/origin")
    assert org_res.status_code == 200
    org_data = org_res.json()
    assert org_data["case_id"] == case_id
    assert "hops" in org_data

    # Criterion 50: Analysis survives application restart
    # Simulate fresh session/restart from PostgreSQL
    fresh_session = TestSessionLocal()
    try:
        fresh_repo = CaseRepository(session=fresh_session)
        persisted_case = fresh_repo.get_case(case_id)
        assert persisted_case is not None
        assert persisted_case["file_sha256"] == expected_sha256
        assert persisted_case["threat_label"] == threat_label
        assert persisted_case["threat_confidence"] == threat_confidence
        assert persisted_case["analysis_status"] == "completed"

        persisted_ev = fresh_repo.get_case_evidence(case_id)
        assert len(persisted_ev) == ev_data["total"]

        persisted_ent = fresh_repo.get_case_entities(case_id)
        assert len(persisted_ent) == ent_data["total"]

        persisted_rels = fresh_repo.get_case_relationships(case_id)
        assert len(persisted_rels) == rel_data["total"]

        persisted_hyps = fresh_repo.get_case_hypotheses(case_id)
        assert len(persisted_hyps) == hyp_data["total"]

        persisted_org = fresh_repo.get_case_origin(case_id)
        assert persisted_org is not None
        assert "hops" in persisted_org
    finally:
        fresh_session.close()
