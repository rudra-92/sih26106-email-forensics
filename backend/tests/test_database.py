"""Unit and integration tests for PostgreSQL persistence and migrations."""

from __future__ import annotations

import os
import subprocess
import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.config import TEST_DATABASE_URL
from backend.db.session import check_db_connection, engine
from backend.repositories.case_repository import CaseRepository
from backend.repositories.user_repository import UserRepository


def test_15_postgresql_connection_works() -> None:
    """Verify active connection to PostgreSQL."""
    assert check_db_connection() is True
    with engine.connect() as conn:
        res = conn.execute(text("SELECT 1")).scalar()
        assert res == 1


def test_16_alembic_migration_creates_schema() -> None:
    """Ensure Alembic migration applies to test database successfully."""
    env = dict(os.environ, DATABASE_URL=TEST_DATABASE_URL)
    res = subprocess.run(
        ["alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "Running upgrade" in res.stderr or res.returncode == 0


def test_17_migration_is_repeatable_and_idempotent() -> None:
    """Ensure Alembic upgrade head can run repeatedly without errors."""
    env = dict(os.environ, DATABASE_URL=TEST_DATABASE_URL)
    res1 = subprocess.run(
        ["alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res1.returncode == 0

    res2 = subprocess.run(
        ["alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert res2.returncode == 0


def test_18_users_persist(temp_backend_env: dict) -> None:
    """Ensure User records persist accurately in PostgreSQL."""
    session: Session = temp_backend_env["session"]
    user_repo = UserRepository(session=session)
    user_repo.create_user(
        user_id="user-persist-1",
        email="persist@forensics.local",
        password_hash="argon2-dummy-hash",
        full_name="Persisted User",
        role="investigator",
    )
    fetched = user_repo.get_user_by_id("user-persist-1")
    assert fetched is not None
    assert fetched.email == "persist@forensics.local"
    assert fetched.full_name == "Persisted User"


def test_19_cases_persist(temp_backend_env: dict) -> None:
    """Ensure Case records persist in PostgreSQL."""
    session: Session = temp_backend_env["session"]
    case_repo = CaseRepository(session=session)
    case_repo.create_case(
        case_id="CASE-PERSIST-1",
        title="Persistence Verification Case",
    )
    fetched = case_repo.get_case("CASE-PERSIST-1")
    assert fetched is not None
    assert fetched["title"] == "Persistence Verification Case"
    assert fetched["status"] == "open"
    assert fetched["analysis_status"] == "pending"


def test_20_owner_user_id_persists(temp_backend_env: dict) -> None:
    """Ensure case owner_user_id persists and links to users table."""
    session: Session = temp_backend_env["session"]
    investigator = temp_backend_env["investigator"]
    case_repo = CaseRepository(session=session)
    case = case_repo.create_case(
        case_id="CASE-OWNED-1",
        title="Owned Case",
        owner_user_id=investigator.id,
    )
    assert case["owner_user_id"] == investigator.id

    fetched = case_repo.get_case("CASE-OWNED-1")
    assert fetched is not None
    assert fetched["owner_user_id"] == investigator.id


def test_21_evidence_persists(temp_backend_env: dict) -> None:
    """Ensure structured evidence items persist correctly in case_evidence."""
    session: Session = temp_backend_env["session"]
    case_repo = CaseRepository(session=session)
    case_repo.create_case(case_id="CASE-EV-1", title="Evidence Test")

    ev_item = {
        "evidence_id": "EV-001",
        "source_module": "header_analysis",
        "rule_id": "SPF_FAIL",
        "trust_state": "untrusted",
        "severity": "high",
        "description": "SPF check failed for sender domain",
        "entity_ids": ["ENT-01"],
        "timestamp": "2026-09-22T10:00:00Z",
        "provenance": ["header_parser"],
        "supporting_fields": {"spf_result": "fail"},
    }
    case_repo.save_analysis_results(
        case_id="CASE-EV-1",
        threat_label="phishing",
        threat_confidence=0.88,
        threat_confidence_metric="bounded_heuristic",
        summary_text="SPF Spoofing detected",
        evidence_items=[ev_item],
        entities=[],
        relationships=[],
        hypotheses=[],
        origin_dict={"hops": []},
        summary_dict={"threat_label": "phishing"},
        full_case_dict={},
    )

    evidence = case_repo.get_case_evidence("CASE-EV-1")
    assert len(evidence) == 1
    assert evidence[0]["evidence_id"] == "EV-001"
    assert evidence[0]["severity"] == "high"
    assert evidence[0]["supporting_fields"]["spf_result"] == "fail"


def test_22_entities_persist(temp_backend_env: dict) -> None:
    """Ensure extracted entities persist in case_entities."""
    session: Session = temp_backend_env["session"]
    case_repo = CaseRepository(session=session)
    case_repo.create_case(case_id="CASE-ENT-1", title="Entity Test")

    entity_item = {
        "entity_id": "ENT-DOMAIN-1",
        "entity_type": "domain",
        "canonical_value": "phishingsite.com",
        "source_modules": ["body_analysis"],
        "first_observed_timestamp": "2026-09-22T10:00:00Z",
        "attributes": {"registrar": "EvilRegistrar"},
    }
    case_repo.save_analysis_results(
        case_id="CASE-ENT-1",
        threat_label="phishing",
        threat_confidence=0.90,
        threat_confidence_metric="ml_prob",
        summary_text="Phishing domain found",
        evidence_items=[],
        entities=[entity_item],
        relationships=[],
        hypotheses=[],
        origin_dict={},
        summary_dict={},
        full_case_dict={},
    )

    entities = case_repo.get_case_entities("CASE-ENT-1")
    assert len(entities) == 1
    assert entities[0]["entity_id"] == "ENT-DOMAIN-1"
    assert entities[0]["canonical_value"] == "phishingsite.com"
    assert entities[0]["attributes"]["registrar"] == "EvilRegistrar"


def test_23_relationships_persist(temp_backend_env: dict) -> None:
    """Ensure entity graph relationships persist in case_relationships."""
    session: Session = temp_backend_env["session"]
    case_repo = CaseRepository(session=session)
    case_repo.create_case(case_id="CASE-REL-1", title="Relationship Test")

    rel_item = {
        "relationship_id": "REL-001",
        "source_entity_id": "ENT-1",
        "target_entity_id": "ENT-2",
        "relationship_type": "hosted_on",
        "evidence_ids": ["EV-01"],
        "source_modules": ["dns_analysis"],
        "trust_state": "corroborated",
        "timestamp": "2026-09-22T10:00:00Z",
        "provenance": ["dns_resolver"],
    }
    case_repo.save_analysis_results(
        case_id="CASE-REL-1",
        threat_label="suspicious",
        threat_confidence=0.75,
        threat_confidence_metric="consensus",
        summary_text="Hosting relation mapped",
        evidence_items=[],
        entities=[],
        relationships=[rel_item],
        hypotheses=[],
        origin_dict={},
        summary_dict={},
        full_case_dict={},
    )

    rels = case_repo.get_case_relationships("CASE-REL-1")
    assert len(rels) == 1
    assert rels[0]["relationship_id"] == "REL-001"
    assert rels[0]["relationship_type"] == "hosted_on"


def test_24_hypotheses_persist(temp_backend_env: dict) -> None:
    """Ensure hypotheses persist in case_hypotheses."""
    session: Session = temp_backend_env["session"]
    case_repo = CaseRepository(session=session)
    case_repo.create_case(case_id="CASE-HYP-1", title="Hypothesis Test")

    hyp_item = {
        "hypothesis_id": "HYP-001",
        "hypothesis_type": "credential_theft",
        "confidence": 0.85,
        "confidence_metric": "heuristic_score",
        "supporting_evidence_ids": ["EV-1"],
        "contradicting_evidence_ids": [],
        "description": "High probability of credential harvesting attack",
        "provenance": ["fusion_engine"],
    }
    case_repo.save_analysis_results(
        case_id="CASE-HYP-1",
        threat_label="phishing",
        threat_confidence=0.85,
        threat_confidence_metric="heuristic_score",
        summary_text="Credential theft attack",
        evidence_items=[],
        entities=[],
        relationships=[],
        hypotheses=[hyp_item],
        origin_dict={},
        summary_dict={},
        full_case_dict={},
    )

    hyps = case_repo.get_case_hypotheses("CASE-HYP-1")
    assert len(hyps) == 1
    assert hyps[0]["hypothesis_id"] == "HYP-001"
    assert hyps[0]["confidence"] == 0.85


def test_25_analysis_data_persists(temp_backend_env: dict) -> None:
    """Ensure origin, summary, and case blobs persist in database."""
    session: Session = temp_backend_env["session"]
    case_repo = CaseRepository(session=session)
    case_repo.create_case(case_id="CASE-DATA-1", title="Data Test")

    origin_data = {"hops": [{"ip": "1.2.3.4", "asn": "AS1234"}]}
    summary_data = {"threat_label": "phishing", "top_findings": ["SPF fail"]}
    full_data = {"raw_details": "complete_pipeline_trace"}

    case_repo.save_analysis_results(
        case_id="CASE-DATA-1",
        threat_label="phishing",
        threat_confidence=0.91,
        threat_confidence_metric="ml_fusion",
        summary_text="Analysis data blobs test",
        evidence_items=[],
        entities=[],
        relationships=[],
        hypotheses=[],
        origin_dict=origin_data,
        summary_dict=summary_data,
        full_case_dict=full_data,
    )

    assert case_repo.get_case_origin("CASE-DATA-1") == origin_data
    assert case_repo.get_case_summary("CASE-DATA-1") == summary_data
    assert case_repo.get_case_full_analysis("CASE-DATA-1") == full_data


def test_26_transaction_rollback_works(temp_backend_env: dict) -> None:
    """Ensure database rolls back atomically if a persistence op fails."""
    session: Session = temp_backend_env["session"]
    case_repo = CaseRepository(session=session)
    case_repo.create_case(case_id="CASE-ROLLBACK-1", title="Rollback Test")

    # Pass invalid payload that triggers an error during save
    with pytest.raises(Exception):
        case_repo.save_analysis_results(
            case_id="CASE-ROLLBACK-1",
            threat_label="phishing",
            threat_confidence="INVALID_FLOAT",  # type: ignore[arg-type]
            threat_confidence_metric="test",
            summary_text="Rollback test",
            evidence_items=[],
            entities=[],
            relationships=[],
            hypotheses=[],
            origin_dict={},
            summary_dict={},
            full_case_dict={},
        )

    # Verify case was not partially updated or corrupted
    case = case_repo.get_case("CASE-ROLLBACK-1")
    assert case is not None
    assert case["analysis_status"] == "pending"
    assert case["evidence_count"] == 0
