"""PostgreSQL repository for investigation cases and forensic results."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..db.models import (
    Case,
    CaseAnalysisData,
    CaseEntity,
    CaseEvidence,
    CaseHypothesis,
    CaseRelationship,
)
from ..db.session import SessionLocal

logger = logging.getLogger(__name__)


class ConcurrencyConflictError(Exception):
    """Raised when an analysis is already running for a case."""
    pass


class CaseRepository:
    """Manages transactional PostgreSQL storage for cases and evidence."""

    def __init__(
        self,
        session: Optional[Session] = None,
        db_path: Optional[str] = None,
    ) -> None:
        if session is not None:
            self.session = session
            self._owned_session = False
        else:
            self.session = SessionLocal()
            self._owned_session = True

    def close(self) -> None:
        """Close session if internally owned."""
        if self._owned_session and self.session:
            self.session.close()

    def _case_to_dict(self, case: Case) -> Dict[str, Any]:
        """Convert a Case ORM instance into a dictionary."""
        return {
            "case_id": case.case_id,
            "owner_user_id": case.owner_user_id,
            "title": case.title,
            "status": case.status,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
            "original_filename": case.original_filename,
            "file_sha256": case.file_sha256,
            "file_path": case.file_path,
            "file_size_bytes": case.file_size_bytes,
            "raw_eml_content": case.raw_eml_content,
            "analysis_status": case.analysis_status,
            "threat_label": case.threat_label,
            "threat_confidence": case.threat_confidence,
            "threat_confidence_metric": case.threat_confidence_metric,
            "summary": case.summary,
            "evidence_count": case.evidence_count,
            "entity_count": case.entity_count,
            "relationship_count": case.relationship_count,
            "hypothesis_count": case.hypothesis_count,
            "error_message": case.error_message,
        }

    def create_case(
        self,
        case_id: str,
        title: str,
        status: str = "open",
        owner_user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new case record in open/pending state."""
        now_ts = datetime.now(timezone.utc).isoformat()
        case = Case(
            case_id=case_id,
            owner_user_id=owner_user_id,
            title=title,
            status=status,
            created_at=now_ts,
            updated_at=now_ts,
            analysis_status="pending",
            evidence_count=0,
            entity_count=0,
            relationship_count=0,
            hypothesis_count=0,
        )
        self.session.add(case)
        self.session.commit()
        self.session.refresh(case)
        return self._case_to_dict(case)

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a case record by case_id."""
        stmt = select(Case).where(Case.case_id == case_id)
        case = self.session.scalars(stmt).first()
        return self._case_to_dict(case) if case else None

    def list_cases(
        self, owner_user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List cases, optionally filtered by owner_user_id."""
        stmt = select(Case)
        if owner_user_id is not None:
            stmt = stmt.where(Case.owner_user_id == owner_user_id)
        stmt = stmt.order_by(Case.updated_at.desc())
        cases = self.session.scalars(stmt).all()
        return [self._case_to_dict(c) for c in cases]

    def update_case_file(
        self,
        case_id: str,
        original_filename: str,
        file_sha256: str,
        file_path: str,
        file_size_bytes: int,
        raw_eml_content: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Associate preserved .eml file metadata with a case."""
        stmt = select(Case).where(Case.case_id == case_id)
        case = self.session.scalars(stmt).first()
        if not case:
            return None

        now_ts = datetime.now(timezone.utc).isoformat()
        case.original_filename = original_filename
        case.file_sha256 = file_sha256
        case.file_path = file_path
        case.file_size_bytes = file_size_bytes
        if raw_eml_content is not None:
            case.raw_eml_content = raw_eml_content
        case.updated_at = now_ts
        self.session.commit()
        self.session.refresh(case)
        return self._case_to_dict(case)

    def acquire_analysis_lock(self, case_id: str) -> bool:
        """Atomically mark analysis_status as 'running' with row-level locking.

        Uses PostgreSQL SELECT ... FOR UPDATE.
        Raises ConcurrencyConflictError if already running.
        """
        now_ts = datetime.now(timezone.utc).isoformat()
        # Row lock using with_for_update()
        stmt = (
            select(Case)
            .where(Case.case_id == case_id)
            .with_for_update()
        )
        case = self.session.scalars(stmt).first()
        if not case:
            return False

        if case.analysis_status == "running":
            raise ConcurrencyConflictError(
                f"Analysis is already running for case '{case_id}'."
            )

        case.analysis_status = "running"
        case.updated_at = now_ts
        case.error_message = None
        self.session.commit()
        return True

    def mark_analysis_failed(
        self, case_id: str, error_message: str
    ) -> None:
        """Atomically set analysis_status to 'failed' and record message."""
        stmt = select(Case).where(Case.case_id == case_id)
        case = self.session.scalars(stmt).first()
        if case:
            now_ts = datetime.now(timezone.utc).isoformat()
            case.analysis_status = "failed"
            case.error_message = error_message
            case.updated_at = now_ts
            self.session.commit()

    def save_analysis_results(
        self,
        case_id: str,
        threat_label: str,
        threat_confidence: float,
        threat_confidence_metric: str,
        summary_text: str,
        evidence_items: List[Dict[str, Any]],
        entities: List[Dict[str, Any]],
        relationships: List[Dict[str, Any]],
        hypotheses: List[Dict[str, Any]],
        origin_dict: Dict[str, Any],
        summary_dict: Dict[str, Any],
        full_case_dict: Dict[str, Any],
    ) -> None:
        """Persist complete analysis results atomically in a transaction."""
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            # 1. Clean previous analysis data for this case
            self.session.execute(
                delete(CaseEvidence).where(CaseEvidence.case_id == case_id)
            )
            self.session.execute(
                delete(CaseEntity).where(CaseEntity.case_id == case_id)
            )
            self.session.execute(
                delete(CaseRelationship).where(
                    CaseRelationship.case_id == case_id
                )
            )
            self.session.execute(
                delete(CaseHypothesis).where(
                    CaseHypothesis.case_id == case_id
                )
            )
            self.session.execute(
                delete(CaseAnalysisData).where(
                    CaseAnalysisData.case_id == case_id
                )
            )

            # 2. Insert Evidence
            for ev in evidence_items:
                ev_obj = CaseEvidence(
                    case_id=case_id,
                    evidence_id=ev.get("evidence_id", ""),
                    source_module=ev.get("source_module", ""),
                    rule_id=ev.get("rule_id", ""),
                    trust_state=ev.get("trust_state", ""),
                    severity=ev.get("severity", ""),
                    description=ev.get("description", ""),
                    entity_ids_json=json.dumps(ev.get("entity_ids", [])),
                    timestamp=ev.get("timestamp"),
                    provenance_json=json.dumps(ev.get("provenance", [])),
                    supporting_fields_json=json.dumps(
                        ev.get("supporting_fields", {})
                    ),
                )
                self.session.add(ev_obj)

            # 3. Insert Entities
            for ent in entities:
                ent_obj = CaseEntity(
                    case_id=case_id,
                    entity_id=ent.get("entity_id", ""),
                    entity_type=ent.get("entity_type", ""),
                    canonical_value=ent.get("canonical_value", ""),
                    source_modules_json=json.dumps(
                        ent.get("source_modules", [])
                    ),
                    first_observed_timestamp=ent.get(
                        "first_observed_timestamp"
                    ),
                    attributes_json=json.dumps(ent.get("attributes", {})),
                )
                self.session.add(ent_obj)

            # 4. Insert Relationships
            for rel in relationships:
                rel_obj = CaseRelationship(
                    case_id=case_id,
                    relationship_id=rel.get("relationship_id", ""),
                    source_entity_id=rel.get("source_entity_id", ""),
                    target_entity_id=rel.get("target_entity_id", ""),
                    relationship_type=rel.get("relationship_type", ""),
                    evidence_ids_json=json.dumps(
                        rel.get("evidence_ids", [])
                    ),
                    source_modules_json=json.dumps(
                        rel.get("source_modules", [])
                    ),
                    trust_state=rel.get("trust_state", ""),
                    timestamp=rel.get("timestamp"),
                    provenance_json=json.dumps(rel.get("provenance", [])),
                )
                self.session.add(rel_obj)

            # 5. Insert Hypotheses
            for hyp in hypotheses:
                hyp_obj = CaseHypothesis(
                    case_id=case_id,
                    hypothesis_id=hyp.get("hypothesis_id", ""),
                    hypothesis_type=hyp.get("hypothesis_type", ""),
                    confidence=float(hyp.get("confidence", 0.0)),
                    confidence_metric=hyp.get("confidence_metric", ""),
                    supporting_evidence_ids_json=json.dumps(
                        hyp.get("supporting_evidence_ids", [])
                    ),
                    contradicting_evidence_ids_json=json.dumps(
                        hyp.get("contradicting_evidence_ids", [])
                    ),
                    description=hyp.get("description", ""),
                    provenance_json=json.dumps(hyp.get("provenance", [])),
                )
                self.session.add(hyp_obj)

            # 6. Insert Analysis Raw / Summary Blobs
            analysis_obj = CaseAnalysisData(
                case_id=case_id,
                origin_json=json.dumps(origin_dict),
                summary_json=json.dumps(summary_dict),
                full_case_json=json.dumps(full_case_dict),
            )
            self.session.add(analysis_obj)

            # 7. Update Case Record Status and Counters
            stmt = select(Case).where(Case.case_id == case_id)
            case = self.session.scalars(stmt).first()
            if case:
                case.analysis_status = "completed"
                case.threat_label = threat_label
                case.threat_confidence = threat_confidence
                case.threat_confidence_metric = threat_confidence_metric
                case.summary = summary_text
                case.evidence_count = len(evidence_items)
                case.entity_count = len(entities)
                case.relationship_count = len(relationships)
                case.hypothesis_count = len(hypotheses)
                case.error_message = None
                case.updated_at = now_ts

            self.session.commit()
        except Exception as exc:
            self.session.rollback()
            logger.error(
                "Atomic transaction failed while saving analysis for %s: %s",
                case_id,
                exc,
            )
            raise

    def get_case_evidence(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve structured evidence items for a case."""
        stmt = (
            select(CaseEvidence)
            .where(CaseEvidence.case_id == case_id)
            .order_by(CaseEvidence.id.asc())
        )
        rows = self.session.scalars(stmt).all()
        items = []
        for r in rows:
            items.append({
                "id": r.id,
                "case_id": r.case_id,
                "evidence_id": r.evidence_id,
                "source_module": r.source_module,
                "rule_id": r.rule_id,
                "trust_state": r.trust_state,
                "severity": r.severity,
                "description": r.description,
                "entity_ids": json.loads(r.entity_ids_json or "[]"),
                "timestamp": r.timestamp,
                "provenance": json.loads(r.provenance_json or "[]"),
                "supporting_fields": json.loads(
                    r.supporting_fields_json or "{}"
                ),
            })
        return items

    def get_case_entities(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve resolved entities for a case."""
        stmt = (
            select(CaseEntity)
            .where(CaseEntity.case_id == case_id)
            .order_by(CaseEntity.id.asc())
        )
        rows = self.session.scalars(stmt).all()
        items = []
        for r in rows:
            items.append({
                "id": r.id,
                "case_id": r.case_id,
                "entity_id": r.entity_id,
                "entity_type": r.entity_type,
                "canonical_value": r.canonical_value,
                "source_modules": json.loads(r.source_modules_json or "[]"),
                "first_observed_timestamp": r.first_observed_timestamp,
                "attributes": json.loads(r.attributes_json or "{}"),
            })
        return items

    def get_case_relationships(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve graph relationships for a case."""
        stmt = (
            select(CaseRelationship)
            .where(CaseRelationship.case_id == case_id)
            .order_by(CaseRelationship.id.asc())
        )
        rows = self.session.scalars(stmt).all()
        items = []
        for r in rows:
            items.append({
                "id": r.id,
                "case_id": r.case_id,
                "relationship_id": r.relationship_id,
                "source_entity_id": r.source_entity_id,
                "target_entity_id": r.target_entity_id,
                "relationship_type": r.relationship_type,
                "evidence_ids": json.loads(r.evidence_ids_json or "[]"),
                "source_modules": json.loads(r.source_modules_json or "[]"),
                "trust_state": r.trust_state,
                "timestamp": r.timestamp,
                "provenance": json.loads(r.provenance_json or "[]"),
            })
        return items

    def get_case_hypotheses(self, case_id: str) -> List[Dict[str, Any]]:
        """Retrieve investigative hypotheses for a case."""
        stmt = (
            select(CaseHypothesis)
            .where(CaseHypothesis.case_id == case_id)
            .order_by(CaseHypothesis.id.asc())
        )
        rows = self.session.scalars(stmt).all()
        items = []
        for r in rows:
            items.append({
                "id": r.id,
                "case_id": r.case_id,
                "hypothesis_id": r.hypothesis_id,
                "hypothesis_type": r.hypothesis_type,
                "confidence": r.confidence,
                "confidence_metric": r.confidence_metric,
                "supporting_evidence_ids": json.loads(
                    r.supporting_evidence_ids_json or "[]"
                ),
                "contradicting_evidence_ids": json.loads(
                    r.contradicting_evidence_ids_json or "[]"
                ),
                "description": r.description,
                "provenance": json.loads(r.provenance_json or "[]"),
            })
        return items

    def get_case_origin(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve origin and infrastructure observations for a case."""
        stmt = select(CaseAnalysisData).where(
            CaseAnalysisData.case_id == case_id
        )
        data = self.session.scalars(stmt).first()
        if data and data.origin_json:
            return json.loads(data.origin_json)
        return None

    def get_case_summary(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve dashboard summary data for a case."""
        stmt = select(CaseAnalysisData).where(
            CaseAnalysisData.case_id == case_id
        )
        data = self.session.scalars(stmt).first()
        if data and data.summary_json:
            return json.loads(data.summary_json)
        return None

    def get_case_full_analysis(
        self, case_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve full pipeline JSON analysis for a case."""
        stmt = select(CaseAnalysisData).where(
            CaseAnalysisData.case_id == case_id
        )
        data = self.session.scalars(stmt).first()
        if data and data.full_case_json:
            return json.loads(data.full_case_json)
        return None

    def delete_case(self, case_id: str) -> bool:
        """Delete a case and all associated evidence, entities, relationships, hypotheses, and analysis."""
        db_case = self.session.scalars(
            select(Case).where(Case.case_id == case_id)
        ).first()
        if not db_case:
            return False

        try:
            self.session.execute(
                delete(CaseEvidence).where(CaseEvidence.case_id == case_id)
            )
            self.session.execute(
                delete(CaseEntity).where(CaseEntity.case_id == case_id)
            )
            self.session.execute(
                delete(CaseRelationship).where(
                    CaseRelationship.case_id == case_id
                )
            )
            self.session.execute(
                delete(CaseHypothesis).where(
                    CaseHypothesis.case_id == case_id
                )
            )
            self.session.execute(
                delete(CaseAnalysisData).where(
                    CaseAnalysisData.case_id == case_id
                )
            )
            self.session.delete(db_case)
            self.session.commit()
            return True
        except Exception:
            self.session.rollback()
            raise

