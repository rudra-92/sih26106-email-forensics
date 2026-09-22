"""Service layer for forensic analysis execution and persistence."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

from ..repositories.case_repository import CaseRepository
from .pipeline_runner import PipelineRunner

logger = logging.getLogger(__name__)


class AnalysisService:
    """Orchestrates forensic pipeline with concurrency lock and persistence."""

    def __init__(
        self,
        repository: CaseRepository,
        runner: Optional[PipelineRunner] = None,
    ) -> None:
        self.repository = repository
        self.runner = runner or PipelineRunner()

    def run_case_analysis(self, case_id: str) -> Dict[str, Any]:
        """Execute forensic pipeline on preserved email and persist results.

        Enforces:
        - Case existence and attached email file verification
        - Concurrency lock (HTTP 409 if already running)
        - Pipeline execution with frozen module preservation
        - Transactional SQLite persistence
        """
        # 1. Validate case existence
        case = self.repository.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        # 2. Validate email file presence
        file_path_str = case.get("file_path")
        if not file_path_str:
            raise ValueError(
                f"Case '{case_id}' has no email file uploaded. "
                "Upload a .eml file before triggering analysis."
            )

        eml_path = Path(file_path_str)
        if not eml_path.is_file():
            raise ValueError(
                f"Preserved email file '{file_path_str}' is missing on disk."
            )

        # 3. Acquire atomic analysis lock
        # Raises ConcurrencyConflictError if already 'running'
        self.repository.acquire_analysis_lock(case_id)

        try:
            logger.info("Starting forensic pipeline for case %s", case_id)
            analysis_results = self.runner.run_pipeline(
                email_path=eml_path, case_id=case_id
            )

            # 5. Persist analysis results atomically
            self.repository.save_analysis_results(
                case_id=case_id,
                threat_label=analysis_results["threat_label"],
                threat_confidence=analysis_results["threat_confidence"],
                threat_confidence_metric=analysis_results[
                    "threat_confidence_metric"
                ],
                summary_text=analysis_results["summary_text"],
                evidence_items=analysis_results["evidence_items"],
                entities=analysis_results["entities"],
                relationships=analysis_results["relationships"],
                hypotheses=analysis_results["hypotheses"],
                origin_dict=analysis_results["origin_dict"],
                summary_dict=analysis_results["summary_dict"],
                full_case_dict=analysis_results["full_case_dict"],
            )
            logger.info("Successfully analyzed and saved case %s", case_id)

            return {
                "case_id": case_id,
                "status": "completed",
                "message": "Forensic analysis completed successfully.",
                "summary": analysis_results.get("summary_dict", {}),
            }
        except Exception as exc:
            logger.exception(
                "Analysis failed for case %s: %s", case_id, str(exc)
            )
            # Record failed state in repository
            self.repository.mark_analysis_failed(case_id, str(exc))
            raise

    def get_evidence(self, case_id: str) -> Dict[str, Any]:
        """Retrieve normalized evidence for a case."""
        case = self.repository.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")
        evidence = self.repository.get_case_evidence(case_id)
        return {"case_id": case_id, "evidence": evidence}

    def get_entities(self, case_id: str) -> Dict[str, Any]:
        """Retrieve resolved entities for a case."""
        case = self.repository.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")
        entities = self.repository.get_case_entities(case_id)
        return {"case_id": case_id, "entities": entities}

    def get_relationships(self, case_id: str) -> Dict[str, Any]:
        """Retrieve graph relationships for a case."""
        case = self.repository.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")
        relationships = self.repository.get_case_relationships(case_id)
        return {"case_id": case_id, "relationships": relationships}

    def get_hypotheses(self, case_id: str) -> Dict[str, Any]:
        """Retrieve generated hypotheses for a case."""
        case = self.repository.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")
        hypotheses = self.repository.get_case_hypotheses(case_id)
        return {"case_id": case_id, "hypotheses": hypotheses}

    def get_origin(self, case_id: str) -> Dict[str, Any]:
        """Retrieve origin observation data for a case."""
        case = self.repository.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")
        origin = self.repository.get_case_origin(case_id)
        return {"case_id": case_id, "origin": origin}

    def get_summary(self, case_id: str) -> Dict[str, Any]:
        """Retrieve investigation dashboard summary for a case."""
        case = self.repository.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")
        summary = self.repository.get_case_summary(case_id)
        return {"case_id": case_id, "summary": summary}
