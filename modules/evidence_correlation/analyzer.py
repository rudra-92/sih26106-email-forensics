"""Top-level orchestrator for Module 6: Evidence Correlation & Attribution Support.

Coordinates the 9-stage correlation pipeline:
1. ML Prediction Ingestion
2. Evidence Normalization
3. Entity Resolution
4. Relationship Engine
5. Cross-Module Corroboration
6. Contradiction Detection
7. Cross-Case & Temporal Correlation
8. Case Hypothesis Evaluation
9. Attribution Support & Unified Case Synthesis
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from .attribution_support import AttributionSupportEngine
from .contradiction import ContradictionEngine
from .corroboration import CorroborationEngine
from .entity_resolution import EntityResolver
from .hypothesis_engine import CaseHypothesisEngine
from .ml_adapters import UnifiedMlAdapter
from .models import InvestigationCase, MlPrediction
from .normalizer import EvidenceNormalizer
from .relationship_engine import RelationshipEngine
from .temporal_correlation import CrossCaseCorrelator


class EvidenceCorrelationAnalyzer:
    """Main investigative orchestrator correlating Modules 1–5 and external ML predictions."""

    def __init__(self, case_store: Optional[CrossCaseCorrelator] = None) -> None:
        self.case_store = case_store or CrossCaseCorrelator()

    def correlate(
        self,
        email_id: str = "E001",
        case_id: Optional[str] = None,
        file_hash_sha256: Optional[str] = None,
        raw_email_reference: Optional[str] = None,
        module1_report: Optional[Union[Dict[str, Any], Any]] = None,
        module2_report: Optional[Union[Dict[str, Any], Any]] = None,
        module3_report: Optional[Union[Dict[str, Any], Any]] = None,
        module4_report: Optional[Union[Dict[str, Any], Any]] = None,
        module5_report: Optional[Union[Dict[str, Any], Any]] = None,
        infrastructure_intelligence_report: Optional[Union[Dict[str, Any], Any]] = None,
        ml_threat_prediction: Optional[Union[Dict[str, Any], Any]] = None,
        ml_bec_prediction: Optional[Union[Dict[str, Any], Any]] = None,
        ml_url_predictions: Optional[List[Union[Dict[str, Any], Any]]] = None,
        ml_fusion_prediction: Optional[Union[Dict[str, Any], Any]] = None,
        ml_predictions: Optional[List[MlPrediction]] = None,
        timestamp: Optional[str] = None,
    ) -> InvestigationCase:
        """Execute full evidence correlation pipeline and return a unified InvestigationCase."""
        c_id = case_id or f"CASE-{email_id}"

        # 1. Ingest and parse ML predictions
        parsed_ml: List[MlPrediction] = []
        if ml_predictions:
            parsed_ml.extend(ml_predictions)

        additional_ml = UnifiedMlAdapter.parse_all(
            threat_prediction=ml_threat_prediction,
            bec_prediction=ml_bec_prediction,
            url_predictions=ml_url_predictions,
            fusion_prediction=ml_fusion_prediction,
            case_id=c_id,
        )
        for p in additional_ml:
            if p not in parsed_ml:
                parsed_ml.append(p)

        # 2. Evidence Normalization
        normalizer = EvidenceNormalizer(case_id=c_id)
        evidence_list = normalizer.normalize_all(
            module1_report=module1_report,
            module2_report=module2_report,
            module3_report=module3_report,
            module4_report=module4_report,
            module5_report=module5_report,
            ml_predictions=parsed_ml,
            infrastructure_intelligence_report=infrastructure_intelligence_report,
        )

        # Extract SHA-256 if not explicitly passed
        calc_sha = file_hash_sha256 or ""
        if not calc_sha and module1_report is not None:
            d1 = module1_report.to_dict() if hasattr(module1_report, "to_dict") else dict(module1_report)
            calc_sha = d1.get("file_hash_sha256", "")

        # 3. Entity Resolution
        resolver = EntityResolver()
        entities = resolver.extract_and_resolve_all(
            email_id=email_id,
            module1_report=module1_report,
            module2_report=module2_report,
            module3_report=module3_report,
            module4_report=module4_report,
            module5_report=module5_report,
            infrastructure_intelligence_report=infrastructure_intelligence_report,
            case_id=c_id,
            timestamp=timestamp,
        )

        # 4. Relationship Engine
        rel_engine = RelationshipEngine()
        relationships = rel_engine.correlate_all(
            resolver=resolver,
            email_id=email_id,
            case_id=c_id,
            evidence_list=evidence_list,
            module1_report=module1_report,
            module2_report=module2_report,
            module3_report=module3_report,
            module4_report=module4_report,
            module5_report=module5_report,
            infrastructure_intelligence_report=infrastructure_intelligence_report,
            timestamp=timestamp,
        )

        # 5. Cross-Module Corroboration
        corroboration_engine = CorroborationEngine()
        corroborated_findings = corroboration_engine.find_corroborations(
            evidence_list=evidence_list,
            ml_predictions=parsed_ml,
        )

        # 6. Contradiction Detection
        contradiction_engine = ContradictionEngine()
        contradictions = contradiction_engine.find_contradictions(
            evidence_list=evidence_list,
            ml_predictions=parsed_ml,
            module1_report=module1_report,
            module5_report=module5_report,
            module2_report=module2_report,
            module3_report=module3_report,
        )

        # 7. Cross-Case & Temporal Correlation
        clusters = self.case_store.correlate_case(
            current_case_id=c_id,
            current_entities=entities,
            current_timestamp=timestamp,
        )

        # 8. Case Hypothesis Generation
        hypo_engine = CaseHypothesisEngine()
        hypotheses = hypo_engine.evaluate_hypotheses(
            evidence_list=evidence_list,
            corroborated_findings=corroborated_findings,
            contradictions=contradictions,
            clusters=clusters,
            ml_predictions=parsed_ml,
        )

        # 9. Attribution Support
        attr_engine = AttributionSupportEngine()
        attribution_support = attr_engine.build_attribution_support(
            entities=entities,
            evidence_list=evidence_list,
            clusters=clusters,
            module5_report=module5_report,
        )

        # Provenance tracking
        prov: List[Dict[str, Any]] = [
            {
                "module": "evidence_correlation",
                "case_id": c_id,
                "email_id": email_id,
                "total_evidence_count": len(evidence_list),
                "total_entities_count": len(entities),
                "total_relationships_count": len(relationships),
                "corroborated_findings_count": len(corroborated_findings),
                "contradictions_count": len(contradictions),
                "hypotheses_count": len(hypotheses),
                "clusters_count": len(clusters),
            }
        ]

        # Construct and register completed case in case store for future correlations
        investigation_case = InvestigationCase(
            case_id=c_id,
            email_id=email_id,
            file_hash_sha256=calc_sha,
            raw_email_reference=raw_email_reference,
            evidence=evidence_list,
            entities=entities,
            relationships=relationships,
            ml_predictions=parsed_ml,
            correlated_findings=corroborated_findings,
            contradictions=contradictions,
            hypotheses=hypotheses,
            campaign_clusters=clusters,
            attribution_support=attribution_support,
            provenance=prov,
        )

        # Add to historical case store
        self.case_store.add_case({
            "case_id": c_id,
            "email_id": email_id,
            "timestamp": timestamp,
            "entities": [e.to_dict() for e in entities],
        })

        return investigation_case


def correlate_evidence(
    email_id: str = "E001",
    case_id: Optional[str] = None,
    module1_report: Optional[Any] = None,
    module2_report: Optional[Any] = None,
    module3_report: Optional[Any] = None,
    module4_report: Optional[Any] = None,
    module5_report: Optional[Any] = None,
    infrastructure_intelligence_report: Optional[Any] = None,
    ml_threat_prediction: Optional[Any] = None,
    ml_bec_prediction: Optional[Any] = None,
    ml_url_predictions: Optional[List[Any]] = None,
    ml_fusion_prediction: Optional[Any] = None,
    ml_predictions: Optional[List[MlPrediction]] = None,
    case_store: Optional[CrossCaseCorrelator] = None,
    timestamp: Optional[str] = None,
) -> InvestigationCase:
    """Convenience functional wrapper for EvidenceCorrelationAnalyzer.correlate."""
    analyzer = EvidenceCorrelationAnalyzer(case_store=case_store)
    return analyzer.correlate(
        email_id=email_id,
        case_id=case_id,
        module1_report=module1_report,
        module2_report=module2_report,
        module3_report=module3_report,
        module4_report=module4_report,
        module5_report=module5_report,
        infrastructure_intelligence_report=infrastructure_intelligence_report,
        ml_threat_prediction=ml_threat_prediction,
        ml_bec_prediction=ml_bec_prediction,
        ml_url_predictions=ml_url_predictions,
        ml_fusion_prediction=ml_fusion_prediction,
        ml_predictions=ml_predictions,
        timestamp=timestamp,
    )
