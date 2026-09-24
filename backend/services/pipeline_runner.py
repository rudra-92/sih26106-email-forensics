"""Pipeline orchestration service invoking the complete forensic engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional
import numpy as np

from enrichment.infrastructure_intelligence import (
    run_infrastructure_intelligence,
)
from ml.inference.predict_fusion import FusionThreatPredictor
from modules.attachment_analysis import analyze_attachments
from modules.evidence_correlation import correlate_evidence
from modules.lookalike_domain import (
    compute_domain_similarity,
    find_similarity_candidates,
    validate_candidate_context,
)
from modules.origin_infrastructure import analyze_origin_infrastructure
from modules.sender_identity import analyze_eml
from modules.url_analysis import analyze_urls


def sanitize_for_json(obj: Any) -> Any:
    """Recursively ensure objects are valid JSON primitives."""
    if isinstance(obj, (np.floating, float)):
        if np.isnan(obj) or np.isinf(obj):
            return None
        return float(obj)
    if isinstance(obj, (np.integer, int)):
        return int(obj)
    if isinstance(obj, np.ndarray):
        return [sanitize_for_json(x) for x in obj.tolist()]
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [sanitize_for_json(x) for x in obj]
    if hasattr(obj, "to_dict"):
        return sanitize_for_json(obj.to_dict())
    return obj


class PipelineRunner:
    """Executes the complete forensic pipeline on preserved email files."""

    def __init__(self) -> None:
        self.ml_predictor: Optional[FusionThreatPredictor] = None

    def _get_predictor(self) -> FusionThreatPredictor:
        if self.ml_predictor is None:
            self.ml_predictor = FusionThreatPredictor()
        return self.ml_predictor

    def run_pipeline(
        self, email_path: Path | str | bytes, case_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Convenience method delegating to run_investigation."""
        effective_case_id = case_id
        if not effective_case_id:
            if isinstance(email_path, Path):
                effective_case_id = email_path.stem
            elif isinstance(email_path, str) and "\n" not in email_path and "\r" not in email_path and len(email_path) < 255:
                try:
                    effective_case_id = Path(email_path).stem
                except (OSError, ValueError):
                    effective_case_id = "case_analysis"
            else:
                effective_case_id = "case_analysis"

        return self.run_investigation(
            case_id=effective_case_id,
            email_path=email_path,
        )

    def run_investigation(
        self, case_id: str, email_path: Path | str | bytes
    ) -> Dict[str, Any]:
        """Execute full Modules 1-6 + ML + Enrichment pipeline on email."""
        if isinstance(email_path, bytes):
            raw_bytes = email_path
            raw_text = raw_bytes.decode("utf-8", errors="replace")
        elif isinstance(email_path, Path):
            raw_bytes = email_path.read_bytes()
            raw_text = raw_bytes.decode("utf-8", errors="replace")
        elif isinstance(email_path, str):
            is_file = False
            if "\n" not in email_path and "\r" not in email_path and len(email_path) < 1024:
                try:
                    p = Path(email_path)
                    if p.is_file():
                        raw_bytes = p.read_bytes()
                        raw_text = raw_bytes.decode("utf-8", errors="replace")
                        is_file = True
                except (OSError, ValueError):
                    is_file = False

            if not is_file:
                raw_text = email_path
                raw_bytes = email_path.encode("utf-8", errors="surrogateescape")
        else:
            raise TypeError(f"Unsupported email_path type: {type(email_path)}")

        # 1. Module 1: Sender Identity
        m1 = analyze_eml(raw_text, email_id=case_id)

        # 2. Module 2: Lookalike Domain
        domains = [
            e.value for e in m1.entities if getattr(e, "type", "") == "domain"
        ]
        # Extract display name from m1 observations if available
        disp_name = None
        for o in getattr(m1, "observations", []):
            ev = getattr(o, "evidence", {})
            if isinstance(ev, dict) and "display_name" in ev:
                disp_name = ev["display_name"]
                break

        if domains:
            primary_dom = domains[0]
            cand_matches = find_similarity_candidates(
                primary_dom, return_all=True, display_name=disp_name
            )
            top_cand = None
            if cand_matches:
                for c in cand_matches:
                    if (
                        hasattr(c, "is_candidate")
                        and c.is_candidate
                        or getattr(c, "candidate", False)
                    ):
                        top_cand = c
                        break
                if top_cand is None:
                    top_cand = cand_matches[0]
            else:
                top_cand = compute_domain_similarity(
                    observed=primary_dom, reference="paypal.com", display_name=disp_name
                )
            m2 = validate_candidate_context(
                candidate=top_cand, sender_identity=m1
            )
        else:
            default_cand = compute_domain_similarity(
                "unknown.local", "paypal.com"
            )
            m2 = validate_candidate_context(
                candidate=default_cand, sender_identity=m1
            )

        # 3. Module 3: URL Analysis
        m3 = analyze_urls(raw_text, email_id=case_id, display_name=disp_name)

        # 4. Module 4: Attachment Analysis
        m4 = analyze_attachments(raw_bytes, email_id=case_id)

        # 5. Module 5: Origin & Infrastructure Reconstruction
        m5 = analyze_origin_infrastructure(raw_text, email_id=case_id)

        # 6. Real ML: Fusion Threat Predictor
        predictor = self._get_predictor()
        ml_out = predictor.predict_email(raw_text, email_id=case_id)

        # 7. Infrastructure Intelligence Layer
        peer = None
        has_peer = (
            m5.origin_assessment is not None
            and m5.origin_assessment.earliest_reliable_peer is not None
        )
        if has_peer and m5.origin_assessment is not None:
            peer_obj = m5.origin_assessment.earliest_reliable_peer
            peer = getattr(peer_obj, "ip", peer_obj)

        target_dom = domains[0] if domains else "example.com"
        infra_rep = run_infrastructure_intelligence(
            target_ip=str(peer) if peer else "",
            target_domain=target_dom,
            module5_report=m5,
        )

        # 8. Module 6: Evidence Correlation & Attribution Support
        corr_case = correlate_evidence(
            email_id=case_id,
            module1_report=m1,
            module2_report=m2,
            module3_report=m3,
            module4_report=m4,
            module5_report=m5,
            infrastructure_intelligence_report=infra_rep,
            ml_fusion_prediction=ml_out,
        )

        full_case_dict = sanitize_for_json(corr_case.to_dict())

        # Extract Evidence
        evidence_items = []
        for ev in corr_case.evidence:
            evidence_items.append(
                sanitize_for_json(
                    {
                        "evidence_id": ev.evidence_id,
                        "source_module": ev.source_module,
                        "rule_id": ev.rule_id,
                        "trust_state": ev.trust_state,
                        "severity": ev.severity,
                        "description": ev.description,
                        "entity_ids": ev.entity_ids,
                        "timestamp": ev.timestamp,
                        "provenance": ev.provenance,
                        "supporting_fields": ev.supporting_fields,
                    }
                )
            )

        # Extract Entities
        entities = []
        for ent in corr_case.entities:
            entities.append(
                sanitize_for_json(
                    {
                        "entity_id": ent.entity_id,
                        "entity_type": ent.type,
                        "canonical_value": ent.value,
                        "source_modules": ent.source_modules,
                        "first_observed_timestamp": ent.first_seen,
                        "attributes": ent.attributes,
                    }
                )
            )

        # Extract Relationships
        relationships = []
        for rel in corr_case.relationships:
            relationships.append(
                sanitize_for_json(
                    {
                        "relationship_id": rel.relationship_id,
                        "source_entity_id": rel.from_entity,
                        "target_entity_id": rel.to_entity,
                        "relationship_type": rel.relationship_type,
                        "evidence_ids": rel.evidence_ids,
                        "source_modules": rel.source_modules,
                        "trust_state": rel.trust_state,
                        "timestamp": rel.timestamp,
                        "provenance": rel.provenance,
                    }
                )
            )

        # Extract Hypotheses
        hypotheses = []
        for idx, hyp in enumerate(corr_case.hypotheses):
            metric_desc = hyp.confidence_metric
            hyp_id = f"HYP-{idx + 1:03d}"
            hypotheses.append(
                sanitize_for_json(
                    {
                        "hypothesis_id": hyp_id,
                        "hypothesis_type": hyp.hypothesis_type,
                        "confidence": float(hyp.heuristic_confidence),
                        "confidence_metric": metric_desc,
                        "supporting_evidence_ids": hyp.supporting_evidence,
                        "contradicting_evidence_ids": (
                            hyp.contradicting_evidence
                        ),
                        "description": (
                            f"Forensic hypothesis: {hyp.hypothesis_type}"
                        ),
                        "provenance": (
                            [str(k) for k in hyp.provenance.keys()]
                            if isinstance(hyp.provenance, dict)
                            else hyp.provenance
                        ),
                    }
                )
            )

        # Extract Origin & Infrastructure
        enriched_peer = None
        if peer and hasattr(m5, "enriched_peers"):
            for p in m5.enriched_peers:
                if getattr(p, "ip", None) == str(peer):
                    enriched_peer = p
                    break

        origin_dict = sanitize_for_json(
            {
                "case_id": case_id,
                "earliest_reliable_peer": str(peer) if peer else None,
                "source_visibility": (
                    m5.origin_assessment.source_visibility
                    if m5.origin_assessment
                    else None
                ),
                "confidence": (
                    float(m5.origin_assessment.confidence)
                    if m5.origin_assessment
                    else None
                ),
                "assessment_reason": (
                    m5.origin_assessment.assessment_reason
                    if m5.origin_assessment
                    else None
                ),
                "infrastructure": infra_rep.hosting_fingerprint.to_dict(),
                "geolocation": (
                    enriched_peer.geolocation.to_dict()
                    if enriched_peer and hasattr(enriched_peer, "geolocation")
                    else {}
                ),
                "asn": (
                    enriched_peer.asn.to_dict()
                    if enriched_peer and hasattr(enriched_peer, "asn")
                    else {}
                ),
                "hops": [h.to_dict() for h in m5.hops],
                "rdap": infra_rep.rdap.to_dict(),
                "reverse_dns": infra_rep.reverse_dns.to_dict(),
                "threat_feed": infra_rep.threat_feed.to_dict(),
                "provenance": {
                    "origin_module": "origin_infrastructure",
                    "enrichment_module": "infrastructure_intelligence",
                    "earliest_peer": str(peer) if peer else None,
                },
                "semantic_note": (
                    "Observed infrastructure geolocation represents routing "
                    "Point-of-Presence (PoP), NOT human attacker location."
                ),
            }
        )

        # Extract Dashboard Summary
        threat_label = ml_out.get("prediction", {}).get("label", "unknown")
        threat_conf = float(
            ml_out.get("prediction", {}).get("confidence", 0.0)
        )

        important_findings = []
        for f_item in corr_case.correlated_findings:
            important_findings.append(
                {
                    "finding_id": f_item.finding_id,
                    "finding_type": f_item.finding_type,
                    "severity": f_item.heuristic_support_strength,
                    "description": f_item.description,
                    "contributing_modules": f_item.source_modules,
                    "evidence_ids": f_item.supporting_evidence_ids,
                }
            )

        ev_counts: Dict[str, int] = {}
        for ev in corr_case.evidence:
            sm = ev.source_module
            ev_counts[sm] = ev_counts.get(sm, 0) + 1

        ent_counts: Dict[str, int] = {}
        for ent in corr_case.entities:
            et = ent.type
            ent_counts[et] = ent_counts.get(et, 0) + 1

        key_doms = [
            e.value
            for e in corr_case.entities
            if e.type == "domain"
        ]
        key_ips = [
            e.value
            for e in corr_case.entities
            if e.type == "ip"
        ]
        key_urls = [
            e.value
            for e in corr_case.entities
            if e.type == "url"
        ]

        attachments = []
        if hasattr(m4, "attachments"):
            for a in m4.attachments:
                if getattr(a, "suspicious", False):
                    attachments.append(getattr(a, "filename", "attachment"))

        auth_obs = []
        if hasattr(m1, "authentication_findings"):
            for af in m1.authentication_findings:
                auth_obs.append(
                    {
                        "mechanism": getattr(af, "mechanism", "auth"),
                        "result": getattr(af, "result", "none"),
                        "domain": getattr(af, "domain", ""),
                    }
                )

        summary_dict = sanitize_for_json(
            {
                "case_id": case_id,
                "threat_label": threat_label,
                "threat_confidence": threat_conf,
                "threat_confidence_metric": "non_calibrated_ml_inference",
                "important_forensic_findings": important_findings,
                "top_hypotheses": [
                    {
                        "type": h["hypothesis_type"],
                        "confidence": h["confidence"],
                        "description": h["description"],
                    }
                    for h in hypotheses
                ],
                "origin_infrastructure_summary": {
                    "earliest_reliable_peer": str(peer) if peer else None,
                    "hosting_classification": (
                        infra_rep.hosting_fingerprint.classification
                    ),
                    "hosting_provider": (
                        infra_rep.hosting_fingerprint.provider_name
                    ),
                    "source_visibility": (
                        m5.origin_assessment.source_visibility
                        if m5.origin_assessment
                        else None
                    ),
                },
                "evidence_counts": ev_counts,
                "entity_counts": ent_counts,
                "key_domains": key_doms[:10],
                "key_ips": key_ips[:10],
                "key_urls": key_urls[:10],
                "suspicious_attachments": attachments,
                "authentication_observations": auth_obs,
            }
        )

        summary_text = (
            f"ML threat classification: {threat_label} "
            f"(Confidence: {threat_conf:.4f}). "
            f"Correlated {len(evidence_items)} evidence items "
            f"across {len(entities)} entities."
        )

        return {
            "threat_label": threat_label,
            "threat_confidence": threat_conf,
            "threat_confidence_metric": "non_calibrated_ml_inference",
            "summary_text": summary_text,
            "evidence_items": evidence_items,
            "entities": entities,
            "relationships": relationships,
            "hypotheses": hypotheses,
            "origin_dict": origin_dict,
            "summary_dict": summary_dict,
            "full_case_dict": full_case_dict,
        }
