"""Data models for Module 6: Evidence Correlation & Attribution Support.

Defines normalized forensic evidence schemas, unified graph entities and relationships,
multi-module corroborations, contradiction records, ML prediction representations,
competing investigative hypotheses, campaign clusters, and unified investigation cases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class NormalizedEvidence:
    """Canonical representation of an observed, reported, or inferred forensic fact.

    Normalizes findings across Modules 1–5 and external ML predictions.
    """
    evidence_id: str
    source_module: str  # 'sender_identity', 'lookalike_domain', 'url_analysis', 'attachment_analysis', 'origin_infrastructure', 'ml_threat_classifier', 'ml_bec_classifier', 'ml_url_classifier'
    evidence_type: str  # 'observation', 'authentication', 'lookalike_signal', 'url_feature', 'attachment_anomaly', 'routing_anomaly', 'ml_prediction'
    rule_id: str
    severity: str  # 'informational', 'low', 'medium', 'high'
    trust_state: str  # 'observed', 'verified', 'enriched', 'inferred', 'unknown'
    description: str
    entity_ids: List[str] = field(default_factory=list)
    timestamp: Optional[str] = None
    provenance: List[str] = field(default_factory=list)
    supporting_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_module": self.source_module,
            "evidence_type": self.evidence_type,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "trust_state": self.trust_state,
            "description": self.description,
            "entity_ids": list(self.entity_ids),
            "timestamp": self.timestamp,
            "provenance": list(self.provenance),
            "supporting_fields": dict(self.supporting_fields),
        }


@dataclass
class CorrelatedEntity:
    """Resolved and merged atomic forensic entity across all contributing modules."""
    entity_id: str  # Canonical identifier (e.g. 'domain:paypa1.com', 'ip:198.51.100.77')
    type: str  # 'email', 'email_address', 'domain', 'url', 'ip', 'asn', 'attachment', 'hash', 'message_id', 'hostname', 'country', 'infrastructure', 'case'
    value: str
    source_modules: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "type": self.type,
            "value": self.value,
            "source_modules": sorted(list(set(self.source_modules))),
            "attributes": dict(self.attributes),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class CorrelatedRelationship:
    """Evidence-bearing directed graph edge connecting two resolved entities."""
    relationship_id: str
    from_entity: str
    to_entity: str
    relationship_type: str  # 'sent_by', 'belongs_to', 'resembles', 'contains_url', 'hosted_on', 'contains_attachment', 'has_hash', 'observed_from', 'located_in', 'infrastructure_type', 'contains'
    evidence_ids: List[str] = field(default_factory=list)
    source_modules: List[str] = field(default_factory=list)
    trust_state: str = "observed"  # 'observed', 'verified', 'enriched', 'inferred', 'unknown'
    timestamp: Optional[str] = None
    provenance: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "from_entity": self.from_entity,
            "to_entity": self.to_entity,
            "relationship_type": self.relationship_type,
            "evidence_ids": sorted(list(set(self.evidence_ids))),
            "source_modules": sorted(list(set(self.source_modules))),
            "trust_state": self.trust_state,
            "timestamp": self.timestamp,
            "provenance": list(self.provenance),
        }


@dataclass(frozen=True)
class CorroboratedFinding:
    """Multi-module synthesis where independent modules support a common conclusion."""
    finding_id: str
    finding_type: str  # 'correlated_identity_deception', 'correlated_credential_phishing', 'correlated_malware_delivery', 'correlated_infrastructure_abuse'
    title: str
    description: str
    supporting_evidence_ids: List[str]
    source_modules: List[str]
    heuristic_support_strength: str  # 'low', 'medium', 'high', 'critical'
    confidence_metric: str = "heuristic_non_calibrated_consensus"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "title": self.title,
            "description": self.description,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "source_modules": sorted(list(set(self.source_modules))),
            "heuristic_support_strength": self.heuristic_support_strength,
            "confidence_metric": self.confidence_metric,
        }


@dataclass(frozen=True)
class ContradictionRecord:
    """Preserved contradiction between two or more forensic findings or predictions."""
    contradiction_id: str
    rule_id: str  # 'RULE-CORR-EVIDENCE-CONFLICT'
    conflict_type: str  # 'auth_vs_lookalike', 'user_vs_server_country', 'ml_vs_deterministic', 'header_identity_divergence'
    evidence_a_id: str
    evidence_b_id: str
    explanation: str
    provenance: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contradiction_id": self.contradiction_id,
            "rule_id": self.rule_id,
            "conflict_type": self.conflict_type,
            "evidence_a_id": self.evidence_a_id,
            "evidence_b_id": self.evidence_b_id,
            "explanation": self.explanation,
            "provenance": list(self.provenance),
        }


@dataclass(frozen=True)
class MlPrediction:
    """Standardized prediction emitted by an external machine learning model.

    FORENSIC SEMANTIC BOUNDARIES:
    - trust_state is strictly 'inferred'; ML predictions are NEVER observed facts.
    - confidence_metric is 'heuristic_non_calibrated_consensus' unless explicitly calibrated.
    - Adapters NEVER assert human attacker identity, home address, or guaranteed attacker IP/location.
    - Model confidence alone NEVER asserts certainty or proves malice as a factual certainty.
    """
    model: str  # 'email_threat_classifier', 'bec_intent_classifier', 'url_risk_classifier'
    model_version: Optional[str]
    label: str  # Predicted class / intent / risk tier
    confidence: float  # Model output score [0.0, 1.0]
    confidence_metric: str = "heuristic_non_calibrated_consensus"
    input_reference: Optional[str] = None
    trust_state: str = "inferred"  # ML predictions are NEVER treated as observed facts
    features_used: List[str] = field(default_factory=list)
    top_features: List[str] = field(default_factory=list)
    provenance: List[str] = field(default_factory=list)
    raw_prediction: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "model_version": self.model_version,
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "confidence_metric": self.confidence_metric,
            "input_reference": self.input_reference,
            "trust_state": self.trust_state,
            "features_used": list(self.features_used),
            "top_features": list(self.top_features),
            "provenance": list(self.provenance),
            "raw_prediction": self.raw_prediction,
        }


@dataclass(frozen=True)
class CaseHypothesis:
    """Case-level competing forensic hypothesis evaluated with bounded consensus."""
    hypothesis_type: str  # 'possible_domain_impersonation', 'possible_phishing', 'possible_bec_attempt', 'possible_credential_harvesting', 'possible_campaign_reuse', 'possible_compromised_account', 'possible_provider_masking', 'possible_anonymized_infrastructure', 'insufficient_evidence'
    heuristic_confidence: float  # Bounded heuristic consensus (<= 0.94)
    confidence_metric: str = "heuristic_non_calibrated_consensus"
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    source_modules: List[str] = field(default_factory=list)
    trust_state: str = "inferred"
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_type": self.hypothesis_type,
            "heuristic_confidence": round(self.heuristic_confidence, 4),
            "confidence_metric": self.confidence_metric,
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "source_modules": sorted(list(set(self.source_modules))),
            "trust_state": self.trust_state,
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True)
class CampaignCluster:
    """Identified cross-case recurring infrastructure or campaign overlap."""
    cluster_id: str
    cluster_type: str  # 'recurring_infrastructure', 'reused_attachment', 'reused_domain_infrastructure', 'possible_campaign_cluster'
    shared_entities: List[Dict[str, str]] = field(default_factory=list)
    case_ids: List[str] = field(default_factory=list)
    occurrence_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    inter_case_time_delta_seconds: Optional[float] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "cluster_type": self.cluster_type,
            "shared_entities": list(self.shared_entities),
            "case_ids": list(self.case_ids),
            "occurrence_count": self.occurrence_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "inter_case_time_delta_seconds": self.inter_case_time_delta_seconds,
            "description": self.description,
        }


@dataclass(frozen=True)
class AttributionSupport:
    """Forensic attribution support mapping observable infrastructure and campaign links.

    STRICT GUARANTEE: Never produces attacker identity, physical home address, or
    guaranteed attacker location/IP without authoritative external verification.
    """
    observable_infrastructure: List[Dict[str, Any]] = field(default_factory=list)
    probable_origin: Optional[Dict[str, Any]] = None
    recurring_infrastructure: List[Dict[str, Any]] = field(default_factory=list)
    campaign_links: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observable_infrastructure": list(self.observable_infrastructure),
            "probable_origin": self.probable_origin,
            "recurring_infrastructure": list(self.recurring_infrastructure),
            "campaign_links": list(self.campaign_links),
            "limitations": list(self.limitations),
        }


@dataclass
class InvestigationCase:
    """Top-level unified investigative case combining Modules 1–5 and ML predictions."""
    case_id: str
    email_id: str
    file_hash_sha256: str = ""
    raw_email_reference: Optional[str] = None
    evidence: List[NormalizedEvidence] = field(default_factory=list)
    entities: List[CorrelatedEntity] = field(default_factory=list)
    relationships: List[CorrelatedRelationship] = field(default_factory=list)
    ml_predictions: List[MlPrediction] = field(default_factory=list)
    correlated_findings: List[CorroboratedFinding] = field(default_factory=list)
    contradictions: List[ContradictionRecord] = field(default_factory=list)
    hypotheses: List[CaseHypothesis] = field(default_factory=list)
    campaign_clusters: List[CampaignCluster] = field(default_factory=list)
    attribution_support: AttributionSupport = field(default_factory=AttributionSupport)
    provenance: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "email_id": self.email_id,
            "file_hash_sha256": self.file_hash_sha256,
            "raw_email_reference": self.raw_email_reference,
            "evidence": [ev.to_dict() for ev in self.evidence],
            "entities": [ent.to_dict() for ent in self.entities],
            "relationships": [rel.to_dict() for rel in self.relationships],
            "ml_predictions": [pred.to_dict() for pred in self.ml_predictions],
            "correlated_findings": [f.to_dict() for f in self.correlated_findings],
            "contradictions": [c.to_dict() for c in self.contradictions],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "campaign_clusters": [cl.to_dict() for cl in self.campaign_clusters],
            "attribution_support": self.attribution_support.to_dict(),
            "provenance": list(self.provenance),
        }
