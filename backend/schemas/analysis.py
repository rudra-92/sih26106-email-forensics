"""Pydantic schemas for evidence, entities, hypotheses, and summaries."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    """Normalized forensic evidence item with provenance and trust state."""

    evidence_id: str
    source_module: str
    rule_id: str
    trust_state: str
    severity: str
    description: str
    entity_ids: List[str] = Field(default_factory=list)
    timestamp: Optional[str] = None
    provenance: List[str] = Field(default_factory=list)
    supporting_fields: Dict[str, Any] = Field(default_factory=dict)


class EvidenceListResponse(BaseModel):
    """Collection of normalized evidence items for a case."""

    case_id: str
    total: int
    evidence: List[EvidenceItem]


class EntityItem(BaseModel):
    """Resolved entity within the investigation case."""

    entity_id: str
    entity_type: str
    canonical_value: str
    source_modules: List[str] = Field(default_factory=list)
    first_observed_timestamp: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class EntityListResponse(BaseModel):
    """Collection of resolved entities for a case."""

    case_id: str
    total: int
    entities: List[EntityItem]


class RelationshipItem(BaseModel):
    """Graph edge / relationship between resolved entities."""

    relationship_id: str
    source_entity_id: str
    target_entity_id: str
    relationship_type: str
    evidence_ids: List[str] = Field(default_factory=list)
    source_modules: List[str] = Field(default_factory=list)
    trust_state: str
    timestamp: Optional[str] = None
    provenance: List[str] = Field(default_factory=list)


class RelationshipListResponse(BaseModel):
    """Collection of graph relationships for a case."""

    case_id: str
    total: int
    relationships: List[RelationshipItem]


class HypothesisItem(BaseModel):
    """Investigative hypothesis synthesized from evidence consensus."""

    hypothesis_id: str
    hypothesis_type: str
    confidence: float
    confidence_metric: str = "heuristic_non_calibrated_consensus"
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    contradicting_evidence_ids: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    provenance: List[str] = Field(default_factory=list)


class HypothesisListResponse(BaseModel):
    """Collection of hypotheses for a case."""

    case_id: str
    total: int
    hypotheses: List[HypothesisItem]


class OriginResponse(BaseModel):
    """Reconstructed origin and technical infrastructure observations."""

    case_id: str
    earliest_reliable_peer: Optional[str] = None
    source_visibility: Optional[str] = None
    confidence: Optional[float] = None
    assessment_reason: Optional[str] = None
    infrastructure: Dict[str, Any] = Field(default_factory=dict)
    geolocation: Dict[str, Any] = Field(default_factory=dict)
    asn: Dict[str, Any] = Field(default_factory=dict)
    hops: List[Dict[str, Any]] = Field(default_factory=list)
    rdap: Optional[Dict[str, Any]] = None
    reverse_dns: Optional[Dict[str, Any]] = None
    threat_feed: Optional[Dict[str, Any]] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)
    semantic_note: str = (
        "Observed infrastructure geolocation represents routing "
        "Point-of-Presence (PoP), NOT human physical attacker location."
    )


class SummaryResponse(BaseModel):
    """Investigation dashboard summary with findings and counts."""

    case_id: str
    threat_label: Optional[str] = None
    threat_confidence: Optional[float] = None
    threat_confidence_metric: Optional[str] = None
    important_forensic_findings: List[Dict[str, Any]] = Field(
        default_factory=list
    )
    top_hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    origin_infrastructure_summary: Dict[str, Any] = Field(
        default_factory=dict
    )
    evidence_counts: Dict[str, int] = Field(default_factory=dict)
    entity_counts: Dict[str, int] = Field(default_factory=dict)
    key_domains: List[str] = Field(default_factory=list)
    key_ips: List[str] = Field(default_factory=list)
    key_urls: List[str] = Field(default_factory=list)
    suspicious_attachments: List[str] = Field(default_factory=list)
    authentication_observations: List[Dict[str, Any]] = Field(
        default_factory=list
    )
