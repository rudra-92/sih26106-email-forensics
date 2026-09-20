"""Data models for sender identity and authentication analysis.

Defines graph-ready entity and relationship models, structured forensic
observations with strict provenance, parsed email evidence representations,
and transparent risk assessment schemas.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Entity:
    """Graph-ready entity representing an atomic forensic object.

    Compatible with future graph databases and correlation engines.
    """
    type: str  # e.g., 'email', 'email_address', 'domain', 'ip', 'message_id'
    value: str
    source: str  # e.g., 'From', 'Reply-To', 'Received', 'Message-ID'
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "type": self.type,
            "value": self.value,
            "source": self.source,
        }
        if self.attributes:
            result["attributes"] = self.attributes
        return result


@dataclass
class Relationship:
    """Graph-ready directed relationship connecting two entities.

    Explicitly preserves forensic roles (e.g. observed_peer_ip, observed_receiver_ip)
    without speculative attribution.
    """
    source: str  # Canonical identifier or value of source entity
    relation: str  # e.g., 'sent_by', 'belongs_to', 'replies_to', 'observed_peer_ip', 'observed_receiver_ip'
    target: str  # Canonical identifier or value of target entity
    evidence: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "source": self.source,
            "relation": self.relation,
            "target": self.target,
        }
        if self.evidence:
            result["evidence"] = self.evidence
        return result


@dataclass
class Observation:
    """Structured finding capturing a specific forensic inconsistency or fact.

    Every observation retains enough provenance to answer:
    - what was observed? (type, description)
    - which rule generated it? (rule_id)
    - which header produced it? (source_header)
    - what exact values were compared? (evidence)
    """
    observation_id: str
    rule_id: str
    type: str
    severity: str  # 'informational', 'low', 'medium', 'high'
    description: str
    evidence: Dict[str, Any]
    source_header: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "rule_id": self.rule_id,
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "source_header": self.source_header,
        }


@dataclass
class Assessment:
    """Transparent, bounded forensic risk evaluation.

    Distinguishes risk level, evidence strength, and confidence,
    explicitly avoiding claims of 100% certainty or attacker attribution.
    """
    category: str
    risk_level: str  # 'none', 'low', 'medium', 'high'
    evidence_strength: str  # 'none', 'weak', 'moderate', 'strong'
    confidence: float  # Bounded float (never 1.0)
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "risk_level": self.risk_level,
            "evidence_strength": self.evidence_strength,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
        }


@dataclass
class ReceivedHop:
    """Structured representation of a single Received header in the relay path.

    Preserves explicit IP roles:
    - from_ip / peer_ip: upstream sending peer observed by receiving server
    - by_ip / receiver_ip: server receiving that hop
    """
    hop_index: int
    raw_header: str
    from_host: Optional[str] = None
    from_ip: Optional[str] = None  # peer_ip
    by_host: Optional[str] = None
    by_ip: Optional[str] = None  # receiver_ip
    other_ips: List[str] = field(default_factory=list)
    timestamp: Optional[str] = None

    @property
    def all_ips(self) -> List[str]:
        """All unique validated IPs discovered in this hop."""
        ips: List[str] = []
        if self.from_ip and self.from_ip not in ips:
            ips.append(self.from_ip)
        if self.by_ip and self.by_ip not in ips:
            ips.append(self.by_ip)
        for ip in self.other_ips:
            if ip not in ips:
                ips.append(ip)
        return ips

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hop_index": self.hop_index,
            "from_host": self.from_host,
            "from_ip": self.from_ip,
            "by_host": self.by_host,
            "by_ip": self.by_ip,
            "other_ips": self.other_ips,
            "timestamp": self.timestamp,
            "raw_header": self.raw_header,
        }


@dataclass
class AuthResults:
    """Extracted authentication findings reported in Authentication-Results headers."""
    spf: Optional[str] = None  # pass, fail, softfail, neutral, none, permerror, temperror
    spf_domain: Optional[str] = None
    dkim: Optional[str] = None  # pass, fail, neutral, none, permerror, temperror
    dkim_domain: Optional[str] = None
    dmarc: Optional[str] = None  # pass, fail, none, permerror, temperror
    dmarc_domain: Optional[str] = None
    raw_headers: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spf": self.spf,
            "spf_domain": self.spf_domain,
            "dkim": self.dkim,
            "dkim_domain": self.dkim_domain,
            "dmarc": self.dmarc,
            "dmarc_domain": self.dmarc_domain,
            "raw_headers": self.raw_headers,
            "details": self.details,
        }


@dataclass
class ParsedEmailEvidence:
    """All raw, normalized, and derived identity/routing evidence extracted from an .eml."""
    file_hash_sha256: str
    message_id: Optional[str] = None
    message_id_domain: Optional[str] = None
    from_raw: Optional[str] = None
    to_raw: Optional[str] = None
    reply_to_raw: Optional[str] = None
    return_path_raw: Optional[str] = None
    display_name: Optional[str] = None
    sender_address: Optional[str] = None
    sender_domain: Optional[str] = None
    reply_to_address: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path_address: Optional[str] = None
    return_path_domain: Optional[str] = None
    auth_results: AuthResults = field(default_factory=AuthResults)
    received_hops: List[ReceivedHop] = field(default_factory=list)


@dataclass
class SenderIdentityReport:
    """Final modular output schema for Module 1."""
    module: str = "sender_identity"
    email_id: str = "E001"
    file_hash_sha256: str = ""
    entities: List[Entity] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    assessment: Optional[Assessment] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "email_id": self.email_id,
            "file_hash_sha256": self.file_hash_sha256,
            "entities": [e.to_dict() for e in self.entities],
            "observations": [o.to_dict() for o in self.observations],
            "relationships": [r.to_dict() for r in self.relationships],
            "assessment": self.assessment.to_dict() if self.assessment else {
                "category": "unknown",
                "risk_level": "none",
                "evidence_strength": "none",
                "confidence": 0.0,
                "reason": "No assessment generated",
            },
        }
