"""Data models for static URL forensic analysis.

Defines extracted URL provenance structures, parsed normalized URL representations,
tabular features exposed for downstream ML models, graph entities/relationships,
and structured URL observations.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from modules.lookalike_domain.normalizer import NormalizedDomain
from modules.sender_identity.models import Entity, Relationship


@dataclass(frozen=True)
class ExtractedUrl:
    """Represents a URL extracted from plain text or HTML with strict provenance."""
    actual_url: str
    raw_url: str
    source: str  # 'plain_text', 'html_href', 'html_visible_text'
    visible_text: Optional[str] = None
    char_offset: int = -1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NormalizedUrl:
    """Decomposed, normalized canonical URL representation."""
    raw_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    query_params: Dict[str, List[str]]
    fragment: str
    username: Optional[str]
    password: Optional[str]
    netloc: str
    is_ip: bool
    normalized_domain: Optional[NormalizedDomain] = None

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "raw_url": self.raw_url,
            "normalized_url": self.normalized_url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "query_params": self.query_params,
            "fragment": self.fragment,
            "username": self.username,
            "password": self.password,
            "netloc": self.netloc,
            "is_ip": self.is_ip,
        }
        if self.normalized_domain:
            res["domain_info"] = self.normalized_domain.to_dict()
        return res


@dataclass(frozen=True)
class UrlMlFeatures:
    """Tabular static numerical and boolean features for future URL ML classifier."""
    url: str
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    subdomain_count: int
    special_character_count: int
    percent_encoded_count: int
    host_is_ip: bool
    non_default_port: bool
    userinfo_present: bool
    login_token_present: bool
    redirect_indicator: bool
    visible_href_mismatch: bool
    domain_similarity_score: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class UrlObservation:
    """Structured forensic observation for URL-level anomalies and mismatches."""
    observation_id: str
    rule_id: str
    source_module: str
    type: str
    severity: str  # 'informational', 'low', 'medium', 'high'
    description: str
    evidence: Dict[str, Any]
    fact_type: str  # 'observed', 'reported', 'inferred'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class UrlAnalysisAssessment:
    """Bounded, transparent structural URL assessment.

    Evaluates structural suspicion without making global email phishing claims.
    """
    category: str  # 'no_significant_url_anomaly', 'url_anomaly_detected', 'suspicious_url_structure'
    risk_level: str  # 'none', 'low', 'medium', 'high'
    evidence_strength: str  # 'none', 'weak', 'moderate', 'strong'
    confidence: float  # Bounded float (0.0 to 0.90)
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
class UrlAnalysisReport:
    """Top-level forensic output for Module 3 URL Analysis."""
    module: str = "url_analysis"
    email_id: str = "E001"
    urls: List[Dict[str, Any]] = field(default_factory=list)
    entities: List[Entity] = field(default_factory=list)
    observations: List[UrlObservation] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    assessment: Optional[UrlAnalysisAssessment] = None
    ml_features: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "email_id": self.email_id,
            "urls": self.urls,
            "entities": [e.to_dict() for e in self.entities],
            "observations": [o.to_dict() for o in self.observations],
            "relationships": [r.to_dict() for r in self.relationships],
            "assessment": self.assessment.to_dict() if self.assessment else {
                "category": "no_significant_url_anomaly",
                "risk_level": "none",
                "evidence_strength": "none",
                "confidence": 0.0,
                "reason": "No URLs analyzed.",
            },
            "ml_features": self.ml_features,
        }
