"""Data models for Origin & Infrastructure Reconstruction Engine (Module 5).

Defines structured models for parsed Received headers, reconstructed transmission hops,
temporal delay/transit results, ARC authentication chain integrity, earliest reliable external
peer candidates, adapter-based infrastructure enrichment (GeoIP, ASN, Cloud/VPN/TOR),
competing origin hypotheses, graph entities/relationships, and forensic observations.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from modules.sender_identity.models import Entity, Relationship


@dataclass(frozen=True)
class HopParsedFields:
    """Detailed components parsed from a single Received header."""
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    by_ip: Optional[str] = None
    with_protocol: Optional[str] = None
    tls_cipher: Optional[str] = None
    id_param: Optional[str] = None
    for_envelope_to: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timezone_raw: Optional[str] = None
    parser_confidence: str = "high"  # 'high', 'medium', 'low'
    is_source_private: bool = False
    is_receiver_private: bool = False
    other_ips: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ParsedReceivedHop:
    """Structured representation of a raw Received header and its parsed fields."""
    hop_index: int
    raw_received_header: str
    parsed_fields: HopParsedFields
    source_header_ref: str  # e.g., 'Received[0]'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hop_index": self.hop_index,
            "raw_received_header": self.raw_received_header,
            "parsed_fields": self.parsed_fields.to_dict(),
            "source_header_ref": self.source_header_ref,
        }


@dataclass(frozen=True)
class ReconstructedHop:
    """Normalized hop ordered according to mail-transit transmission path (1 to N)."""
    hop_sequence_num: int  # 1 = earliest sender-side hop, N = final receiver hop
    original_header_index: int  # Original position in email header (0 = top/most recent)
    source_host: Optional[str]
    source_ip: Optional[str]
    receiver_host: Optional[str]
    receiver_ip: Optional[str]
    timestamp_raw: Optional[str]
    timestamp_utc: Optional[str]  # ISO format UTC timestamp string
    protocol: Optional[str]
    is_source_private: bool
    is_receiver_private: bool
    trust_state: str = "observed"  # 'observed', 'verified', 'enriched', 'inferred', 'unknown'
    direction: str = "upstream_to_downstream"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TemporalAnalysisResult:
    """Results of hop-to-hop and date-to-received chronology analysis."""
    chronology_consistent: bool
    negative_intervals: int
    abnormal_delays: int
    hop_delays_seconds: List[Optional[float]]
    total_transit_seconds: Optional[float]
    date_to_first_received_seconds: Optional[float]
    future_timestamps: int
    malformed_timestamps: int
    possible_clock_skew: bool
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ArcInstance:
    """Status and completeness of a single ARC instance (i=1, 2, ...)."""
    instance_index: int
    seal_result: Optional[str]  # 'pass', 'fail', 'none'
    has_seal: bool
    has_signature: bool
    has_auth_results: bool
    is_complete: bool
    domain: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ArcAnalysisResult:
    """Evaluation of the Authenticated Received Chain (RFC 8617)."""
    has_arc: bool
    instances: List[ArcInstance] = field(default_factory=list)
    is_chain_complete: bool = False
    is_chain_consistent: bool = False
    is_chain_valid: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_arc": self.has_arc,
            "instances": [inst.to_dict() for inst in self.instances],
            "is_chain_complete": self.is_chain_complete,
            "is_chain_consistent": self.is_chain_consistent,
            "is_chain_valid": self.is_chain_valid,
            "details": self.details,
        }


@dataclass(frozen=True)
class GeoLocationData:
    """Observed network infrastructure geolocation metadata."""
    status: str = "unavailable"  # 'available', 'unavailable', 'not_found', 'invalid_input', 'not_queried'
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    accuracy_radius_km: Optional[float] = None
    source_dataset: str = "local_database"
    dataset_name: Optional[str] = None
    dataset_date: Optional[str] = None
    lookup_timestamp: Optional[str] = None
    semantic_note: str = "Observed infrastructure geolocation, NOT human attacker physical location."
    observed_infrastructure_geolocation: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AsnData:
    """Autonomous System Number metadata for observed infrastructure."""
    status: str = "unavailable"  # 'available', 'unavailable', 'not_found', 'invalid_input'
    asn: Optional[str] = None
    organization: Optional[str] = None
    network_cidr: Optional[str] = None
    source_dataset: str = "local_database"
    dataset_name: Optional[str] = None
    dataset_date: Optional[str] = None
    lookup_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class InfrastructureData:
    """Contextual classification of observed network infrastructure."""
    is_hosting: Optional[bool] = None
    is_proxy: Optional[bool] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    provider_name: Optional[str] = None
    classification: str = "unknown"  # 'direct_origin', 'mail_provider', 'enterprise_gateway', 'cloud_hosting', 'hosting_provider', 'vpn_indicator', 'proxy_indicator', 'tor_indicator', 'unknown'
    tor_exit_indicator: Optional[str] = None  # 'true', 'false', 'unknown'
    tor_feed_date: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class UserCountryData:
    """Country associated with likely end-user/network endpoint."""
    status: str = "unavailable"  # 'available', 'unavailable', 'not_found', 'invalid_input'
    country_code: Optional[str] = None
    trust_state: str = "unknown"  # 'enriched', 'unknown'
    source_dataset: str = "sapics/ip-location-db (user-country)"
    license: str = "PDDL-1.0"
    lookup_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ServerCountryData:
    """Country associated with server/relay infrastructure."""
    status: str = "unavailable"  # 'available', 'unavailable', 'not_found', 'invalid_input'
    country_code: Optional[str] = None
    trust_state: str = "unknown"  # 'enriched', 'unknown'
    source_dataset: str = "sapics/ip-location-db (server-country)"
    license: str = "PDDL-1.0"
    lookup_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OriginAsnData:
    """Autonomous System Number from global BGP routing tables."""
    status: str = "unavailable"  # 'available', 'unavailable', 'not_found', 'invalid_input'
    asn: Optional[str] = None
    organization: Optional[str] = None
    trust_state: str = "unknown"  # 'enriched', 'unknown'
    source_dataset: str = "sapics/ip-location-db (origin-asn)"
    license: str = "PDDL-1.0"
    lookup_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LocationEvidence:
    """Multi-source geographic & infrastructure evidence aggregation.

    CRITICAL SEMANTIC PRINCIPLES:
    1. Aggregates observable evidence regarding network endpoint vs server/relay infrastructure.
       NEVER establishes physical human or attacker location.
    2. Country agreement or disagreement alone does NOT determine infrastructure type.
       Same country can contain relays/proxies; cross-border routes can be benign anycast.
    3. country_confidence is an explicitly bounded, heuristic, non-calibrated consensus score
       reflecting database agreement, NOT a statistical probability.
    4. Origin location type is synthesized ONLY using broader Module 5 evidence (hop position,
       trust state, temporal delay, infrastructure classification, ASN, and authentication).
    """
    ip: str
    dbip_infrastructure_location: Dict[str, Any] = field(default_factory=dict)
    user_country: Dict[str, Any] = field(default_factory=dict)
    server_country: Dict[str, Any] = field(default_factory=dict)
    origin_asn: Dict[str, Any] = field(default_factory=dict)
    country_agreement: Optional[bool] = None
    interpretation: str = "insufficient_country_evidence"
    country_confidence: float = 0.0  # Bounded heuristic consensus score (0.0 - 0.95), NOT a probability
    confidence_metric: str = "heuristic_non_calibrated_consensus"  # Explicitly documents non-probabilistic metric
    location_type: str = "unknown"  # 'direct_origin_infrastructure', 'relay_infrastructure', 'provider_infrastructure', 'anonymized_infrastructure', 'campaign_infrastructure', 'unknown'
    provenance: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "dbip_infrastructure_location": self.dbip_infrastructure_location,
            "user_country": self.user_country,
            "server_country": self.server_country,
            "origin_asn": self.origin_asn,
            "country_agreement": self.country_agreement,
            "interpretation": self.interpretation,
            "country_confidence": round(self.country_confidence, 4),
            "confidence_metric": self.confidence_metric,
            "location_type": self.location_type,
            "provenance": list(self.provenance),
        }


@dataclass(frozen=True)
class EnrichedInfrastructure:
    """Composite enrichment bundle for an observed IP address."""
    ip: str
    geolocation: GeoLocationData
    asn: AsnData
    infrastructure: InfrastructureData
    location_evidence: Optional[LocationEvidence] = None

    def to_dict(self) -> Dict[str, Any]:
        geo_dict = self.geolocation.to_dict()
        res = {
            "ip": self.ip,
            "geolocation": geo_dict,
            "observed_infrastructure_geolocation": geo_dict,
            "asn": self.asn.to_dict(),
            "infrastructure": self.infrastructure.to_dict(),
        }
        if self.location_evidence:
            res["location_evidence"] = self.location_evidence.to_dict()
        return res


@dataclass(frozen=True)
class OriginCandidate:
    """Candidate observed origin infrastructure or peer."""
    ip: str
    hostname: Optional[str]
    role: str  # 'earliest_reliable_external_peer', 'upstream_relay', 'mail_provider', 'enterprise_gateway', 'cloud_infrastructure', 'anonymization_endpoint', 'unknown'
    confidence: float  # Bounded heuristic confidence (<= 0.94)
    trust_state: str  # 'observed', 'verified', 'enriched', 'inferred', 'unknown'
    hop_sequence_num: int
    source_visibility: str  # 'visible', 'provider_masked', 'insufficient_evidence', 'anonymized'
    reasoning: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "role": self.role,
            "confidence": round(self.confidence, 4),
            "trust_state": self.trust_state,
            "hop_sequence_num": self.hop_sequence_num,
            "source_visibility": self.source_visibility,
            "reasoning": self.reasoning,
        }


@dataclass(frozen=True)
class OriginAssessment:
    """Bounded origin evaluation for the email transport route."""
    earliest_reliable_peer: Optional[str]
    peer_hostname: Optional[str]
    source_visibility: str  # 'visible', 'provider_masked', 'insufficient_evidence', 'anonymized'
    confidence: float  # Bounded heuristic confidence (<= 0.94)
    assessment_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "earliest_reliable_peer": self.earliest_reliable_peer,
            "peer_hostname": self.peer_hostname,
            "source_visibility": self.source_visibility,
            "confidence": round(self.confidence, 4),
            "assessment_reason": self.assessment_reason,
        }


@dataclass(frozen=True)
class OriginHypothesis:
    """A competing hypothesis explaining origin infrastructure observations."""
    hypothesis_type: str  # 'possible_direct_origin', 'possible_mail_relay', 'possible_provider_masking', 'possible_cloud_infrastructure', 'possible_anonymized_infrastructure', 'possible_compromised_account', 'insufficient_origin_evidence'
    confidence: float  # Heuristic confidence (<= 0.94)
    supporting_evidence: List[str]
    contradicting_evidence: List[str]
    trust_state: str = "inferred"
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_type": self.hypothesis_type,
            "confidence": round(self.confidence, 4),
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "trust_state": self.trust_state,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class OriginObservation:
    """Structured finding capturing an origin or infrastructure anomaly/indicator."""
    observation_id: str
    rule_id: str
    source_module: str = "origin_infrastructure"
    source_header: str = "Received"
    severity: str = "informational"  # 'informational', 'low', 'medium', 'high'
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    trust_state: str = "observed"  # 'observed', 'verified', 'enriched', 'inferred', 'unknown'
    fact_type: str = "observed"  # 'observed', 'reported', 'inferred'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OriginInfrastructureReport:
    """Top-level forensic output schema for Module 5 Origin & Infrastructure Reconstruction."""
    module: str = "origin_infrastructure"
    email_id: str = "E001"
    file_hash_sha256: str = ""
    origin_assessment: Optional[OriginAssessment] = None
    temporal_analysis: Optional[TemporalAnalysisResult] = None
    hops: List[ReconstructedHop] = field(default_factory=list)
    enriched_peers: List[EnrichedInfrastructure] = field(default_factory=list)
    hypotheses: List[OriginHypothesis] = field(default_factory=list)
    observations: List[OriginObservation] = field(default_factory=list)
    entities: List[Entity] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    provenance: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "email_id": self.email_id,
            "file_hash_sha256": self.file_hash_sha256,
            "origin_assessment": self.origin_assessment.to_dict() if self.origin_assessment else {
                "earliest_reliable_peer": None,
                "peer_hostname": None,
                "source_visibility": "insufficient_evidence",
                "confidence": 0.0,
                "assessment_reason": "No assessment generated.",
            },
            "temporal_analysis": self.temporal_analysis.to_dict() if self.temporal_analysis else {
                "chronology_consistent": True,
                "negative_intervals": 0,
                "abnormal_delays": 0,
                "hop_delays_seconds": [],
                "total_transit_seconds": None,
                "date_to_first_received_seconds": None,
                "future_timestamps": 0,
                "malformed_timestamps": 0,
                "possible_clock_skew": False,
                "details": {},
            },
            "hops": [h.to_dict() for h in self.hops],
            "enriched_peers": [p.to_dict() for p in self.enriched_peers],
            "hypotheses": [hypo.to_dict() for hypo in self.hypotheses],
            "observations": [o.to_dict() for o in self.observations],
            "entities": [e.to_dict() for e in self.entities],
            "relationships": [r.to_dict() for r in self.relationships],
            "provenance": self.provenance,
        }
