"""Data models for Infrastructure Intelligence Layer.

Defines passive infrastructure enrichment models covering RDAP, passive DNS,
MX, Reverse DNS / FCrDNS, local threat feeds, and hosting fingerprinting.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ThreatFeedMatch:
    """Deterministic local threat feed matching result."""

    status: str = "unavailable"  # 'available', 'unavailable', 'synthetic_test'
    is_listed: bool = False
    feed_name: Optional[str] = None
    feed_version: Optional[str] = None
    download_timestamp: Optional[str] = None
    matched_cidr: Optional[str] = None
    source_url: Optional[str] = None
    provider_attribution: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RdapRegistrationData:
    """Registration/allocation intelligence from RFC 9082/9083/9224 RDAP."""

    status: str = "unavailable"
    query: str = ""
    query_type: str = "ip"  # 'ip', 'domain', 'autnum'
    rir: Optional[str] = None
    network_name: Optional[str] = None
    cidr: Optional[str] = None
    handle: Optional[str] = None
    registrar: Optional[str] = None
    registrar_id: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    nameservers: List[str] = field(default_factory=list)
    abuse_contact_email: Optional[str] = None
    lookup_source: str = "rdap_bootstrap"
    error_message: Optional[str] = None
    lookup_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PassiveDnsData:
    """Passive DNS observations extracted without active probing."""

    status: str = "unavailable"
    query_name: str = ""
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    error_message: Optional[str] = None
    lookup_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MxRecordData:
    """Passive mail exchanger (MX) resolution and classification."""

    status: str = "unavailable"
    query_domain: str = ""
    records: List[Dict[str, Any]] = field(default_factory=list)
    primary_provider: str = "unknown"
    is_null_mx: bool = False
    mx_status: str = "unavailable"
    error_message: Optional[str] = None
    lookup_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReverseDnsData:
    """Reverse DNS (PTR) resolution and FCrDNS verification."""

    status: str = "unavailable"
    query_ip: str = ""
    ptr_hostnames: List[str] = field(default_factory=list)
    fcrdns_valid: Optional[bool] = None
    helo_ptr_match: Optional[bool] = None
    forward_ips: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    lookup_timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HostingFingerprintData:
    """Neutral hosting infrastructure classification."""

    classification: str = "unknown"
    provider_name: Optional[str] = None
    evidence_basis: List[str] = field(default_factory=list)
    is_bulletproof_reported: bool = False
    bulletproof_source: Optional[str] = None
    lookup_timestamp: Optional[str] = None
    infrastructure_role: Optional[str] = None

    def __post_init__(self) -> None:
        if self.infrastructure_role is None:
            object.__setattr__(
                self, "infrastructure_role", self.classification
            )

    @property
    def provider(self) -> Optional[str]:
        return self.provider_name

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d.get("infrastructure_role") is None:
            d["infrastructure_role"] = self.classification
        d["provider"] = self.provider_name
        return d


@dataclass(frozen=True)
class InfrastructureIntelligenceReport:
    """Consolidated enrichment report generated between M5 and M6."""

    target_ip: str
    target_domain: Optional[str] = None
    is_documentation_ip: bool = False
    is_synthetic_test: bool = False
    rdap: RdapRegistrationData = field(default_factory=RdapRegistrationData)
    dns: PassiveDnsData = field(default_factory=PassiveDnsData)
    mx: MxRecordData = field(default_factory=MxRecordData)
    reverse_dns: ReverseDnsData = field(default_factory=ReverseDnsData)
    threat_feed: ThreatFeedMatch = field(default_factory=ThreatFeedMatch)
    hosting_fingerprint: HostingFingerprintData = field(
        default_factory=HostingFingerprintData
    )
    observations: List[Dict[str, Any]] = field(default_factory=list)
    lookup_timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ip": self.target_ip,
            "target_domain": self.target_domain,
            "is_documentation_ip": self.is_documentation_ip,
            "is_synthetic_test": self.is_synthetic_test,
            "rdap": self.rdap.to_dict(),
            "dns": self.dns.to_dict(),
            "mx": self.mx.to_dict(),
            "reverse_dns": self.reverse_dns.to_dict(),
            "threat_feed": self.threat_feed.to_dict(),
            "hosting_fingerprint": self.hosting_fingerprint.to_dict(),
            "observations": list(self.observations),
            "lookup_timestamp": self.lookup_timestamp,
        }
