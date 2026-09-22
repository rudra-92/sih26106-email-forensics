"""Main orchestrator for the Infrastructure Intelligence Layer.

Coordinates passive lookups, offline threat feed matching, and synthetic tests.
Guarantees zero commercial lookups, zero crawling, and graceful containment.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List, Optional

from .fingerprinter import classify_hosting
from .models import (
    HostingFingerprintData,
    InfrastructureIntelligenceReport,
    MxRecordData,
    PassiveDnsData,
    RdapRegistrationData,
    ReverseDnsData,
    ThreatFeedMatch,
)
from .passive_dns import resolve_mx_records, resolve_passive_dns
from .rdap_client import RdapClient
from .reverse_dns import resolve_reverse_dns
from .threat_feeds import LocalThreatFeedMatcher

# Strictly intercepted documentation, private, and loopback netblocks
SYNTHETIC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("2001:db8::/32"),     # Documentation IPv6 (RFC 3849)
    ipaddress.ip_network("10.0.0.0/8"),        # Private (RFC 1918)
    ipaddress.ip_network("172.16.0.0/12"),     # Private (RFC 1918)
    ipaddress.ip_network("192.168.0.0/16"),    # Private (RFC 1918)
    ipaddress.ip_network("127.0.0.0/8"),       # IPv4 Loopback
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
]

DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
]


def is_synthetic_or_private_ip(ip_str: str) -> bool:
    """Check if IP belongs to RFC 5737, RFC 3849, RFC 1918, or loopback."""
    if not ip_str or not ip_str.strip():
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in SYNTHETIC_NETWORKS)
    except (ValueError, TypeError):
        return False


def is_rfc5737_documentation_ip(ip_str: str) -> bool:
    """Check if an IP string belongs strictly to documentation ranges."""
    if not ip_str or not ip_str.strip():
        return False
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in DOCUMENTATION_NETWORKS)
    except (ValueError, TypeError):
        return False


class InfrastructureIntelligenceDispatcher:
    """Coordinates enrichment workers with strict safety and isolation."""

    def __init__(
        self,
        threat_matcher: Optional[LocalThreatFeedMatcher] = None,
        rdap_client: Optional[RdapClient] = None,
        timeout: float = 2.0,
    ) -> None:
        self.threat_matcher = threat_matcher or LocalThreatFeedMatcher()
        self.rdap_client = rdap_client or RdapClient(timeout=timeout)
        self.timeout = timeout

    def run(
        self,
        target_ip: str,
        target_domain: Optional[str] = None,
        helo_name: Optional[str] = None,
        asn_str: Optional[str] = None,
        asn_org: Optional[str] = None,
        module5_report: Optional[Any] = None,
    ) -> InfrastructureIntelligenceReport:
        """Run complete infrastructure intelligence enrichment."""
        now_ts = datetime.now(timezone.utc).isoformat()
        clean_ip = target_ip.strip() if target_ip else ""
        clean_domain = (
            target_domain.strip().lower().rstrip(".")
            if target_domain
            else None
        )

        # Extract earliest reliable peer from module5_report if IP not passed
        if not clean_ip and module5_report is not None:
            m5_d = (
                module5_report.to_dict()
                if hasattr(module5_report, "to_dict")
                else dict(module5_report)
            )
            ass = m5_d.get("origin_assessment", {})
            peer = (
                ass.get("earliest_reliable_peer")
                if isinstance(ass, dict)
                else getattr(ass, "earliest_reliable_peer", None)
            )
            if peer:
                clean_ip = str(getattr(peer, "ip", peer)).strip()

        is_doc = is_rfc5737_documentation_ip(clean_ip)
        is_synthetic = is_synthetic_or_private_ip(clean_ip)

        # =====================================================================
        # GUARD: Synthetic / RFC 5737 / RFC 1918 / Loopback Protection
        # =====================================================================
        if is_synthetic:
            return InfrastructureIntelligenceReport(
                target_ip=clean_ip,
                target_domain=clean_domain,
                is_documentation_ip=is_doc,
                is_synthetic_test=True,
                rdap=RdapRegistrationData(
                    status="synthetic_test",
                    query=clean_ip,
                    query_type="ip",
                    lookup_timestamp=now_ts,
                ),
                dns=PassiveDnsData(
                    status="synthetic_test",
                    query_name=clean_domain or "",
                    lookup_timestamp=now_ts,
                ),
                mx=MxRecordData(
                    status="synthetic_test",
                    query_domain=clean_domain or "",
                    mx_status="synthetic_test",
                    lookup_timestamp=now_ts,
                ),
                reverse_dns=ReverseDnsData(
                    status="synthetic_test",
                    query_ip=clean_ip,
                    lookup_timestamp=now_ts,
                ),
                threat_feed=ThreatFeedMatch(
                    status="synthetic_test", is_listed=False
                ),
                hosting_fingerprint=HostingFingerprintData(
                    classification="unknown",
                    infrastructure_role="unknown",
                    provider_name="Documentation / Synthetic Network",
                    evidence_basis=[
                        "Synthetic/documentation address bypassed queries"
                    ],
                    lookup_timestamp=now_ts,
                ),
                observations=[
                    {
                        "rule_id": "RULE-INFRA-SYNTHETIC-BYPASS",
                        "severity": "informational",
                        "trust_state": "observed",
                        "description": (
                            f"IP '{clean_ip}' is a synthetic/test range. "
                            "External queries bypassed."
                        ),
                        "evidence": {
                            "target_ip": clean_ip,
                            "is_documentation": is_doc,
                            "is_synthetic": True,
                        },
                    }
                ],
                lookup_timestamp=now_ts,
            )

        observations: List[Dict[str, Any]] = []

        # =====================================================================
        # 1. Local Offline Threat Feed Matching (100% Offline)
        # =====================================================================
        threat_match = (
            self.threat_matcher.lookup(clean_ip)
            if clean_ip
            else ThreatFeedMatch(status="unavailable")
        )
        if threat_match.is_listed:
            observations.append(
                {
                    "rule_id": "RULE-ORIGIN-DROP-MATCH",
                    "severity": "high",
                    "trust_state": "observed",
                    "description": (
                        f"Peer IP '{clean_ip}' matches local public threat "
                        f"feed '{threat_match.feed_name}' "
                        f"(CIDR: {threat_match.matched_cidr}, "
                        f"Provider: {threat_match.provider_attribution})."
                    ),
                    "evidence": threat_match.to_dict(),
                }
            )

        # =====================================================================
        # 2. Reverse DNS & Forward-Confirmed Reverse DNS (FCrDNS)
        # =====================================================================
        reverse_dns_data, ptr_obs = (
            resolve_reverse_dns(
                clean_ip, helo_name=helo_name, timeout=self.timeout
            )
            if clean_ip
            else (ReverseDnsData(status="unavailable"), [])
        )
        observations.extend(ptr_obs)

        # =====================================================================
        # 3. Passive DNS (A, AAAA, CNAME, NS, TXT/SPF/DMARC)
        # =====================================================================
        dns_data = (
            resolve_passive_dns(clean_domain, timeout=self.timeout)
            if clean_domain
            else PassiveDnsData(status="unavailable")
        )

        # =====================================================================
        # 4. MX Record Resolution
        # =====================================================================
        mx_data = (
            resolve_mx_records(clean_domain, timeout=self.timeout)
            if clean_domain
            else MxRecordData(status="unavailable")
        )

        # =====================================================================
        # 5. RDAP / Registration Intelligence (RFC 9082/9083/9224)
        # =====================================================================
        rdap_data: RdapRegistrationData
        if clean_domain:
            rdap_data = self.rdap_client.lookup_domain(clean_domain)
        elif clean_ip:
            rdap_data = self.rdap_client.lookup_ip(clean_ip)
        else:
            rdap_data = RdapRegistrationData(status="unavailable")

        # Domain age contextual observation
        if rdap_data.domain_age_days is not None:
            age = rdap_data.domain_age_days
            if age < 30:
                observations.append(
                    {
                        "rule_id": "RULE-ORIGIN-DOMAIN-AGE",
                        "severity": "low" if age < 14 else "informational",
                        "trust_state": "observed",
                        "description": (
                            f"Domain '{clean_domain}' registered {age} "
                            f"days ago ({rdap_data.creation_date})."
                        ),
                        "evidence": {
                            "domain": clean_domain,
                            "domain_age_days": age,
                            "creation_date": rdap_data.creation_date,
                        },
                    }
                )

        # =====================================================================
        # 6. Neutral Hosting Fingerprinting
        # =====================================================================
        hosting_data = classify_hosting(
            asn_str=asn_str,
            org_name=asn_org,
            ptr_hosts=reverse_dns_data.ptr_hostnames,
            rdap_network_name=rdap_data.network_name or rdap_data.registrar,
            threat_match=threat_match,
            ip_str=clean_ip,
        )

        observations.append(
            {
                "rule_id": "RULE-ORIGIN-HOSTING-CLASSIFICATION",
                "severity": "informational",
                "trust_state": "inferred",
                "description": (
                    f"Hosting infrastructure classified as "
                    f"'{hosting_data.classification}' (Provider: "
                    f"'{hosting_data.provider_name or 'unknown'}'). "
                    f"Basis: {', '.join(hosting_data.evidence_basis)}."
                ),
                "evidence": hosting_data.to_dict(),
            }
        )

        return InfrastructureIntelligenceReport(
            target_ip=clean_ip,
            target_domain=clean_domain,
            is_documentation_ip=False,
            is_synthetic_test=False,
            rdap=rdap_data,
            dns=dns_data,
            mx=mx_data,
            reverse_dns=reverse_dns_data,
            threat_feed=threat_match,
            hosting_fingerprint=hosting_data,
            observations=observations,
            lookup_timestamp=now_ts,
        )


def run_infrastructure_intelligence(
    target_ip: str,
    target_domain: Optional[str] = None,
    helo_name: Optional[str] = None,
    asn_str: Optional[str] = None,
    asn_org: Optional[str] = None,
    module5_report: Optional[Any] = None,
    timeout: float = 2.0,
) -> InfrastructureIntelligenceReport:
    """Convenience functional entry point for Infrastructure Intelligence."""
    dispatcher = InfrastructureIntelligenceDispatcher(timeout=timeout)
    return dispatcher.run(
        target_ip=target_ip,
        target_domain=target_domain,
        helo_name=helo_name,
        asn_str=asn_str,
        asn_org=asn_org,
        module5_report=module5_report,
    )
