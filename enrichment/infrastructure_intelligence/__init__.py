"""Infrastructure Intelligence Layer for SIH26106 Email Forensics.

Provides passive external enrichment and local threat intelligence matching:
- RDAP (RFC 9082/9083/9224) over HTTPS
- Passive DNS (A, AAAA, CNAME, NS, TXT, SPF, DMARC)
- MX resolution & classification
- Reverse DNS / FCrDNS verification
- Local offline Spamhaus DROP / DROPv6 matching (zero runtime network calls)
- Neutral hosting infrastructure classification
- Synthetic & private IP protection (RFC 5737, RFC 3849, RFC 1918, loopback)
"""

from .dispatcher import (
    InfrastructureIntelligenceDispatcher,
    is_rfc5737_documentation_ip,
    is_synthetic_or_private_ip,
    run_infrastructure_intelligence,
)
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

__all__ = [
    "InfrastructureIntelligenceDispatcher",
    "run_infrastructure_intelligence",
    "is_synthetic_or_private_ip",
    "is_rfc5737_documentation_ip",
    "LocalThreatFeedMatcher",
    "RdapClient",
    "resolve_passive_dns",
    "resolve_mx_records",
    "resolve_reverse_dns",
    "classify_hosting",
    "ThreatFeedMatch",
    "RdapRegistrationData",
    "PassiveDnsData",
    "MxRecordData",
    "ReverseDnsData",
    "HostingFingerprintData",
    "InfrastructureIntelligenceReport",
]
