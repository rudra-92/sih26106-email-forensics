"""Neutral hosting infrastructure classifier.

Classifies observable technical infrastructure into objective, neutral roles.
Never labels cloud/VPS/CDN infrastructure as malicious by default.
Only asserts 'reported_bulletproof_infrastructure' when an explicit local
maintained source identifies it as such.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .models import HostingFingerprintData, ThreatFeedMatch

# Explicit maintained list of documented bulletproof ASNs
KNOWN_BULLETPROOF_ASNS = {
    "210558": "Biterika LLC / Bulletproof",
    "206499": "Hostkey / Known High-Risk Infrastructure",
}

# Well-known public recursive DNS resolver IPs
PUBLIC_DNS_IPS = {
    "8.8.8.8": "Google",
    "8.8.4.4": "Google",
    "2001:4860:4860::8888": "Google",
    "2001:4860:4860::8844": "Google",
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "2606:4700:4700::1111": "Cloudflare",
    "2606:4700:4700::1001": "Cloudflare",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "2620:fe::fe": "Quad9",
    "208.67.222.222": "Cisco Umbrella / OpenDNS",
    "208.67.220.220": "Cisco Umbrella / OpenDNS",
}

# Well-known public recursive DNS host patterns
PUBLIC_DNS_HOST_PATTERNS: List[Tuple[str, str]] = [
    ("dns.google", "Google"),
    ("cloudflare-dns.com", "Cloudflare"),
    ("one.one.one.one", "Cloudflare"),
    ("quad9.net", "Quad9"),
    ("opendns.com", "Cisco Umbrella / OpenDNS"),
]

# Explicit mail infrastructure patterns (requires actual mail indicators)
ENTERPRISE_MAIL_PATTERNS: List[Tuple[str, str]] = [
    ("mail.protection.outlook.com", "Microsoft"),
    ("protection.outlook.com", "Microsoft"),
    ("mail-protection", "Microsoft"),
    ("outlook.com", "Microsoft"),
    ("aspmx.l.google.com", "Google"),
    ("alt1.aspmx.l.google.com", "Google"),
    ("alt2.aspmx.l.google.com", "Google"),
    ("aspmx", "Google"),
    ("gmail-smtp", "Google"),
    ("googlemail.com", "Google"),
    ("pphosted.com", "Proofpoint"),
    ("proofpoint.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("barracudanetworks.com", "Barracuda Networks"),
    ("ess.barracuda.com", "Barracuda Networks"),
    ("ironport.com", "Cisco IronPort"),
    ("ciscoesa", "Cisco IronPort"),
    ("protonmail.ch", "Proton Mail"),
    ("mailroute.net", "MailRoute"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("mandrillapp.com", "Mandrill / Mailchimp"),
]

CLOUD_PROVIDERS = {
    "amazon": "Amazon Web Services (AWS)",
    "aws": "Amazon Web Services (AWS)",
    "azure": "Microsoft Azure",
    "microsoft azure": "Microsoft Azure",
    "google cloud": "Google Cloud Platform (GCP)",
    "gcp": "Google Cloud Platform (GCP)",
    "oracle": "Oracle Cloud",
    "alibaba": "Alibaba Cloud",
}
VPS_PROVIDERS = {
    "hetzner": "Hetzner Online",
    "digitalocean": "DigitalOcean",
    "ovh": "OVHcloud",
    "linode": "Linode / Akamai",
    "vultr": "Vultr",
    "scaleway": "Scaleway",
    "leaseweb": "Leaseweb",
}
CDN_PROVIDERS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai Technologies",
    "fastly": "Fastly",
}
COMMERCIAL_HOSTING = {
    "godaddy": "GoDaddy",
    "namecheap": "Namecheap",
    "bluehost": "Bluehost",
    "hostinger": "Hostinger",
    "ionos": "IONOS",
}


def _detect_provider(
    org_name: str, rdap_net_name: str, all_text: str
) -> Optional[str]:
    """Deterministically identify provider identity separate from role."""
    combined = f"{org_name} {rdap_net_name} {all_text}".lower()
    if "google" in combined:
        return "Google"
    if "microsoft" in combined:
        return "Microsoft"
    if "amazon" in combined or "aws" in combined:
        return "Amazon Web Services (AWS)"
    if "cloudflare" in combined:
        return "Cloudflare"
    if "hetzner" in combined:
        return "Hetzner Online"
    if "digitalocean" in combined:
        return "DigitalOcean"
    if "ovh" in combined:
        return "OVHcloud"
    if "proofpoint" in combined:
        return "Proofpoint"
    if "mimecast" in combined:
        return "Mimecast"
    if "barracuda" in combined:
        return "Barracuda Networks"
    if "proton" in combined:
        return "Proton Mail"
    if org_name and not any(
        r in org_name.lower() for r in ("reserved", "iana")
    ):
        return org_name
    return None


def classify_hosting(
    asn_str: Optional[str] = None,
    org_name: Optional[str] = None,
    ptr_hosts: Optional[List[str]] = None,
    rdap_network_name: Optional[str] = None,
    threat_match: Optional[ThreatFeedMatch] = None,
    ip_str: Optional[str] = None,
) -> HostingFingerprintData:
    """Classify server hosting role objectively based on technical evidence.

    Separates provider identity from infrastructure role/category.
    """
    now_ts = datetime.now(timezone.utc).isoformat()
    evidence_basis: List[str] = []

    clean_asn = str(asn_str or "").strip().upper().replace("AS", "")
    clean_ip = str(ip_str or "").strip()
    ptr_list = ptr_hosts or []

    all_text = " ".join(
        [
            str(org_name or "").lower(),
            str(rdap_network_name or "").lower(),
            " ".join(str(h).lower() for h in ptr_list),
        ]
    )

    detected_provider = _detect_provider(
        str(org_name or ""), str(rdap_network_name or ""), all_text
    )

    # 1. Explicit reported bulletproof check (Requires maintained record)
    if clean_asn in KNOWN_BULLETPROOF_ASNS:
        src_name = KNOWN_BULLETPROOF_ASNS[clean_asn]
        evidence_basis.append(
            f"ASN {clean_asn} matches documented bulletproof registry: "
            f"{src_name}"
        )
        return HostingFingerprintData(
            classification="reported_bulletproof_infrastructure",
            infrastructure_role="reported_bulletproof_infrastructure",
            provider_name=src_name,
            evidence_basis=evidence_basis,
            is_bulletproof_reported=True,
            bulletproof_source="Local Maintained Bulletproof AS Registry",
            lookup_timestamp=now_ts,
        )

    if threat_match and threat_match.is_listed:
        evidence_basis.append(
            f"Listed in local public threat feed ({threat_match.feed_name}: "
            f"{threat_match.matched_cidr})"
        )

    # 2. Public Recursive DNS Infrastructure (e.g. 8.8.8.8, 8.8.4.4, 1.1.1.1)
    if clean_ip and clean_ip in PUBLIC_DNS_IPS:
        dns_prov = PUBLIC_DNS_IPS[clean_ip]
        evidence_basis.append(
            f"IP {clean_ip} matches well-known public recursive DNS resolver "
            f"({dns_prov})"
        )
        return HostingFingerprintData(
            classification="public_dns_infrastructure",
            infrastructure_role="public_dns_infrastructure",
            provider_name=dns_prov,
            evidence_basis=evidence_basis,
            lookup_timestamp=now_ts,
        )

    for host in ptr_list:
        h_lower = str(host).lower().strip(".")
        for pattern, dns_prov in PUBLIC_DNS_HOST_PATTERNS:
            if h_lower == pattern or h_lower.endswith(f".{pattern}"):
                evidence_basis.append(
                    f"PTR '{host}' matches public DNS service ({dns_prov})"
                )
                return HostingFingerprintData(
                    classification="public_dns_infrastructure",
                    infrastructure_role="public_dns_infrastructure",
                    provider_name=dns_prov,
                    evidence_basis=evidence_basis,
                    lookup_timestamp=now_ts,
                )

    # 3. IANA / Reserved Infrastructure (e.g. example.com)
    iana_markers = (
        "internet assigned numbers authority",
        "iana",
        "reserved",
        "example.com",
    )
    if any(m in all_text for m in iana_markers):
        evidence_basis.append(
            "Matches IANA / RFC reserved non-production allocation"
        )
        return HostingFingerprintData(
            classification="unknown",
            infrastructure_role="unknown",
            provider_name=org_name or "IANA / Reserved",
            evidence_basis=evidence_basis,
            lookup_timestamp=now_ts,
        )

    # 4. Enterprise Mail Infrastructure (requires actual mail indicators)
    for host in ptr_list:
        h_lower = str(host).lower()
        for pattern, mail_prov in ENTERPRISE_MAIL_PATTERNS:
            if pattern in h_lower:
                evidence_basis.append(
                    f"PTR host '{host}' matches enterprise mail pattern "
                    f"'{pattern}'"
                )
                return HostingFingerprintData(
                    classification="enterprise_mail_infrastructure",
                    infrastructure_role="enterprise_mail_infrastructure",
                    provider_name=mail_prov,
                    evidence_basis=evidence_basis,
                    lookup_timestamp=now_ts,
                )

    # Check for dedicated email security vendor identity
    if detected_provider in ("Proofpoint", "Mimecast", "Barracuda Networks"):
        evidence_basis.append(
            f"Organization matches dedicated email security vendor "
            f"'{detected_provider}'"
        )
        return HostingFingerprintData(
            classification="enterprise_mail_infrastructure",
            infrastructure_role="enterprise_mail_infrastructure",
            provider_name=detected_provider,
            evidence_basis=evidence_basis,
            lookup_timestamp=now_ts,
        )

    # Check general mail service prefix in PTR with known provider
        mail_prefixes = ("mail.", "smtp.", "mx.", "relay.")
        if any(h_lower.startswith(p) for p in mail_prefixes):
            if detected_provider:
                evidence_basis.append(
                    f"PTR host '{host}' has mail service hostname structure"
                )
                return HostingFingerprintData(
                    classification="enterprise_mail_infrastructure",
                    infrastructure_role="enterprise_mail_infrastructure",
                    provider_name=detected_provider,
                    evidence_basis=evidence_basis,
                    lookup_timestamp=now_ts,
                )

    # 5. CDN / Proxy
    for kw, p_name in CDN_PROVIDERS.items():
        if kw in all_text:
            evidence_basis.append(
                f"Host/Org matches CDN/Proxy provider '{p_name}'"
            )
            return HostingFingerprintData(
                classification="cdn_proxy",
                infrastructure_role="cdn_proxy",
                provider_name=p_name,
                evidence_basis=evidence_basis,
                lookup_timestamp=now_ts,
            )

    # 6. Cloud Infrastructure
    for kw, p_name in CLOUD_PROVIDERS.items():
        if kw in all_text:
            evidence_basis.append(
                f"Host/Org matches hyperscale cloud provider '{p_name}'"
            )
            return HostingFingerprintData(
                classification="cloud_infrastructure",
                infrastructure_role="cloud_infrastructure",
                provider_name=p_name,
                evidence_basis=evidence_basis,
                lookup_timestamp=now_ts,
            )

    # 7. VPS Infrastructure
    for kw, p_name in VPS_PROVIDERS.items():
        if kw in all_text:
            evidence_basis.append(
                f"Host/Org matches unmanaged VPS provider '{p_name}'"
            )
            return HostingFingerprintData(
                classification="vps_infrastructure",
                infrastructure_role="vps_infrastructure",
                provider_name=p_name,
                evidence_basis=evidence_basis,
                lookup_timestamp=now_ts,
            )

    # 8. Commercial Shared Hosting
    for kw, p_name in COMMERCIAL_HOSTING.items():
        if kw in all_text:
            evidence_basis.append(
                f"Host/Org matches commercial hosting provider '{p_name}'"
            )
            return HostingFingerprintData(
                classification="commercial_hosting",
                infrastructure_role="commercial_hosting",
                provider_name=p_name,
                evidence_basis=evidence_basis,
                lookup_timestamp=now_ts,
            )

    # Default: Unknown / Unclassified
    if org_name:
        evidence_basis.append(
            f"Autonomous System Organization: '{org_name}'"
        )
    return HostingFingerprintData(
        classification="unknown",
        infrastructure_role="unknown",
        provider_name=detected_provider or org_name,
        evidence_basis=evidence_basis,
        lookup_timestamp=now_ts,
    )
