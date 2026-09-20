"""Base interfaces and composite enrichment manager for Origin & Infrastructure Reconstruction.

Defines abstract base providers for GeoIP, ASN, and Infrastructure indicator lookups,
ensuring offline-first behavior with graceful degradation if datasets are unavailable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from ..models import (
    AsnData,
    EnrichedInfrastructure,
    GeoLocationData,
    InfrastructureData,
    LocationEvidence,
    OriginAsnData,
    ServerCountryData,
    UserCountryData,
)


class BaseGeoIPProvider(ABC):
    """Abstract interface for local IP geolocation lookup providers."""

    @abstractmethod
    def lookup(self, ip: str) -> GeoLocationData:
        """Lookup observed network infrastructure geolocation for an IP address.

        Must return GeoLocationData with status='unavailable' if data is missing,
        never raising unhandled exceptions.
        """
        pass


class BaseASNProvider(ABC):
    """Abstract interface for local Autonomous System Number lookup providers."""

    @abstractmethod
    def lookup(self, ip: str) -> AsnData:
        """Lookup ASN and organization information for an IP address."""
        pass


class BaseInfrastructureProvider(ABC):
    """Abstract interface for hosting, cloud, VPN, proxy, and TOR indicators."""

    @abstractmethod
    def lookup(self, ip: str) -> InfrastructureData:
        """Classify infrastructure type and detect anonymization indicators."""
        pass


class BaseUserCountryProvider(ABC):
    """Abstract interface for local User-Country lookup providers."""

    @abstractmethod
    def lookup(self, ip: str) -> "UserCountryData":
        """Lookup likely end-user network endpoint country."""
        pass


class BaseServerCountryProvider(ABC):
    """Abstract interface for local Server-Country lookup providers."""

    @abstractmethod
    def lookup(self, ip: str) -> "ServerCountryData":
        """Lookup physical server or relay infrastructure country."""
        pass


class BaseOriginASNProvider(ABC):
    """Abstract interface for local Origin-ASN lookup providers."""

    @abstractmethod
    def lookup(self, ip: str) -> "OriginAsnData":
        """Lookup ASN and organization from BGP origin routing."""
        pass


class CompositeEnrichmentProvider:
    """Combines GeoIP, ASN, Infrastructure, and secondary PDDL providers into an enrichment pipeline."""

    def __init__(
        self,
        geoip_provider: Optional[BaseGeoIPProvider] = None,
        asn_provider: Optional[BaseASNProvider] = None,
        infrastructure_provider: Optional[BaseInfrastructureProvider] = None,
        user_country_provider: Optional[BaseUserCountryProvider] = None,
        server_country_provider: Optional[BaseServerCountryProvider] = None,
        origin_asn_provider: Optional[BaseOriginASNProvider] = None,
    ) -> None:
        self.geoip_provider = geoip_provider
        self.asn_provider = asn_provider
        self.infrastructure_provider = infrastructure_provider
        self.user_country_provider = user_country_provider
        self.server_country_provider = server_country_provider
        self.origin_asn_provider = origin_asn_provider

    def _correlate_location_evidence(
        self,
        ip: str,
        geo: GeoLocationData,
        user_c: "UserCountryData",
        server_c: "ServerCountryData",
        origin_a: "OriginAsnData",
        infra: InfrastructureData,
        asn: AsnData,
        hop_context: Optional[Dict[str, Any]] = None,
    ) -> LocationEvidence:
        # 1. Country agreement and explicit interpretation
        u_cc = user_c.country_code
        s_cc = server_c.country_code
        dbip_cc = geo.country_code

        country_agree: Optional[bool] = None
        interpretation = "insufficient_country_evidence"

        if u_cc is not None and s_cc is not None:
            if u_cc == s_cc:
                country_agree = True
                interpretation = "country-level evidence is consistent"
            else:
                country_agree = False
                interpretation = "country-level geographic evidence is inconsistent"
        elif u_cc is not None or s_cc is not None:
            interpretation = "single_country_evidence_available"

        # 2. Heuristic consensus score (bounded 0.0 - 0.95, non-calibrated heuristic metric, NOT probability)
        countries = [c for c in [dbip_cc, u_cc, s_cc] if c]
        if not countries:
            conf = 0.0
        elif len(set(countries)) == 1 and len(countries) >= 2:
            conf = 0.95  # Multi-dataset consensus
        elif country_agree is True:
            conf = 0.85  # User and server country match
        elif country_agree is False:
            conf = 0.45  # Divergent country evidence
        else:
            conf = 0.70  # Single country observation

        # 3. Origin location type determination
        # SEMANTIC RULE: Neither agreement nor disagreement alone may determine location type.
        # Origin location type must be determined only using broader Module 5 evidence:
        # hop position, trust state, temporal consistency, infrastructure classification,
        # ASN, authentication context, and cross-case evidence.
        loc_type = "unknown"
        if hop_context:
            is_tor = infra.is_tor or hop_context.get("is_tor", False)
            is_vpn = infra.is_vpn or hop_context.get("is_vpn", False)
            is_proxy = infra.is_proxy or hop_context.get("is_proxy", False)
            role = hop_context.get("role")
            hop_seq = hop_context.get("hop_sequence_num")
            is_recurring = hop_context.get("is_recurring", False)
            trust_state = hop_context.get("trust_state")
            temp_consistent = hop_context.get("temporal_consistent", True)
            delay_anomaly = hop_context.get("temporal_delay_anomaly", False)
            auth_aligned = hop_context.get("auth_aligned", False)

            if is_tor or is_vpn or is_proxy or role == "anonymization_endpoint":
                loc_type = "anonymized_infrastructure"
            elif is_recurring:
                loc_type = "campaign_infrastructure"
            elif infra.is_hosting or role in ("cloud_infrastructure", "mail_provider"):
                loc_type = "provider_infrastructure"
            elif role == "upstream_relay" or (hop_seq is not None and hop_seq > 1) or (country_agree is False and role == "intermediate_hop") or delay_anomaly:
                # Relays can exist even within the exact same country, or cross international borders
                loc_type = "relay_infrastructure"
            elif role == "earliest_reliable_external_peer" and trust_state in ("verified", "observed") and not infra.is_hosting and (temp_consistent or auth_aligned):
                loc_type = "direct_origin_infrastructure"
            else:
                loc_type = "unknown"
        else:
            # Standalone IP enrichment without full hop chain context:
            if infra.is_tor or infra.is_vpn or infra.is_proxy:
                loc_type = "anonymized_infrastructure"
            elif infra.is_hosting:
                loc_type = "provider_infrastructure"
            else:
                loc_type = "unknown"

        # 4. Provenance tracking
        prov = []
        if geo.status == "available":
            prov.append(geo.source_dataset)
        if user_c.status == "available":
            prov.append(user_c.source_dataset)
        if server_c.status == "available":
            prov.append(server_c.source_dataset)
        if origin_a.status == "available":
            prov.append(origin_a.source_dataset)

        return LocationEvidence(
            ip=ip,
            dbip_infrastructure_location=geo.to_dict() if geo.status == "available" else {},
            user_country=user_c.to_dict() if user_c.status == "available" else {},
            server_country=server_c.to_dict() if server_c.status == "available" else {},
            origin_asn=origin_a.to_dict() if origin_a.status == "available" else {},
            country_agreement=country_agree,
            interpretation=interpretation,
            country_confidence=conf,
            confidence_metric="heuristic_non_calibrated_consensus",
            location_type=loc_type,
            provenance=prov,
        )

    def enrich(
        self,
        ip: str,
        hop_context: Optional[Dict[str, Any]] = None,
    ) -> EnrichedInfrastructure:
        """Enrich an observed IP address using all configured local providers."""
        geo_data = (
            self.geoip_provider.lookup(ip)
            if self.geoip_provider
            else GeoLocationData(status="unavailable")
        )
        asn_data = (
            self.asn_provider.lookup(ip)
            if self.asn_provider
            else AsnData(status="unavailable")
        )
        infra_data = (
            self.infrastructure_provider.lookup(ip)
            if self.infrastructure_provider
            else InfrastructureData()
        )

        loc_evidence = None
        if self.user_country_provider or self.server_country_provider or self.origin_asn_provider:
            u_data = (
                self.user_country_provider.lookup(ip)
                if self.user_country_provider
                else UserCountryData(status="unavailable")
            )
            s_data = (
                self.server_country_provider.lookup(ip)
                if self.server_country_provider
                else ServerCountryData(status="unavailable")
            )
            o_data = (
                self.origin_asn_provider.lookup(ip)
                if self.origin_asn_provider
                else OriginAsnData(status="unavailable")
            )
            loc_evidence = self._correlate_location_evidence(
                ip=ip,
                geo=geo_data,
                user_c=u_data,
                server_c=s_data,
                origin_a=o_data,
                infra=infra_data,
                asn=asn_data,
                hop_context=hop_context,
            )

        return EnrichedInfrastructure(
            ip=ip,
            geolocation=geo_data,
            asn=asn_data,
            infrastructure=infra_data,
            location_evidence=loc_evidence,
        )

