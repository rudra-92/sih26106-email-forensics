"""Base interfaces and composite enrichment manager for Origin & Infrastructure Reconstruction.

Defines abstract base providers for GeoIP, ASN, and Infrastructure indicator lookups,
ensuring offline-first behavior with graceful degradation if datasets are unavailable.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ..models import (
    AsnData,
    EnrichedInfrastructure,
    GeoLocationData,
    InfrastructureData,
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


class CompositeEnrichmentProvider:
    """Combines GeoIP, ASN, and Infrastructure providers into a single enrichment pipeline."""

    def __init__(
        self,
        geoip_provider: Optional[BaseGeoIPProvider] = None,
        asn_provider: Optional[BaseASNProvider] = None,
        infrastructure_provider: Optional[BaseInfrastructureProvider] = None,
    ) -> None:
        self.geoip_provider = geoip_provider
        self.asn_provider = asn_provider
        self.infrastructure_provider = infrastructure_provider

    def enrich(self, ip: str) -> EnrichedInfrastructure:
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

        return EnrichedInfrastructure(
            ip=ip,
            geolocation=geo_data,
            asn=asn_data,
            infrastructure=infra_data,
        )
