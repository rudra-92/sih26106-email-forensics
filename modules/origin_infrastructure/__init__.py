"""Module 5: Origin & Infrastructure Reconstruction Engine.

Reconstructs observable email transport paths from Received headers, identifies
earliest reliable external peers, evaluates temporal consistency, correlates
authentication/ARC evidence, enriches network infrastructure via offline local datasets,
and generates competing origin hypotheses.
"""

from .analyzer import OriginInfrastructureAnalyzer, analyze_origin_infrastructure
from .authentication import AuthenticationCorrelator
from .correlation import CrossCaseCorrelator
from .enrichment import (
    BaseASNProvider,
    BaseGeoIPProvider,
    BaseInfrastructureProvider,
    CompositeEnrichmentProvider,
    LocalASNProvider,
    LocalGeoIPProvider,
    LocalInfrastructureProvider,
)
from .hop_reconstructor import HopReconstructor
from .hypotheses import OriginHypothesisEngine
from .models import (
    ArcAnalysisResult,
    ArcInstance,
    AsnData,
    EnrichedInfrastructure,
    GeoLocationData,
    HopParsedFields,
    InfrastructureData,
    OriginAssessment,
    OriginCandidate,
    OriginHypothesis,
    OriginInfrastructureReport,
    OriginObservation,
    ParsedReceivedHop,
    ReconstructedHop,
    TemporalAnalysisResult,
)
from .origin_engine import OriginEngine
from .received_parser import ReceivedHeaderParser, is_private_ip
from .temporal import TemporalAnalyzer, parse_timestamp_to_utc

__all__ = [
    "OriginInfrastructureAnalyzer",
    "analyze_origin_infrastructure",
    "ReceivedHeaderParser",
    "HopReconstructor",
    "TemporalAnalyzer",
    "AuthenticationCorrelator",
    "OriginEngine",
    "CrossCaseCorrelator",
    "OriginHypothesisEngine",
    "CompositeEnrichmentProvider",
    "LocalGeoIPProvider",
    "LocalASNProvider",
    "LocalInfrastructureProvider",
    "BaseGeoIPProvider",
    "BaseASNProvider",
    "BaseInfrastructureProvider",
    "ParsedReceivedHop",
    "HopParsedFields",
    "ReconstructedHop",
    "TemporalAnalysisResult",
    "ArcAnalysisResult",
    "ArcInstance",
    "OriginCandidate",
    "OriginAssessment",
    "GeoLocationData",
    "AsnData",
    "InfrastructureData",
    "EnrichedInfrastructure",
    "OriginHypothesis",
    "OriginObservation",
    "OriginInfrastructureReport",
    "is_private_ip",
    "parse_timestamp_to_utc",
]
