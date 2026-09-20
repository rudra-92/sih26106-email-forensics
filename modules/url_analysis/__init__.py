"""Module 3: Static URL Forensic Analysis.

Provides deterministic, non-network static URL extraction, decomposition,
structural analysis, visible-vs-href mismatch detection, Module 2 lookalike
integration, graph-ready entity/relationship emission, and tabular ML features.
"""

from .analyzer import StaticUrlAnalyzer, analyze_urls
from .extractor import UrlExtractor, extract_urls
from .models import (
    ExtractedUrl,
    NormalizedUrl,
    UrlAnalysisAssessment,
    UrlAnalysisReport,
    UrlMlFeatures,
    UrlObservation,
)
from .normalizer import normalize_url

__all__ = [
    "ExtractedUrl",
    "NormalizedUrl",
    "UrlAnalysisAssessment",
    "UrlAnalysisReport",
    "UrlMlFeatures",
    "UrlObservation",
    "UrlExtractor",
    "extract_urls",
    "normalize_url",
    "StaticUrlAnalyzer",
    "analyze_urls",
]
