"""Module 6: Evidence Correlation & Attribution Support.

Aggregates and correlates deterministic forensic evidence from Modules 1–5 with
external machine learning predictions (Email Threat Classifier, BEC / Intent Classifier,
URL Risk Classifier), producing unified, graph-ready forensic investigation cases.
"""

from .analyzer import EvidenceCorrelationAnalyzer, correlate_evidence
from .attribution_support import AttributionSupportEngine
from .contradiction import ContradictionEngine
from .corroboration import CorroborationEngine
from .entity_resolution import EntityResolver
from .hypothesis_engine import CaseHypothesisEngine
from .ml_adapters import (
    BECIntentModelAdapter,
    BecIntentClassifierAdapter,
    EmailThreatClassifierAdapter,
    EmailThreatModelAdapter,
    EXPECTED_MODULE3_FEATURES,
    ForensicFusionModelAdapter,
    UnifiedMlAdapter,
    URLRiskModelAdapter,
    UrlRiskClassifierAdapter,
)
from .models import (
    AttributionSupport,
    CampaignCluster,
    CaseHypothesis,
    ContradictionRecord,
    CorrelatedEntity,
    CorrelatedRelationship,
    CorroboratedFinding,
    InvestigationCase,
    MlPrediction,
    NormalizedEvidence,
)
from .normalizer import EvidenceNormalizer
from .relationship_engine import RelationshipEngine
from .temporal_correlation import CrossCaseCorrelator

__all__ = [
    # Top-level Orchestrator
    "EvidenceCorrelationAnalyzer",
    "correlate_evidence",
    # Sub-engines
    "EvidenceNormalizer",
    "EntityResolver",
    "RelationshipEngine",
    "CorroborationEngine",
    "ContradictionEngine",
    "CrossCaseCorrelator",
    "CaseHypothesisEngine",
    "AttributionSupportEngine",
    # ML Adapters & Contracts
    "ForensicFusionModelAdapter",
    "EmailThreatModelAdapter",
    "BECIntentModelAdapter",
    "URLRiskModelAdapter",
    "EmailThreatClassifierAdapter",
    "BecIntentClassifierAdapter",
    "UrlRiskClassifierAdapter",
    "UnifiedMlAdapter",
    "EXPECTED_MODULE3_FEATURES",
    # Core Models
    "NormalizedEvidence",
    "CorrelatedEntity",
    "CorrelatedRelationship",
    "CorroboratedFinding",
    "ContradictionRecord",
    "MlPrediction",
    "CaseHypothesis",
    "CampaignCluster",
    "AttributionSupport",
    "InvestigationCase",
]
