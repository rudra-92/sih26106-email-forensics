"""Module 2: Lookalike Domain Detection.

Layer 1: Normalization & Reference Store.
Layer 2: Multi-Signal Similarity & Candidate Generation.
Layer 3: Contextual Validation & Evidence Correlation.
"""

from .context import (
    ContextualAssessmentReport,
    ContextualObservation,
    HypothesisEvaluation,
    validate_candidate_context,
)
from .evaluation import SyntheticVariant, generate_synthetic_variants
from .normalizer import (
    DomainNormalizationError,
    NormalizedDomain,
    RegistrableDomainInfo,
    create_domain_comparison_edge,
    load_reference_domains,
    normalize_domain,
)
from .similarity import (
    CandidateResult,
    SimilaritySignals,
    compute_candidate_score,
    compute_domain_similarity,
    damerau_levenshtein_distance,
    find_similarity_candidates,
    jaro_winkler_similarity,
)

__all__ = [
    # Layer 1
    "DomainNormalizationError",
    "NormalizedDomain",
    "RegistrableDomainInfo",
    "create_domain_comparison_edge",
    "load_reference_domains",
    "normalize_domain",
    # Layer 2
    "CandidateResult",
    "SimilaritySignals",
    "compute_candidate_score",
    "compute_domain_similarity",
    "damerau_levenshtein_distance",
    "find_similarity_candidates",
    "jaro_winkler_similarity",
    # Layer 3
    "ContextualAssessmentReport",
    "ContextualObservation",
    "HypothesisEvaluation",
    "validate_candidate_context",
    # Evaluation
    "SyntheticVariant",
    "generate_synthetic_variants",
]
