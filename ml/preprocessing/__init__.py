"""Preprocessing pipeline package for SIH26106."""

from .clean_text import clean_email_text, clean_subject, clean_body, normalize_encoding, normalize_whitespace
from .quality_filter import check_record_quality, QualityDecision
from .deduplicate import deduplicate_dataset, compute_text_hash, compute_normalized_hash
from .build_dataset import run_pipeline

__all__ = [
    "clean_email_text",
    "clean_subject",
    "clean_body",
    "normalize_encoding",
    "normalize_whitespace",
    "check_record_quality",
    "QualityDecision",
    "deduplicate_dataset",
    "compute_text_hash",
    "compute_normalized_hash",
    "run_pipeline",
]
