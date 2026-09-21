"""
quality_filter.py - Data Quality Assessment and Flagging for SIH26106.

Policy:
- Never silently drop records without logging and provenance tracking.
- Every rejected or borderline record is flagged with a specific, auditable reason
  and routed to `emails_quarantine.csv`.
- High-quality accepted records are routed to candidate deduplication and `emails_cleaned.csv`.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class QualityDecision:
    """Represents the quality evaluation outcome for a single email record."""
    is_valid: bool
    reasons: List[str] = field(default_factory=list)
    quarantine_category: Optional[str] = None


# Minimum length thresholds
MIN_CLEAN_TEXT_LENGTH = 20  # Characters (subject + body combined)
MAX_SUSPICIOUS_CHAR_RATIO = 0.20  # Max acceptable ratio of unprintable/control characters


def check_record_quality(
    subject: Optional[str],
    body: Optional[str],
    clean_text: Optional[str],
    source: str,
    original_label: Optional[object] = None,
    our_label: Optional[str] = None
) -> QualityDecision:
    """
    Evaluates whether an email record meets quality standards for model training.
    
    Checks applied:
    1. MISSING_SUBJECT_AND_BODY: Completely empty content.
    2. MISSING_BODY: No body text present (subject alone is insufficient for email threat classification).
    3. EXTREMELY_SHORT_TEXT: Total cleaned content < 20 characters.
    4. NON_EMAIL_FOLDER_DATA: Mbox / mail server internal records (e.g. UW-IMAP / Pine folder headers).
    5. MALFORMED_ENCODING: Corrupted text with null bytes or excessive unprintable characters.
    6. INVALID_LABEL: Missing or unmapped label.
    """
    reasons: List[str] = []
    
    s_clean = (subject or "").strip()
    b_clean = (body or "").strip()
    t_clean = (clean_text or "").strip()
    
    # 1. Check for completely missing content
    if not s_clean and not b_clean:
        reasons.append("missing_subject_and_body")
        return QualityDecision(
            is_valid=False,
            reasons=reasons,
            quarantine_category="empty_content"
        )
    
    # 2. Check for missing body
    # (Email threat detection requires body context; subject alone is insufficient for legitimate/threat differentiation)
    if not b_clean:
        reasons.append("missing_body")
        return QualityDecision(
            is_valid=False,
            reasons=reasons,
            quarantine_category="missing_body"
        )
    
    # 3. Check for obviously non-email mbox / server internal records
    # Reason: Unix mbox folder separators or server state dumps erroneously indexed as emails
    if "FOLDER INTERNAL DATA" in s_clean.upper() or "THIS TEXT IS PART OF THE INTERNAL FORMAT OF YOUR MAIL FOLDER" in b_clean.upper():
        reasons.append("non_email_folder_internal_data")
        return QualityDecision(
            is_valid=False,
            reasons=reasons,
            quarantine_category="non_email_metadata"
        )
    
    # 4. Check for extremely short text
    # Reason: Single-word messages (e.g., 'hi', ')', 'thanks') lack linguistic/threat features
    if len(t_clean) < MIN_CLEAN_TEXT_LENGTH:
        reasons.append(f"extremely_short_text_len_{len(t_clean)}")
        return QualityDecision(
            is_valid=False,
            reasons=reasons,
            quarantine_category="extremely_short"
        )
    
    # 5. Check for null bytes or binary corruption
    if '\x00' in b_clean or '\x00' in s_clean:
        reasons.append("contains_null_bytes")
        return QualityDecision(
            is_valid=False,
            reasons=reasons,
            quarantine_category="malformed_binary"
        )
    
    # Check printable character ratio (detect raw binary / uuencode / base64 dump corruptions)
    printable_count = sum(1 for ch in b_clean if ch.isprintable() or ch in ('\n', '\t', ' '))
    if len(b_clean) > 0 and (printable_count / len(b_clean)) < (1.0 - MAX_SUSPICIOUS_CHAR_RATIO):
        reasons.append("high_unprintable_character_ratio")
        return QualityDecision(
            is_valid=False,
            reasons=reasons,
            quarantine_category="malformed_encoding"
        )
        
    # 6. Check for label validity
    if our_label not in ("legitimate", "phishing", "fraud_related"):
        reasons.append(f"unsupported_label_{our_label}")
        return QualityDecision(
            is_valid=False,
            reasons=reasons,
            quarantine_category="invalid_label"
        )

    # Passed all quality checks
    return QualityDecision(is_valid=True, reasons=[], quarantine_category=None)
