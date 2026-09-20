"""Module 1: Sender Identity Spoofing & Authentication Analysis.

Examines raw .eml emails for sender identity integrity, authentication
headers (SPF, DKIM, DMARC), and routing hops to generate structured,
graph-ready evidence and transparent risk assessments.
"""

from pathlib import Path
from typing import Union

from .analyzer import SenderIdentityAnalyzer
from .models import (
    Assessment,
    AuthResults,
    Entity,
    Observation,
    ParsedEmailEvidence,
    ReceivedHop,
    Relationship,
    SenderIdentityReport,
)
from .parser import SenderIdentityParser

__all__ = [
    "SenderIdentityParser",
    "SenderIdentityAnalyzer",
    "Entity",
    "Relationship",
    "Observation",
    "Assessment",
    "ReceivedHop",
    "AuthResults",
    "ParsedEmailEvidence",
    "SenderIdentityReport",
    "analyze_eml",
]


def analyze_eml(
    eml_input: Union[bytes, str, Path], email_id: str = "E001"
) -> SenderIdentityReport:
    """Convenience pipeline function to parse and analyze a raw .eml message.

    Pipeline:
        .eml -> parse -> extract identity/auth/routing -> analyze -> structured findings

    Args:
        eml_input: Raw email bytes, string, or filesystem Path to .eml file.
        email_id: Identifier for the email being investigated (default: 'E001').

    Returns:
        SenderIdentityReport containing entities, observations, relationships,
        and rule-based forensic assessment.
    """
    parser = SenderIdentityParser()
    evidence = parser.parse(eml_input)
    analyzer = SenderIdentityAnalyzer()
    return analyzer.analyze(evidence, email_id=email_id)
