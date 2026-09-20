"""Data models for static attachment forensic analysis.

Defines data structures for extracted attachment metadata, filename analysis,
modular file signature detection, safe archive inspection, tabular ML features,
graph entities/relationships, and structured forensic observations.
"""

from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any, Dict, List, Optional

from modules.sender_identity.models import Entity, Relationship


@dataclass
class ExtractedAttachment:
    """Represents an attachment extracted from MIME email content in memory."""
    attachment_id: str
    filename: str
    declared_mime: str
    content_disposition: Optional[str]
    content_id: Optional[str]
    size: int
    raw_bytes: bytes
    sha256: str
    is_inline: bool = False

    def to_dict(self, include_bytes: bool = False) -> Dict[str, Any]:
        """Convert to dictionary representation, omitting raw bytes by default."""
        res: Dict[str, Any] = {
            "attachment_id": self.attachment_id,
            "filename": self.filename,
            "declared_mime": self.declared_mime,
            "content_disposition": self.content_disposition,
            "content_id": self.content_id,
            "size": self.size,
            "sha256": self.sha256,
            "is_inline": self.is_inline,
        }
        if include_bytes:
            res["raw_bytes"] = self.raw_bytes
        return res


@dataclass(frozen=True)
class FilenameAnalysis:
    """Structural decomposition of an attachment filename."""
    full_filename: str
    extension: str
    base_name: str
    filename_length: int
    dot_count: int
    extension_count: int
    extensions: List[str]
    has_double_extension: bool
    is_suspicious_double_extension: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FileSignature:
    """Result of magic-byte inspection on attachment content."""
    detected_type: str
    signature: Optional[str]
    confidence: str  # 'high', 'medium', 'low', 'none'
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ArchiveMetadata:
    """Safe static metadata extracted from archive attachments."""
    is_archive: bool
    member_count: int = 0
    member_filenames: List[str] = field(default_factory=list)
    total_uncompressed_size: int = 0
    max_nesting_depth: int = 0
    suspicious_members: List[str] = field(default_factory=list)
    nested_archives: List[str] = field(default_factory=list)
    limits_exceeded: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttachmentMlFeatures:
    """Tabular static numerical and boolean features for future attachment ML models."""
    file_size: int
    filename_length: int
    extension_count: int
    dot_count: int
    has_double_extension: bool
    executable_extension: bool
    script_extension: bool
    macro_capable: bool
    archive: bool
    nested_archive: bool
    member_count: int
    contains_executable_member: bool
    mime_mismatch: bool
    signature_mismatch: bool
    detected_type: str
    sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttachmentObservation:
    """Structured finding capturing a specific attachment anomaly or forensic indicator."""
    observation_id: str
    rule_id: str
    source_module: str
    attachment_id: str
    severity: str  # 'informational', 'low', 'medium', 'high'
    description: str
    evidence: Dict[str, Any]
    fact_type: str  # 'observed', 'reported', 'inferred'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttachmentAssessment:
    """Bounded structural risk evaluation for analyzed attachments."""
    category: str  # 'no_significant_attachment_anomaly', 'attachment_anomaly_detected', 'suspicious_attachment'
    risk_level: str  # 'none', 'low', 'medium', 'high'
    evidence_strength: str  # 'none', 'weak', 'moderate', 'strong'
    confidence: float  # Bounded float (0.0 to 0.90)
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "risk_level": self.risk_level,
            "evidence_strength": self.evidence_strength,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
        }


@dataclass
class AttachmentReport:
    """Top-level forensic output for Module 4 Attachment Analysis."""
    module: str = "attachment_analysis"
    email_id: str = "E001"
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    entities: List[Entity] = field(default_factory=list)
    observations: List[AttachmentObservation] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    assessment: Optional[AttachmentAssessment] = None
    ml_features: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "email_id": self.email_id,
            "attachments": self.attachments,
            "entities": [e.to_dict() for e in self.entities],
            "observations": [o.to_dict() for o in self.observations],
            "relationships": [r.to_dict() for r in self.relationships],
            "assessment": self.assessment.to_dict() if self.assessment else {
                "category": "no_significant_attachment_anomaly",
                "risk_level": "none",
                "evidence_strength": "none",
                "confidence": 0.0,
                "reason": "No attachments analyzed.",
            },
            "ml_features": self.ml_features,
        }
