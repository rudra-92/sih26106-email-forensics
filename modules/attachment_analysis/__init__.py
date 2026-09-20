"""Module 4: Static Attachment Forensics.

Provides deterministic, offline, non-ML static forensic analysis of email attachments:
- Attachment extraction from parsed MIME structures
- Filename and double-extension analysis
- Declared MIME vs extension consistency checks
- Magic-byte file signature detection
- Safe in-memory ZIP archive inspection
- Graph-ready entities and relationships
- Tabular static features for future ML models
- Bounded forensic structural assessments
"""

from .analyzer import (
    ARCHIVE_EXTENSIONS,
    DOCUMENT_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    IMAGE_EXTENSIONS,
    INNOCUOUS_INNER_EXTENSIONS,
    MACRO_CAPABLE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    SignatureDetector,
    StaticAttachmentAnalyzer,
    analyze_attachments,
    analyze_filename,
)
from .extractor import AttachmentExtractor, extract_attachments
from .models import (
    ArchiveMetadata,
    AttachmentAssessment,
    AttachmentMlFeatures,
    AttachmentObservation,
    AttachmentReport,
    ExtractedAttachment,
    FilenameAnalysis,
    FileSignature,
)

__all__ = [
    "AttachmentExtractor",
    "extract_attachments",
    "StaticAttachmentAnalyzer",
    "analyze_attachments",
    "SignatureDetector",
    "analyze_filename",
    "ExtractedAttachment",
    "FilenameAnalysis",
    "FileSignature",
    "ArchiveMetadata",
    "AttachmentMlFeatures",
    "AttachmentObservation",
    "AttachmentAssessment",
    "AttachmentReport",
    "EXECUTABLE_EXTENSIONS",
    "SCRIPT_EXTENSIONS",
    "MACRO_CAPABLE_EXTENSIONS",
    "DOCUMENT_EXTENSIONS",
    "IMAGE_EXTENSIONS",
    "ARCHIVE_EXTENSIONS",
    "INNOCUOUS_INNER_EXTENSIONS",
]
