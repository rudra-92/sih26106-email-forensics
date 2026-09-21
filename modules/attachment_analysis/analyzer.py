"""Static attachment forensic analyzer.

Performs deterministic offline analysis of extracted email attachments:
1. Filename structural analysis (dots, double extensions, length).
2. MIME vs extension consistency evaluation.
3. Modular magic-byte file signature detection.
4. Extension vs detected signature consistency checks.
5. Safe in-memory ZIP archive metadata inspection.
6. Safe file-type classification without executing content.
7. Graph-ready entities and relationships (email, attachment, hash, file_type).
8. Tabular static features exposed for future ML models.
9. Bounded, transparent structural risk assessment.
"""

from email.message import EmailMessage, Message
import io
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import zipfile

from modules.sender_identity.models import Entity, Relationship
from .extractor import extract_attachments
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

# Executable and binary file extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".cpl", ".com", ".hta", ".msi", ".jar",
    ".dll", ".sys", ".drv", ".ocx",
}

# Script file extensions
SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh",
    ".sh", ".py", ".pl", ".rb", ".vbe",
}

# Macro-capable Microsoft Office extensions
MACRO_CAPABLE_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".xlam",
}

# Common document extensions
DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".odt", ".ods", ".odp", ".csv", ".tsv",
}

# Common image extensions
IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif",
    ".svg", ".webp", ".ico",
}

# Common archive extensions
ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".iso", ".cab", ".dmg",
}

# Innocuous extensions commonly targeted for deceptive double extension disguises
INNOCUOUS_INNER_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".csv",
}

# Standard mapping of extension to expected MIME types
EXTENSION_TO_MIMES: Dict[str, Set[str]] = {
    ".pdf": {"application/pdf", "application/x-pdf", "binary/octet-stream"},
    ".zip": {
        "application/zip", "application/x-zip-compressed", "application/x-zip",
        "multipart/x-zip",
    },
    ".png": {"image/png", "application/png"},
    ".jpg": {"image/jpeg", "image/pjpeg"},
    ".jpeg": {"image/jpeg", "image/pjpeg"},
    ".gif": {"image/gif"},
    ".bmp": {"image/bmp", "image/x-ms-bmp"},
    ".webp": {"image/webp"},
    ".exe": {
        "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
        "application/x-executable",
    },
    ".scr": {
        "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
    },
    ".bat": {"text/plain", "application/x-bat", "application/x-msdos-program"},
    ".cmd": {"text/plain", "application/x-cmd"},
    ".ps1": {"text/plain", "application/x-powershell"},
    ".js": {"application/javascript", "text/javascript", "application/x-javascript"},
    ".vbs": {"text/plain", "application/x-vbs", "text/vbscript"},
    ".doc": {"application/msword"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".xls": {"application/vnd.ms-excel"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    ".ppt": {"application/vnd.ms-powerpoint"},
    ".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    ".docm": {"application/vnd.ms-word.document.macroenabled.12"},
    ".xlsm": {"application/vnd.ms-excel.sheet.macroenabled.12"},
    ".pptm": {"application/vnd.ms-powerpoint.presentation.macroenabled.12"},
    ".txt": {"text/plain"},
    ".csv": {"text/csv", "application/csv", "text/plain"},
    ".html": {"text/html"},
    ".htm": {"text/html"},
    ".7z": {"application/x-7z-compressed"},
    ".rar": {"application/x-rar-compressed", "application/vnd.rar"},
    ".tar": {"application/x-tar"},
    ".gz": {"application/gzip", "application/x-gzip"},
}

# Generic fallback MIME types used by email clients when specific type is omitted
GENERIC_MIME_TYPES = {
    "application/octet-stream",
    "binary/octet-stream",
    "application/unknown",
}


def analyze_filename(filename: str) -> FilenameAnalysis:
    """Analyze filename structural properties, dot count, and double extensions."""
    full_filename = filename.strip()
    length = len(full_filename)
    dots = full_filename.count(".")

    if dots == 0:
        return FilenameAnalysis(
            full_filename=full_filename,
            extension="",
            base_name=full_filename,
            filename_length=length,
            dot_count=0,
            extension_count=0,
            extensions=[],
            has_double_extension=False,
            is_suspicious_double_extension=False,
        )

    # Split on dots to identify multiple extensions
    parts = full_filename.split(".")
    base_name = parts[0]
    raw_extensions = [f".{p.lower()}" for p in parts[1:] if p]
    terminal_extension = raw_extensions[-1] if raw_extensions else ""

    has_double_extension = len(raw_extensions) >= 2
    is_suspicious_double_extension = False

    if has_double_extension:
        # Check if an inner extension looks like an innocuous document/media/archive
        # while terminal extension is executable or script
        inner_extensions = raw_extensions[:-1]
        terminal_is_executable = (
            terminal_extension in EXECUTABLE_EXTENSIONS
            or terminal_extension in SCRIPT_EXTENSIONS
        )
        inner_is_innocuous = any(
            ext in INNOCUOUS_INNER_EXTENSIONS or ext in ARCHIVE_EXTENSIONS
            for ext in inner_extensions
        )
        if terminal_is_executable and inner_is_innocuous:
            is_suspicious_double_extension = True

    return FilenameAnalysis(
        full_filename=full_filename,
        extension=terminal_extension,
        base_name=base_name,
        filename_length=length,
        dot_count=dots,
        extension_count=len(raw_extensions),
        extensions=raw_extensions,
        has_double_extension=has_double_extension,
        is_suspicious_double_extension=is_suspicious_double_extension,
    )


class SignatureDetector:
    """Modular registry of magic-byte file signatures for safe static inspection."""

    SignatureRule = Tuple[str, Callable[[bytes], bool], str, str]

    def __init__(self) -> None:
        # List of (detected_type, predicate, signature_tag, description)
        self._rules: List[SignatureDetector.SignatureRule] = [
            # PDF
            (
                "PDF document",
                lambda b: b.startswith(b"%PDF-") or b[:1024].find(b"%PDF-") != -1,
                "%PDF-",
                "Adobe Portable Document Format (PDF)",
            ),
            # ZIP
            (
                "ZIP archive",
                lambda b: b.startswith(b"PK\x03\x04") or b.startswith(b"PK\x05\x06") or b.startswith(b"PK\x07\x08"),
                "PK\\x03\\x04",
                "ZIP compressed archive",
            ),
            # PNG
            (
                "PNG image",
                lambda b: b.startswith(b"\x89PNG\r\n\x1a\n"),
                "89 50 4E 47",
                "Portable Network Graphics image",
            ),
            # JPEG
            (
                "JPEG image",
                lambda b: b.startswith(b"\xff\xd8\xff"),
                "FF D8 FF",
                "JPEG image",
            ),
            # GIF
            (
                "GIF image",
                lambda b: b.startswith(b"GIF87a") or b.startswith(b"GIF89a"),
                "GIF87a/89a",
                "Graphics Interchange Format (GIF) image",
            ),
            # Microsoft Compound File (OLE) - used by legacy .doc, .xls, .ppt
            (
                "Microsoft Compound File (OLE)",
                lambda b: b.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
                "D0 CF 11 E0",
                "Microsoft Compound Document / OLE structure",
            ),
            # Windows Portable Executable (PE / DOS MZ)
            (
                "PE executable",
                lambda b: b.startswith(b"MZ"),
                "MZ",
                "Windows Portable Executable (PE) / DOS MZ binary",
            ),
            # ELF executable
            (
                "ELF executable",
                lambda b: b.startswith(b"\x7fELF"),
                "7F 45 4C 46",
                "Executable and Linkable Format (ELF) binary",
            ),
            # Mach-O executable
            (
                "Mach-O executable",
                lambda b: (
                    b.startswith(b"\xfe\xed\xfa\xce")
                    or b.startswith(b"\xfe\xed\xfa\xcf")
                    or b.startswith(b"\xce\xfa\xed\xfe")
                    or b.startswith(b"\xcf\xfa\xed\xfe")
                    or b.startswith(b"\xca\xfe\xba\xbe")
                ),
                "Mach-O magic",
                "Mach-O binary executable",
            ),
            # 7-Zip
            (
                "7-Zip archive",
                lambda b: b.startswith(b"7z\xbc\xaf'\x1c"),
                "7z\\xbc\\xaf",
                "7-Zip compressed archive",
            ),
            # RAR
            (
                "RAR archive",
                lambda b: b.startswith(b"Rar!\x1a\x07"),
                "Rar!\\x1a\\x07",
                "RAR compressed archive",
            ),
            # GZIP
            (
                "GZIP archive",
                lambda b: b.startswith(b"\x1f\x8b"),
                "1F 8B",
                "GZIP compressed archive",
            ),
        ]

    def register_rule(
        self,
        detected_type: str,
        predicate: Callable[[bytes], bool],
        signature_tag: str,
        description: str,
    ) -> None:
        """Register a new signature rule at the beginning of the evaluation chain."""
        self._rules.insert(0, (detected_type, predicate, signature_tag, description))

    def detect(self, raw_bytes: bytes) -> FileSignature:
        """Detect file signature from raw bytes statically."""
        if not raw_bytes:
            return FileSignature(
                detected_type="empty",
                signature=None,
                confidence="high",
                description="Empty file payload (0 bytes)",
            )

        for detected_type, predicate, sig_tag, desc in self._rules:
            try:
                if predicate(raw_bytes):
                    return FileSignature(
                        detected_type=detected_type,
                        signature=sig_tag,
                        confidence="high",
                        description=desc,
                    )
            except Exception:
                continue

        return FileSignature(
            detected_type="unknown",
            signature=None,
            confidence="none",
            description="No matching file magic byte signature detected",
        )


class StaticAttachmentAnalyzer:
    """Forensic engine analyzing extracted attachments and compiling explainable evidence."""

    def __init__(
        self,
        max_filename_length: int = 100,
        signature_detector: Optional[SignatureDetector] = None,
        max_archive_members: int = 1000,
        max_archive_total_size: int = 100 * 1024 * 1024,
        max_archive_nesting_depth: int = 2,
    ) -> None:
        self.max_filename_length = max_filename_length
        self.signature_detector = signature_detector or SignatureDetector()
        self.max_archive_members = max_archive_members
        self.max_archive_total_size = max_archive_total_size
        self.max_archive_nesting_depth = max_archive_nesting_depth

    def analyze(
        self,
        email_input: Union[EmailMessage, Message, bytes, str, Path, Dict[str, Any], List[Any]],
        email_id: str = "E001",
    ) -> AttachmentReport:
        """Run static forensic analysis on all attachments in an email.

        Args:
            email_input: Parsed EmailMessage, Message, raw bytes, path, or attachment list.
            email_id: Forensic email identifier for graph provenance.

        Returns:
            AttachmentReport containing extracted attachments, structural observations,
            graph entities/relationships, tabular ML features, and bounded assessment.
        """
        extracted = extract_attachments(email_input)

        if not extracted:
            assessment = AttachmentAssessment(
                category="no_significant_attachment_anomaly",
                risk_level="none",
                evidence_strength="none",
                confidence=0.0,
                reason="No attachments found in the analyzed email.",
            )
            return AttachmentReport(
                module="attachment_analysis",
                email_id=email_id,
                attachments=[],
                entities=[Entity(type="email", value=email_id, source="attachment_analysis")],
                observations=[],
                relationships=[],
                assessment=assessment,
                ml_features=[],
            )

        report_attachments: List[Dict[str, Any]] = []
        observations: List[AttachmentObservation] = []
        entities: List[Entity] = [
            Entity(type="email", value=email_id, source="attachment_analysis")
        ]
        relationships: List[Relationship] = []
        ml_features: List[Dict[str, Any]] = []

        obs_counter = 1

        for att in extracted:
            report_attachments.append(att.to_dict(include_bytes=False))

            # 1. Structural filename decomposition
            fn_analysis = analyze_filename(att.filename)

            # 2. Magic-byte signature inspection
            sig = self.signature_detector.detect(att.raw_bytes)

            # 3. Safe archive inspection if ZIP
            archive_meta = self._inspect_archive_safe(att.raw_bytes, sig.detected_type, fn_analysis.extension)

            # 4. Safe file-type classification
            classified_type = self._classify_file_type(fn_analysis.extension, sig.detected_type)

            # 5. Build Graph Entities & Relationships
            entities.append(
                Entity(
                    type="attachment",
                    value=att.attachment_id,
                    source="attachment_analysis",
                    attributes={
                        "filename": att.filename,
                        "size": att.size,
                        "declared_mime": att.declared_mime,
                        "is_inline": att.is_inline,
                    },
                )
            )
            entities.append(
                Entity(
                    type="sha256",
                    value=att.sha256,
                    source="attachment_analysis",
                )
            )
            entities.append(
                Entity(
                    type="file_type",
                    value=classified_type,
                    source="attachment_analysis",
                )
            )

            # email -> contains_attachment -> attachment
            relationships.append(
                Relationship(
                    source=email_id,
                    relation="contains_attachment",
                    target=att.attachment_id,
                    evidence={"filename": att.filename, "size": att.size},
                )
            )
            # attachment -> has_hash -> sha256
            relationships.append(
                Relationship(
                    source=att.attachment_id,
                    relation="has_hash",
                    target=att.sha256,
                )
            )
            # attachment -> detected_as -> file_type
            relationships.append(
                Relationship(
                    source=att.attachment_id,
                    relation="detected_as",
                    target=classified_type,
                    evidence={"detected_type": sig.detected_type, "signature": sig.signature},
                )
            )

            # 6. Evaluate Forensic Observations
            att_obs, mime_mismatch, sig_mismatch = self._evaluate_observations(
                att, fn_analysis, sig, archive_meta, obs_counter
            )
            obs_counter += len(att_obs)
            observations.extend(att_obs)

            # 7. Tabular ML Features
            ml_feat = AttachmentMlFeatures(
                file_size=att.size,
                filename_length=fn_analysis.filename_length,
                extension_count=fn_analysis.extension_count,
                dot_count=fn_analysis.dot_count,
                has_double_extension=fn_analysis.has_double_extension,
                executable_extension=fn_analysis.extension in EXECUTABLE_EXTENSIONS,
                script_extension=fn_analysis.extension in SCRIPT_EXTENSIONS,
                macro_capable=fn_analysis.extension in MACRO_CAPABLE_EXTENSIONS,
                archive=archive_meta.is_archive,
                nested_archive=len(archive_meta.nested_archives) > 0,
                member_count=archive_meta.member_count,
                contains_executable_member=len(archive_meta.suspicious_members) > 0,
                mime_mismatch=mime_mismatch,
                signature_mismatch=sig_mismatch,
                detected_type=sig.detected_type,
                sha256=att.sha256,
            )
            ml_features.append(ml_feat.to_dict())

        # 8. Compute Bounded Assessment
        assessment = self._compute_assessment(observations, len(extracted))

        return AttachmentReport(
            module="attachment_analysis",
            email_id=email_id,
            attachments=report_attachments,
            entities=entities,
            observations=observations,
            relationships=relationships,
            assessment=assessment,
            ml_features=ml_features,
        )

    def _evaluate_observations(
        self,
        att: ExtractedAttachment,
        fn_analysis: FilenameAnalysis,
        sig: FileSignature,
        archive_meta: ArchiveMetadata,
        start_counter: int,
    ) -> Tuple[List[AttachmentObservation], bool, bool]:
        """Evaluate structural anomalies and consistency checks for an attachment."""
        obs: List[AttachmentObservation] = []
        counter = start_counter

        mime_mismatch = False
        sig_mismatch = False

        # Rule A: Suspicious Double Extension (e.g. invoice.pdf.exe)
        if fn_analysis.is_suspicious_double_extension:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-DOUBLE-EXTENSION",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="high",
                    description=(
                        f"Filename '{att.filename}' employs a deceptive double-extension pattern "
                        f"disguising terminal extension '{fn_analysis.extension}' with an innocuous inner extension."
                    ),
                    evidence={
                        "filename": att.filename,
                        "extensions": fn_analysis.extensions,
                        "terminal_extension": fn_analysis.extension,
                    },
                    fact_type="observed",
                )
            )
            counter += 1
        elif fn_analysis.has_double_extension and fn_analysis.extension_count >= 2:
            # Multiple extensions without specific doc+exe pattern
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-MULTIPLE-EXTENSIONS",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="low",
                    description=(
                        f"Filename '{att.filename}' contains multiple dot-separated extensions "
                        f"({', '.join(fn_analysis.extensions)})."
                    ),
                    evidence={
                        "filename": att.filename,
                        "extensions": fn_analysis.extensions,
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule B: Directly Executable Extension
        if fn_analysis.extension in EXECUTABLE_EXTENSIONS:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-EXECUTABLE-EXTENSION",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="medium",
                    description=(
                        f"Attachment has directly executable extension '{fn_analysis.extension}'. "
                        "Recorded as contextual forensic indicator."
                    ),
                    evidence={
                        "filename": att.filename,
                        "extension": fn_analysis.extension,
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule C: Script Extension
        if fn_analysis.extension in SCRIPT_EXTENSIONS:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-SCRIPT-EXTENSION",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="medium",
                    description=(
                        f"Attachment has script extension '{fn_analysis.extension}'. "
                        "Recorded as contextual forensic indicator."
                    ),
                    evidence={
                        "filename": att.filename,
                        "extension": fn_analysis.extension,
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule D: Macro-Capable Office Format
        if fn_analysis.extension in MACRO_CAPABLE_EXTENSIONS:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-MACRO-CAPABLE",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="low",
                    description=(
                        f"Attachment format '{fn_analysis.extension}' is macro-capable. "
                        "Macro execution not evaluated."
                    ),
                    evidence={
                        "filename": att.filename,
                        "extension": fn_analysis.extension,
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule E: Excessive Filename Length
        if fn_analysis.filename_length > self.max_filename_length:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-EXCESSIVE-FILENAME-LENGTH",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="low",
                    description=(
                        f"Attachment filename exceeds configured length threshold "
                        f"({fn_analysis.filename_length} > {self.max_filename_length} chars)."
                    ),
                    evidence={
                        "filename": att.filename,
                        "length": fn_analysis.filename_length,
                        "threshold": self.max_filename_length,
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule F: Declared MIME vs Extension Mismatch
        if fn_analysis.extension in EXTENSION_TO_MIMES:
            expected_mimes = EXTENSION_TO_MIMES[fn_analysis.extension]
            declared = att.declared_mime.lower()
            if declared not in expected_mimes and declared not in GENERIC_MIME_TYPES:
                mime_mismatch = True
                obs.append(
                    AttachmentObservation(
                        observation_id=f"OBS-ATT-{counter:03d}",
                        rule_id="RULE-ATTACHMENT-MIME-MISMATCH",
                        source_module="attachment_analysis",
                        attachment_id=att.attachment_id,
                        severity="medium",
                        description=(
                            f"Declared MIME type '{att.declared_mime}' conflicts with "
                            f"extension '{fn_analysis.extension}' (expected one of: {sorted(list(expected_mimes))[:3]})."
                        ),
                        evidence={
                            "filename": att.filename,
                            "extension": fn_analysis.extension,
                            "declared_mime": att.declared_mime,
                            "expected_mimes": list(expected_mimes),
                        },
                        fact_type="observed",
                    )
                )
                counter += 1

        # Rule G: Extension vs Detected File Signature Mismatch
        is_type_mismatch, mismatch_desc = self._check_type_mismatch(fn_analysis.extension, sig.detected_type)
        if is_type_mismatch:
            sig_mismatch = True
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-TYPE-MISMATCH",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="high",
                    description=mismatch_desc,
                    evidence={
                        "filename": att.filename,
                        "extension": fn_analysis.extension,
                        "declared_mime": att.declared_mime,
                        "detected_type": sig.detected_type,
                        "signature": sig.signature,
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule H: Archive Suspicious Members
        if archive_meta.is_archive and archive_meta.suspicious_members:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-ARCHIVE-SUSPICIOUS-MEMBER",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="high",
                    description=(
                        f"Archive '{att.filename}' contains suspicious executable or script member(s): "
                        f"{', '.join(archive_meta.suspicious_members)}."
                    ),
                    evidence={
                        "filename": att.filename,
                        "suspicious_members": archive_meta.suspicious_members,
                        "member_count": archive_meta.member_count,
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule I: Archive Nested Archives
        if archive_meta.is_archive and archive_meta.nested_archives:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-ARCHIVE-NESTED",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="medium",
                    description=(
                        f"Archive '{att.filename}' contains nested archive member(s): "
                        f"{', '.join(archive_meta.nested_archives)}."
                    ),
                    evidence={
                        "filename": att.filename,
                        "nested_archives": archive_meta.nested_archives,
                        "max_nesting_depth": archive_meta.max_nesting_depth,
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule J: Archive Member Count Safety Limit Exceeded
        if "member_count" in archive_meta.limits_exceeded:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-ARCHIVE-MEMBER-LIMIT",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="medium",
                    description=(
                        f"Archive '{att.filename}' member count ({archive_meta.member_count}) "
                        f"exceeds safety limit ({self.max_archive_members}). Member inspection was bounded."
                    ),
                    evidence={
                        "filename": att.filename,
                        "member_count": archive_meta.member_count,
                        "limit": self.max_archive_members,
                        "limit_type": "max_members",
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule K: Archive Total Size Safety Limit Exceeded
        if "total_size" in archive_meta.limits_exceeded:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-ARCHIVE-SIZE-LIMIT",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="medium",
                    description=(
                        f"Archive '{att.filename}' declared uncompressed size ({archive_meta.total_uncompressed_size} bytes) "
                        f"exceeds safety limit ({self.max_archive_total_size} bytes)."
                    ),
                    evidence={
                        "filename": att.filename,
                        "total_uncompressed_size": archive_meta.total_uncompressed_size,
                        "limit": self.max_archive_total_size,
                        "limit_type": "max_total_size",
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        # Rule L: Archive Nesting Depth Safety Limit Exceeded
        if "nesting_depth" in archive_meta.limits_exceeded:
            obs.append(
                AttachmentObservation(
                    observation_id=f"OBS-ATT-{counter:03d}",
                    rule_id="RULE-ATTACHMENT-ARCHIVE-NESTING-LIMIT",
                    source_module="attachment_analysis",
                    attachment_id=att.attachment_id,
                    severity="medium",
                    description=(
                        f"Archive '{att.filename}' nested archive depth exceeds safety limit "
                        f"({self.max_archive_nesting_depth}). Deeper levels were not inspected."
                    ),
                    evidence={
                        "filename": att.filename,
                        "limit": self.max_archive_nesting_depth,
                        "limit_type": "max_nesting_depth",
                    },
                    fact_type="observed",
                )
            )
            counter += 1

        return obs, mime_mismatch, sig_mismatch

    def _check_type_mismatch(self, extension: str, detected_type: str) -> Tuple[bool, str]:
        """Compare filename extension against magic-byte detected type."""
        if detected_type in ("unknown", "empty"):
            return False, ""

        ext = extension.lower()

        # Document claimed, but executable signature detected
        if ext in DOCUMENT_EXTENSIONS:
            if detected_type in ("PE executable", "ELF executable", "Mach-O executable"):
                return True, (
                    f"Attachment extension '{ext}' indicates a document, but file content has a "
                    f"binary executable signature ('{detected_type}')."
                )
            if detected_type in ("ZIP archive", "7-Zip archive", "RAR archive"):
                # Notice: modern Office formats (.docx, .xlsx, .pptx) are internally ZIP containers!
                if ext not in (".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"):
                    return True, (
                        f"Attachment extension '{ext}' indicates a document, but file content has an "
                        f"archive signature ('{detected_type}')."
                    )

        # Image claimed, but executable or archive detected
        if ext in IMAGE_EXTENSIONS:
            if detected_type in ("PE executable", "ELF executable", "Mach-O executable"):
                return True, (
                    f"Attachment extension '{ext}' indicates an image, but file content has a "
                    f"binary executable signature ('{detected_type}')."
                )
            if detected_type in ("ZIP archive", "7-Zip archive", "RAR archive"):
                return True, (
                    f"Attachment extension '{ext}' indicates an image, but file content has an "
                    f"archive signature ('{detected_type}')."
                )

        # Executable claimed, but non-executable signature detected
        if ext in EXECUTABLE_EXTENSIONS:
            if detected_type in ("PDF document", "PNG image", "JPEG image", "GIF image"):
                return True, (
                    f"Attachment extension '{ext}' indicates an executable, but file content has a "
                    f"'{detected_type}' signature."
                )

        return False, ""

    def _inspect_archive_safe(
        self,
        raw_bytes: bytes,
        detected_type: str,
        extension: str,
    ) -> ArchiveMetadata:
        """Safely inspect archive metadata in memory without executing or extracting files."""
        is_zip = detected_type == "ZIP archive" or extension.lower() in (".zip",)
        if not is_zip or not raw_bytes:
            return ArchiveMetadata(is_archive=False)

        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                infolist = zf.infolist()
                namelist = zf.namelist()
                member_count = len(namelist)
                total_size = sum(info.file_size for info in infolist)

                suspicious_members: List[str] = []
                nested_archives: List[str] = []
                limits_exceeded: List[str] = []
                max_nesting_depth = 1

                # Check member count limit
                if member_count > self.max_archive_members:
                    limits_exceeded.append("member_count")

                # Check total size limit
                if total_size > self.max_archive_total_size:
                    limits_exceeded.append("total_size")

                # Bounded iteration: inspect at most min(member_count, self.max_archive_members)
                inspect_names = namelist[: self.max_archive_members]

                for name in inspect_names:
                    # Check member extension
                    m_ext = Path(name).suffix.lower()

                    # Check for suspicious double extensions inside archive
                    m_analysis = analyze_filename(name)
                    if m_analysis.is_suspicious_double_extension or m_ext in EXECUTABLE_EXTENSIONS or m_ext in SCRIPT_EXTENSIONS:
                        suspicious_members.append(name)

                    # Check for nested archive
                    if m_ext in ARCHIVE_EXTENSIONS:
                        nested_archives.append(name)
                        # Check nesting depth limit before attempting nested zip inspection
                        target_depth = 2
                        if target_depth > self.max_archive_nesting_depth:
                            if "nesting_depth" not in limits_exceeded:
                                limits_exceeded.append("nesting_depth")
                        else:
                            if m_ext == ".zip":
                                try:
                                    nested_bytes = zf.read(name)
                                    with zipfile.ZipFile(io.BytesIO(nested_bytes)) as nested_zf:
                                        max_nesting_depth = max(max_nesting_depth, 2)
                                        nested_members = nested_zf.namelist()
                                        if len(nested_members) > self.max_archive_members and "member_count" not in limits_exceeded:
                                            limits_exceeded.append("member_count")
                                        for n_name in nested_members[: self.max_archive_members]:
                                            n_ext = Path(n_name).suffix.lower()
                                            n_analysis = analyze_filename(n_name)
                                            if n_analysis.is_suspicious_double_extension or n_ext in EXECUTABLE_EXTENSIONS or n_ext in SCRIPT_EXTENSIONS:
                                                suspicious_members.append(f"{name}::{n_name}")
                                            if n_ext in ARCHIVE_EXTENSIONS:
                                                if 3 > self.max_archive_nesting_depth:
                                                    if "nesting_depth" not in limits_exceeded:
                                                        limits_exceeded.append("nesting_depth")
                                except Exception:
                                    pass

                return ArchiveMetadata(
                    is_archive=True,
                    member_count=member_count,
                    member_filenames=namelist,
                    total_uncompressed_size=total_size,
                    max_nesting_depth=max_nesting_depth,
                    suspicious_members=suspicious_members,
                    nested_archives=nested_archives,
                    limits_exceeded=limits_exceeded,
                )
        except Exception:
            return ArchiveMetadata(is_archive=False)

    def _classify_file_type(self, extension: str, detected_type: str) -> str:
        """Classify file into a safe, non-evaluative descriptive category."""
        ext = extension.lower()

        if detected_type in ("PE executable", "ELF executable", "Mach-O executable") or ext in EXECUTABLE_EXTENSIONS:
            return "executable"

        if ext in SCRIPT_EXTENSIONS:
            return "script"

        if detected_type in ("ZIP archive", "7-Zip archive", "RAR archive", "GZIP archive") or ext in ARCHIVE_EXTENSIONS:
            return "archive"

        if detected_type in ("PDF document", "Microsoft Compound File (OLE)") or ext in DOCUMENT_EXTENSIONS or ext in MACRO_CAPABLE_EXTENSIONS:
            return "document"

        if detected_type in ("PNG image", "JPEG image", "GIF image") or ext in IMAGE_EXTENSIONS:
            return "image"

        return "unknown"

    def _compute_assessment(
        self,
        observations: List[AttachmentObservation],
        attachment_count: int,
    ) -> AttachmentAssessment:
        """Compute bounded forensic structural assessment based strictly on attachment evidence."""
        if not observations:
            return AttachmentAssessment(
                category="no_significant_attachment_anomaly",
                risk_level="none",
                evidence_strength="none",
                confidence=0.0,
                reason=f"No structural anomalies detected across {attachment_count} attachment(s).",
            )

        high_sev = [o for o in observations if o.severity == "high"]
        med_sev = [o for o in observations if o.severity == "medium"]
        low_sev = [o for o in observations if o.severity == "low"]

        if high_sev:
            risk_level = "high"
            evidence_strength = "strong"
            confidence = min(0.90, 0.80 + 0.05 * len(high_sev))
            category = "attachment_anomaly_detected"
            details = "; ".join(o.description.rstrip(".") for o in high_sev)
            reason = f"Attachment structural analysis detected {len(high_sev)} high-severity anomaly indicator(s): {details}."
        elif med_sev:
            risk_level = "medium"
            evidence_strength = "moderate"
            confidence = min(0.75, 0.60 + 0.05 * len(med_sev))
            category = "attachment_anomaly_detected"
            details = "; ".join(o.description.rstrip(".") for o in med_sev)
            reason = f"Attachment structural analysis detected {len(med_sev)} medium-severity anomaly indicator(s): {details}."
        else:
            risk_level = "low"
            evidence_strength = "weak"
            confidence = 0.40
            category = "suspicious_attachment"
            details = "; ".join(o.description.rstrip(".") for o in low_sev)
            reason = f"Attachment structural analysis detected {len(low_sev)} low-severity anomaly indicator(s): {details}."

        return AttachmentAssessment(
            category=category,
            risk_level=risk_level,
            evidence_strength=evidence_strength,
            confidence=round(confidence, 4),
            reason=reason,
        )


def analyze_attachments(
    email_input: Union[EmailMessage, Message, bytes, str, Path, Dict[str, Any], List[Any]],
    email_id: str = "E001",
    max_filename_length: int = 100,
    max_archive_members: int = 1000,
    max_archive_total_size: int = 100 * 1024 * 1024,
    max_archive_nesting_depth: int = 2,
) -> AttachmentReport:
    """Convenience helper to analyze email attachments statically."""
    return StaticAttachmentAnalyzer(
        max_filename_length=max_filename_length,
        max_archive_members=max_archive_members,
        max_archive_total_size=max_archive_total_size,
        max_archive_nesting_depth=max_archive_nesting_depth,
    ).analyze(email_input, email_id=email_id)
