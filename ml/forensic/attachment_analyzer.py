"""
attachment_analyzer.py - Forensic Email Attachment and Static Byte Analyzer for SIH26106.

Performs static analysis on email attachments:
- Metadata extraction: filename, extensions, MIME type, size, SHA256, MD5
- Extension heuristics: double extensions, executables, scripts, archives, macro-capable formats
- MIME vs extension discrepancy detection
- Byte-level analysis: Shannon file entropy, printable strings, embedded URLs/IPs/emails

Strict Security: Static inspection only. Never executes binaries, scripts, or macros.
"""

import math
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

EXECUTABLE_EXTS = {".exe", ".dll", ".bat", ".cmd", ".scr", ".pif", ".cpl", ".com", ".hta"}
SCRIPT_EXTS = {".js", ".vbs", ".ps1", ".vbe", ".jse", ".wsf", ".wsh", ".py", ".sh", ".bash"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".cab"}
DOCUMENT_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt"}
MACRO_CAPABLE_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xla"}

MIME_EXT_MAP = {
    "application/pdf": {".pdf"},
    "application/x-dosexec": {".exe", ".dll", ".scr"},
    "application/x-msdownload": {".exe", ".dll"},
    "application/zip": {".zip"},
    "application/x-rar-compressed": {".rar"},
    "application/x-tar": {".tar"},
    "application/msword": {".doc", ".dot"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.ms-excel": {".xls", ".xla"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
}

IPV4_REGEX = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(rb"https?://[^\s<>\"']+")
EMAIL_REGEX = re.compile(rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def compute_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of byte data (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class AttachmentAnalyzer:
    """Forensic static attachment analyzer."""

    def __init__(self, max_file_size_bytes: int = 20971520):
        self.max_file_size_bytes = max_file_size_bytes

    def analyze_single_attachment(self, att: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Analyzes a single attachment object."""
        filename = str(att.get("filename") or "unnamed").strip()
        content_bytes = att.get("content_bytes") or b""
        mime_type = str(att.get("mime_type") or "application/octet-stream").lower().strip()
        size_bytes = len(content_bytes) if content_bytes else int(att.get("size_bytes") or 0)

        # Enforce size limit
        if len(content_bytes) > self.max_file_size_bytes:
            content_bytes = content_bytes[:self.max_file_size_bytes]

        # Hashes
        sha256_hash = hashlib.sha256(content_bytes).hexdigest() if content_bytes else None
        md5_hash = hashlib.md5(content_bytes).hexdigest() if content_bytes else None

        # Extensions
        filename_lower = filename.lower()
        parts = filename_lower.split(".")
        extension = f".{parts[-1]}" if len(parts) > 1 else ""

        # Double extension detection (e.g. invoice.pdf.exe or report.docx.js)
        double_extension = 0
        if len(parts) >= 3:
            penultimate_ext = f".{parts[-2]}"
            if penultimate_ext in DOCUMENT_EXTS or penultimate_ext in ARCHIVE_EXTS:
                if extension in EXECUTABLE_EXTS or extension in SCRIPT_EXTS:
                    double_extension = 1

        executable_ext = 1 if extension in EXECUTABLE_EXTS else 0
        script_ext = 1 if extension in SCRIPT_EXTS else 0
        archive_ext = 1 if extension in ARCHIVE_EXTS else 0
        document_ext = 1 if extension in DOCUMENT_EXTS else 0
        macro_capable = 1 if extension in MACRO_CAPABLE_EXTS else 0

        # MIME vs extension mismatch
        mime_mismatch = 0
        if mime_type in MIME_EXT_MAP:
            expected_exts = MIME_EXT_MAP[mime_type]
            if extension and extension not in expected_exts:
                mime_mismatch = 1

        # File entropy & embedded strings
        entropy = compute_shannon_entropy(content_bytes) if content_bytes else np.nan

        printable_count = 0
        url_count = 0
        ip_count = 0
        email_count = 0

        if content_bytes:
            # Printable ASCII strings (len >= 4)
            strings = re.findall(rb"[ -~]{4,}", content_bytes)
            printable_count = len(strings)
            url_count = len(URL_REGEX.findall(content_bytes))
            ip_count = len(IPV4_REGEX.findall(content_bytes))
            email_count = len(EMAIL_REGEX.findall(content_bytes))

        features = {
            "size_bytes": size_bytes,
            "double_extension": double_extension,
            "executable_extension": executable_ext,
            "script_extension": script_ext,
            "archive_extension": archive_ext,
            "document_extension": document_ext,
            "macro_capable_document": macro_capable,
            "MIME_extension_mismatch": mime_mismatch,
            "file_entropy": entropy,
            "printable_string_count": printable_count,
            "url_string_count": url_count,
            "ip_string_count": ip_count,
            "email_string_count": email_count,
        }

        evidence = {
            "filename": filename,
            "extension": extension,
            "mime_type": mime_type,
            "sha256": sha256_hash,
            "md5": md5_hash,
            "raw_size": size_bytes,
        }

        return features, evidence

    def analyze(self, attachments: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Analyzes all attachments in an email, aggregating features."""
        attachment_count = len(attachments)
        has_attachment = 1 if attachment_count > 0 else 0

        if not attachments:
            features = {
                "attachment_count": 0,
                "has_attachment": 0,
                "total_attachment_size_bytes": 0,
                "double_extension": 0,
                "executable_attachment": 0,
                "script_attachment": 0,
                "archive_attachment": 0,
                "document_attachment": 0,
                "macro_capable_document": 0,
                "MIME_extension_mismatch": 0,
                "file_entropy": np.nan,
                "printable_string_count": 0,
                "url_string_count": 0,
                "ip_string_count": 0,
                "email_string_count": 0,
            }
            evidence = {"attachments": []}
            return features, evidence

        total_size = 0
        has_double_ext = 0
        has_exec = 0
        has_script = 0
        has_archive = 0
        has_doc = 0
        has_macro_doc = 0
        has_mime_mismatch = 0
        entropies = []
        tot_printable = 0
        tot_urls = 0
        tot_ips = 0
        tot_emails = 0

        att_evidence_list = []

        for att in attachments:
            f, e = self.analyze_single_attachment(att)
            total_size += f["size_bytes"]
            if f["double_extension"]:
                has_double_ext = 1
            if f["executable_extension"]:
                has_exec = 1
            if f["script_extension"]:
                has_script = 1
            if f["archive_extension"]:
                has_archive = 1
            if f["document_extension"]:
                has_doc = 1
            if f["macro_capable_document"]:
                has_macro_doc = 1
            if f["MIME_extension_mismatch"]:
                has_mime_mismatch = 1
            if not np.isnan(f["file_entropy"]):
                entropies.append(f["file_entropy"])
            tot_printable += f["printable_string_count"]
            tot_urls += f["url_string_count"]
            tot_ips += f["ip_string_count"]
            tot_emails += f["email_string_count"]

            att_evidence_list.append(e)

        features = {
            "attachment_count": attachment_count,
            "has_attachment": has_attachment,
            "total_attachment_size_bytes": total_size,
            "double_extension": has_double_ext,
            "executable_attachment": has_exec,
            "script_attachment": has_script,
            "archive_attachment": has_archive,
            "document_attachment": has_doc,
            "macro_capable_document": has_macro_doc,
            "MIME_extension_mismatch": has_mime_mismatch,
            "file_entropy": round(float(np.mean(entropies)), 4) if entropies else np.nan,
            "printable_string_count": tot_printable,
            "url_string_count": tot_urls,
            "ip_string_count": tot_ips,
            "email_string_count": tot_emails,
        }

        evidence = {"attachments": att_evidence_list}
        return features, evidence
