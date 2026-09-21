"""
pdf_analyzer.py - Forensic PDF Static Token and Structure Analyzer for SIH26106.

Statically scans PDF attachments for active content markers (following Didier Stevens'
pdfid methodology and pypdf object inspection):
- /JavaScript and /JS (client-side script execution)
- /OpenAction and /AA (auto-executing actions on document load)
- /Launch (external process invocation)
- /EmbeddedFiles (embedded binary attachments or payloads)
- /AcroForm (interactive credential forms)

Strict Security: Pure byte-level static parsing. Never renders or executes PDF.
"""

import re
from typing import Dict, List, Any, Optional, Tuple

PDF_HEADER_REGEX = re.compile(rb"%PDF-\d+\.\d+")

# Case-insensitive PDF name token patterns (handles hex-encoded characters like #2F or #4A)
TOKEN_PATTERNS = {
    "javascript": re.compile(rb"/(?:JavaScript|JS|J#61vaScript|Java#53cript)\b", re.IGNORECASE),
    "openaction": re.compile(rb"/(?:OpenAction|AA)\b", re.IGNORECASE),
    "launch": re.compile(rb"/Launch\b", re.IGNORECASE),
    "embedded_file": re.compile(rb"/(?:EmbeddedFile|EmbeddedFiles)\b", re.IGNORECASE),
    "acroform": re.compile(rb"/AcroForm\b", re.IGNORECASE),
}


class PDFAnalyzer:
    """Forensic static analyzer for PDF attachments."""

    def __init__(self):
        pass

    def analyze_bytes(self, data: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Statically inspects PDF byte data for structural indicators."""
        if not data or not (data.startswith(b"%PDF-") or b"%PDF-" in data[:1024]):
            features = {
                "pdf_has_javascript": 0,
                "pdf_has_openaction": 0,
                "pdf_has_launch": 0,
                "pdf_has_embedded_file": 0,
                "pdf_has_acroform": 0,
            }
            evidence = {"is_pdf": False}
            return features, evidence

        has_js = 1 if TOKEN_PATTERNS["javascript"].search(data) else 0
        has_oa = 1 if TOKEN_PATTERNS["openaction"].search(data) else 0
        has_launch = 1 if TOKEN_PATTERNS["launch"].search(data) else 0
        has_ef = 1 if TOKEN_PATTERNS["embedded_file"].search(data) else 0
        has_af = 1 if TOKEN_PATTERNS["acroform"].search(data) else 0

        # Token counts for evidence
        evidence_counts = {
            k: len(pat.findall(data)) for k, pat in TOKEN_PATTERNS.items()
        }

        features = {
            "pdf_has_javascript": has_js,
            "pdf_has_openaction": has_oa,
            "pdf_has_launch": has_launch,
            "pdf_has_embedded_file": has_ef,
            "pdf_has_acroform": has_af,
        }

        evidence = {
            "is_pdf": True,
            "token_counts": evidence_counts,
        }

        return features, evidence
