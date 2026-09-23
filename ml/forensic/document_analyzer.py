"""
document_analyzer.py - Forensic Office Document and Macro Analyzer for SIH26106.

Statically inspects Microsoft Office formats (OLE2 .doc/.xls and OOXML .docm/.xlsm)
using oletools (olevba, olefile):
- Macro detection (VBA code streams)
- Macro counts
- Embedded object counts (OLE package objects)
- Suspicious keyword indicators (AutoOpen, Document_Open, Shell, Powershell, WScript)

Strict Security: Pure static parser inspection. Never executes macros.
"""

import io
import re
import zipfile
from typing import Dict, List, Any, Tuple

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False


SUSPICIOUS_MACRO_PATTERNS = re.compile(
    r"\b(autoopen|document_open|workbook_open|auto_open|autoexec|"
    r"wscript\.shell|shell\.application|powershell|cmd\.exe|urldownloadtofile|"
    r"virtualalloc|writeprocessmemory)\b",
    re.IGNORECASE
)


class DocumentAnalyzer:
    """Forensic static analyzer for Office document attachments."""

    def __init__(self):
        pass

    def analyze_bytes(self, filename: str, data: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Statically analyzes document attachment bytes."""
        if not data:
            features = {
                "has_macro": 0,
                "macro_count": 0,
                "embedded_object_count": 0,
                "suspicious_macro_indicator": 0,
            }
            evidence = {"analyzed": False, "reason": "No data"}
            return features, evidence

        filename_clean = filename.lower()
        is_office_ext = any(filename_clean.endswith(ext) for ext in [
            ".doc", ".docx", ".docm", ".dot", ".dotm",
            ".xls", ".xlsx", ".xlsm", ".xlt", ".xltm",
            ".ppt", ".pptx", ".pptm"
        ])

        is_ooxml_container = data.startswith(b"PK\x03\x04") or zipfile.is_zipfile(io.BytesIO(data))
        is_ole_container = data.startswith(b"\xd0\xcf\x11\xe0")

        if not is_office_ext and not is_ooxml_container and not is_ole_container:
            # Not an OLE or OOXML container
            features = {
                "has_macro": 0,
                "macro_count": 0,
                "embedded_object_count": 0,
                "suspicious_macro_indicator": 0,
            }
            evidence = {"analyzed": False, "reason": "Not an Office container format"}
            return features, evidence

        has_macro = 0
        macro_count = 0
        suspicious_macro = 0
        embedded_object_count = 0
        vba_stream_names: List[str] = []
        analysis_method = "none"

        # 1. Inspect OOXML containers (ZIP archives: .docm, .xlsm, .pptm, etc.)
        if is_ooxml_container:
            try:
                with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                    namelist = zf.namelist()
                    # Check for embedded objects
                    for name in namelist:
                        name_lower = name.lower()
                        if any(term in name_lower for term in ("embeddings/", "package", "oleobject")):
                            embedded_object_count += 1

                    # Look for VBA macro project binary streams
                    macro_entries = [
                        name for name in namelist
                        if name.lower().endswith("vbaproject.bin")
                        or "vbaproject" in name.lower()
                        or "macrosheets" in name.lower()
                    ]

                    if macro_entries:
                        has_macro = 1
                        analysis_method = "ooxml_zip_vba_parser"
                        for m_entry in macro_entries:
                            vba_stream_names.append(m_entry)
                            try:
                                vba_stream_bytes = zf.read(m_entry)
                                procedures = re.findall(rb"\b(?:sub|function)\s+\w+", vba_stream_bytes, re.IGNORECASE)
                                macro_count += max(1, len(procedures))
                                if SUSPICIOUS_MACRO_PATTERNS.search(vba_stream_bytes.decode(errors="ignore")):
                                    suspicious_macro = 1
                            except Exception:
                                macro_count = max(1, macro_count)
            except Exception:
                pass

        # 2. Inspect OLE2 compound containers (.doc, .xls, etc.)
        elif is_ole_container:
            if OLETOOLS_AVAILABLE:
                try:
                    vbaparser = VBA_Parser(filename=filename, data=data)
                    if vbaparser.detect_vba_macros():
                        has_macro = 1
                        analysis_method = "oletools"
                        for (subfilename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                            macro_count += 1
                            vba_stream_names.append(stream_path)
                            if SUSPICIOUS_MACRO_PATTERNS.search(vba_code):
                                suspicious_macro = 1

                    # Check for embedded objects via olefile if present
                    if hasattr(vbaparser, "ole_file") and vbaparser.ole_file:
                        for entry in vbaparser.ole_file.listdir():
                            if any("package" in part.lower() or "ole" in part.lower() for part in entry):
                                embedded_object_count += 1

                    vbaparser.close()
                except Exception:
                    pass

            # Pure-Python OLE2 directory stream inspection if oletools unavailable or failed
            if not has_macro:
                # OLE directory stream identifiers for VBA: "VBA", "_VBA_PROJECT", "dir" in UTF-16LE
                ole_vba_signatures = [
                    b"V\x00B\x00A\x00",
                    b"_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T\x00",
                    b"d\x00i\x00r\x00",
                ]
                has_ole_vba_stream = any(sig in data for sig in ole_vba_signatures)
                if has_ole_vba_stream:
                    has_macro = 1
                    analysis_method = "ole2_vba_stream_parser"
                    vba_stream_names.append("VBA")
                    procedures = re.findall(rb"\b(?:sub|function)\s+\w+", data, re.IGNORECASE)
                    macro_count = max(1, len(procedures))
                    if SUSPICIOUS_MACRO_PATTERNS.search(data.decode(errors="ignore")):
                        suspicious_macro = 1

                    # Embedded package markers in OLE directory entries
                    if b"P\x00a\x00c\x00k\x00a\x00g\x00e\x00" in data or b"O\x00l\x00e\x00" in data:
                        embedded_object_count += 1

        features = {
            "has_macro": has_macro,
            "macro_count": macro_count,
            "embedded_object_count": embedded_object_count,
            "suspicious_macro_indicator": suspicious_macro,
        }

        evidence = {
            "analyzed": True,
            "analysis_method": analysis_method,
            "has_macro": bool(has_macro),
            "macro_count": macro_count,
            "vba_streams": vba_stream_names,
            "suspicious_patterns_detected": bool(suspicious_macro),
        }

        return features, evidence
