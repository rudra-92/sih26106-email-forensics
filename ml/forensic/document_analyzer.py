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

import re
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

        if not is_office_ext and not (data.startswith(b"\xd0\xcf\x11\xe0") or data.startswith(b"PK\x03\x04")):
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
        analysis_method = "oletools" if OLETOOLS_AVAILABLE else "fallback_heuristic"

        if OLETOOLS_AVAILABLE:
            try:
                vbaparser = VBA_Parser(filename=filename, data=data)
                if vbaparser.detect_vba_macros():
                    has_macro = 1
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
                # Fallback scan for VBA procedure signatures
                analysis_method = "fallback_heuristic"
                data_lower = data.lower()
                if b"sub " in data_lower or b"function " in data_lower or b"autoopen" in data_lower or b"vb_name" in data_lower:
                    has_macro = 1
                    macro_count = max(1, len(re.findall(rb"\b(?:sub|function)\s+\w+", data, re.IGNORECASE)))
                    if SUSPICIOUS_MACRO_PATTERNS.search(data.decode(errors="ignore")):
                        suspicious_macro = 1
        else:
            # Fallback scan for VBA procedure signatures when oletools is unavailable
            analysis_method = "fallback_heuristic"
            data_lower = data.lower()
            if b"sub " in data_lower or b"function " in data_lower or b"autoopen" in data_lower or b"vb_name" in data_lower:
                has_macro = 1
                macro_count = max(1, len(re.findall(rb"\b(?:sub|function)\s+\w+", data, re.IGNORECASE)))
                if SUSPICIOUS_MACRO_PATTERNS.search(data.decode(errors="ignore")):
                    suspicious_macro = 1

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
