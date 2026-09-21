"""
yara_scanner.py - Modular YARA Scanning Engine for SIH26106 Forensic Pipeline.

Compiles external YARA rules from rules/ or ml/rules/ and scans file paths or byte buffers.
Returns match counts and matched rule identifiers in raw evidence.
Graceful fallback: Continues gracefully if yara-python is unavailable or rules are empty.
"""

import os
import glob
from typing import Dict, List, Any, Optional, Tuple

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraScanner:
    """Forensic static signature scanner using external YARA rules."""

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules = None
        self.rules_loaded = False
        self.rule_files = []

        if not YARA_AVAILABLE:
            return

        # Check candidate directories
        candidate_dirs = [rules_dir] if rules_dir else ["rules", os.path.join("ml", "rules")]
        found_files = []
        for d in candidate_dirs:
            if d and os.path.exists(d):
                yar_files = glob.glob(os.path.join(d, "*.yar")) + glob.glob(os.path.join(d, "*.yara"))
                if yar_files:
                    found_files = yar_files
                    break

        self.rule_files = found_files
        if self.rule_files:
            try:
                filepaths = {f"rule_{i}": fpath for i, fpath in enumerate(self.rule_files)}
                self.rules = yara.compile(filepaths=filepaths)
                self.rules_loaded = True
            except Exception as e:
                self.rules = None
                self.rules_loaded = False

    def scan_bytes(self, data: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Scans in-memory byte buffer with compiled YARA rules."""
        if not data or not self.rules_loaded or self.rules is None:
            features = {
                "yara_match_count": 0,
            }
            evidence = {
                "yara_scanner_available": YARA_AVAILABLE,
                "rules_loaded": self.rules_loaded,
                "yara_rule_names": [],
            }
            return features, evidence

        try:
            matches = self.rules.match(data=data)
            matched_names = [m.rule for m in matches]
            features = {
                "yara_match_count": len(matched_names),
            }
            evidence = {
                "yara_scanner_available": True,
                "rules_loaded": True,
                "yara_rule_names": matched_names,
            }
            return features, evidence
        except Exception as e:
            return {"yara_match_count": 0}, {"error": str(e), "yara_rule_names": []}

    def scan_file(self, file_path: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Scans file at path with compiled YARA rules."""
        if not os.path.exists(file_path):
            return {"yara_match_count": 0}, {"yara_rule_names": []}
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self.scan_bytes(data)
        except Exception as e:
            return {"yara_match_count": 0}, {"error": str(e), "yara_rule_names": []}
