"""
pe_analyzer.py - Forensic Windows PE Executable Static Analyzer for SIH26106.

Performs static analysis of Windows PE binary attachments using pefile:
- PE structural verification (MZ / PE signatures)
- Section counts, entropy, and suspicious packer sections (UPX, ASPack, etc.)
- Import, export, and DLL counts
- Categorized suspicious API import counts (process creation, command execution,
  network communication, memory manipulation, persistence, credential access)

Strict Security: Pure static parser inspection. Never executes binary.
"""

import os
import math
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


SUSPICIOUS_SECTION_NAMES = {
    ".upx0", ".upx1", ".upx2", ".aspack", ".adata", ".mpress", "pec1", "pec2", ".petite"
}

SUSPICIOUS_API_CATEGORIES = {
    "process_creation": {
        "createprocessa", "createprocessw", "shellexecutea", "shellexecutew", "winexec", "createprocesswithtokenw"
    },
    "command_execution": {
        "system", "popen", "_wsystem", "_popen"
    },
    "network_communication": {
        "internetopena", "internetopenw", "internetconnecta", "httpopenrequesta",
        "httpsendrequesta", "wsastartup", "socket", "connect", "send", "recv",
        "urldownloadtofilea", "urldownloadtofilew"
    },
    "memory_manipulation": {
        "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
        "writeprocessmemory", "readprocessmemory"
    },
    "persistence": {
        "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "createservicea", "createservicew"
    },
    "credential_access": {
        "cryptunprotectdata", "lsaretrieveprivatedata", "samiconnect", "credreada", "credreadw"
    }
}


class PEAnalyzer:
    """Static PE header and section analyzer."""

    def __init__(self):
        pass

    def analyze_bytes(self, data: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Statically inspects PE byte data."""
        if not data or not data.startswith(b"MZ") or not PEFILE_AVAILABLE:
            features = {
                "is_pe": 0,
                "pe_entropy": np.nan,
                "section_count": 0,
                "suspicious_section_count": 0,
                "import_count": 0,
                "dll_count": 0,
                "export_count": 0,
                "pe_process_creation_apis": 0,
                "pe_command_execution_apis": 0,
                "pe_network_communication_apis": 0,
                "pe_memory_manipulation_apis": 0,
                "pe_persistence_apis": 0,
                "pe_credential_access_apis": 0,
            }
            evidence = {"is_pe": False, "reason": "No MZ header or pefile unavailable"}
            return features, evidence

        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories()
        except Exception as e:
            features = {
                "is_pe": 1,
                "pe_entropy": np.nan,
                "section_count": 0,
                "suspicious_section_count": 0,
                "import_count": 0,
                "dll_count": 0,
                "export_count": 0,
                "pe_process_creation_apis": 0,
                "pe_command_execution_apis": 0,
                "pe_network_communication_apis": 0,
                "pe_memory_manipulation_apis": 0,
                "pe_persistence_apis": 0,
                "pe_credential_access_apis": 0,
            }
            evidence = {"is_pe": True, "parse_error": str(e)}
            return features, evidence

        # Sections
        section_count = len(pe.sections)
        suspicious_section_count = 0
        section_entropies = []
        section_names = []

        for sec in pe.sections:
            sec_name = sec.Name.decode(errors="ignore").strip().strip("\x00").lower()
            section_names.append(sec_name)
            if sec_name in SUSPICIOUS_SECTION_NAMES:
                suspicious_section_count += 1
            # Check for executable + writable sections (common in packers/malware)
            # IMAGE_SCN_MEM_EXECUTE (0x20000000) & IMAGE_SCN_MEM_WRITE (0x80000000)
            if (sec.Characteristics & 0x20000000) and (sec.Characteristics & 0x80000000):
                suspicious_section_count += 1
            try:
                entropy = sec.get_entropy()
                section_entropies.append(entropy)
            except Exception:
                pass

        pe_entropy = round(float(np.mean(section_entropies)), 4) if section_entropies else np.nan

        # Imports & DLLs
        dll_count = 0
        import_count = 0
        imported_apis = []

        cat_counts = {
            "process_creation": 0,
            "command_execution": 0,
            "network_communication": 0,
            "memory_manipulation": 0,
            "persistence": 0,
            "credential_access": 0,
        }

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_count += 1
                    if imp.name:
                        api_name = imp.name.decode(errors="ignore").lower()
                        imported_apis.append(api_name)
                        for cat, api_set in SUSPICIOUS_API_CATEGORIES.items():
                            if api_name in api_set:
                                cat_counts[cat] += 1

        # Exports
        export_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
            export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

        pe.close()

        features = {
            "is_pe": 1,
            "pe_entropy": pe_entropy,
            "section_count": section_count,
            "suspicious_section_count": suspicious_section_count,
            "import_count": import_count,
            "dll_count": dll_count,
            "export_count": export_count,
            "pe_process_creation_apis": cat_counts["process_creation"],
            "pe_command_execution_apis": cat_counts["command_execution"],
            "pe_network_communication_apis": cat_counts["network_communication"],
            "pe_memory_manipulation_apis": cat_counts["memory_manipulation"],
            "pe_persistence_apis": cat_counts["persistence"],
            "pe_credential_access_apis": cat_counts["credential_access"],
        }

        evidence = {
            "is_pe": True,
            "section_names": section_names,
            "dll_count": dll_count,
            "imported_apis_count": import_count,
            "sample_imported_apis": imported_apis[:50],
        }

        return features, evidence
