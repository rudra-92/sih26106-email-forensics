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

import math
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


VALID_PE_MACHINES = {
    0x014C,  # IMAGE_FILE_MACHINE_I386
    0x8664,  # IMAGE_FILE_MACHINE_AMD64
    0x01C0,  # IMAGE_FILE_MACHINE_ARM
    0x01C4,  # IMAGE_FILE_MACHINE_ARMNT
    0xAA64,  # IMAGE_FILE_MACHINE_ARM64
    0x0200,  # IMAGE_FILE_MACHINE_IA64
}

VALID_OPTIONAL_HEADER_MAGICS = {
    0x010B,  # PE32
    0x020B,  # PE32+
    0x0107,  # ROM
}


def _shannon_entropy(data_bytes: bytes) -> float:
    """Computes Shannon entropy of byte data."""
    if not data_bytes:
        return 0.0
    occ = [0] * 256
    for b in data_bytes:
        occ[b] += 1
    entropy = 0.0
    length = len(data_bytes)
    for c in occ:
        if c > 0:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


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

    def _validate_pe_structure(self, data: bytes) -> Tuple[bool, Dict[str, Any]]:
        """
        Pure-Python structural PE verification:
        1. DOS Header: Starts with b"MZ", minimum length >= 0x40.
        2. e_lfanew offset at 0x3C points to PE signature within data bounds.
        3. PE signature: b"PE\x00\x00" at e_lfanew.
        4. COFF File Header (20 bytes):
           - Machine architecture in valid PE architectures
           - NumberOfSections between 1 and 96
           - SizeOfOptionalHeader >= 0
        5. Optional Header (if present):
           - Fits in bounds
           - Magic is 0x010B (PE32), 0x020B (PE32+), or 0x0107 (ROM)
        6. Section Table:
           - Section headers fit in bounds
           - Extracts section names, characteristics, and computes entropy
        """
        if len(data) < 0x40 or not data.startswith(b"MZ"):
            return False, {"reason": "Missing or truncated DOS MZ header"}

        e_lfanew = int.from_bytes(data[0x3C:0x40], byteorder="little")
        # Must fit PE signature (4 bytes) + COFF header (20 bytes)
        if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
            return False, {"reason": f"Invalid e_lfanew offset {e_lfanew} out of bounds"}

        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return False, {"reason": "Missing PE\\0\\0 signature at e_lfanew"}

        # COFF Header (20 bytes)
        coff_offset = e_lfanew + 4
        machine = int.from_bytes(data[coff_offset:coff_offset + 2], byteorder="little")
        num_sections = int.from_bytes(data[coff_offset + 2:coff_offset + 4], byteorder="little")
        size_of_opt_header = int.from_bytes(data[coff_offset + 16:coff_offset + 18], byteorder="little")
        characteristics = int.from_bytes(data[coff_offset + 18:coff_offset + 20], byteorder="little")

        if machine not in VALID_PE_MACHINES:
            return False, {"reason": f"Unrecognized PE machine architecture: {hex(machine)}"}

        if not (1 <= num_sections <= 96):
            return False, {"reason": f"Invalid section count: {num_sections}"}

        # Optional Header
        opt_offset = coff_offset + 20
        if size_of_opt_header > 0:
            if opt_offset + size_of_opt_header > len(data):
                return False, {"reason": "Optional header truncated"}
            if size_of_opt_header >= 2:
                opt_magic = int.from_bytes(data[opt_offset:opt_offset + 2], byteorder="little")
                if opt_magic not in VALID_OPTIONAL_HEADER_MAGICS:
                    return False, {"reason": f"Invalid optional header magic: {hex(opt_magic)}"}

        # Section Table
        sec_table_offset = opt_offset + size_of_opt_header
        section_names: List[str] = []
        suspicious_section_count = 0
        section_entropies: List[float] = []

        if sec_table_offset + num_sections * 40 <= len(data):
            for i in range(num_sections):
                s_off = sec_table_offset + i * 40
                s_name_raw = data[s_off:s_off + 8].rstrip(b"\x00")
                s_name = s_name_raw.decode(errors="ignore").strip().lower()
                section_names.append(s_name)

                s_chars = int.from_bytes(data[s_off + 36:s_off + 40], byteorder="little")
                if s_name in SUSPICIOUS_SECTION_NAMES:
                    suspicious_section_count += 1
                # IMAGE_SCN_MEM_EXECUTE (0x20000000) & IMAGE_SCN_MEM_WRITE (0x80000000)
                if (s_chars & 0x20000000) and (s_chars & 0x80000000):
                    suspicious_section_count += 1

                raw_size = int.from_bytes(data[s_off + 16:s_off + 20], byteorder="little")
                raw_ptr = int.from_bytes(data[s_off + 20:s_off + 24], byteorder="little")
                if raw_ptr > 0 and raw_size > 0 and raw_ptr + raw_size <= len(data):
                    sec_entropy = _shannon_entropy(data[raw_ptr:raw_ptr + raw_size])
                    section_entropies.append(sec_entropy)

        overall_entropy = (
            round(float(np.mean(section_entropies)), 4)
            if section_entropies
            else round(_shannon_entropy(data), 4)
        )

        return True, {
            "machine": hex(machine),
            "section_count": num_sections,
            "section_names": section_names,
            "suspicious_section_count": suspicious_section_count,
            "pe_entropy": overall_entropy,
            "characteristics": characteristics,
        }

    def analyze_bytes(self, data: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Statically inspects PE byte data."""
        if not data or not data.startswith(b"MZ"):
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
            evidence = {"is_pe": False, "reason": "No MZ header"}
            return features, evidence

        if not PEFILE_AVAILABLE:
            is_valid_pe, details = self._validate_pe_structure(data)
            features = {
                "is_pe": 1 if is_valid_pe else 0,
                "pe_entropy": details.get("pe_entropy", np.nan) if is_valid_pe else np.nan,
                "section_count": details.get("section_count", 0) if is_valid_pe else 0,
                "suspicious_section_count": details.get("suspicious_section_count", 0) if is_valid_pe else 0,
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
            evidence = {
                "is_pe": is_valid_pe,
                "analysis_method": "structural_pe_parser",
                "section_names": details.get("section_names", []),
                "details": details,
            }
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
