"""Offline-first local Origin-ASN adapter for Origin & Infrastructure Reconstruction.

Queries the PDDL-licensed origin-asn dataset (sapics/ip-location-db).
Provides ASN and AS Organization derived from global BGP routing tables.
"""

from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union

try:
    import maxminddb
except ImportError:
    maxminddb = None  # type: ignore[assignment]

from ..models import OriginAsnData


class OriginASNProvider:
    """Offline local Origin-ASN provider (PDDL).

    Queries local origin-asn.mmdb for ASN and organization metadata.
    Gracefully degrades to status='unavailable' when database is not present.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        custom_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        raw_path = (
            db_path
            or os.environ.get("ORIGIN_ASN_DB")
        )
        if not raw_path:
            for cand in [Path("data/geoip/origin-asn.mmdb"), Path("benchmark/ip_location_db/origin-asn.mmdb")]:
                if cand.is_file():
                    raw_path = str(cand)
                    break

        self.db_path = str(raw_path) if raw_path else None
        self._custom_lookup = custom_lookup  # Explicit test fixtures
        self.is_db_available = False
        self._reader: Any = None

        if self.db_path and maxminddb is not None:
            p = Path(self.db_path)
            if p.is_file() and p.stat().st_size > 0:
                try:
                    self._reader = maxminddb.open_database(self.db_path)
                    self.is_db_available = True
                except Exception:
                    self.is_db_available = False
                    self._reader = None

    def lookup(self, ip: str) -> OriginAsnData:
        """Query origin-asn for an IPv4 or IPv6 address."""
        clean_ip = ip.strip() if ip else ""
        if not clean_ip:
            return OriginAsnData(status="invalid_input", trust_state="unknown")

        try:
            ipaddress.ip_address(clean_ip)
        except ValueError:
            return OriginAsnData(status="invalid_input", trust_state="unknown")

        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Custom lookup for test fixtures
        if self._custom_lookup is not None:
            if clean_ip in self._custom_lookup:
                entry = self._custom_lookup[clean_ip]
                raw_asn = entry.get("asn") or entry.get("autonomous_system_number")
                asn_str = f"AS{raw_asn}" if raw_asn and not str(raw_asn).startswith("AS") else (str(raw_asn) if raw_asn else None)
                return OriginAsnData(
                    status="available",
                    asn=asn_str,
                    organization=entry.get("organization") or entry.get("autonomous_system_organization"),
                    trust_state="enriched",
                    lookup_timestamp=now_iso,
                )
            return OriginAsnData(status="not_found", trust_state="unknown", lookup_timestamp=now_iso)

        # 2. Real MMDB lookup
        if self._reader is not None and self.is_db_available:
            try:
                record = self._reader.get(clean_ip)
                if record and isinstance(record, dict):
                    raw_num = record.get("autonomous_system_number")
                    org = record.get("autonomous_system_organization")
                    asn_str = f"AS{raw_num}" if raw_num else None
                    if asn_str or org:
                        return OriginAsnData(
                            status="available",
                            asn=asn_str,
                            organization=org,
                            trust_state="enriched",
                            lookup_timestamp=now_iso,
                        )
                return OriginAsnData(status="not_found", trust_state="unknown", lookup_timestamp=now_iso)
            except Exception:
                return OriginAsnData(status="unavailable", trust_state="unknown")

        return OriginAsnData(status="unavailable", trust_state="unknown")

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
            self.is_db_available = False

    def __enter__(self) -> "OriginASNProvider":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
