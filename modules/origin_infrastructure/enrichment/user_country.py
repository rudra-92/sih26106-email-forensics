"""Offline-first local User-Country adapter for Origin & Infrastructure Reconstruction.

Queries the PDDL-licensed user-country dataset (sapics/ip-location-db).
Provides country associated with likely end-user network endpoint.

CRITICAL FORENSIC SEMANTIC:
user-country reflects network endpoint aggregation, NEVER physical attacker location.
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

from ..models import UserCountryData


class UserCountryProvider:
    """Offline local User-Country provider (PDDL).

    Queries local user-country.mmdb for network endpoint country code.
    Gracefully degrades to status='unavailable' when database is not present.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        custom_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        raw_path = (
            db_path
            or os.environ.get("USER_COUNTRY_DB")
        )
        if not raw_path:
            for cand in [Path("data/geoip/user-country.mmdb"), Path("benchmark/ip_location_db/user-country.mmdb")]:
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

    def lookup(self, ip: str) -> UserCountryData:
        """Query user-country for an IPv4 or IPv6 address."""
        clean_ip = ip.strip() if ip else ""
        if not clean_ip:
            return UserCountryData(status="invalid_input", trust_state="unknown")

        try:
            ipaddress.ip_address(clean_ip)
        except ValueError:
            return UserCountryData(status="invalid_input", trust_state="unknown")

        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Custom lookup for test fixtures
        if self._custom_lookup is not None:
            if clean_ip in self._custom_lookup:
                entry = self._custom_lookup[clean_ip]
                return UserCountryData(
                    status="available",
                    country_code=entry.get("country_code"),
                    trust_state="enriched",
                    lookup_timestamp=now_iso,
                )
            return UserCountryData(status="not_found", trust_state="unknown", lookup_timestamp=now_iso)

        # 2. Real MMDB lookup
        if self._reader is not None and self.is_db_available:
            try:
                record = self._reader.get(clean_ip)
                if record and isinstance(record, dict):
                    cc = record.get("country_code")
                    if cc:
                        return UserCountryData(
                            status="available",
                            country_code=str(cc).upper(),
                            trust_state="enriched",
                            lookup_timestamp=now_iso,
                        )
                return UserCountryData(status="not_found", trust_state="unknown", lookup_timestamp=now_iso)
            except Exception:
                return UserCountryData(status="unavailable", trust_state="unknown")

        return UserCountryData(status="unavailable", trust_state="unknown")

    def close(self) -> None:
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
            self.is_db_available = False

    def __enter__(self) -> "UserCountryProvider":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
