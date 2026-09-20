"""Offline-first local GeoIP adapter for Origin & Infrastructure Reconstruction.

Design Reality:
This module provides an adapter interface (BaseGeoIPProvider / LocalGeoIPProvider)
for offline geolocation lookups. It includes an in-memory reference table for synthetic
and documentation IP ranges (RFC 5737). When no external database is configured
(or if the database file is missing or an unknown IP is queried), it gracefully returns
status='unavailable' without making external network calls or raising exceptions.

Compatible Free / Open Datasets:
- IP2Location LITE (BIN format): Free database requiring attribution under CC BY-SA 4.0
  ("This site or product includes IP2Location LITE data available from https://lite.ip2location.com")
- MaxMind GeoLite2 (MMDB format): Free database requiring attribution under CC BY-SA 4.0 / GeoLite2 EULA
  ("This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com")

Semantic Rule:
Always produces 'observed_infrastructure_geolocation' and NEVER 'attacker_physical_location'.
"""

import ipaddress
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

try:
    import maxminddb
except ImportError:
    maxminddb = None  # type: ignore[assignment]

from ..models import GeoLocationData
from .base import BaseGeoIPProvider


class LocalGeoIPProvider(BaseGeoIPProvider):
    """Offline local GeoIP provider supporting DB-IP Lite MMDB.

    Accepts arbitrary IPv4 and IPv6 addresses and queries the local MMDB database dynamically.
    Contains zero hardcoded IP-to-location mappings in production.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        custom_lookup: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        raw_path = (
            db_path
            or os.environ.get("GEOIP_CITY_DB")
            or os.environ.get("GEOIP_COUNTRY_DB")
            or os.environ.get("SIH_GEOIP_DB_PATH")
        )
        if not raw_path:
            default_mmdb = Path("data/geoip/dbip-city-lite.mmdb")
            if default_mmdb.is_file():
                raw_path = str(default_mmdb)

        self.db_path = str(raw_path) if raw_path else None
        self._custom_lookup = custom_lookup  # Explicit test fixtures only
        self.is_db_available = False
        self._reader: Any = None
        self._db_type: Optional[str] = None
        self._db_date: Optional[str] = None

        if self.db_path:
            p = Path(self.db_path)
            if p.is_file() and maxminddb is not None:
                try:
                    self._reader = maxminddb.open_database(str(p))
                    self.is_db_available = True
                    try:
                        meta = self._reader.metadata()
                        self._db_type = getattr(meta, "database_type", "DBIP-City-Lite")
                        epoch = getattr(meta, "build_epoch", None)
                        if epoch:
                            self._db_date = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")
                    except Exception:
                        self._db_type = "DBIP-City-Lite"
                except Exception:
                    self._reader = None
                    self.is_db_available = False

    def close(self) -> None:
        """Close reader handle if open."""
        if self._reader is not None:
            try:
                self._reader.close()
            except Exception:
                pass
            self._reader = None
            self.is_db_available = False

    def __enter__(self) -> "LocalGeoIPProvider":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def lookup(self, ip: str) -> GeoLocationData:
        """Lookup geolocation for an observed IP address.

        Semantic rule: Geolocation reflects OBSERVED INFRASTRUCTURE location,
        not physical attacker location.
        """
        if not ip or not isinstance(ip, str):
            return GeoLocationData(status="invalid_input")

        clean_ip = ip.strip()
        if not clean_ip:
            return GeoLocationData(status="invalid_input")

        # Syntactic IP validation
        try:
            ipaddress.ip_address(clean_ip)
        except ValueError:
            return GeoLocationData(
                status="invalid_input",
                semantic_note="Observed infrastructure geolocation, NOT human attacker physical location.",
            )

        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Real MMDB reader lookup
        if self.is_db_available and self._reader is not None:
            try:
                record = self._reader.get(clean_ip)
                if record is not None and isinstance(record, dict):
                    country_dict = record.get("country") or {}
                    country_names = country_dict.get("names") or {}
                    country = country_names.get("en") or country_dict.get("name")
                    country_code = country_dict.get("iso_code")

                    subdivisions = record.get("subdivisions") or []
                    region = None
                    if subdivisions and isinstance(subdivisions, list) and len(subdivisions) > 0:
                        first_sub = subdivisions[0]
                        if isinstance(first_sub, dict):
                            sub_names = first_sub.get("names") or {}
                            region = sub_names.get("en") or first_sub.get("iso_code")

                    city_dict = record.get("city") or {}
                    city_names = city_dict.get("names") or {}
                    city = city_names.get("en") or city_dict.get("name")

                    loc_dict = record.get("location") or {}
                    lat = loc_dict.get("latitude")
                    lon = loc_dict.get("longitude")
                    lat_float = float(lat) if lat is not None else None
                    lon_float = float(lon) if lon is not None else None
                    tz = loc_dict.get("time_zone")
                    acc_radius = loc_dict.get("accuracy_radius")
                    acc_float = float(acc_radius) if acc_radius is not None else None

                    return GeoLocationData(
                        status="available",
                        country=str(country) if country else None,
                        country_code=str(country_code) if country_code else None,
                        region=str(region) if region else None,
                        city=str(city) if city else None,
                        latitude=lat_float,
                        longitude=lon_float,
                        timezone=str(tz) if tz else None,
                        accuracy_radius_km=acc_float,
                        source_dataset="DB-IP Lite",
                        dataset_name=self._db_type or "DBIP-City-Lite",
                        dataset_date=self._db_date,
                        lookup_timestamp=now_iso,
                        semantic_note="Observed infrastructure geolocation, NOT human attacker physical location.",
                        observed_infrastructure_geolocation=True,
                    )

                # Real DB queried but IP not found in database
                if self._custom_lookup and clean_ip in self._custom_lookup:
                    info = self._custom_lookup[clean_ip]
                    return GeoLocationData(
                        status="available",
                        country=str(info.get("country")) if info.get("country") else None,
                        country_code=str(info.get("country_code")) if info.get("country_code") else None,
                        region=str(info.get("region")) if info.get("region") else None,
                        city=str(info.get("city")) if info.get("city") else None,
                        latitude=float(info["latitude"]) if "latitude" in info else None,
                        longitude=float(info["longitude"]) if "longitude" in info else None,
                        timezone=str(info.get("timezone")) if info.get("timezone") else None,
                        source_dataset="test_fixture",
                        dataset_name="test_fixture",
                        dataset_date=self._db_date,
                        lookup_timestamp=now_iso,
                        semantic_note="Observed infrastructure geolocation, NOT human attacker physical location.",
                        observed_infrastructure_geolocation=True,
                    )

                return GeoLocationData(
                    status="not_found",
                    source_dataset="DB-IP Lite",
                    dataset_name=self._db_type or "DBIP-City-Lite",
                    dataset_date=self._db_date,
                    lookup_timestamp=now_iso,
                    semantic_note="Observed infrastructure geolocation, NOT human attacker physical location.",
                )
            except Exception:
                return GeoLocationData(
                    status="unavailable",
                    source_dataset="DB-IP Lite",
                    semantic_note="Observed infrastructure geolocation, NOT human attacker physical location.",
                )

        # 2. Database unavailable: check explicit test fixture if configured
        if self._custom_lookup and clean_ip in self._custom_lookup:
            info = self._custom_lookup[clean_ip]
            return GeoLocationData(
                status="available",
                country=str(info.get("country")) if info.get("country") else None,
                country_code=str(info.get("country_code")) if info.get("country_code") else None,
                region=str(info.get("region")) if info.get("region") else None,
                city=str(info.get("city")) if info.get("city") else None,
                latitude=float(info["latitude"]) if "latitude" in info else None,
                longitude=float(info["longitude"]) if "longitude" in info else None,
                timezone=str(info.get("timezone")) if info.get("timezone") else None,
                source_dataset="test_fixture",
                semantic_note="Observed infrastructure geolocation, NOT human attacker physical location.",
                observed_infrastructure_geolocation=True,
            )

        return GeoLocationData(
            status="unavailable",
            source_dataset="none",
            semantic_note="Observed infrastructure geolocation, NOT human attacker physical location.",
        )
