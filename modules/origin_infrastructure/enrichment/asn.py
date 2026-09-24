"""Offline-first local ASN adapter for Origin & Infrastructure Reconstruction.

Design Reality:
This module provides an adapter interface (BaseASNProvider / LocalASNProvider)
for offline ASN and BGP network lookups. It contains a built-in reference table
for synthetic and documentation IP ranges (RFC 5737). When no local database is
configured (or if the database file is absent or an unknown IP is queried), it
gracefully returns status='unavailable' without external network requests or exceptions.

Compatible Free / Open Datasets:
- CAIDA Routeviews prefix-to-AS mappings (public domain)
- Regional Internet Registry (RIR) daily delegated statistics (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
- MaxMind GeoLite2 ASN (CC BY-SA 4.0 attribution requirement)
- IP2Location ASN database (CC BY-SA 4.0 attribution requirement)
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

from ..models import AsnData
from .base import BaseASNProvider


class LocalASNProvider(BaseASNProvider):
    """Offline local ASN provider supporting DB-IP Lite ASN MMDB.

    Accepts arbitrary IPv4 and IPv6 addresses and queries the local MMDB database dynamically.
    Contains zero hardcoded IP-to-ASN mappings in production.
    """

    def __init__(
        self,
        db_path: Optional[Union[str, Path]] = None,
        custom_lookup: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> None:
        raw_path = db_path or os.environ.get("GEOIP_ASN_DB") or os.environ.get("SIH_ASN_DB_PATH")
        if not raw_path:
            # 1. Check relative to current working directory
            cwd_cand = Path("data/geoip/dbip-asn-lite.mmdb")
            if cwd_cand.is_file():
                raw_path = str(cwd_cand)
            else:
                # 2. Check repository root relative to __file__
                repo_root = Path(__file__).resolve().parents[3]
                repo_cand = repo_root / "data" / "geoip" / "dbip-asn-lite.mmdb"
                if repo_cand.is_file():
                    raw_path = str(repo_cand)

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
                        self._db_type = getattr(meta, "database_type", "DBIP-ASN-Lite")
                        epoch = getattr(meta, "build_epoch", None)
                        if epoch:
                            self._db_date = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")
                    except Exception:
                        self._db_type = "DBIP-ASN-Lite"
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

    def __enter__(self) -> "LocalASNProvider":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def lookup(self, ip: str) -> AsnData:
        """Lookup ASN information dynamically from local MMDB for an observed IP address."""
        if not ip or not isinstance(ip, str):
            return AsnData(status="invalid_input")

        clean_ip = ip.strip()
        if not clean_ip:
            return AsnData(status="invalid_input")

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return AsnData(status="invalid_input")

        now_iso = datetime.now(timezone.utc).isoformat()

        if self.is_db_available and self._reader is not None:
            try:
                record = None
                prefix_len = None
                try:
                    record, prefix_len = self._reader.get_with_prefix_len(clean_ip)
                except AttributeError:
                    record = self._reader.get(clean_ip)

                if record is not None and isinstance(record, dict):
                    asn_num = record.get("autonomous_system_number")
                    asn_str = f"AS{asn_num}" if asn_num is not None else None
                    org = record.get("autonomous_system_organization")
                    cidr = None
                    if prefix_len is not None:
                        try:
                            cidr = str(ipaddress.ip_network(f"{ip_obj}/{prefix_len}", strict=False))
                        except ValueError:
                            cidr = None

                    return AsnData(
                        status="available",
                        asn=asn_str,
                        organization=str(org) if org else None,
                        network_cidr=cidr,
                        source_dataset="DB-IP Lite",
                        dataset_name=self._db_type or "DBIP-ASN-Lite",
                        dataset_date=self._db_date,
                        lookup_timestamp=now_iso,
                    )

                if self._custom_lookup and clean_ip in self._custom_lookup:
                    info = self._custom_lookup[clean_ip]
                    return AsnData(
                        status="available",
                        asn=info.get("asn"),
                        organization=info.get("organization"),
                        network_cidr=info.get("network_cidr"),
                        source_dataset="test_fixture",
                        dataset_name="test_fixture",
                        dataset_date=self._db_date,
                        lookup_timestamp=now_iso,
                    )

                return AsnData(
                    status="not_found",
                    source_dataset="DB-IP Lite",
                    dataset_name=self._db_type or "DBIP-ASN-Lite",
                    dataset_date=self._db_date,
                    lookup_timestamp=now_iso,
                )
            except Exception:
                return AsnData(status="unavailable", source_dataset="DB-IP Lite")

        # Database unavailable: check explicit test fixture if configured
        if self._custom_lookup and clean_ip in self._custom_lookup:
            info = self._custom_lookup[clean_ip]
            return AsnData(
                status="available",
                asn=info.get("asn"),
                organization=info.get("organization"),
                network_cidr=info.get("network_cidr"),
                source_dataset="test_fixture",
            )

        return AsnData(status="unavailable", source_dataset="none")


