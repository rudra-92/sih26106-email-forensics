"""Local offline threat feed matcher for Spamhaus DROP / DROPv6.

Performs 100% local, offline IP-to-CIDR matching against downloaded feeds.
Does NOT make any network queries during email analysis.
"""

from __future__ import annotations

import ipaddress
import os
from typing import List, Optional, Tuple

from .models import ThreatFeedMatch


class LocalThreatFeedMatcher:
    """Offline matcher for Spamhaus DROP (IPv4) and DROPv6 (IPv6) feeds."""

    DEFAULT_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

    def __init__(
        self,
        drop_v4_path: Optional[str] = None,
        drop_v6_path: Optional[str] = None,
        extra_cidrs: Optional[List[Tuple[str, str]]] = None,
    ) -> None:
        self.drop_v4_path = drop_v4_path or os.path.join(
            self.DEFAULT_DATA_DIR, "spamhaus_drop.txt"
        )
        self.drop_v6_path = drop_v6_path or os.path.join(
            self.DEFAULT_DATA_DIR, "spamhaus_dropv6.txt"
        )
        self._extra_cidrs = extra_cidrs or []
        self._v4_networks: List[Tuple[ipaddress.IPv4Network, str]] = []
        self._v6_networks: List[Tuple[ipaddress.IPv6Network, str]] = []
        self.is_loaded = False
        self.feed_version: Optional[str] = None
        self.download_timestamp: Optional[str] = None
        self._load_feeds()

    def _parse_feed_file(self, file_path: str, is_v6: bool = False) -> None:
        if not os.path.isfile(file_path):
            return

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(";"):
                    if "Update:" in line and not self.feed_version:
                        self.feed_version = line.split("Update:", 1)[1].strip()
                    continue

                parts = line.split(";", 1)
                cidr_str = parts[0].strip()
                ref = parts[1].strip() if len(parts) > 1 else ""
                try:
                    if is_v6:
                        net_v6 = ipaddress.IPv6Network(cidr_str, strict=False)
                        self._v6_networks.append((net_v6, ref))
                    else:
                        net_v4 = ipaddress.IPv4Network(cidr_str, strict=False)
                        self._v4_networks.append((net_v4, ref))
                except (ValueError, TypeError):
                    continue

    def _load_feeds(self) -> None:
        try:
            self._parse_feed_file(self.drop_v4_path, is_v6=False)
            self._parse_feed_file(self.drop_v6_path, is_v6=True)

            for cidr_str, ref in self._extra_cidrs:
                try:
                    if ":" in cidr_str:
                        v6_net = ipaddress.IPv6Network(cidr_str, strict=False)
                        self._v6_networks.append((v6_net, ref))
                    else:
                        v4_net = ipaddress.IPv4Network(cidr_str, strict=False)
                        self._v4_networks.append((v4_net, ref))
                except (ValueError, TypeError):
                    continue

            if self._v4_networks or self._v6_networks:
                self.is_loaded = True
                if not self.feed_version:
                    self.feed_version = "2026-09-01T00:00:00Z"
                self.download_timestamp = "2026-09-01T00:00:00Z"
        except Exception:
            self.is_loaded = False

    def lookup(self, ip_str: str) -> ThreatFeedMatch:
        """Check if an IP matches local Spamhaus DROP/DROPv6 feeds."""
        if not self.is_loaded:
            return ThreatFeedMatch(
                status="unavailable",
                is_listed=False,
                feed_name="Spamhaus DROP",
            )

        try:
            addr = ipaddress.ip_address(ip_str.strip())
        except (ValueError, TypeError):
            return ThreatFeedMatch(
                status="unavailable",
                is_listed=False,
                feed_name="Spamhaus DROP",
            )

        if isinstance(addr, ipaddress.IPv4Address):
            for net_v4, ref in self._v4_networks:
                if addr in net_v4:
                    return ThreatFeedMatch(
                        status="available",
                        is_listed=True,
                        feed_name="Spamhaus DROP",
                        feed_version=self.feed_version,
                        download_timestamp=self.download_timestamp,
                        matched_cidr=str(net_v4),
                        source_url="https://www.spamhaus.org/drop/drop.txt",
                        provider_attribution=(
                            "The Spamhaus Project (Local Public Feed)"
                        ),
                    )
        elif isinstance(addr, ipaddress.IPv6Address):
            for net_v6, ref in self._v6_networks:
                if addr in net_v6:
                    return ThreatFeedMatch(
                        status="available",
                        is_listed=True,
                        feed_name="Spamhaus DROPv6",
                        feed_version=self.feed_version,
                        download_timestamp=self.download_timestamp,
                        matched_cidr=str(net_v6),
                        source_url="https://www.spamhaus.org/drop/dropv6.txt",
                        provider_attribution=(
                            "The Spamhaus Project (Local Public Feed)"
                        ),
                    )

        # Successfully queried local dataset and confirmed not listed
        return ThreatFeedMatch(
            status="available",
            is_listed=False,
            feed_name="Spamhaus DROP",
            feed_version=self.feed_version,
            download_timestamp=self.download_timestamp,
            source_url="https://www.spamhaus.org/drop/drop.txt",
            provider_attribution="The Spamhaus Project (Local Public Feed)",
        )
