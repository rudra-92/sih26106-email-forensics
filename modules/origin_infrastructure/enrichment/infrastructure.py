"""Offline-first local infrastructure classification provider for Origin & Infrastructure Reconstruction.

Identifies cloud hosting, VPN endpoints, proxy relays, and Tor exit nodes using
local offline reference datasets without external network requests.

Explicit constraint: Cloud hosting, VPN, proxy, or Tor indicators are contextual
network attributes and do NOT constitute proof of malicious behavior.
"""

import ipaddress
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Tuple, Union

from ..models import InfrastructureData
from .base import BaseInfrastructureProvider

# Known public enterprise mail and cloud gateway CIDR ranges
_KNOWN_CLOUD_RANGES: List[Tuple[str, str]] = [
    ("13.64.0.0/11", "Microsoft Azure"),
    ("52.96.0.0/12", "Microsoft 365"),
    ("54.240.0.0/18", "Amazon SES"),
    ("198.2.128.0/18", "SendGrid"),
]


class LocalInfrastructureProvider(BaseInfrastructureProvider):
    """Local offline infrastructure classification provider supporting local Tor exit feeds."""

    def __init__(
        self,
        cloud_ranges: Optional[List[Tuple[str, str]]] = None,
        tor_exit_ips: Optional[Set[str]] = None,
        vpn_ips: Optional[Set[str]] = None,
        tor_exit_list_path: Optional[Union[str, Path]] = None,
    ) -> None:
        raw_ranges = cloud_ranges if cloud_ranges is not None else _KNOWN_CLOUD_RANGES
        self._parsed_ranges: List[Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], str]] = []
        for cidr_str, provider in raw_ranges:
            try:
                net = ipaddress.ip_network(cidr_str, strict=False)
                self._parsed_ranges.append((net, provider))
            except ValueError:
                pass

        self._tor_feed_date: Optional[str] = None
        self._tor_list_available = False
        loaded_tor_ips: Set[str] = set()

        raw_tor_path = tor_exit_list_path or os.environ.get("TOR_EXIT_LIST_PATH")
        if not raw_tor_path:
            default_tor = Path("data/geoip/tor_exit_nodes.txt")
            if default_tor.is_file():
                raw_tor_path = str(default_tor)

        if raw_tor_path:
            p = Path(raw_tor_path)
            if p.is_file():
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            cleaned = line.strip()
                            if cleaned and not cleaned.startswith("#"):
                                loaded_tor_ips.add(cleaned)
                    self._tor_list_available = True
                    mtime = p.stat().st_mtime
                    self._tor_feed_date = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
                except Exception:
                    pass

        if tor_exit_ips is not None:
            self._tor_ips = set(tor_exit_ips) | loaded_tor_ips
            self._tor_list_available = True
        else:
            self._tor_ips = loaded_tor_ips

        self._vpn_ips = set(vpn_ips) if vpn_ips is not None else set()

    def lookup(self, ip: str) -> InfrastructureData:
        """Classify infrastructure type and detect anonymization indicators.

        Contextual rule: Cloud hosting, VPN, proxy, or Tor indicators are transport
        attributes and do NOT constitute proof of malicious intent.
        """
        if not ip or not isinstance(ip, str):
            return InfrastructureData(tor_exit_indicator="unknown")

        try:
            clean_ip = ip.strip()
            is_tor = clean_ip in self._tor_ips
            is_vpn = clean_ip in self._vpn_ips
            is_proxy = is_vpn or is_tor  # Tor/VPN act as proxying layers

            # Tor exit indicator: true / false / unknown
            if is_tor:
                tor_exit_indicator = "true"
            elif self._tor_list_available:
                tor_exit_indicator = "false"
            else:
                tor_exit_indicator = "unknown"

            is_hosting = False
            provider_name = None

            # Check CIDR cloud ranges
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
                for net, prov in self._parsed_ranges:
                    if ip_obj in net:
                        is_hosting = True
                        provider_name = prov
                        break
            except ValueError:
                pass

            # Determine contextual classification
            classification = "unknown"
            if is_tor:
                classification = "tor_indicator"
            elif is_vpn:
                classification = "vpn_indicator"
            elif is_hosting:
                if provider_name and any(m in provider_name.lower() for m in ("google", "microsoft", "ses", "sendgrid")):
                    classification = "mail_provider"
                else:
                    classification = "cloud_hosting"
            else:
                classification = "direct_origin"

            return InfrastructureData(
                is_hosting=is_hosting,
                is_proxy=is_proxy,
                is_vpn=is_vpn,
                is_tor=is_tor,
                provider_name=provider_name,
                classification=classification,
                tor_exit_indicator=tor_exit_indicator,
                tor_feed_date=self._tor_feed_date,
            )
        except Exception:
            return InfrastructureData(tor_exit_indicator="unknown")

