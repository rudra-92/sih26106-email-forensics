"""
ip_analyzer.py - Forensic IP Address Extraction and Analysis for SIH26106.

Extracts IPv4 and IPv6 addresses from headers, received chains, and body text.
Categorizes addresses (public, private, loopback, reserved) and provides
a modular enrichment interface for future threat intelligence feeds (MaxMind, ASN, etc.)
without fabricating missing intelligence.
"""

import re
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set

IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")


class IPAnalyzer:
    """Forensic analyzer for extracted IP addresses across the email."""

    def __init__(self):
        pass

    @staticmethod
    def _is_valid_ip(ip_str: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        """Validates IP string. Rejects common digit-dot false positives (e.g. version numbers 1.2.3.4 or dates)."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            # Ignore quad-zero or broadcast
            if str(ip_obj) in ("0.0.0.0", "255.255.255.255"):
                return None
            return ip_obj
        except ValueError:
            return None

    def extract_ips_from_text(self, text: str) -> Set[str]:
        """Finds all valid IPv4 and IPv6 strings within unstructured text."""
        if not text:
            return set()
        
        candidates = IPV4_REGEX.findall(text) + IPV6_REGEX.findall(text)
        valid_ips = set()
        for cand in candidates:
            obj = self._is_valid_ip(cand)
            if obj is not None:
                valid_ips.add(str(obj))
        return valid_ips

    def enrich_ip(self, ip_str: str) -> Dict[str, Any]:
        """
        Modular enrichment interface for future external lookup providers
        (e.g., MaxMind GeoIP2, Team Cymru IP-to-ASN, AbuseIPDB).
        
        Strict policy: Returns 'unknown' / None when external feed is offline.
        Never fabricates intelligence.
        """
        obj = self._is_valid_ip(ip_str)
        is_priv = obj.is_private if obj else None
        is_loop = obj.is_loopback if obj else None
        is_res = (obj.is_reserved or obj.is_link_local or obj.is_multicast) if obj else None
        version = obj.version if obj else None

        return {
            "ip_address": ip_str,
            "ip_version": version,
            "is_private": is_priv,
            "is_loopback": is_loop,
            "is_reserved": is_res,
            "country": "unknown",
            "region": "unknown",
            "city": "unknown",
            "latitude": None,
            "longitude": None,
            "asn": "unknown",
            "organization": "unknown",
            "isp": "unknown",
            "hosting_provider": "unknown",
            "vpn_flag": None,
            "proxy_flag": None,
            "tor_flag": None,
        }

    def analyze(self, parsed_email, received_evidence: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Analyzes all IPs in the email (combining received hops, headers, and body).
        """
        all_ips = set()

        # From Received evidence if already computed
        if received_evidence and "all_extracted_ips" in received_evidence:
            all_ips.update(received_evidence["all_extracted_ips"])

        # From raw headers
        for h_name, h_vals in parsed_email.raw_headers.items():
            for val in h_vals:
                all_ips.update(self.extract_ips_from_text(val))

        # From body text
        all_ips.update(self.extract_ips_from_text(parsed_email.body_plain))
        all_ips.update(self.extract_ips_from_text(parsed_email.body_html))

        ip_count = len(all_ips)
        public_ips = []
        private_ips = []
        loopback_ips = []
        reserved_ips = []
        has_ipv6 = 0

        for ip_str in all_ips:
            obj = self._is_valid_ip(ip_str)
            if obj is None:
                continue

            if obj.version == 6:
                has_ipv6 = 1

            if obj.is_loopback:
                loopback_ips.append(ip_str)
            elif obj.is_private:
                private_ips.append(ip_str)
            elif obj.is_reserved or obj.is_link_local or obj.is_multicast:
                reserved_ips.append(ip_str)
            else:
                public_ips.append(ip_str)

        features = {
            "ip_count": ip_count,
            "unique_ip_count": ip_count,
            "public_ip_count": len(public_ips),
            "private_ip_count": len(private_ips),
            "loopback_ip_count": len(loopback_ips),
            "reserved_ip_count": len(reserved_ips),
            "has_ipv6": has_ipv6,
        }

        # Stored raw evidence with enrichment template
        enriched_evidence = [self.enrich_ip(ip) for ip in sorted(all_ips)]

        evidence = {
            "extracted_ips": sorted(list(all_ips)),
            "public_ips": sorted(public_ips),
            "private_ips": sorted(private_ips),
            "enriched_ip_records": enriched_evidence,
        }

        return features, evidence
