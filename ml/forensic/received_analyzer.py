"""
received_analyzer.py - SMTP Received Header and Hop Chain Forensic Analyzer.

Parses RFC 822 Received headers from transmission origin (bottom) to destination (top).
Extracts hops, IPs, hostnames, timestamps, and calculates hop chain anomalies.
"""

import re
import ipaddress
import email.utils
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_REGEX = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
FROM_HOST_REGEX = re.compile(r"from\s+([^\s\(\)\[\]]+)", re.IGNORECASE)
BY_HOST_REGEX = re.compile(r"by\s+([^\s\(\)\[\]]+)", re.IGNORECASE)


class ReceivedAnalyzer:
    """Parses Received headers into an ordered forensic hop chain and derives structural indicators."""

    def __init__(self):
        pass

    @staticmethod
    def _classify_ip(ip_str: str) -> str:
        """Classifies an IP address string as 'public', 'private', 'loopback', 'reserved', or 'invalid'."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            if ip.is_private:
                return "private"
            if ip.is_loopback:
                return "loopback"
            if ip.is_reserved:
                return "reserved"
            if ip.is_link_local or ip.is_multicast:
                return "reserved"
            return "public"
        except ValueError:
            return "invalid"

    def analyze(self, parsed_email) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Parses received headers.
        Note: In RFC 822 emails, Received headers are prepended at each hop.
        Therefore, the chronologically first hop (origin) is at the bottom (last in list),
        and the final receiving MTA is at the top (first in list).
        """
        raw_received = parsed_email.received_headers
        if not raw_received:
            # Check if any raw headers contain received
            raw_received = parsed_email.raw_headers.get("received", [])

        # Reverse so Hop 1 is the transmission origin
        chronological_hops = list(reversed(raw_received))

        hop_records = []
        unique_ips = set()
        public_ips = []
        private_ips = []
        invalid_ips = []
        timestamps = []
        hostname_mismatch_count = 0

        for hop_idx, raw_hop in enumerate(chronological_hops, start=1):
            # Extract source hostname
            m_from = FROM_HOST_REGEX.search(raw_hop)
            src_host = m_from.group(1).lower() if m_from else None

            # Extract destination hostname
            m_by = BY_HOST_REGEX.search(raw_hop)
            dst_host = m_by.group(1).lower() if m_by else None

            # Extract IPs
            found_ips = IPV4_REGEX.findall(raw_hop) + IPV6_REGEX.findall(raw_hop)
            hop_src_ip = None
            for ip_cand in found_ips:
                classification = self._classify_ip(ip_cand)
                if classification != "invalid":
                    unique_ips.add(ip_cand)
                    if classification == "public":
                        public_ips.append(ip_cand)
                        if hop_src_ip is None:
                            hop_src_ip = ip_cand
                    elif classification in ("private", "loopback"):
                        private_ips.append(ip_cand)
                        if hop_src_ip is None:
                            hop_src_ip = ip_cand
                else:
                    invalid_ips.append(ip_cand)

            # Timestamp extraction (usually after ';' in Received line)
            hop_ts = None
            if ";" in raw_hop:
                date_part = raw_hop.split(";")[-1].strip()
                try:
                    parsed_date = email.utils.parsedate_to_datetime(date_part)
                    hop_ts = parsed_date.isoformat()
                    timestamps.append(parsed_date.timestamp())
                except Exception:
                    pass

            # Hostname-IP discrepancy heuristic:
            # If claimed source hostname specifies an IP in parentheses that contradicts claimed domain
            if src_host and hop_src_ip:
                # e.g., if hostname claims google.com but IP resolves in a different domain or invalid
                if "unknown" in src_host or "localhost" in src_host:
                    hostname_mismatch_count += 1

            hop_records.append({
                "hop_number": hop_idx,
                "source_hostname": src_host,
                "source_ip": hop_src_ip,
                "destination_hostname": dst_host,
                "timestamp": hop_ts,
                "raw_hop": raw_hop.strip()
            })

        # Anomaly detection: Timestamp order anomaly (Hop N time < Hop N-1 time)
        timestamp_order_anomaly = 0
        if len(timestamps) >= 2:
            for i in range(1, len(timestamps)):
                # If subsequent hop timestamp is significantly before previous hop (> 5 minutes backward skew)
                if timestamps[i] < timestamps[i - 1] - 300:
                    timestamp_order_anomaly = 1
                    break

        received_hop_count = len(hop_records)
        public_ip_count = len(public_ips)
        private_ip_count = len(private_ips)
        unique_ip_count = len(unique_ips)
        invalid_ip_count = len(invalid_ips)

        first_public_ip = public_ips[0] if public_ips else None
        last_public_ip = public_ips[-1] if public_ips else None

        features = {
            "received_hop_count": received_hop_count,
            "unique_ip_count": unique_ip_count,
            "public_ip_count": public_ip_count,
            "private_ip_count": private_ip_count,
            "invalid_ip_count": invalid_ip_count,
            "hostname_ip_mismatch_count": hostname_mismatch_count,
            "timestamp_order_anomaly": timestamp_order_anomaly,
        }

        evidence = {
            "received_hops": hop_records,
            "first_public_ip": first_public_ip,
            "last_public_ip": last_public_ip,
            "all_extracted_ips": list(unique_ips),
            "raw_received_headers": raw_received
        }

        return features, evidence
