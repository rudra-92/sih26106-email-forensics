"""Received header parser for Origin & Infrastructure Reconstruction Engine.

Parses RFC 5321 / RFC 5322 Received headers into structured HopParsedFields and
ParsedReceivedHop objects, extracting sender/receiver hostnames, IPv4/IPv6 addresses,
transport protocols, TLS ciphers, envelope IDs/recipients, and raw timestamps.

Preserves exact raw evidence and tolerates malformed or partially formatted headers.
"""

from email.message import EmailMessage, Message
import ipaddress
import re
from typing import Any, List, Optional, Set, Union

from .models import HopParsedFields, ParsedReceivedHop

# Regex matching valid IPv4 addresses
_IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)

# Regex matching bracketed or prefixed IPv6 addresses
_IPV6_BRACKET_REGEX = re.compile(
    r"\[(?:IPv6:)?\s*([0-9a-fA-F:]+)\]", re.IGNORECASE
)

# Regex matching unbracketed IPv6 tokens with at least 2 colons
_IPV6_TOKEN_REGEX = re.compile(
    r"\b(?:IPv6:\s*)?([0-9a-fA-F]{1,4}(?:::[0-9a-fA-F]{1,4}|(?::[0-9a-fA-F]{1,4}){2,7}|::|:(?:[0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4}))\b"
)


_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("::/128"),
]


def is_private_ip(ip_str: Optional[str]) -> bool:
    """Determine whether an IP address is an internal/private LAN, loopback, or link-local address."""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return any(ip_obj in net for net in _INTERNAL_NETWORKS)
    except ValueError:
        return False


def extract_ips_from_text(text: str) -> List[str]:
    """Extract all valid unique IPv4 and IPv6 addresses from a text block."""
    found_ips: List[str] = []
    seen: Set[str] = set()

    # 1. Bracketed IPv6
    for match in _IPV6_BRACKET_REGEX.finditer(text):
        raw_candidate = match.group(1).strip()
        try:
            addr = str(ipaddress.ip_address(raw_candidate))
            if addr not in seen:
                seen.add(addr)
                found_ips.append(addr)
        except ValueError:
            pass

    # 2. IPv4
    for match in _IPV4_REGEX.finditer(text):
        raw_candidate = match.group(0).strip()
        try:
            addr = str(ipaddress.ip_address(raw_candidate))
            if addr not in seen:
                seen.add(addr)
                found_ips.append(addr)
        except ValueError:
            pass

    # 3. Unbracketed IPv6
    for match in _IPV6_TOKEN_REGEX.finditer(text):
        raw_candidate = match.group(1).strip()
        try:
            addr = str(ipaddress.ip_address(raw_candidate))
            if addr not in seen:
                seen.add(addr)
                found_ips.append(addr)
        except ValueError:
            pass

    return found_ips


class ReceivedHeaderParser:
    """Forensic parser for email Received headers."""

    def __init__(self) -> None:
        pass

    def parse_all(
        self,
        received_headers: Union[List[str], Message, EmailMessage, Any],
    ) -> List[ParsedReceivedHop]:
        """Parse all Received headers from a list or an EmailMessage.

        Args:
            received_headers: List of raw header strings, or an email.message.Message.

        Returns:
            List of ParsedReceivedHop objects with exact raw and decomposed fields.
        """
        raw_list: List[str] = []
        if isinstance(received_headers, (Message, EmailMessage)):
            raw_list = [str(h) for h in received_headers.get_all("Received", [])]
        elif isinstance(received_headers, list):
            raw_list = [str(h) for h in received_headers]
        elif isinstance(received_headers, str):
            raw_list = [received_headers]

        parsed_hops: List[ParsedReceivedHop] = []
        for idx, header_val in enumerate(raw_list):
            parsed_fields = self.parse_single(header_val)
            parsed_hops.append(
                ParsedReceivedHop(
                    hop_index=idx,
                    raw_received_header=header_val,
                    parsed_fields=parsed_fields,
                    source_header_ref=f"Received[{idx}]",
                )
            )

        return parsed_hops

    def parse_single(self, raw_header: str) -> HopParsedFields:
        """Parse a single Received header string tolerating malformed formatting."""
        clean_header = " ".join(raw_header.split())
        if not clean_header:
            return HopParsedFields(parser_confidence="low")

        # 1. Separate routing clauses from timestamp (timestamp follows the last semicolon)
        routing_part = clean_header
        timestamp_raw: Optional[str] = None
        timezone_raw: Optional[str] = None

        if ";" in clean_header:
            parts = clean_header.rsplit(";", 1)
            candidate_ts = parts[1].strip()
            # Verify candidate timestamp looks like a date/time (contains digit)
            if any(char.isdigit() for char in candidate_ts):
                timestamp_raw = candidate_ts
                routing_part = parts[0].strip()

                # Extract trailing timezone if present (e.g. +0000, -0500, UTC, EST)
                tz_match = re.search(r"([+-]\d{4}|[A-Z]{3,4})$", candidate_ts)
                if tz_match:
                    timezone_raw = tz_match.group(1)

        # 2. Extract 'from' clause
        from_host: Optional[str] = None
        from_ip: Optional[str] = None
        other_ips: List[str] = []

        from_match = re.search(
            r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|\s+for\s+|$)",
            routing_part,
            re.IGNORECASE,
        )
        if from_match:
            from_text = from_match.group(1).strip()
            # Hostname is first token
            h_match = re.match(r"([^\s();]+)", from_text)
            if h_match:
                candidate_h = h_match.group(1).strip()
                if candidate_h and candidate_h.lower() != "unknown":
                    from_host = candidate_h

            from_ips = extract_ips_from_text(from_text)
            if from_ips:
                from_ip = from_ips[0]
                other_ips.extend(from_ips[1:])

        # 3. Extract 'by' clause
        by_host: Optional[str] = None
        by_ip: Optional[str] = None

        by_match = re.search(
            r"\bby\s+(.+?)(?=\s+with\s+|\s+id\s+|\s+for\s+|$)",
            routing_part,
            re.IGNORECASE,
        )
        if by_match:
            by_text = by_match.group(1).strip()
            h_match = re.match(r"([^\s();]+)", by_text)
            if h_match:
                by_host = h_match.group(1).strip()

            by_ips = extract_ips_from_text(by_text)
            if by_ips:
                by_ip = by_ips[0]
                for ip in by_ips[1:]:
                    if ip not in other_ips and ip != from_ip:
                        other_ips.append(ip)

        # 4. Extract 'with' protocol & cipher clause
        with_protocol: Optional[str] = None
        tls_cipher: Optional[str] = None

        with_match = re.search(
            r"\bwith\s+(.+?)(?=\s+id\s+|\s+for\s+|$)",
            routing_part,
            re.IGNORECASE,
        )
        if with_match:
            with_text = with_match.group(1).strip()
            # First token is the protocol (e.g. ESMTP, ESMTPS, HTTP, SMTP)
            tokens = with_text.split()
            if tokens:
                with_protocol = tokens[0].upper()
            if "tls" in with_text.lower() or "cipher" in with_text.lower():
                tls_cipher = with_text

        # 5. Extract queue id
        id_param: Optional[str] = None
        id_match = re.search(
            r"\bid\s+([^\s;]+)",
            routing_part,
            re.IGNORECASE,
        )
        if id_match:
            id_param = id_match.group(1).strip()

        # 6. Extract envelope 'for' recipient
        for_envelope_to: Optional[str] = None
        for_match = re.search(
            r"\bfor\s+<([^>]+)>|\bfor\s+([^\s;]+)",
            routing_part,
            re.IGNORECASE,
        )
        if for_match:
            for_envelope_to = (for_match.group(1) or for_match.group(2) or "").strip()

        # 7. Collect any remaining IPs in the header
        all_remaining = extract_ips_from_text(routing_part)
        for ip in all_remaining:
            if ip != from_ip and ip != by_ip and ip not in other_ips:
                other_ips.append(ip)

        # 8. Check private IP status
        is_source_private = is_private_ip(from_ip) if from_ip else False
        is_receiver_private = is_private_ip(by_ip) if by_ip else False

        # 9. Evaluate parser confidence
        confidence = "high"
        if not from_host and not from_ip and not by_host:
            confidence = "low"
        elif not from_ip or not timestamp_raw:
            confidence = "medium"

        return HopParsedFields(
            from_host=from_host,
            from_ip=from_ip,
            by_host=by_host,
            by_ip=by_ip,
            with_protocol=with_protocol,
            tls_cipher=tls_cipher,
            id_param=id_param,
            for_envelope_to=for_envelope_to,
            timestamp_raw=timestamp_raw,
            timezone_raw=timezone_raw,
            parser_confidence=confidence,
            is_source_private=is_source_private,
            is_receiver_private=is_receiver_private,
            other_ips=other_ips,
        )
