"""Email parser for sender identity, authentication, and routing forensics.

Extracts identity headers, authentication results (SPF, DKIM, DMARC),
routing chain (Received hops) with explicit peer/receiver IP roles,
IPv4/IPv6 addresses, and cryptographic hash using Python's standard library.
"""

from email import message_from_bytes, policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import parseaddr
import hashlib
import ipaddress
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .models import AuthResults, ParsedEmailEvidence, ReceivedHop


class SenderIdentityParser:
    """Forensic parser for .eml files producing structured identity evidence."""

    # Regex to capture IPv4 candidates
    IPV4_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
    )

    # Regex patterns for IPv6 candidates:
    # 1. Bracketed or IPv6-prefixed: [IPv6:...], [2001:...], IPv6: 2001:...
    # 2. Tokenized hex strings with at least 2 colons
    IPV6_BRACKET_PATTERN = re.compile(
        r"\[(?:IPv6:)?\s*([0-9a-fA-F:]+)\]", re.IGNORECASE
    )
    IPV6_TOKEN_PATTERN = re.compile(
        r"(?:IPv6:\s*)?([0-9a-fA-F]{1,4}(?:::[0-9a-fA-F]{1,4}|(?::[0-9a-fA-F]{1,4}){2,7}|::|:(?:[0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4}))"
    )

    def __init__(self) -> None:
        pass

    def parse(self, eml_input: Union[bytes, str, Path]) -> ParsedEmailEvidence:
        """Parse raw email content and extract structured identity & routing evidence.

        Args:
            eml_input: Raw bytes, string content, or Path to .eml file.

        Returns:
            ParsedEmailEvidence containing all extracted identity artifacts.
        """
        raw_bytes = self._read_bytes(eml_input)
        file_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Parse message without altering original bytes
        msg = message_from_bytes(raw_bytes, policy=policy.default)

        # Extract primary identity headers
        from_raw = msg.get("From")
        to_raw = msg.get("To")
        reply_to_raw = msg.get("Reply-To")
        return_path_raw = msg.get("Return-Path")
        message_id = msg.get("Message-ID")

        # Derive identity fields
        display_name, sender_address, sender_domain = self._parse_address_field(from_raw)
        _, reply_to_address, reply_to_domain = self._parse_address_field(reply_to_raw)
        _, return_path_address, return_path_domain = self._parse_address_field(return_path_raw)
        clean_msg_id, message_id_domain = self._parse_message_id(message_id)

        # Parse authentication headers
        auth_results = self._parse_authentication_results(msg)

        # Parse received routing headers preserving original sequence & IP roles
        received_hops = self._parse_received_headers(msg)

        return ParsedEmailEvidence(
            file_hash_sha256=file_hash,
            message_id=clean_msg_id,
            message_id_domain=message_id_domain,
            from_raw=str(from_raw) if from_raw else None,
            to_raw=str(to_raw) if to_raw else None,
            reply_to_raw=str(reply_to_raw) if reply_to_raw else None,
            return_path_raw=str(return_path_raw) if return_path_raw else None,
            display_name=display_name,
            sender_address=sender_address,
            sender_domain=sender_domain,
            reply_to_address=reply_to_address,
            reply_to_domain=reply_to_domain,
            return_path_address=return_path_address,
            return_path_domain=return_path_domain,
            auth_results=auth_results,
            received_hops=received_hops,
        )

    def _read_bytes(self, eml_input: Union[bytes, str, Path]) -> bytes:
        """Convert input to raw bytes without mutation."""
        if isinstance(eml_input, bytes):
            return eml_input
        if isinstance(eml_input, Path):
            return eml_input.read_bytes()
        if isinstance(eml_input, str):
            try:
                p = Path(eml_input)
                if p.is_file():
                    return p.read_bytes()
            except OSError:
                pass
            return eml_input.encode("utf-8", errors="surrogateescape")
        raise TypeError(f"Unsupported eml_input type: {type(eml_input)}")

    def _decode_header_str(self, header_val: Optional[str]) -> Optional[str]:
        """Safely decode RFC 2047 encoded header strings."""
        if not header_val:
            return None
        try:
            return str(make_header(decode_header(str(header_val))))
        except Exception:
            return str(header_val).strip()

    def _parse_address_field(
        self, header_val: Optional[Any]
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Parse display name, email address, and domain from an address header.

        Returns:
            Tuple of (display_name, email_address, domain)
        """
        if not header_val:
            return None, None, None

        header_str = self._decode_header_str(str(header_val))
        if not header_str:
            return None, None, None

        name, addr = parseaddr(header_str)
        name = name.strip().strip('"').strip("'") if name else None
        addr = addr.strip().lower() if addr else None

        domain: Optional[str] = None
        if addr and "@" in addr:
            domain = addr.split("@", 1)[1].strip().lower()

        return (name if name else None), (addr if addr else None), domain

    def _parse_message_id(self, message_id_val: Optional[Any]) -> Tuple[Optional[str], Optional[str]]:
        """Extract clean Message-ID and its domain."""
        if not message_id_val:
            return None, None

        msg_id_str = str(message_id_val).strip()
        match = re.search(r"<([^>]+)>", msg_id_str)
        clean_id = match.group(1) if match else msg_id_str

        domain: Optional[str] = None
        if "@" in clean_id:
            domain = clean_id.split("@", 1)[1].strip().lower()

        return clean_id, domain

    def _parse_authentication_results(self, msg: EmailMessage) -> AuthResults:
        """Parse Authentication-Results and Received-SPF headers."""
        auth = AuthResults()
        auth_headers = msg.get_all("Authentication-Results", [])
        received_spf_headers = msg.get_all("Received-SPF", [])

        all_headers: List[str] = []
        details: Dict[str, Any] = {}

        # 1. Parse Authentication-Results headers (RFC 8601 / RFC 7601)
        for header in auth_headers:
            h_str = str(header)
            all_headers.append(h_str)

            # SPF result
            spf_match = re.search(
                r"\bspf\s*=\s*([a-zA-Z]+)(?:\s+\(([^)]*)\))?", h_str, re.IGNORECASE
            )
            if spf_match and not auth.spf:
                auth.spf = spf_match.group(1).lower()
                if spf_match.group(2):
                    details["spf_comment"] = spf_match.group(2)

            # SPF domain/mailfrom
            spf_domain_match = re.search(
                r"smtp\.(?:mailfrom|helo)\s*=\s*([^\s;()]+)", h_str, re.IGNORECASE
            )
            if spf_domain_match and not auth.spf_domain:
                val = spf_domain_match.group(1).strip()
                if "@" in val:
                    auth.spf_domain = val.split("@", 1)[1].lower()
                else:
                    auth.spf_domain = val.lower()

            # DKIM result
            dkim_match = re.search(
                r"\bdkim\s*=\s*([a-zA-Z]+)(?:\s+\(([^)]*)\))?", h_str, re.IGNORECASE
            )
            if dkim_match and not auth.dkim:
                auth.dkim = dkim_match.group(1).lower()
                if dkim_match.group(2):
                    details["dkim_comment"] = dkim_match.group(2)

            # DKIM signing domain (header.d or header.i)
            dkim_domain_match = re.search(
                r"header\.(?:d|i)\s*=\s*@?([^\s;()]+)", h_str, re.IGNORECASE
            )
            if dkim_domain_match and not auth.dkim_domain:
                auth.dkim_domain = dkim_domain_match.group(1).strip().lower()

            # DMARC result
            dmarc_match = re.search(
                r"\bdmarc\s*=\s*([a-zA-Z]+)(?:\s+\(([^)]*)\))?", h_str, re.IGNORECASE
            )
            if dmarc_match and not auth.dmarc:
                auth.dmarc = dmarc_match.group(1).lower()
                if dmarc_match.group(2):
                    details["dmarc_comment"] = dmarc_match.group(2)

            # DMARC header.from
            dmarc_domain_match = re.search(
                r"header\.from\s*=\s*([^\s;()]+)", h_str, re.IGNORECASE
            )
            if dmarc_domain_match and not auth.dmarc_domain:
                auth.dmarc_domain = dmarc_domain_match.group(1).strip().lower()

        # 2. Fallback to Received-SPF headers if SPF was not in Authentication-Results
        for r_spf in received_spf_headers:
            h_str = str(r_spf)
            all_headers.append(f"Received-SPF: {h_str}")
            if not auth.spf:
                spf_match = re.match(r"^\s*([a-zA-Z]+)", h_str)
                if spf_match:
                    auth.spf = spf_match.group(1).lower()
            if not auth.spf_domain:
                spf_domain_match = re.search(
                    r"(?:envelope-from|identity=mailfrom|domain of)\s+<?(?:[^@\s]+@)?([a-zA-Z0-9.\-]+)>?",
                    h_str,
                    re.IGNORECASE,
                )
                if spf_domain_match:
                    auth.spf_domain = spf_domain_match.group(1).strip().lower()

        auth.raw_headers = all_headers
        auth.details = details
        return auth

    def _parse_received_headers(self, msg: EmailMessage) -> List[ReceivedHop]:
        """Extract all Received headers preserving original order and distinguishing IP roles."""
        raw_received = msg.get_all("Received", [])
        hops: List[ReceivedHop] = []

        for idx, header_val in enumerate(raw_received):
            hop_raw = str(header_val)
            from_host, from_ip, by_host, by_ip, other_ips, timestamp = (
                self._parse_single_received_header(hop_raw)
            )

            hops.append(
                ReceivedHop(
                    hop_index=idx,
                    raw_header=hop_raw,
                    from_host=from_host,
                    from_ip=from_ip,
                    by_host=by_host,
                    by_ip=by_ip,
                    other_ips=other_ips,
                    timestamp=timestamp,
                )
            )

        return hops

    def _parse_single_received_header(
        self, received_str: str
    ) -> Tuple[
        Optional[str],
        Optional[str],
        Optional[str],
        Optional[str],
        List[str],
        Optional[str],
    ]:
        """Parse structured hop details with role distinction between from_ip and by_ip.

        Returns:
            (from_host, from_ip, by_host, by_ip, other_ips, timestamp)
        """
        # 1. Extract timestamp if present after last semicolon
        routing_part = received_str
        timestamp: Optional[str] = None
        if ";" in received_str:
            parts = received_str.rsplit(";", 1)
            candidate_ts = parts[1].strip()
            if any(char.isdigit() for char in candidate_ts):
                timestamp = candidate_ts
                routing_part = parts[0]

        # 2. Extract 'from' clause and 'by' clause
        from_host: Optional[str] = None
        from_ip: Optional[str] = None
        by_host: Optional[str] = None
        by_ip: Optional[str] = None

        from_match = re.search(
            r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|\s+for\s+|$)",
            routing_part,
            re.IGNORECASE | re.DOTALL,
        )
        by_match = re.search(
            r"\bby\s+(.+?)(?=\s+with\s+|\s+id\s+|\s+for\s+|$)",
            routing_part,
            re.IGNORECASE | re.DOTALL,
        )

        if from_match:
            from_clause = from_match.group(1).strip()
            # Hostname is first token
            h_match = re.match(r"([^\s();]+)", from_clause)
            if h_match:
                from_host = h_match.group(1).strip()
            # peer_ip: upstream sending IP observed by receiving server
            from_ips = self.extract_ips(from_clause)
            if from_ips:
                from_ip = from_ips[0]

        if by_match:
            by_clause = by_match.group(1).strip()
            # Hostname is first token
            h_match = re.match(r"([^\s();]+)", by_clause)
            if h_match:
                by_host = h_match.group(1).strip()
            # receiver_ip: receiving server IP
            by_ips = self.extract_ips(by_clause)
            if by_ips:
                by_ip = by_ips[0]

        # Fallback if hosts were not extracted by clause regex
        if not from_host:
            fh_match = re.search(r"\bfrom\s+([^\s();]+)", routing_part, re.IGNORECASE)
            if fh_match:
                from_host = fh_match.group(1).strip()
        if not by_host:
            bh_match = re.search(r"\bby\s+([^\s();]+)", routing_part, re.IGNORECASE)
            if bh_match:
                by_host = bh_match.group(1).strip()

        # All discovered IPs in this hop
        all_hop_ips = self.extract_ips(received_str)
        assigned = {from_ip, by_ip} - {None}
        other_ips = [ip for ip in all_hop_ips if ip not in assigned]

        return from_host, from_ip, by_host, by_ip, other_ips, timestamp

    def extract_ips(self, text: str) -> List[str]:
        """Extract and validate all IPv4 and IPv6 addresses from header text.

        Preserves discovery order and ensures no duplicates within the same hop.
        """
        discovered: List[str] = []
        seen: Set[str] = set()

        def _add_ip(ip_str: str) -> None:
            try:
                parsed = ipaddress.ip_address(ip_str.strip())
                canonical = str(parsed)
                if canonical not in seen:
                    seen.add(canonical)
                    discovered.append(canonical)
            except ValueError:
                pass

        # 1. Bracketed or prefixed IPv6 extraction (e.g. [IPv6:2001:db8::1], [2001:db8::1])
        for match in self.IPV6_BRACKET_PATTERN.finditer(text):
            _add_ip(match.group(1))

        # 2. Free-text IPv6 token matches
        for match in self.IPV6_TOKEN_PATTERN.finditer(text):
            candidate = match.group(1).strip()
            if candidate.count(":") >= 2:
                _add_ip(candidate)

        # 3. IPv4 pattern matches
        for match in self.IPV4_PATTERN.finditer(text):
            _add_ip(match.group(0))

        return discovered
