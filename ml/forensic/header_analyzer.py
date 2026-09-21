"""
header_analyzer.py - Forensic Email Header Analysis for SIH26106.

Extracts header fields and derives measurable structural anomaly indicators:
- From, Reply-To, To, Cc, Subject, Date, Message-ID, Return-Path
- Sender and Reply-To domain decomposition
- Display name extraction and mismatch detection
- Missing field indicators (explicit binary/numerical signals)
"""

import re
import email.utils
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
from .domain_analyzer import get_base_domain

EMAIL_ADDRESS_REGEX = re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")


class HeaderAnalyzer:
    """Extracts forensic features from email headers."""

    def __init__(self):
        pass

    @staticmethod
    def _parse_address(addr_str: str) -> Tuple[str, str, str]:
        """
        Parses an address string into (display_name, email_address, domain).
        Example: 'John Doe <john@example.com>' -> ('John Doe', 'john@example.com', 'example.com')
        """
        if not addr_str or not addr_str.strip():
            return "", "", ""

        name, email_addr = email.utils.parseaddr(addr_str)
        email_addr = email_addr.strip().lower()

        # Fallback if parseaddr failed but an email regex matches
        if not email_addr:
            m = EMAIL_ADDRESS_REGEX.search(addr_str)
            if m:
                email_addr = m.group(1).lower()
                name = addr_str[:m.start()].strip(" <\"'")

        domain = email_addr.split("@")[-1] if "@" in email_addr else ""
        return name.strip(), email_addr, domain

    def analyze(self, parsed_email) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Analyzes headers of a ParsedEmail.
        Returns:
            features: numerical and binary features for ML
            evidence: raw header strings and extracted entities
        """
        raw_from = parsed_email.from_header
        raw_reply_to = parsed_email.reply_to_header
        raw_to_list = parsed_email.to_headers
        raw_cc_list = parsed_email.cc_headers
        raw_date = parsed_email.date_header
        raw_msg_id = parsed_email.message_id_header
        raw_return_path = parsed_email.return_path_header
        subject = parsed_email.subject

        # Parse From
        from_display, from_email, sender_domain = self._parse_address(raw_from)
        
        # Parse Reply-To
        reply_to_display, reply_to_email, reply_to_domain = self._parse_address(raw_reply_to)
        
        # Parse Return-Path
        _, return_path_email, return_path_domain = self._parse_address(raw_return_path)

        # Missing field checks
        missing_from = 1 if not from_email else 0
        missing_to = 1 if not raw_to_list else 0
        missing_date = 1 if not raw_date else 0
        missing_message_id = 1 if not raw_msg_id else 0

        # Has Reply-To
        has_reply_to = 1 if (reply_to_email or raw_reply_to.strip()) else 0

        # Mismatches (strictly NaN if Reply-To is missing, rather than false positive)
        if has_reply_to and from_email and reply_to_email:
            from_replyto_mismatch = 1 if from_email != reply_to_email else 0
            s_base = get_base_domain(sender_domain)
            r_base = get_base_domain(reply_to_domain)
            if s_base and r_base and s_base == r_base:
                sender_domain_replyto_domain_mismatch = 0
            else:
                sender_domain_replyto_domain_mismatch = 1 if sender_domain != reply_to_domain else 0
        else:
            from_replyto_mismatch = np.nan
            sender_domain_replyto_domain_mismatch = np.nan

        # Display name analysis
        display_name_present = 1 if bool(from_display) else 0
        
        # Display name email mismatch:
        # e.g., display name contains another email address: "security@paypal.com <attacker@gmail.com>"
        display_name_email_mismatch = 0
        if display_name_present:
            embedded_emails = EMAIL_ADDRESS_REGEX.findall(from_display)
            if embedded_emails:
                # Embedded email differs from actual sender email
                if any(emb.lower() != from_email for emb in embedded_emails):
                    display_name_email_mismatch = 1

        # Multiple addresses check
        multiple_from = 1 if (len(EMAIL_ADDRESS_REGEX.findall(raw_from)) > 1) else 0
        multiple_reply_to = 1 if (len(EMAIL_ADDRESS_REGEX.findall(raw_reply_to)) > 1) else 0

        # Counts
        to_address_count = len(raw_to_list)
        cc_address_count = len(raw_cc_list)

        features = {
            "has_reply_to": has_reply_to,
            "from_replyto_mismatch": from_replyto_mismatch,
            "sender_domain_replyto_domain_mismatch": sender_domain_replyto_domain_mismatch,
            "display_name_present": display_name_present,
            "display_name_email_mismatch": display_name_email_mismatch,
            "multiple_from_addresses": multiple_from,
            "multiple_reply_to_addresses": multiple_reply_to,
            "missing_message_id": missing_message_id,
            "missing_date": missing_date,
            "missing_from": missing_from,
            "missing_to": missing_to,
            "to_address_count": to_address_count,
            "cc_address_count": cc_address_count,
        }

        evidence = {
            "from_address": from_email or None,
            "from_display_name": from_display or None,
            "sender_domain": sender_domain or None,
            "reply_to_address": reply_to_email or None,
            "reply_to_domain": reply_to_domain or None,
            "return_path_address": return_path_email or None,
            "return_path_domain": return_path_domain or None,
            "subject": subject or None,
            "date": raw_date or None,
            "message_id": raw_msg_id or None,
            "to_addresses": raw_to_list,
            "cc_addresses": raw_cc_list,
        }

        return features, evidence
