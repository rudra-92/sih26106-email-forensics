"""
content_analyzer.py - Forensic Linguistic, Structural, and BEC Signal Analyzer for SIH26106.

Extracts measurable linguistic features, ratios, and configurable lexical categories
defined in forensic_config.yaml (urgency, financial, credential, account action, BEC signals).
All outputs are strictly statistical features and signals, never hardcoded classifications.
"""

import os
import re
import yaml
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

CURRENCY_SYMBOLS = {"$", "€", "£", "¥", "₹", "₦", "USD", "EUR", "GBP"}


class ContentAnalyzer:
    """Forensic email content linguistic and BEC signal analyzer."""

    def __init__(self, config_path: Optional[str] = None):
        self.lexical_categories = {
            "urgency": ["urgent", "immediately", "deadline", "action required", "suspended", "expire", "critical"],
            "financial": ["payment", "invoice", "transfer", "bank", "wire", "remittance", "funds"],
            "credential": ["password", "login", "verify", "account", "pin", "credentials", "sign in"],
            "account_action": ["update account", "confirm identity", "verify details", "reactivate", "unlock", "click here"]
        }
        self.bec_signals = {
            "financial_request": ["invoice", "payment", "compensation", "transfer sum"],
            "payment_request": ["pay now", "remit payment", "make payment", "wire amount"],
            "credential_request": ["send password", "confirm password", "enter credentials"],
            "gift_card_request": ["gift card", "apple card", "itunes card", "steam card", "amazon card"],
            "bank_change_request": ["new bank details", "updated account number", "change of bank", "wire instructions"],
            "wire_transfer_request": ["wire transfer", "swift code", "telegraphic transfer"],
            "secrecy_request": ["confidential", "keep this secret", "do not inform", "strictly confidential"],
            "urgent_request": ["asap", "urgent assistance", "immediate attention", "without delay"],
            "executive_titles": ["ceo", "cfo", "coo", "chief executive", "president", "director", "managing director"]
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                    if "lexical_categories" in cfg:
                        self.lexical_categories = cfg["lexical_categories"]
                    if "bec_signals" in cfg:
                        self.bec_signals = cfg["bec_signals"]
            except Exception:
                pass

        # Compile phrase regexes
        self._compiled_lexical = {}
        for cat, phrases in self.lexical_categories.items():
            pattern = r"\b(?:" + "|".join(re.escape(p) for p in phrases) + r")\b"
            self._compiled_lexical[cat] = re.compile(pattern, re.IGNORECASE)

        self._compiled_bec = {}
        for sig, phrases in self.bec_signals.items():
            pattern = r"\b(?:" + "|".join(re.escape(p) for p in phrases) + r")\b"
            self._compiled_bec[sig] = re.compile(pattern, re.IGNORECASE)

    def analyze(self, text_plain: str = "", text_html: str = "", display_name: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Extracts content features from email body."""
        html_present = 1 if (text_html and ("<html" in text_html.lower() or "<div" in text_html.lower() or "<body" in text_html.lower())) else 0
        plain_present = 1 if (text_plain and text_plain.strip()) else 0

        effective_text = text_plain if text_plain.strip() else (re.sub(r"<[^>]+>", " ", text_html) if text_html else "")
        body_length = len(effective_text)

        # Word count & sentence count
        words = re.findall(r"\b\w+\b", effective_text)
        word_count = len(words)
        sentences = re.split(r"[.!?]+", effective_text)
        sentence_count = len([s for s in sentences if s.strip()])

        # HTML to text ratio
        html_len = len(text_html) if text_html else 0
        plain_len = len(text_plain) if text_plain else len(effective_text)
        html_to_text_ratio = round(html_len / (plain_len + 1), 2) if html_len > 0 else 0.0

        # Casing, digit, and special character ratios
        if body_length > 0:
            uppercase_count = sum(1 for c in effective_text if c.isupper())
            digit_count = sum(1 for c in effective_text if c.isdigit())
            special_count = sum(1 for c in effective_text if not c.isalnum() and not c.isspace())

            uppercase_ratio = round(uppercase_count / body_length, 4)
            digit_ratio = round(digit_count / body_length, 4)
            special_character_ratio = round(special_count / body_length, 4)
        else:
            uppercase_ratio = 0.0
            digit_ratio = 0.0
            special_character_ratio = 0.0

        exclamation_count = effective_text.count("!")
        question_count = effective_text.count("?")
        currency_count = sum(effective_text.count(sym) for sym in CURRENCY_SYMBOLS)

        # Lexical category counts
        urgency_term_count = len(self._compiled_lexical["urgency"].findall(effective_text)) if "urgency" in self._compiled_lexical else 0
        financial_term_count = len(self._compiled_lexical["financial"].findall(effective_text)) if "financial" in self._compiled_lexical else 0
        credential_term_count = len(self._compiled_lexical["credential"].findall(effective_text)) if "credential" in self._compiled_lexical else 0
        account_action_term_count = len(self._compiled_lexical["account_action"].findall(effective_text)) if "account_action" in self._compiled_lexical else 0

        # BEC / Impersonation binary signals
        check_bec = lambda k: 1 if (k in self._compiled_bec and bool(self._compiled_bec[k].search(effective_text))) else 0

        financial_request_present = check_bec("financial_request")
        payment_request_present = check_bec("payment_request")
        credential_request_present = check_bec("credential_request")
        gift_card_request_present = check_bec("gift_card_request")
        bank_change_request_present = check_bec("bank_change_request")
        wire_transfer_request_present = check_bec("wire_transfer_request")
        secrecy_request_present = check_bec("secrecy_request")
        urgent_request_present = check_bec("urgent_request")

        # Executive display name check
        exec_display = 0
        combined_header_check = f"{display_name}\n{effective_text[:200]}"
        if "executive_titles" in self._compiled_bec and self._compiled_bec["executive_titles"].search(combined_header_check):
            exec_display = 1

        features = {
            "body_length": body_length,
            "word_count": word_count,
            "sentence_count": sentence_count,
            "html_present": html_present,
            "plain_text_present": plain_present,
            "html_to_text_ratio": html_to_text_ratio,
            "uppercase_ratio": uppercase_ratio,
            "digit_ratio": digit_ratio,
            "special_character_ratio": special_character_ratio,
            "exclamation_count": exclamation_count,
            "question_count": question_count,
            "currency_symbol_count": currency_count,
            "urgency_term_count": urgency_term_count,
            "financial_term_count": financial_term_count,
            "credential_term_count": credential_term_count,
            "account_action_term_count": account_action_term_count,
            "financial_request_present": financial_request_present,
            "payment_request_present": payment_request_present,
            "credential_request_present": credential_request_present,
            "gift_card_request_present": gift_card_request_present,
            "bank_change_request_present": bank_change_request_present,
            "wire_transfer_request_present": wire_transfer_request_present,
            "secrecy_request_present": secrecy_request_present,
            "urgent_request_present": urgent_request_present,
            "executive_style_display_name": exec_display,
        }

        evidence = {
            "urgency_matches": self._compiled_lexical["urgency"].findall(effective_text) if "urgency" in self._compiled_lexical else [],
            "financial_matches": self._compiled_lexical["financial"].findall(effective_text) if "financial" in self._compiled_lexical else [],
            "credential_matches": self._compiled_lexical["credential"].findall(effective_text) if "credential" in self._compiled_lexical else [],
        }

        return features, evidence
