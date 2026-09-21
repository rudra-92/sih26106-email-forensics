"""
domain_analyzer.py - Forensic Domain Analysis and Lookalike Detection for SIH26106.

Analyzes structural domain properties (length, depth, hyphens, digits, punycode),
detects visual spoofing / homoglyphs / typosquatting via edit distance and character
mapping against popular impersonated targets, and provides a modular DNS enrichment stub.
"""

import os
import re
import yaml
from typing import Dict, List, Any, Optional, Tuple
import numpy as np

# Cyrillic to Latin visually identical homoglyphs
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u0455': 's', '\u0432': 'b', '\u043d': 'h',
    '\u043c': 'm', '\u0442': 't',
}

# Common character substitution pairs in typosquatting
CHAR_SUBSTITUTIONS = [
    ('1', 'l'), ('1', 'i'), ('0', 'o'), ('5', 's'),
    ('vv', 'w'), ('rn', 'm'), ('cl', 'd'), ('nn', 'm')
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def get_base_domain(domain_str: str) -> str:
    """
    Extracts base organization domain (e.g., 'reskilll.in' -> 'reskilll', 'reskilll.com' -> 'reskilll').
    Prevents false spoof flags when same company uses different country-code TLDs or subdomains.
    """
    if not domain_str:
        return ""
    clean = domain_str.strip().lower().rstrip(".")
    for prefix in ("www.", "mail.", "smtp.", "webmail.", "secure.", "build."):
        if clean.startswith(prefix):
            clean = clean[len(prefix):]
    parts = clean.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return clean


class DomainAnalyzer:
    """Forensic analyzer for sender, reply-to, and URL domains."""

    def __init__(self, config_path: Optional[str] = None):
        self.target_brand_domains = [
            "paypal.com", "microsoft.com", "google.com", "apple.com",
            "amazon.com", "netflix.com", "wellsfargo.com", "chase.com",
            "bankofamerica.com", "citibank.com", "dhl.com", "fedex.com",
            "ups.com", "irs.gov", "facebook.com", "linkedin.com",
            "dropbox.com", "adobe.com", "office.com", "outlook.com"
        ]
        self.suspicious_tld_candidates = [
            "xyz", "top", "work", "click", "loan", "fit", "country",
            "gq", "cf", "tk", "ml", "ga", "buzz", "surf", "icu", "cam"
        ]

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                    if "target_brand_domains" in cfg:
                        self.target_brand_domains = cfg["target_brand_domains"]
                    if "suspicious_tld_candidates" in cfg:
                        self.suspicious_tld_candidates = cfg["suspicious_tld_candidates"]
            except Exception:
                pass

    def extract_domain_metrics(self, domain_str: str) -> Dict[str, Any]:
        """Calculates structural syntactic metrics for a domain."""
        if not domain_str:
            return {
                "domain_length": 0,
                "subdomain_depth": 0,
                "hyphen_count": 0,
                "digit_count": 0,
                "special_character_count": 0,
                "tld": "unknown",
                "punycode_flag": 0,
                "unicode_flag": 0,
                "suspicious_tld_candidate": 0,
            }

        domain_clean = domain_str.strip().lower().rstrip(".")
        domain_length = len(domain_clean)
        parts = domain_clean.split(".")
        subdomain_depth = max(0, len(parts) - 2) if len(parts) >= 2 else 0
        tld = parts[-1] if len(parts) > 1 else "unknown"

        hyphen_count = domain_clean.count("-")
        digit_count = sum(c.isdigit() for c in domain_clean)
        special_character_count = sum(not c.isalnum() and c not in (".", "-") for c in domain_clean)

        punycode_flag = 1 if "xn--" in domain_clean else 0
        unicode_flag = 1 if any(ord(c) > 127 for c in domain_str) else 0
        suspicious_tld = 1 if tld in self.suspicious_tld_candidates else 0

        return {
            "domain_length": domain_length,
            "subdomain_depth": subdomain_depth,
            "hyphen_count": hyphen_count,
            "digit_count": digit_count,
            "special_character_count": special_character_count,
            "tld": tld,
            "punycode_flag": punycode_flag,
            "unicode_flag": unicode_flag,
            "suspicious_tld_candidate": suspicious_tld,
        }

    def detect_lookalike(self, domain_str: str) -> Tuple[int, int, float, Optional[str]]:
        """
        Detects if domain is a lookalike / homoglyph candidate against target brands.
        Returns:
            (lookalike_candidate_flag, homoglyph_candidate_flag, min_distance_ratio, matched_target)
        """
        if not domain_str:
            return 0, 0, 1.0, None

        domain_norm = domain_str.strip().lower().rstrip(".")
        # Strip common subdomains (mail., smtp., www.)
        for prefix in ("www.", "mail.", "smtp.", "webmail.", "secure."):
            if domain_norm.startswith(prefix):
                domain_norm = domain_norm[len(prefix):]

        # 1. Homoglyph check
        homoglyph_found = 0
        normalized_from_homoglyph = []
        for char in domain_str:
            if char in HOMOGLYPH_MAP:
                homoglyph_found = 1
                normalized_from_homoglyph.append(HOMOGLYPH_MAP[char])
            else:
                normalized_from_homoglyph.append(char)
        homoglyph_domain = "".join(normalized_from_homoglyph).lower()

        # 2. Normalized character substitutions (e.g. paypa1 -> paypal)
        subbed_domain = domain_norm
        for pair_src, pair_dst in CHAR_SUBSTITUTIONS:
            subbed_domain = subbed_domain.replace(pair_src, pair_dst)

        lookalike_candidate = 0
        min_dist_ratio = 1.0
        best_match = None

        # Compare against target brand domains
        for target in self.target_brand_domains:
            target_norm = target.lower().strip()
            # If exactly equal, it is legitimate target, not lookalike
            if domain_norm == target_norm:
                continue

            # Compare raw domain, homoglyph domain, and substituted domain
            dist_raw = levenshtein_distance(domain_norm, target_norm)
            dist_homo = levenshtein_distance(homoglyph_domain, target_norm)
            dist_sub = levenshtein_distance(subbed_domain, target_norm)

            min_dist = min(dist_raw, dist_homo, dist_sub)
            max_len = max(len(domain_norm), len(target_norm))
            dist_ratio = min_dist / max_len if max_len > 0 else 1.0

            # Also check base name without TLD and hyphen-split tokens (e.g. paypa1 in paypa1-security.com)
            domain_base = domain_norm.split(".")[0]
            target_base = target_norm.split(".")[0]
            tokens = domain_base.split("-")
            for tok in tokens:
                sub_tok = tok
                for pair_src, pair_dst in CHAR_SUBSTITUTIONS:
                    sub_tok = sub_tok.replace(pair_src, pair_dst)
                d_tok = min(levenshtein_distance(tok, target_base), levenshtein_distance(sub_tok, target_base))
                r_tok = d_tok / max(len(tok), len(target_base))
                if r_tok < dist_ratio:
                    dist_ratio = r_tok
                    min_dist = d_tok

            if dist_ratio < min_dist_ratio:
                min_dist_ratio = dist_ratio
                best_match = target_norm

            # Threshold for lookalike: 1 or 2 edits away on brand domain (ratio <= 0.25)
            if min_dist <= 2 and len(target_base) >= 4:
                lookalike_candidate = 1
            elif dist_ratio <= 0.20:
                lookalike_candidate = 1

        return lookalike_candidate, homoglyph_found, round(min_dist_ratio, 3), best_match

    def analyze_domain(self, domain_str: str) -> Dict[str, Any]:
        """
        Modular external DNS enrichment interface.
        Strict policy: Returns None / unknown when offline. Never fabricates records.
        """
        if not domain_str:
            return {}

        return {
            "domain": domain_str,
            "has_mx": None,
            "has_a_record": None,
            "has_aaaa_record": None,
            "mx_count": None,
            "nameserver_count": None,
            "domain_age_days": None,
            "registrar": "unknown",
            "nameserver": "unknown",
            "mx_provider": "unknown",
            "country": "unknown",
        }

    def analyze(self, sender_domain: str, reply_to_domain: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Analyzes sender and reply-to domain forensics."""
        metrics = self.extract_domain_metrics(sender_domain)
        lookalike_flag, homoglyph_flag, dist_ratio, matched_target = self.detect_lookalike(sender_domain)

        domain_mismatch = np.nan
        if sender_domain and reply_to_domain:
            # Check full domain and organizational base domain (e.g. reskilll.in vs reskilll.com)
            s_base = get_base_domain(sender_domain)
            r_base = get_base_domain(reply_to_domain)
            if s_base and r_base and s_base == r_base:
                domain_mismatch = 0
            else:
                domain_mismatch = 1 if sender_domain.lower() != reply_to_domain.lower() else 0

        features = {
            "domain_length": metrics["domain_length"],
            "subdomain_depth": metrics["subdomain_depth"],
            "hyphen_count": metrics["hyphen_count"],
            "digit_count": metrics["digit_count"],
            "special_character_count": metrics["special_character_count"],
            "punycode_flag": metrics["punycode_flag"],
            "unicode_flag": metrics["unicode_flag"],
            "suspicious_tld_candidate": metrics["suspicious_tld_candidate"],
            "lookalike_domain_candidate": lookalike_flag,
            "homoglyph_candidate": homoglyph_flag,
            "target_domain_min_distance_ratio": dist_ratio,
            "domain_mismatch": domain_mismatch,
        }

        evidence = {
            "sender_domain": sender_domain or None,
            "reply_to_domain": reply_to_domain or None,
            "sender_tld": metrics["tld"],
            "closest_brand_target": matched_target,
            "dns_enrichment": self.analyze_domain(sender_domain) if sender_domain else None,
        }

        return features, evidence
