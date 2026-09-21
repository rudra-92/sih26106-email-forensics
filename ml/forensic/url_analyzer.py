"""
url_analyzer.py - Forensic URL Extraction, Structural Analysis, and Reputation Interface for SIH26106.

Extracts URLs from plain text, HTML anchors/attributes, and headers.
Calculates structural forensic metrics (lengths, protocols, IP hostnames, encoding,
open redirect parameters, suspicious TLDs), and provides a modular URL reputation interface.
"""

import re
import urllib.parse
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set
import numpy as np

# Robust, linear-time URL and naked domain extraction pattern
URL_REGEX = re.compile(
    r"""(?i)\b(?:https?://|www\d{0,3}[.]|[a-z0-9][a-z0-9\-_.]+\.(?:com|org|net|in|edu|gov|io|co|ai|xyz|tech|info|me|online|site|app|dev)/?)[^\s<>"'()\[\]{}:;,\.?!]*""",
    re.VERBOSE
)

HTML_HREF_REGEX = re.compile(r"""(?:href|src)=["'](https?://[^"']+)["']""", re.IGNORECASE)

REDIRECT_PARAM_REGEX = re.compile(r"""(?i)[?&](?:url|redirect|link|dest|destination|goto|return_to|target|next)=https?://""")


class URLAnalyzer:
    """Forensic URL extractor and structural heuristic analyzer."""

    def __init__(self, suspicious_tlds: Optional[List[str]] = None):
        self.suspicious_tlds = set(suspicious_tlds or [
            "xyz", "top", "work", "click", "loan", "fit", "country",
            "gq", "cf", "tk", "ml", "ga", "buzz", "surf", "icu", "cam"
        ])

    def extract_urls(self, text_plain: str = "", text_html: str = "") -> List[str]:
        """Extracts and deduplicates URLs from plain text and HTML."""
        found_urls = set()

        # HTML attributes (href, src)
        if text_html:
            for match in HTML_HREF_REGEX.finditer(text_html):
                found_urls.add(match.group(1).strip())

        # Plain text regex
        combined = f"{text_plain}\n{text_html}"
        for match in URL_REGEX.finditer(combined):
            url_str = match.group(0).strip()
            # If naked domain or www, add protocol for uniform parsing
            if not url_str.lower().startswith("http://") and not url_str.lower().startswith("https://"):
                url_str = "http://" + url_str
            if url_str.startswith("http://") or url_str.startswith("https://"):
                found_urls.add(url_str)

        return sorted(list(found_urls))

    @staticmethod
    def _is_ip_hostname(hostname: str) -> bool:
        """Checks if a hostname is an IPv4 or IPv6 literal."""
        if not hostname:
            return False
        # Strip brackets if IPv6
        clean_host = hostname.strip("[]")
        try:
            ipaddress.ip_address(clean_host)
            return True
        except ValueError:
            return False

    def check_url_reputation(self, url: str) -> Dict[str, Any]:
        """
        Modular external URL reputation interface (VirusTotal, URLhaus, PhishTank).
        Strict policy: Returns 'unknown' when offline. Never fabricates intelligence.
        """
        return {
            "url": url,
            "url_reputation": "unknown",
            "url_reputation_source": "none",
            "positives": None,
            "total_scanners": None,
        }

    def analyze(self, text_plain: str = "", text_html: str = "", explicit_urls: Optional[List[str]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Analyzes all URLs in the email."""
        if explicit_urls:
            urls = explicit_urls
        else:
            urls = self.extract_urls(text_plain, text_html)

        url_count = len(urls)
        unique_urls = set(urls)
        unique_url_count = len(unique_urls)

        if url_count == 0:
            features = {
                "url_count": 0,
                "unique_url_count": 0,
                "https_count": 0,
                "http_count": 0,
                "ip_based_url_count": 0,
                "url_with_port_count": 0,
                "average_url_length": 0.0,
                "max_url_length": 0,
                "max_domain_length": 0,
                "max_path_length": 0,
                "max_query_length": 0,
                "has_ip_as_hostname": 0,
                "has_at_symbol": 0,
                "has_encoded_characters": 0,
                "has_punycode": 0,
                "has_unicode_domain": 0,
                "has_suspicious_structure": 0,
                "has_suspicious_tld_candidate": 0,
            }
            evidence = {
                "urls": [],
                "unique_domains": [],
            }
            return features, evidence

        https_count = 0
        http_count = 0
        ip_based_url_count = 0
        url_with_port_count = 0
        url_lengths = []
        domain_lengths = []
        path_lengths = []
        query_lengths = []

        has_ip_as_hostname = 0
        has_at_symbol = 0
        has_encoded_characters = 0
        has_punycode = 0
        has_unicode_domain = 0
        has_suspicious_structure = 0
        has_suspicious_tld = 0

        parsed_url_evidence = []
        unique_domains = set()

        for u in urls:
            u_len = len(u)
            url_lengths.append(u_len)

            if "@" in u:
                has_at_symbol = 1
            if "%" in u:
                has_encoded_characters = 1
            if REDIRECT_PARAM_REGEX.search(u):
                has_suspicious_structure = 1

            try:
                parsed = urllib.parse.urlparse(u)
            except Exception:
                continue

            scheme = parsed.scheme.lower()
            if scheme == "https":
                https_count += 1
            elif scheme == "http":
                http_count += 1

            try:
                hostname = parsed.hostname or ""
            except (ValueError, Exception):
                hostname = ""

            domain_clean = hostname.lower().strip()
            unique_domains.add(domain_clean)
            domain_lengths.append(len(domain_clean))
            path_lengths.append(len(parsed.path))
            query_lengths.append(len(parsed.query))

            try:
                if parsed.port:
                    url_with_port_count += 1
            except (ValueError, Exception):
                pass

            if self._is_ip_hostname(domain_clean):
                ip_based_url_count += 1
                has_ip_as_hostname = 1

            if "xn--" in domain_clean:
                has_punycode = 1
            if any(ord(c) > 127 for c in domain_clean):
                has_unicode_domain = 1

            # Subdomain depth anomaly (e.g. login.secure.verify.bank.evil.com)
            parts = domain_clean.split(".")
            if len(parts) > 4:
                has_suspicious_structure = 1

            # TLD check
            tld = parts[-1] if len(parts) > 1 else ""
            if tld in self.suspicious_tlds:
                has_suspicious_tld = 1

            parsed_url_evidence.append({
                "url": u,
                "domain": domain_clean,
                "tld": tld,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment,
                "reputation": self.check_url_reputation(u)
            })

        features = {
            "url_count": url_count,
            "unique_url_count": unique_url_count,
            "https_count": https_count,
            "http_count": http_count,
            "ip_based_url_count": ip_based_url_count,
            "url_with_port_count": url_with_port_count,
            "average_url_length": round(float(np.mean(url_lengths)), 2) if url_lengths else 0.0,
            "max_url_length": int(np.max(url_lengths)) if url_lengths else 0,
            "max_domain_length": int(np.max(domain_lengths)) if domain_lengths else 0,
            "max_path_length": int(np.max(path_lengths)) if path_lengths else 0,
            "max_query_length": int(np.max(query_lengths)) if query_lengths else 0,
            "has_ip_as_hostname": has_ip_as_hostname,
            "has_at_symbol": has_at_symbol,
            "has_encoded_characters": has_encoded_characters,
            "has_punycode": has_punycode,
            "has_unicode_domain": has_unicode_domain,
            "has_suspicious_structure": has_suspicious_structure,
            "has_suspicious_tld_candidate": has_suspicious_tld,
        }

        evidence = {
            "urls": parsed_url_evidence,
            "unique_domains": sorted(list(unique_domains)),
        }

        return features, evidence
