"""
auth_analyzer.py - SPF, DKIM, and DMARC Authentication Forensic Analyzer for SIH26106.

Parses authentication results from standard headers:
- Authentication-Results
- Received-SPF
- DKIM-Signature
- ARC-Authentication-Results

Strict rule: Missing authentication headers are marked as present=0,
and NEVER fabricated or converted to fail=1.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
import numpy as np


class AuthAnalyzer:
    """Forensic email authentication analyzer (SPF, DKIM, DMARC)."""

    def __init__(self):
        pass

    def analyze(self, parsed_email, sender_domain: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Analyzes authentication headers from a ParsedEmail.
        Returns:
            features: binary indicators and failure counts
            evidence: raw header strings, extracted domains, and policies
        """
        auth_headers = parsed_email.auth_results_headers
        spf_headers = parsed_email.spf_headers
        dkim_sigs = parsed_email.dkim_signatures

        # Aggregate all text containing auth traces
        combined_auth_text = " ".join(
            auth_headers + spf_headers + dkim_sigs + 
            parsed_email.raw_headers.get("authentication-results", []) +
            parsed_email.raw_headers.get("received-spf", []) +
            parsed_email.raw_headers.get("dkim-signature", [])
        ).lower()

        # ----------------------------------------------------------------------
        # 1. SPF Analysis
        # ----------------------------------------------------------------------
        spf_present = 1 if ("spf=" in combined_auth_text or "received-spf" in combined_auth_text or bool(spf_headers)) else 0
        spf_pass = 0
        spf_fail = 0
        spf_softfail = 0
        spf_neutral = 0
        spf_none = 0
        spf_domain = None

        if spf_present:
            # Extract result token
            m_spf = re.search(r"(?:spf=|received-spf:\s*)([a-z]+)", combined_auth_text)
            if m_spf:
                res = m_spf.group(1).lower()
                if "pass" in res:
                    spf_pass = 1
                elif "softfail" in res:
                    spf_softfail = 1
                elif "fail" in res:
                    spf_fail = 1
                elif "neutral" in res:
                    spf_neutral = 1
                elif "none" in res:
                    spf_none = 1

            # Extract SPF domain if mentioned
            m_dom = re.search(r"identity=mailfrom;[\s\w]*domain=([a-z0-9.-]+)", combined_auth_text)
            if not m_dom:
                m_dom = re.search(r"smtp\.mailfrom=([a-z0-9.-]+)", combined_auth_text)
            if not m_dom:
                m_dom = re.search(r"spf=[\w\s]+\((?:sender\s+)?([a-z0-9.-]+)", combined_auth_text)
            if m_dom:
                spf_domain = m_dom.group(1)

        # ----------------------------------------------------------------------
        # 2. DKIM Analysis
        # ----------------------------------------------------------------------
        dkim_present = 1 if ("dkim=" in combined_auth_text or "dkim-signature" in combined_auth_text or bool(dkim_sigs)) else 0
        dkim_pass = 0
        dkim_fail = 0
        dkim_domain = None

        if dkim_present:
            m_dkim = re.search(r"dkim=([a-z]+)", combined_auth_text)
            if m_dkim:
                res = m_dkim.group(1).lower()
                if "pass" in res:
                    dkim_pass = 1
                elif "fail" in res:
                    dkim_fail = 1
            else:
                # If DKIM-Signature header exists without verifier auth results, it is present
                if dkim_sigs:
                    dkim_present = 1

            # Extract d= domain from signature or auth-results
            m_d = re.search(r"header\.d=([a-z0-9.-]+)", combined_auth_text)
            if not m_d:
                m_d = re.search(r"\bd=([a-z0-9.-]+)", combined_auth_text)
            if m_d:
                dkim_domain = m_d.group(1)

        # ----------------------------------------------------------------------
        # 3. DMARC Analysis
        # ----------------------------------------------------------------------
        dmarc_present = 1 if "dmarc=" in combined_auth_text else 0
        dmarc_pass = 0
        dmarc_fail = 0
        dmarc_policy_none = 0
        dmarc_policy_quarantine = 0
        dmarc_policy_reject = 0
        dmarc_domain = None

        if dmarc_present:
            m_dmarc = re.search(r"dmarc=([a-z]+)", combined_auth_text)
            if m_dmarc:
                res = m_dmarc.group(1).lower()
                if "pass" in res:
                    dmarc_pass = 1
                elif "fail" in res:
                    dmarc_fail = 1

            # Policy
            if "p=none" in combined_auth_text or "action=none" in combined_auth_text:
                dmarc_policy_none = 1
            elif "p=quarantine" in combined_auth_text or "action=quarantine" in combined_auth_text:
                dmarc_policy_quarantine = 1
            elif "p=reject" in combined_auth_text or "action=reject" in combined_auth_text:
                dmarc_policy_reject = 1

            m_dm_dom = re.search(r"header\.from=([a-z0-9.-]+)", combined_auth_text)
            if m_dm_dom:
                dmarc_domain = m_dm_dom.group(1)

        # ----------------------------------------------------------------------
        # 4. Alignment & Derived Metrics
        # ----------------------------------------------------------------------
        # Alignment check: does authenticated domain match From header sender domain?
        sender_domain_norm = sender_domain.lower().strip()

        spf_alignment_issue = np.nan
        if spf_present and sender_domain_norm and spf_domain:
            # Domain matches or is parent
            spf_alignment_issue = 0 if (sender_domain_norm.endswith(spf_domain) or spf_domain.endswith(sender_domain_norm)) else 1

        dkim_alignment_issue = np.nan
        if dkim_present and sender_domain_norm and dkim_domain:
            dkim_alignment_issue = 0 if (sender_domain_norm.endswith(dkim_domain) or dkim_domain.endswith(sender_domain_norm)) else 1

        dmarc_alignment_issue = np.nan
        if dmarc_present and sender_domain_norm and dmarc_domain:
            dmarc_alignment_issue = 0 if (sender_domain_norm == dmarc_domain) else 1

        # Failure count
        auth_failure_count = spf_fail + dkim_fail + dmarc_fail

        features = {
            "spf_present": spf_present,
            "spf_pass": spf_pass,
            "spf_fail": spf_fail,
            "spf_softfail": spf_softfail,
            "spf_neutral": spf_neutral,
            "spf_none": spf_none,
            "dkim_present": dkim_present,
            "dkim_pass": dkim_pass,
            "dkim_fail": dkim_fail,
            "dmarc_present": dmarc_present,
            "dmarc_pass": dmarc_pass,
            "dmarc_fail": dmarc_fail,
            "dmarc_policy_none": dmarc_policy_none,
            "dmarc_policy_quarantine": dmarc_policy_quarantine,
            "dmarc_policy_reject": dmarc_policy_reject,
            "spf_alignment_issue": spf_alignment_issue,
            "dkim_alignment_issue": dkim_alignment_issue,
            "dmarc_alignment_issue": dmarc_alignment_issue,
            "authentication_failure_count": auth_failure_count,
        }

        evidence = {
            "spf_domain": spf_domain,
            "dkim_domain": dkim_domain,
            "dmarc_domain": dmarc_domain,
            "raw_authentication_results": auth_headers,
            "raw_spf_headers": spf_headers,
            "raw_dkim_signatures": dkim_sigs,
        }

        return features, evidence
