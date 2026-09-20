"""Static URL forensic analyzer.

Performs deterministic, non-network structural inspection:
1. IP-address hostname detection (IPv4 / IPv6)
2. Excessive subdomain nesting
3. Unusual non-standard ports
4. Length analysis (total URL, hostname, path, query)
5. Percent-encoding and nested encoding detection
6. Host/userinfo ambiguity detection (e.g. paypal.com@evil.example)
7. Sensitive path keyword inspection (/login, /verify, /auth, etc.)
8. Potential open-redirect parameter detection
9. Visible text vs actual href mismatch detection
10. Module 2 Lookalike Domain integration
11. Graph-ready entity and relationship generation
12. Static tabular feature extraction for future ML classifier
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import unquote

from modules.lookalike_domain import (
    CandidateResult,
    find_similarity_candidates,
    load_reference_domains,
    normalize_domain,
)
from modules.sender_identity.models import Entity, Relationship

from .extractor import _URL_REGEX, UrlExtractor, extract_urls
from .models import (
    ExtractedUrl,
    NormalizedUrl,
    UrlAnalysisAssessment,
    UrlAnalysisReport,
    UrlMlFeatures,
    UrlObservation,
)
from .normalizer import DEFAULT_PORTS, is_ip_address, normalize_url

# Sensitive keywords commonly abused in phishing / credential harvesting paths
SENSITIVE_PATH_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "password",
    "passwd", "auth", "authenticate", "update", "security", "wallet",
    "banking", "secure", "confirm", "validation", "credential",
}

# Query parameter names commonly associated with open redirects
REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirect_uri", "redirect_url", "dest", "destination",
    "target", "r", "next", "return", "return_to", "return_url", "link",
    "continue", "goto", "out",
}

# Regex matching percent-encoded byte sequences (e.g. %2F, %20)
_PERCENT_ENCODING_REGEX = re.compile(r"%[0-9a-fA-F]{2}")

# Regex matching double/nested encoding (e.g. %252F, %253A)
_NESTED_ENCODING_REGEX = re.compile(r"%25[0-9a-fA-F]{2}", re.IGNORECASE)


class StaticUrlAnalyzer:
    """Forensic engine analyzing extracted URLs and compiling explainable evidence."""

    def __init__(
        self,
        max_url_length: int = 120,
        max_hostname_length: int = 40,
        max_query_length: int = 80,
        reference_domains: Optional[List[str]] = None,
    ) -> None:
        self.max_url_length = max_url_length
        self.max_hostname_length = max_hostname_length
        self.max_query_length = max_query_length
        # Load reference domains once for fast candidate checks
        self._reference_domains = reference_domains

    def analyze(
        self,
        content: Union[str, bytes, Dict[str, Any], Any],
        email_id: str = "E001",
    ) -> UrlAnalysisReport:
        """Run complete static forensic URL analysis on input content.

        Args:
            content: Raw text, HTML, dictionary payload, or email body.
            email_id: Forensic email identifier for graph provenance.

        Returns:
            UrlAnalysisReport containing extracted URLs, structural observations,
            graph entities/relationships, ML features, and bounded assessment.
        """
        extracted_list = extract_urls(content)

        if not extracted_list:
            assessment = UrlAnalysisAssessment(
                category="no_significant_url_anomaly",
                risk_level="none",
                evidence_strength="none",
                confidence=0.0,
                reason="No URLs found in the analyzed email content.",
            )
            return UrlAnalysisReport(
                module="url_analysis",
                email_id=email_id,
                urls=[],
                entities=[Entity(type="email", value=email_id, source="url_analysis")],
                observations=[],
                relationships=[],
                assessment=assessment,
                ml_features=[],
            )

        report_urls: List[Dict[str, Any]] = []
        observations: List[UrlObservation] = []
        entities: List[Entity] = [
            Entity(type="email", value=email_id, source="url_analysis")
        ]
        relationships: List[Relationship] = []
        ml_features: List[Dict[str, Any]] = []

        obs_counter = 1

        def _next_obs_id() -> str:
            nonlocal obs_counter
            oid = f"OBS-URL-{obs_counter:03d}"
            obs_counter += 1
            return oid

        seen_entities: Set[Tuple[str, str]] = set()

        def _add_entity(ent_type: str, value: str, source: str, **attrs: Any) -> None:
            key = (ent_type, value)
            if key not in seen_entities:
                seen_entities.add(key)
                entities.append(
                    Entity(type=ent_type, value=value, source=source, attributes=attrs)
                )

        seen_relationships: Set[Tuple[str, str, str]] = set()

        def _add_relationship(src: str, rel: str, tgt: str, evidence: Optional[Dict[str, Any]] = None) -> None:
            key = (src, rel, tgt)
            if key not in seen_relationships:
                seen_relationships.add(key)
                relationships.append(Relationship(source=src, relation=rel, target=tgt, evidence=evidence))

        for ext in extracted_list:
            norm = normalize_url(ext.actual_url)

            # Build URL and Domain entities & relationships
            _add_entity(
                "url",
                norm.normalized_url,
                ext.source,
                scheme=norm.scheme,
                hostname=norm.hostname,
                path=norm.path,
            )
            _add_relationship(
                email_id,
                "contains_url",
                norm.normalized_url,
                evidence={"source": ext.source, "visible_text": ext.visible_text},
            )

            if norm.hostname:
                _add_entity(
                    "domain" if not norm.is_ip else "ip",
                    norm.hostname,
                    "url_analysis",
                    is_ip=norm.is_ip,
                )
                _add_relationship(
                    norm.normalized_url,
                    "hosted_on",
                    norm.hostname,
                    evidence={"port": norm.port, "scheme": norm.scheme},
                )

            # -----------------------------------------------------------------
            # Structural Anomaly Checks
            # -----------------------------------------------------------------
            # 1. IP-address hostname
            if norm.is_ip:
                observations.append(
                    UrlObservation(
                        observation_id=_next_obs_id(),
                        rule_id="RULE-URL-IP-HOST",
                        source_module="url_analysis",
                        type="ip_hostname",
                        severity="high",
                        description=f"URL uses raw IP address '{norm.hostname}' instead of a registered domain.",
                        evidence={"url": norm.normalized_url, "hostname": norm.hostname},
                        fact_type="observed",
                    )
                )

            # 2. Excessive subdomains
            subdomain_count = 0
            if norm.normalized_domain and len(norm.normalized_domain.labels) > 2:
                # Labels before SLD and TLD
                subdomain_count = len(norm.normalized_domain.labels) - 2
                if subdomain_count >= 3:
                    observations.append(
                        UrlObservation(
                            observation_id=_next_obs_id(),
                            rule_id="RULE-URL-EXCESSIVE-SUBDOMAINS",
                            source_module="url_analysis",
                            type="excessive_subdomains",
                            severity="medium",
                            description=(
                                f"Hostname '{norm.hostname}' contains an unusually high number of subdomains "
                                f"({subdomain_count} subdomains)."
                            ),
                            evidence={
                                "hostname": norm.hostname,
                                "subdomain_count": subdomain_count,
                                "labels": list(norm.normalized_domain.labels),
                            },
                            fact_type="observed",
                        )
                    )

            # 3. Non-default port
            is_non_default_port = False
            if norm.port is not None and norm.port != DEFAULT_PORTS.get(norm.scheme):
                is_non_default_port = True
                observations.append(
                    UrlObservation(
                        observation_id=_next_obs_id(),
                        rule_id="RULE-URL-NON-DEFAULT-PORT",
                        source_module="url_analysis",
                        type="unusual_port",
                        severity="medium",
                        description=f"URL targets non-standard port {norm.port} for {norm.scheme.upper()} protocol.",
                        evidence={"port": norm.port, "scheme": norm.scheme, "url": norm.normalized_url},
                        fact_type="observed",
                    )
                )

            # 4. Length analysis
            url_len = len(norm.normalized_url)
            host_len = len(norm.hostname)
            path_len = len(norm.path)
            query_len = len(norm.query)

            if url_len > self.max_url_length:
                observations.append(
                    UrlObservation(
                        observation_id=_next_obs_id(),
                        rule_id="RULE-URL-EXCESSIVE-LENGTH",
                        source_module="url_analysis",
                        type="excessive_length",
                        severity="low",
                        description=f"URL length ({url_len} chars) exceeds standard threshold ({self.max_url_length} chars).",
                        evidence={"url_length": url_len, "threshold": self.max_url_length},
                        fact_type="observed",
                    )
                )

            # 5. Special character and obfuscation indicators
            special_chars = sum(norm.raw_url.count(c) for c in ("@", "%", "?", "&", "=", "#"))
            percent_enc_matches = _PERCENT_ENCODING_REGEX.findall(norm.raw_url)
            percent_enc_count = len(percent_enc_matches)

            if percent_enc_count >= 5:
                observations.append(
                    UrlObservation(
                        observation_id=_next_obs_id(),
                        rule_id="RULE-URL-DENSE-PERCENT-ENCODING",
                        source_module="url_analysis",
                        type="obfuscation_encoding",
                        severity="medium",
                        description=f"URL contains dense percent-encoding ({percent_enc_count} encoded sequences).",
                        evidence={"percent_encoded_count": percent_enc_count, "url": norm.normalized_url},
                        fact_type="observed",
                    )
                )

            if _NESTED_ENCODING_REGEX.search(norm.raw_url):
                observations.append(
                    UrlObservation(
                        observation_id=_next_obs_id(),
                        rule_id="RULE-URL-NESTED-ENCODING",
                        source_module="url_analysis",
                        type="nested_encoding",
                        severity="high",
                        description="URL exhibits nested/double percent-encoding (e.g. %25xx sequences).",
                        evidence={"raw_url": norm.raw_url},
                        fact_type="observed",
                    )
                )

            # 6. Host/userinfo ambiguity
            userinfo_present = bool(norm.username or norm.password or ("@" in norm.netloc))
            if userinfo_present:
                observations.append(
                    UrlObservation(
                        observation_id=_next_obs_id(),
                        rule_id="RULE-URL-USERINFO-AMBIGUITY",
                        source_module="url_analysis",
                        type="userinfo_spoofing",
                        severity="high",
                        description=(
                            f"URL authority contains userinfo ('{norm.username}') disguising the actual destination "
                            f"host '{norm.hostname}'."
                        ),
                        evidence={
                            "username": norm.username,
                            "actual_hostname": norm.hostname,
                            "url": norm.normalized_url,
                        },
                        fact_type="observed",
                    )
                )

            # 7. Sensitive path tokens
            path_tokens = set(re.split(r"[/._\-]", norm.path.lower()))
            matched_sensitive_keywords = sorted(list(path_tokens & SENSITIVE_PATH_KEYWORDS))
            login_token_present = bool(matched_sensitive_keywords)

            if login_token_present:
                observations.append(
                    UrlObservation(
                        observation_id=_next_obs_id(),
                        rule_id="RULE-URL-SENSITIVE-PATH-KEYWORD",
                        source_module="url_analysis",
                        type="sensitive_path",
                        severity="low",
                        description=f"URL path contains authentication keywords: {', '.join(matched_sensitive_keywords)}.",
                        evidence={"matched_keywords": matched_sensitive_keywords, "path": norm.path},
                        fact_type="observed",
                    )
                )

            # 8. Open redirect indicators
            redirect_param_found = None
            redirect_target_val = None
            for p_name in norm.query_params:
                if p_name.lower() in REDIRECT_PARAM_NAMES:
                    redirect_param_found = p_name
                    val_list = norm.query_params[p_name]
                    redirect_target_val = val_list[0] if val_list else ""
                    break

            redirect_indicator = bool(redirect_param_found)
            if redirect_indicator:
                observations.append(
                    UrlObservation(
                        observation_id=_next_obs_id(),
                        rule_id="RULE-URL-REDIRECT-PARAMETER",
                        source_module="url_analysis",
                        type="potential_redirect",
                        severity="medium",
                        description=(
                            f"URL contains potential redirect parameter '{redirect_param_found}' "
                            f"pointing to '{redirect_target_val}'."
                        ),
                        evidence={
                            "param_name": redirect_param_found,
                            "target_value": redirect_target_val,
                            "url": norm.normalized_url,
                        },
                        fact_type="observed",
                    )
                )

            # 9. Visible text vs actual href mismatch
            visible_href_mismatch = False
            if ext.source in ("html_href", "html_visible_text") and ext.visible_text:
                v_text = ext.visible_text.strip()
                is_url_display = (not any(c in v_text for c in (" ", "\t", "\n"))) and (
                    bool(_URL_REGEX.search(v_text)) or ("." in v_text and not v_text.startswith("."))
                )

                if is_url_display:
                    vis_norm = normalize_url(v_text)
                    if vis_norm.hostname and norm.hostname and vis_norm.hostname.lower() != norm.hostname.lower():
                        visible_href_mismatch = True
                        observations.append(
                            UrlObservation(
                                observation_id=_next_obs_id(),
                                rule_id="RULE-URL-VISIBLE-HREF-MISMATCH",
                                source_module="url_analysis",
                                type="visible_href_mismatch",
                                severity="high",
                                description=(
                                    f"Visible link displays destination '{vis_norm.hostname}' "
                                    f"but actual hyperlink navigates to '{norm.hostname}'."
                                ),
                                evidence={
                                    "visible_text": ext.visible_text,
                                    "visible_hostname": vis_norm.hostname,
                                    "actual_url": norm.normalized_url,
                                    "actual_hostname": norm.hostname,
                                },
                                fact_type="observed",
                            )
                        )
                else:
                    if any(brand in v_text.lower() for brand in ("login", "secure", "support", "account", "verify", "portal", "update", "sign in")):
                        observations.append(
                            UrlObservation(
                                observation_id=_next_obs_id(),
                                rule_id="RULE-URL-VISIBLE-TEXT-MISMATCH",
                                source_module="url_analysis",
                                type="brand_text_mismatch",
                                severity="medium",
                                description=(
                                    f"Visible link text '{v_text}' suggests a secure/login portal "
                                    f"while actual target is '{norm.hostname}'."
                                ),
                                evidence={
                                    "visible_text": v_text,
                                    "actual_url": norm.normalized_url,
                                    "actual_hostname": norm.hostname,
                                },
                                fact_type="observed",
                            )
                        )

            # 10. Module 2 Lookalike Domain integration
            domain_similarity_score = 0.0
            if norm.normalized_domain and not norm.is_ip:
                try:
                    candidates = find_similarity_candidates(
                        observed=norm.normalized_domain,
                        reference_domains=self._reference_domains,
                        threshold=0.80,
                        limit=1,
                    )
                    if candidates:
                        best_cand = candidates[0]
                        # Only record candidate if it is not an exact match to the reference domain
                        if best_cand.reference_domain != norm.hostname:
                            domain_similarity_score = best_cand.candidate_score
                            observations.append(
                                UrlObservation(
                                    observation_id=_next_obs_id(),
                                    rule_id="RULE-URL-HOST-LOOKALIKE-CANDIDATE",
                                    source_module="url_analysis",
                                    type="lookalike_hostname_candidate",
                                    severity="medium",
                                    description=(
                                        f"URL hostname '{norm.hostname}' is a candidate resemblance to protected brand "
                                        f"'{best_cand.reference_domain}' with similarity score {best_cand.candidate_score:.4f} "
                                        f"({best_cand.reason}). Contextual validation required to determine impersonation."
                                    ),
                                    evidence={
                                        "hostname": norm.hostname,
                                        "reference_domain": best_cand.reference_domain,
                                        "candidate_score": best_cand.candidate_score,
                                        "similarity_reason": best_cand.reason,
                                    },
                                    fact_type="inferred",
                                )
                            )
                except Exception:
                    pass

            # Compile ML Features for this URL
            ml_feat = UrlMlFeatures(
                url=norm.normalized_url,
                url_length=url_len,
                hostname_length=host_len,
                path_length=path_len,
                query_length=query_len,
                subdomain_count=subdomain_count,
                special_character_count=special_chars,
                percent_encoded_count=percent_enc_count,
                host_is_ip=norm.is_ip,
                non_default_port=is_non_default_port,
                userinfo_present=userinfo_present,
                login_token_present=login_token_present,
                redirect_indicator=redirect_indicator,
                visible_href_mismatch=visible_href_mismatch,
                domain_similarity_score=round(domain_similarity_score, 4),
            )
            ml_features.append(ml_feat.to_dict())

            report_urls.append({
                "extracted": ext.to_dict(),
                "normalized": norm.to_dict(),
                "ml_features": ml_feat.to_dict(),
                "redirects": [],  # Architectural placeholder for future sandboxed enrichment
            })

        # ---------------------------------------------------------------------
        # Final Structural Assessment
        # ---------------------------------------------------------------------
        high_sev = [o for o in observations if o.severity == "high"]
        med_sev = [o for o in observations if o.severity == "medium"]

        if high_sev:
            category = "suspicious_url_structure"
            risk_level = "high"
            evidence_strength = "strong" if len(high_sev) >= 2 else "moderate"
            confidence = min(0.90, 0.70 + (len(high_sev) * 0.08))
            reason = (
                f"URL structural analysis detected {len(high_sev)} high-severity anomaly indicator(s): "
                f"{'; '.join(o.description for o in high_sev)}."
            )
        elif med_sev:
            category = "url_anomaly_detected"
            risk_level = "medium"
            evidence_strength = "moderate"
            confidence = min(0.75, 0.50 + (len(med_sev) * 0.08))
            reason = (
                f"URL structural analysis detected {len(med_sev)} moderate-severity anomaly indicator(s): "
                f"{'; '.join(o.description for o in med_sev)}."
            )
        else:
            category = "no_significant_url_anomaly"
            risk_level = "none"
            evidence_strength = "none"
            confidence = 0.15
            reason = "No prominent static URL anomalies or structural mismatches detected."

        assessment = UrlAnalysisAssessment(
            category=category,
            risk_level=risk_level,
            evidence_strength=evidence_strength,
            confidence=round(confidence, 4),
            reason=reason,
        )

        return UrlAnalysisReport(
            module="url_analysis",
            email_id=email_id,
            urls=report_urls,
            entities=entities,
            observations=observations,
            relationships=relationships,
            assessment=assessment,
            ml_features=ml_features,
        )


def analyze_urls(
    content: Union[str, bytes, Dict[str, Any], Any],
    email_id: str = "E001",
    reference_domains: Optional[List[str]] = None,
) -> UrlAnalysisReport:
    """Convenience function to run static forensic URL analysis on email content."""
    analyzer = StaticUrlAnalyzer(reference_domains=reference_domains)
    return analyzer.analyze(content, email_id=email_id)
