"""Contradiction detection engine for Module 6: Evidence Correlation & Attribution Support.

Detects, records, and preserves genuine forensic contradictions across deterministic
evidence and external ML predictions.

CRITICAL RULE: Never suppresses conflicting evidence. Emits explicit ContradictionRecord
items under standardized rule IDs (e.g. 'RULE-CORR-EVIDENCE-CONFLICT').
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import ContradictionRecord, MlPrediction, NormalizedEvidence


class ContradictionEngine:
    """Detects and documents conflicting evidence across modules and models."""

    def __init__(self) -> None:
        self._counter = 1

    def _next_id(self) -> str:
        cid = f"CONTRADICT-{self._counter:04d}"
        self._counter += 1
        return cid

    def find_contradictions(
        self,
        evidence_list: List[NormalizedEvidence],
        ml_predictions: Optional[List[MlPrediction]] = None,
        module1_report: Optional[Any] = None,
        module5_report: Optional[Any] = None,
        module2_report: Optional[Any] = None,
        module3_report: Optional[Any] = None,
    ) -> List[ContradictionRecord]:
        """Evaluate evidence base for contradictions and return all conflict records."""
        contradictions: List[ContradictionRecord] = []

        by_module: Dict[str, List[NormalizedEvidence]] = {}
        for ev in evidence_list:
            by_module.setdefault(ev.source_module, []).append(ev)

        # 1. SPF / DKIM Pass vs. Lookalike Domain Evidence
        c_auth = self._check_auth_vs_lookalike(by_module, module1_report, module2_report)
        if c_auth:
            contradictions.append(c_auth)

        # 2. Geographic Divergence (user_country != server_country)
        c_geo = self._check_geographic_conflict(by_module, module5_report)
        if c_geo:
            contradictions.append(c_geo)

        # 3. ML Legitimate/Benign vs. High-Severity Deterministic Forensic Findings
        c_ml = self._check_ml_vs_deterministic(evidence_list, ml_predictions or [])
        if c_ml:
            contradictions.extend(c_ml)

        # 4. ML Threat (Phishing/Fraud) vs. Authentication Pass (SPF/DKIM)
        c_ml_auth = self._check_ml_vs_auth_pass(by_module, ml_predictions or [], module1_report)
        if c_ml_auth:
            contradictions.append(c_ml_auth)

        # 5. ML Phishing vs. Explicitly Benign / Trusted URL Evidence
        c_ml_url = self._check_ml_vs_url_analysis(by_module, ml_predictions or [], module3_report)
        if c_ml_url:
            contradictions.append(c_ml_url)

        # 6. Header Identity Divergence (From vs Reply-To / Return-Path)
        c_hdr = self._check_header_identity_divergence(by_module)
        if c_hdr:
            contradictions.append(c_hdr)

        return contradictions

    def _check_auth_vs_lookalike(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
        module1_report: Optional[Any],
        module2_report: Optional[Any] = None,
    ) -> Optional[ContradictionRecord]:
        """SPF or DKIM pass on an identified lookalike domain."""
        m2_ev = by_module.get("lookalike_domain", [])
        has_lookalike = any(
            (
                e.evidence_type in ("lookalike_signal", "candidate_score")
                and e.severity in ("medium", "high")
                and e.supporting_fields.get("candidate", True) is not False
                and e.supporting_fields.get("is_candidate", True) is not False
                and not e.supporting_fields.get("rejected", False)
            )
            for e in m2_ev
        )

        if not has_lookalike and module2_report is not None:
            d2 = module2_report.to_dict() if hasattr(module2_report, "to_dict") else dict(module2_report)
            is_cand = bool(d2.get("candidate", False) or d2.get("is_candidate", False) or d2.get("is_lookalike", False))
            score = float(d2.get("candidate_score", 0.0))
            is_rej = d2.get("candidate") is False or d2.get("is_candidate") is False or d2.get("category") == "unlikely_domain_impersonation"
            if not is_rej and ((is_cand and score >= 0.70) or d2.get("is_lookalike")):
                has_lookalike = True

        auth_pass = False
        auth_eid = ""

        # Check Module 1 auth evidence
        m1_ev = by_module.get("sender_identity", [])
        for e in m1_ev:
            if "pass" in e.description.lower() and ("spf" in e.description.lower() or "dkim" in e.description.lower()):
                auth_pass = True
                auth_eid = e.evidence_id
                break

        if not auth_pass and module1_report is not None:
            d1 = module1_report.to_dict() if hasattr(module1_report, "to_dict") else dict(module1_report)
            auth_res = d1.get("auth_results", {})
            if isinstance(auth_res, dict):
                for k in ("spf", "dkim", "dmarc"):
                    v = auth_res.get(k)
                    res = v.get("result") if isinstance(v, dict) else v
                    if str(res).lower() == "pass":
                        auth_pass = True
                        auth_eid = f"M1-{k.upper()}-PASS"
                        break

        if has_lookalike and auth_pass:
            lookalike_eid = next(
                (e.evidence_id for e in m2_ev if e.evidence_type in ("lookalike_signal", "candidate_score")),
                "M2-LOOKALIKE",
            )
            return ContradictionRecord(
                contradiction_id=self._next_id(),
                rule_id="RULE-CORR-AUTH-LOOKALIKE-CONFLICT",
                conflict_type="auth_vs_lookalike",
                evidence_a_id=auth_eid,
                evidence_b_id=lookalike_eid,
                explanation=(
                    "Authentication check (SPF/DKIM) PASSED, but the sending domain is an identified "
                    "lookalike/impersonation domain. The threat actor likely provisioned valid DNS/auth records "
                    "for their deceptive domain."
                ),
                provenance=["sender_identity", "lookalike_domain"],
            )
        return None

    def _check_geographic_conflict(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
        module5_report: Optional[Any],
    ) -> Optional[ContradictionRecord]:
        """Geographic routing inconsistency between user endpoint and server relay."""
        m5_ev = by_module.get("origin_infrastructure", [])
        geo_ev = next(
            (e for e in m5_ev if e.evidence_type == "location_evidence" and e.supporting_fields.get("country_agreement") is False),
            None,
        )

        if geo_ev:
            u_cc = geo_ev.supporting_fields.get("user_country", {}).get("country_code", "Unknown")
            s_cc = geo_ev.supporting_fields.get("server_country", {}).get("country_code", "Unknown")
            return ContradictionRecord(
                contradiction_id=self._next_id(),
                rule_id="RULE-CORR-GEOGRAPHIC-CONFLICT",
                conflict_type="user_vs_server_country",
                evidence_a_id=f"{geo_ev.evidence_id}:user_country({u_cc})",
                evidence_b_id=f"{geo_ev.evidence_id}:server_country({s_cc})",
                explanation=(
                    f"Country-level geographic evidence is inconsistent: endpoint user-country ({u_cc}) "
                    f"differs from relay server-country ({s_cc}). Indicates possible international roaming, VPN, or proxy relay."
                ),
                provenance=["origin_infrastructure", "sapics/ip-location-db"],
            )
        return None

    def _check_ml_vs_deterministic(
        self,
        evidence_list: List[NormalizedEvidence],
        ml_predictions: List[MlPrediction],
    ) -> List[ContradictionRecord]:
        """ML model predicts benign/legitimate while deterministic rules flag high-severity threats."""
        records: List[ContradictionRecord] = []

        benign_preds = [
            p for p in ml_predictions
            if p.label in ("legitimate", "benign", "safe", "clean", "low_risk")
            and p.confidence >= 0.70
        ]

        high_sev_deterministic = [
            e for e in evidence_list
            if e.source_module not in (
                "email_threat_classifier",
                "bec_intent_classifier",
                "url_risk_classifier",
                "ml_forensic_fusion",
            )
            and e.severity == "high"
        ]

        if benign_preds and high_sev_deterministic:
            for pred in benign_preds:
                for det in high_sev_deterministic[:2]:
                    records.append(
                        ContradictionRecord(
                            contradiction_id=self._next_id(),
                            rule_id="RULE-CORR-ML-FORENSIC-CONFLICT",
                            conflict_type="ml_vs_deterministic",
                            evidence_a_id=f"ML:{pred.model}:{pred.label}",
                            evidence_b_id=det.evidence_id,
                            explanation=(
                                f"Machine learning model '{pred.model}' predicted '{pred.label}' (confidence: {pred.confidence:.2f}), "
                                f"contradicting deterministic high-severity finding '{det.rule_id}' ({det.description})."
                            ),
                            provenance=[pred.model, det.source_module],
                        )
                    )
        return records

    def _check_ml_vs_auth_pass(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
        ml_predictions: List[MlPrediction],
        module1_report: Optional[Any] = None,
    ) -> Optional[ContradictionRecord]:
        """ML predicts phishing or fraud with high confidence while SPF or DKIM passed."""
        threat_preds = [
            p for p in ml_predictions
            if p.label in ("phishing", "fraud_related", "fraud", "credential_harvesting")
            and p.confidence >= 0.70
        ]
        if not threat_preds:
            return None

        m1_ev = by_module.get("sender_identity", [])
        auth_pass_ev = next(
            (
                e for e in m1_ev
                if "pass" in e.description.lower() and ("spf" in e.description.lower() or "dkim" in e.description.lower())
            ),
            None,
        )

        if auth_pass_ev:
            pred = threat_preds[0]
            return ContradictionRecord(
                contradiction_id=self._next_id(),
                rule_id="RULE-CORR-ML-AUTH-CONFLICT",
                conflict_type="ml_vs_auth",
                evidence_a_id=f"ML:{pred.model}:{pred.label}",
                evidence_b_id=auth_pass_ev.evidence_id,
                explanation=(
                    f"Machine learning model '{pred.model}' predicted '{pred.label}' (confidence: {pred.confidence:.2f}), "
                    f"but email authentication check PASSED ({auth_pass_ev.description}). Indicates possible compromised infrastructure, "
                    f"legitimate relay misuse, or authenticated deceptive domain."
                ),
                provenance=[pred.model, "sender_identity"],
            )
        return None

    def _check_ml_vs_url_analysis(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
        ml_predictions: List[MlPrediction],
        module3_report: Optional[Any] = None,
    ) -> Optional[ContradictionRecord]:
        """ML predicts phishing with high confidence while deterministic URL analysis explicitly verified URL as benign/trusted.

        NOTE: Mere absence of suspicious URL indicators does NOT create a contradiction,
        as phishing often operates via social engineering, credential harvesting forms,
        or non-URL vectors. A contradiction requires explicit deterministic findings
        marking the relevant URL as verified benign or trusted.
        """
        phish_preds = [
            p for p in ml_predictions
            if p.label in ("phishing", "credential_harvesting")
            and p.confidence >= 0.70
        ]
        if not phish_preds:
            return None

        m3_ev = by_module.get("url_analysis", [])

        # 1. Search for explicit benign or trusted evidence in normalized URL evidence
        explicit_benign_ev = next(
            (
                e for e in m3_ev
                if e.rule_id in ("RULE-URL-BENIGN", "RULE-URL-TRUSTED", "RULE-URL-SAFE", "RULE-URL-ALLOWLIST")
                or "explicitly benign" in e.description.lower()
                or "trusted" in e.description.lower()
                or e.supporting_fields.get("risk_level") in ("benign", "trusted")
                or e.supporting_fields.get("is_trusted") is True
                or e.supporting_fields.get("is_benign") is True
            ),
            None,
        )

        # 2. Search in raw module3_report if provided
        if explicit_benign_ev is None and module3_report is not None:
            d3 = module3_report.to_dict() if hasattr(module3_report, "to_dict") else dict(module3_report)
            assessment = d3.get("assessment", {}) if isinstance(d3.get("assessment"), dict) else {}
            is_explicit_benign = (
                assessment.get("risk_level") in ("benign", "trusted")
                or assessment.get("category") in ("benign", "trusted_domain", "trusted_url")
            )
            if not is_explicit_benign:
                for item in d3.get("url_findings", []) + d3.get("urls", []):
                    if isinstance(item, dict) and (
                        item.get("risk_level") in ("benign", "trusted")
                        or item.get("is_trusted") is True
                        or item.get("is_benign") is True
                    ):
                        is_explicit_benign = True
                        break

            if is_explicit_benign:
                url_eid = next((e.evidence_id for e in m3_ev if e.evidence_type == "extracted_url"), "M3-URL-BENIGN")
                pred = phish_preds[0]
                return ContradictionRecord(
                    contradiction_id=self._next_id(),
                    rule_id="RULE-CORR-ML-URL-CONFLICT",
                    conflict_type="ml_vs_url_analysis",
                    evidence_a_id=f"ML:{pred.model}:{pred.label}",
                    evidence_b_id=url_eid,
                    explanation=(
                        f"Machine learning model '{pred.model}' predicted '{pred.label}' (confidence: {pred.confidence:.2f}), "
                        f"contradicting deterministic URL analysis which explicitly verified the URL as benign/trusted. "
                        f"Threat may involve multi-stage redirects, compromised legitimate site, or model false positive."
                    ),
                    provenance=[pred.model, "url_analysis"],
                )

        if explicit_benign_ev:
            pred = phish_preds[0]
            return ContradictionRecord(
                contradiction_id=self._next_id(),
                rule_id="RULE-CORR-ML-URL-CONFLICT",
                conflict_type="ml_vs_url_analysis",
                evidence_a_id=f"ML:{pred.model}:{pred.label}",
                evidence_b_id=explicit_benign_ev.evidence_id,
                explanation=(
                    f"Machine learning model '{pred.model}' predicted '{pred.label}' (confidence: {pred.confidence:.2f}), "
                    f"contradicting deterministic URL analysis which explicitly verified the URL as benign/trusted ({explicit_benign_ev.description}). "
                    f"Threat may involve multi-stage redirects, compromised legitimate site, or model false positive."
                ),
                provenance=[pred.model, "url_analysis"],
            )

        # Mere absence of suspicious URL evidence does NOT create a contradiction record.
        return None

    def _check_header_identity_divergence(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
    ) -> Optional[ContradictionRecord]:
        """From header domain conflicts with Return-Path or Reply-To domain."""
        m1_ev = by_module.get("sender_identity", [])
        div_ev = next(
            (e for e in m1_ev if e.rule_id in ("RULE-ID-REPLY-TO-MISMATCH", "RULE-ID-RETURN-PATH-MISMATCH")),
            None,
        )

        if div_ev:
            return ContradictionRecord(
                contradiction_id=self._next_id(),
                rule_id="RULE-CORR-EVIDENCE-CONFLICT",
                conflict_type="header_identity_divergence",
                evidence_a_id=f"{div_ev.evidence_id}:From",
                evidence_b_id=f"{div_ev.evidence_id}:Divergence",
                explanation=f"Header identity divergence observed: {div_ev.description}",
                provenance=["sender_identity"],
            )
        return None
