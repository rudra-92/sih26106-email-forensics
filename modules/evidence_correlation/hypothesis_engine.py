"""Hypothesis engine for Module 6: Evidence Correlation & Attribution Support.

Generates and ranks competing, case-level forensic hypotheses explaining observed multi-module
evidence and ML predictions.

STRICT FORENSIC PRINCIPLES:
- Evaluates competing explanations with explicit supporting and contradicting evidence.
- Bounded heuristic confidence (<= 0.94); never claims 100% mathematical certainty.
- Explicitly sets confidence_metric = 'heuristic_non_calibrated_consensus'.
- Never outputs guaranteed attacker identity.
"""

from __future__ import annotations

import re
from typing import List, Optional

from .models import (
    CampaignCluster,
    CaseHypothesis,
    ContradictionRecord,
    CorroboratedFinding,
    MlPrediction,
    NormalizedEvidence,
)
from .normalizer import is_documentation_or_test_ip


class CaseHypothesisEngine:
    """Evaluates multi-module evidence and ML predictions into ranked investigative hypotheses."""

    def evaluate_hypotheses(
        self,
        evidence_list: List[NormalizedEvidence],
        corroborated_findings: List[CorroboratedFinding],
        contradictions: List[ContradictionRecord],
        clusters: List[CampaignCluster],
        ml_predictions: Optional[List[MlPrediction]] = None,
    ) -> List[CaseHypothesis]:
        """Generate competing case hypotheses supported by observable evidence."""
        hypotheses: List[CaseHypothesis] = []
        ml_preds = ml_predictions or []

        # Find contradicting evidence items for reference
        contradicting_summaries = [c.explanation for c in contradictions]

        # 1. Hypothesis: possible_domain_impersonation
        h_impersonation = self._eval_domain_impersonation(evidence_list, corroborated_findings, contradicting_summaries)
        if h_impersonation:
            hypotheses.append(h_impersonation)

        # 2. Hypothesis: possible_phishing / possible_credential_harvesting
        h_phish = self._eval_phishing_and_credential_harvesting(evidence_list, corroborated_findings, ml_preds, contradicting_summaries)
        if h_phish:
            hypotheses.append(h_phish)

        # 3. Hypothesis: possible_bec_attempt
        h_bec = self._eval_bec_attempt(evidence_list, corroborated_findings, ml_preds, contradicting_summaries)
        if h_bec:
            hypotheses.append(h_bec)

        # 4. Hypothesis: possible_campaign_reuse
        h_campaign = self._eval_campaign_reuse(clusters, contradicting_summaries)
        if h_campaign:
            hypotheses.append(h_campaign)

        # 5. Hypothesis: possible_provider_masking
        h_masking = self._eval_provider_masking(evidence_list, contradicting_summaries)
        if h_masking:
            hypotheses.append(h_masking)

        # 6. Hypothesis: possible_anonymized_infrastructure
        h_anon = self._eval_anonymized_infrastructure(evidence_list, contradicting_summaries)
        if h_anon:
            hypotheses.append(h_anon)

        # 7. Hypothesis: possible_compromised_account
        h_comp = self._eval_compromised_account(evidence_list, contradictions, contradicting_summaries)
        if h_comp:
            hypotheses.append(h_comp)

        # Fallback: insufficient_evidence if no hypotheses generated
        if not hypotheses:
            hypotheses.append(
                CaseHypothesis(
                    hypothesis_type="insufficient_evidence",
                    heuristic_confidence=0.10,
                    confidence_metric="heuristic_non_calibrated_consensus",
                    supporting_evidence=["No conclusive cross-module anomalies detected."],
                    contradicting_evidence=[],
                    source_modules=["evidence_correlation"],
                    trust_state="inferred",
                    provenance={"engine": "CaseHypothesisEngine"},
                )
            )

        # Sort descending by heuristic confidence
        hypotheses.sort(key=lambda h: h.heuristic_confidence, reverse=True)
        return hypotheses

    def _eval_domain_impersonation(
        self,
        evidence: List[NormalizedEvidence],
        findings: List[CorroboratedFinding],
        contradictions: List[str],
    ) -> Optional[CaseHypothesis]:
        # Only consider positive M2 evidence
        m2_pos = [
            e for e in evidence
            if e.source_module == "lookalike_domain"
            and e.severity in ("medium", "high")
            and e.evidence_type in ("lookalike_signal", "candidate_score")
            and e.supporting_fields.get("candidate", True) is not False
            and e.supporting_fields.get("is_candidate", True) is not False
            and e.supporting_fields.get("is_lookalike", True) is not False
            and not e.supporting_fields.get("rejected", False)
        ]
        has_id_finding = any(f.finding_type == "correlated_identity_deception" for f in findings)

        # Explicit check: Never convert unlikely_domain_impersonation into possible_domain_impersonation
        # without positive Module 2 evidence
        m2_explicitly_unlikely = any(
            e.source_module == "lookalike_domain"
            and (
                e.rule_id in ("RULE-LOOKALIKE-REJECTED-CANDIDATE", "RULE-LOOKALIKE-UNLIKELY")
                or e.supporting_fields.get("hypothesis") == "unlikely_domain_impersonation"
                or e.supporting_fields.get("candidate") is False
                or e.supporting_fields.get("is_candidate") is False
                or e.supporting_fields.get("rejected") is True
            )
            for e in evidence
        )

        if m2_explicitly_unlikely and not m2_pos:
            return None

        if not m2_pos and not has_id_finding:
            return None

        supp = [e.description for e in m2_pos[:3]]
        if has_id_finding:
            supp.append("Corroborated identity deception across sender headers and lookalike domain.")

        conf = 0.88 if has_id_finding else 0.75
        return CaseHypothesis(
            hypothesis_type="possible_domain_impersonation",
            heuristic_confidence=conf,
            confidence_metric="heuristic_non_calibrated_consensus",
            supporting_evidence=supp,
            contradicting_evidence=list(contradictions[:2]),
            source_modules=["lookalike_domain", "sender_identity"],
            trust_state="inferred",
            provenance={"engine": "CaseHypothesisEngine"},
        )

    def _eval_phishing_and_credential_harvesting(
        self,
        evidence: List[NormalizedEvidence],
        findings: List[CorroboratedFinding],
        ml_preds: List[MlPrediction],
        contradictions: List[str],
    ) -> Optional[CaseHypothesis]:
        m3_ev = [e for e in evidence if e.source_module == "url_analysis" and e.severity in ("medium", "high")]
        phish_findings = [f for f in findings if f.finding_type == "correlated_credential_phishing"]
        ml_phish = [p for p in ml_preds if p.label in ("phishing", "credential_harvesting") and p.confidence >= 0.70]

        if m3_ev or phish_findings or ml_phish:
            supp = [e.description for e in m3_ev[:2]]
            if phish_findings:
                supp.append(phish_findings[0].description)
            for p in ml_phish:
                supp.append(f"ML model '{p.model}' predicted '{p.label}' (score: {p.confidence:.2f})")

            conf = 0.90 if (phish_findings and ml_phish) else (0.80 if phish_findings else 0.68)
            return CaseHypothesis(
                hypothesis_type="possible_credential_harvesting" if any("credential" in s.lower() for s in supp) else "possible_phishing",
                heuristic_confidence=conf,
                confidence_metric="heuristic_non_calibrated_consensus",
                supporting_evidence=supp,
                contradicting_evidence=list(contradictions[:2]),
                source_modules=["url_analysis", "external_ml"],
                trust_state="inferred",
                provenance={"engine": "CaseHypothesisEngine"},
            )
        return None

    def _eval_bec_attempt(
        self,
        evidence: List[NormalizedEvidence],
        findings: List[CorroboratedFinding],
        ml_preds: List[MlPrediction],
        contradictions: List[str],
    ) -> Optional[CaseHypothesis]:
        bec_findings = [f for f in findings if f.finding_type == "correlated_bec_impersonation"]
        ml_bec = [p for p in ml_preds if p.model == "bec_intent_classifier" and p.confidence >= 0.70]
        m1_display = [e for e in evidence if e.source_module == "sender_identity" and "display" in e.description.lower()]

        if bec_findings or (ml_bec and m1_display):
            supp = []
            if bec_findings:
                supp.append(bec_findings[0].description)
            for p in ml_bec:
                supp.append(f"BEC Intent classifier predicted '{p.label}' (score: {p.confidence:.2f})")
            supp.extend([e.description for e in m1_display[:2]])

            return CaseHypothesis(
                hypothesis_type="possible_bec_attempt",
                heuristic_confidence=0.86 if bec_findings else 0.74,
                confidence_metric="heuristic_non_calibrated_consensus",
                supporting_evidence=supp,
                contradicting_evidence=list(contradictions[:2]),
                source_modules=["bec_intent_classifier", "sender_identity"],
                trust_state="inferred",
                provenance={"engine": "CaseHypothesisEngine"},
            )
        return None

    def _eval_campaign_reuse(
        self,
        clusters: List[CampaignCluster],
        contradictions: List[str],
    ) -> Optional[CaseHypothesis]:
        if clusters:
            supp = [c.description for c in clusters[:3]]
            return CaseHypothesis(
                hypothesis_type="possible_campaign_reuse",
                heuristic_confidence=0.82,
                confidence_metric="heuristic_non_calibrated_consensus",
                supporting_evidence=supp,
                contradicting_evidence=list(contradictions[:2]),
                source_modules=["temporal_correlation"],
                trust_state="inferred",
                provenance={"engine": "CaseHypothesisEngine"},
            )
        return None

    def _eval_provider_masking(
        self,
        evidence: List[NormalizedEvidence],
        contradictions: List[str],
    ) -> Optional[CaseHypothesis]:
        m5_masking = [e for e in evidence if e.source_module == "origin_infrastructure" and "hosting" in e.description.lower()]
        if m5_masking:
            return CaseHypothesis(
                hypothesis_type="possible_provider_masking",
                heuristic_confidence=0.72,
                confidence_metric="heuristic_non_calibrated_consensus",
                supporting_evidence=[e.description for e in m5_masking[:2]],
                contradicting_evidence=list(contradictions[:2]),
                source_modules=["origin_infrastructure"],
                trust_state="inferred",
                provenance={"engine": "CaseHypothesisEngine"},
            )
        return None

    def _eval_anonymized_infrastructure(
        self,
        evidence: List[NormalizedEvidence],
        contradictions: List[str],
    ) -> Optional[CaseHypothesis]:
        # 1. Check if direct_origin was explicitly assessed by Module 5
        has_direct_origin = any(
            e.source_module == "origin_infrastructure"
            and (
                e.supporting_fields.get("hypothesis_type") == "possible_direct_origin"
                or e.supporting_fields.get("classification") == "direct_origin"
                or e.rule_id == "HYPO-DIRECT-ORIGIN"
                or "possible_direct_origin" in e.description
            )
            for e in evidence
        )

        # 2. Check for explicit anonymized infrastructure indicators
        m5_anon = []
        for e in evidence:
            if e.source_module != "origin_infrastructure":
                continue

            # Documentation/test IPs must not be interpreted as real anonymized infrastructure
            peer_ip = str(e.supporting_fields.get("earliest_reliable_peer") or e.supporting_fields.get("ip") or "")
            if is_documentation_or_test_ip(peer_ip) or e.supporting_fields.get("is_documentation_ip") is True:
                continue

            # Explicit rule IDs or hypothesis types
            if e.rule_id in ("RULE-ORIGIN-TOR-EXIT", "RULE-ORIGIN-VPN-EXIT", "HYPO-ANONYMIZED-INFRA"):
                m5_anon.append(e)
            elif (
                e.evidence_type == "origin_hypothesis"
                and e.supporting_fields.get("hypothesis_type") == "possible_anonymized_infrastructure"
            ):
                m5_anon.append(e)
            elif (
                e.supporting_fields.get("is_tor") is True
                or e.supporting_fields.get("is_vpn") is True
                or e.supporting_fields.get("is_proxy") is True
            ):
                m5_anon.append(e)
            elif re.search(
                r"\b(tor exit|tor node|vpn endpoint|vpn relay|anonymizer|anonymizing proxy)\b",
                e.description,
                re.IGNORECASE,
            ):
                m5_anon.append(e)

        # If direct origin was assessed and there is NO explicit anonymizer proof, do not infer anonymized infrastructure
        if has_direct_origin and not m5_anon:
            return None

        if m5_anon:
            return CaseHypothesis(
                hypothesis_type="possible_anonymized_infrastructure",
                heuristic_confidence=0.85,
                confidence_metric="heuristic_non_calibrated_consensus",
                supporting_evidence=[e.description for e in m5_anon[:2]],
                contradicting_evidence=list(contradictions[:2]),
                source_modules=["origin_infrastructure"],
                trust_state="inferred",
                provenance={"engine": "CaseHypothesisEngine"},
            )
        return None

    def _eval_compromised_account(
        self,
        evidence: List[NormalizedEvidence],
        contradictions: List[ContradictionRecord],
        contradicting_summaries: List[str],
    ) -> Optional[CaseHypothesis]:
        # Valid auth pass + suspicious behavior from genuine domain or user/server country conflict
        auth_conflict = any(c.conflict_type == "auth_vs_lookalike" for c in contradictions)
        geo_conflict = any(c.conflict_type == "user_vs_server_country" for c in contradictions)

        if auth_conflict or geo_conflict:
            supp = []
            if auth_conflict:
                supp.append("Authentication passes on unaligned or suspicious domain.")
            if geo_conflict:
                supp.append("User country differs from transmission server relay country.")

            return CaseHypothesis(
                hypothesis_type="possible_compromised_account",
                heuristic_confidence=0.65,
                confidence_metric="heuristic_non_calibrated_consensus",
                supporting_evidence=supp,
                contradicting_evidence=contradicting_summaries[:2],
                source_modules=["origin_infrastructure", "sender_identity"],
                trust_state="inferred",
                provenance={"engine": "CaseHypothesisEngine"},
            )
        return None
