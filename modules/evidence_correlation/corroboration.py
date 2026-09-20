"""Cross-module corroboration engine for Module 6.

Identifies multi-module forensic alignment where independent evidence sources
(e.g., identity divergence + lookalike domain + deceptive URL + macro attachment)
jointly substantiate high-order forensic findings.

STRICT SEMANTIC RULES:
- Never sums or multiplies probabilities.
- Uses explicit heuristic support strength ('low', 'medium', 'high', 'critical').
- Sets confidence_metric = 'heuristic_non_calibrated_consensus'.
- Emits comprehensive lists of backing evidence IDs.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from .models import CorroboratedFinding, MlPrediction, NormalizedEvidence


class CorroborationEngine:
    """Evaluates multi-module evidence alignment and produces corroborated findings."""

    def __init__(self) -> None:
        self._counter = 1

    def _next_id(self) -> str:
        fid = f"CORR-FIND-{self._counter:04d}"
        self._counter += 1
        return fid

    def find_corroborations(
        self,
        evidence_list: List[NormalizedEvidence],
        ml_predictions: Optional[List[MlPrediction]] = None,
    ) -> List[CorroboratedFinding]:
        """Correlate all normalized evidence items and ML predictions into findings."""
        findings: List[CorroboratedFinding] = []

        # Index evidence by source module and rule IDs
        by_module: Dict[str, List[NormalizedEvidence]] = {}
        for ev in evidence_list:
            by_module.setdefault(ev.source_module, []).append(ev)

        # 1. Correlated Identity Deception (M1 + M2 + M3)
        id_finding = self._check_identity_deception(by_module)
        if id_finding:
            findings.append(id_finding)

        # 2. Correlated Credential Phishing (M3 + M1/M2 + ML)
        phish_finding = self._check_credential_phishing(by_module, ml_predictions or [])
        if phish_finding:
            findings.append(phish_finding)

        # 3. Correlated Malware Delivery (M4 + M5 + ML)
        mal_finding = self._check_malware_delivery(by_module, ml_predictions or [])
        if mal_finding:
            findings.append(mal_finding)

        # 4. Correlated Infrastructure Abuse (M5 + M1/M3)
        infra_finding = self._check_infrastructure_abuse(by_module)
        if infra_finding:
            findings.append(infra_finding)

        # 5. Correlated BEC Impersonation (BEC ML + M1 Display Name / Divergence)
        bec_finding = self._check_bec_impersonation(by_module, ml_predictions or [])
        if bec_finding:
            findings.append(bec_finding)

        return findings

    def _check_identity_deception(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
    ) -> Optional[CorroboratedFinding]:
        """M2 lookalike domain + M1 reply-to/return-path divergence + M3 matching URL domain."""
        m1_ev = by_module.get("sender_identity", [])
        m2_ev = by_module.get("lookalike_domain", [])
        m3_ev = by_module.get("url_analysis", [])

        has_m1_div = any(
            "divergence" in ev.description.lower()
            or "reply-to" in ev.description.lower()
            or "spoof" in ev.description.lower()
            or ev.rule_id in ("RULE-ID-REPLY-TO-MISMATCH", "RULE-ID-RETURN-PATH-MISMATCH")
            for ev in m1_ev
        )
        has_m2_lookalike = any(
            ev.evidence_type in ("lookalike_signal", "candidate_score")
            or "resembles" in ev.description.lower()
            for ev in m2_ev
        )
        has_m3_url_domain = any(
            ev.evidence_type == "extracted_url"
            for ev in m3_ev
        )

        supporting_eids: List[str] = []
        modules: List[str] = []

        if has_m1_div and has_m2_lookalike:
            modules.extend(["sender_identity", "lookalike_domain"])
            for e in m1_ev:
                if "divergence" in e.description.lower() or "reply-to" in e.description.lower():
                    supporting_eids.append(e.evidence_id)
            for e in m2_ev:
                if e.evidence_type in ("lookalike_signal", "candidate_score"):
                    supporting_eids.append(e.evidence_id)

            strength = "high"
            if has_m3_url_domain:
                modules.append("url_analysis")
                for e in m3_ev[:2]:
                    supporting_eids.append(e.evidence_id)
                strength = "critical"

            return CorroboratedFinding(
                finding_id=self._next_id(),
                finding_type="correlated_identity_deception",
                title="Correlated Identity Deception Across Sender and Domain",
                description=(
                    "Independent evidence from Sender Identity (M1) and Lookalike Domain Detection (M2) "
                    "corroborates active identity deception through unaligned routing headers and deceptive domain registration."
                ),
                supporting_evidence_ids=supporting_eids,
                source_modules=modules,
                heuristic_support_strength=strength,
                confidence_metric="heuristic_non_calibrated_consensus",
            )
        return None

    def _check_credential_phishing(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
        ml_predictions: List[MlPrediction],
    ) -> Optional[CorroboratedFinding]:
        """M3 visible/href mismatch or login cues + M1/M2 brand mismatch + ML phishing prediction."""
        m3_ev = by_module.get("url_analysis", [])
        m2_ev = by_module.get("lookalike_domain", [])
        m1_ev = by_module.get("sender_identity", [])

        has_url_mismatch = any(
            "mismatch" in ev.description.lower()
            or "visible" in ev.description.lower()
            or "login" in ev.description.lower()
            or "redirect" in ev.description.lower()
            for ev in m3_ev
        )
        has_sender_anomaly = any(ev.severity in ("medium", "high") for ev in m1_ev)
        has_domain_deception = any(e.evidence_type == "lookalike_signal" for e in m2_ev)
        has_ml_phishing = any(
            p.label in ("phishing", "credential_harvesting") and p.confidence >= 0.70
            for p in ml_predictions
        )

        supporting_eids: List[str] = []
        modules: List[str] = []

        if (has_url_mismatch and (has_domain_deception or has_ml_phishing or has_sender_anomaly)) or (has_domain_deception and has_ml_phishing):
            if has_url_mismatch:
                modules.append("url_analysis")
                for e in m3_ev:
                    if "mismatch" in e.description.lower() or "login" in e.description.lower():
                        supporting_eids.append(e.evidence_id)

            if has_sender_anomaly:
                modules.append("sender_identity")
                for e in m1_ev:
                    if e.severity in ("medium", "high"):
                        supporting_eids.append(e.evidence_id)

            if has_domain_deception:
                modules.append("lookalike_domain")
                for e in m2_ev:
                    if e.evidence_type == "lookalike_signal":
                        supporting_eids.append(e.evidence_id)

            if has_ml_phishing:
                modules.append("external_ml")

            return CorroboratedFinding(
                finding_id=self._next_id(),
                finding_type="correlated_credential_phishing",
                title="Correlated Credential Phishing Attack Vectors",
                description=(
                    "Identified lookalike/impersonation domain corroborates with external ML threat classifier "
                    "or structural URL deception, indicating an active phishing vector."
                ),
                supporting_evidence_ids=supporting_eids,
                source_modules=modules,
                heuristic_support_strength="critical" if (has_domain_deception and has_ml_phishing) else "high",
                confidence_metric="heuristic_non_calibrated_consensus",
            )
        return None

    def _check_malware_delivery(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
        ml_predictions: List[MlPrediction],
    ) -> Optional[CorroboratedFinding]:
        """M4 suspicious attachment + M5 provider masking/anonymization + ML malware threat."""
        m4_ev = by_module.get("attachment_analysis", [])
        m5_ev = by_module.get("origin_infrastructure", [])

        has_att_anomaly = any(
            "macro" in ev.description.lower()
            or "executable" in ev.description.lower()
            or "double extension" in ev.description.lower()
            or "signature mismatch" in ev.description.lower()
            or ev.severity in ("high", "medium")
            for ev in m4_ev
        )
        has_m5_suspicious = any(
            "anonymized" in ev.description.lower()
            or "tor" in ev.description.lower()
            or "hosting" in ev.description.lower()
            for ev in m5_ev
        )
        has_ml_malware = any(p.label == "malware" and p.confidence >= 0.70 for p in ml_predictions)

        supporting_eids: List[str] = []
        modules: List[str] = []

        if has_att_anomaly and (has_m5_suspicious or has_ml_malware):
            modules.append("attachment_analysis")
            for e in m4_ev:
                if e.severity in ("high", "medium"):
                    supporting_eids.append(e.evidence_id)

            if has_m5_suspicious:
                modules.append("origin_infrastructure")
                for e in m5_ev:
                    if "anonymized" in e.description.lower() or "tor" in e.description.lower():
                        supporting_eids.append(e.evidence_id)

            if has_ml_malware:
                modules.append("external_ml")

            return CorroboratedFinding(
                finding_id=self._next_id(),
                finding_type="correlated_malware_delivery",
                title="Correlated Malicious Attachment Delivery",
                description=(
                    "Static attachment anomalies (executable/macro capability) corroborated by "
                    "anonymized/cloud origin infrastructure and machine learning threat models."
                ),
                supporting_evidence_ids=supporting_eids,
                source_modules=modules,
                heuristic_support_strength="critical" if has_ml_malware else "high",
                confidence_metric="heuristic_non_calibrated_consensus",
            )
        return None

    def _check_infrastructure_abuse(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
    ) -> Optional[CorroboratedFinding]:
        """M5 cloud/hosting/anonymized origin + M1 unverified earliest peer."""
        m5_ev = by_module.get("origin_infrastructure", [])
        m1_ev = by_module.get("sender_identity", [])

        has_m5_hosting = any(
            "hosting" in ev.description.lower()
            or "cloud" in ev.description.lower()
            or "tor" in ev.description.lower()
            for ev in m5_ev
        )
        has_m1_unverified = any(
            "unverified" in ev.description.lower() or "unaligned" in ev.description.lower()
            for ev in m1_ev
        )

        if has_m5_hosting and has_m1_unverified:
            supp_eids = [e.evidence_id for e in m5_ev[:2]] + [e.evidence_id for e in m1_ev[:2]]
            return CorroboratedFinding(
                finding_id=self._next_id(),
                finding_type="correlated_infrastructure_abuse",
                title="Correlated Infrastructure Abuse & Masking",
                description=(
                    "Origin infrastructure demonstrates commercial cloud hosting or proxying coupled with "
                    "unverified peer transport boundaries."
                ),
                supporting_evidence_ids=supp_eids,
                source_modules=["origin_infrastructure", "sender_identity"],
                heuristic_support_strength="medium",
                confidence_metric="heuristic_non_calibrated_consensus",
            )
        return None

    def _check_bec_impersonation(
        self,
        by_module: Dict[str, List[NormalizedEvidence]],
        ml_predictions: List[MlPrediction],
    ) -> Optional[CorroboratedFinding]:
        """BEC ML prediction + M1 display name spoofing / Reply-To divergence."""
        bec_preds = [
            p for p in ml_predictions
            if p.model == "bec_intent_classifier"
            and p.label in ("wire_fraud", "gift_card", "urgent_request", "payroll_diversion", "credential_harvesting")
            and p.confidence >= 0.70
        ]
        m1_ev = by_module.get("sender_identity", [])
        has_display_spoof = any(
            "display" in ev.description.lower()
            or "reply-to" in ev.description.lower()
            for ev in m1_ev
        )

        if bec_preds and (has_display_spoof or len(m1_ev) > 0):
            supp_eids = [e.evidence_id for e in m1_ev[:2]]
            return CorroboratedFinding(
                finding_id=self._next_id(),
                finding_type="correlated_bec_impersonation",
                title="Correlated Business Email Compromise (BEC) Indicator",
                description=(
                    f"External BEC Intent model classified message as '{bec_preds[0].label}' "
                    f"(confidence: {bec_preds[0].confidence:.2f}), corroborated by sender header patterns."
                ),
                supporting_evidence_ids=supp_eids,
                source_modules=["bec_intent_classifier", "sender_identity"],
                heuristic_support_strength="high",
                confidence_metric="heuristic_non_calibrated_consensus",
            )
        return None
