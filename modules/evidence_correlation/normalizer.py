"""Evidence normalizer for Module 6: Evidence Correlation & Attribution Support.

Ingests heterogeneous forensic report outputs from Modules 1–5 (as dataclass instances or dicts)
and external ML model predictions, transforming them into a unified list of NormalizedEvidence
with standardized trust states ('observed', 'verified', 'enriched', 'inferred', 'unknown').
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from .ml_adapters import UnifiedMlAdapter
from .models import MlPrediction, NormalizedEvidence


class EvidenceNormalizer:
    """Normalizes heterogeneous findings across all pipeline modules and ML models."""

    def __init__(self, case_id: str = "CASE-001") -> None:
        self.case_id = case_id
        self._counter = 1

    def _next_id(self, prefix: str) -> str:
        eid = f"EV-{prefix}-{self._counter:04d}"
        self._counter += 1
        return eid

    def normalize_all(
        self,
        module1_report: Optional[Union[Dict[str, Any], Any]] = None,
        module2_report: Optional[Union[Dict[str, Any], Any]] = None,
        module3_report: Optional[Union[Dict[str, Any], Any]] = None,
        module4_report: Optional[Union[Dict[str, Any], Any]] = None,
        module5_report: Optional[Union[Dict[str, Any], Any]] = None,
        ml_predictions: Optional[List[MlPrediction]] = None,
    ) -> List[NormalizedEvidence]:
        """Normalize all available forensic reports and ML predictions into a unified evidence list."""
        all_evidence: List[NormalizedEvidence] = []

        if module1_report is not None:
            all_evidence.extend(self._normalize_module1(module1_report))

        if module2_report is not None:
            all_evidence.extend(self._normalize_module2(module2_report))

        if module3_report is not None:
            all_evidence.extend(self._normalize_module3(module3_report))

        if module4_report is not None:
            all_evidence.extend(self._normalize_module4(module4_report))

        if module5_report is not None:
            all_evidence.extend(self._normalize_module5(module5_report))

        if ml_predictions:
            ml_ev = UnifiedMlAdapter.to_normalized_evidence(ml_predictions, start_index=self._counter)
            self._counter += len(ml_ev)
            all_evidence.extend(ml_ev)

        return all_evidence

    def _normalize_module1(self, report: Any) -> List[NormalizedEvidence]:
        """Normalize Module 1 (Sender Identity & Authentication) findings."""
        ev_list: List[NormalizedEvidence] = []
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        # Authentication results (deterministic observed facts)
        auth_res = d.get("auth_results")
        if isinstance(auth_res, dict):
            for method in ("spf", "dkim", "dmarc"):
                val = auth_res.get(method)
                if val:
                    if isinstance(val, dict):
                        res_str = str(val.get("result", "")).lower()
                        scope = str(val.get("scope", ""))
                        dom = str(val.get("domain", ""))
                        desc = f"{method.upper()} authentication result: {res_str}"
                        if scope or dom:
                            desc += f" (scope={scope}, domain={dom})"
                        supp = dict(val)
                    else:
                        res_str = str(val).lower()
                        dom = ""
                        desc = f"{method.upper()} authentication result: {res_str}"
                        supp = {"result": res_str}

                    sev = "informational" if res_str in ("pass", "none") else "medium"
                    ev_list.append(
                        NormalizedEvidence(
                            evidence_id=self._next_id(f"M1-{method.upper()}"),
                            source_module="sender_identity",
                            evidence_type="authentication_result",
                            rule_id=f"RULE-M1-AUTH-{method.upper()}-{res_str.upper()}",
                            severity=sev,
                            trust_state="observed",
                            description=desc,
                            entity_ids=[dom] if dom else [],
                            timestamp=None,
                            provenance=["sender_identity", f"auth_results.{method}"],
                            supporting_fields=supp,
                        )
                    )

        # Observations
        for obs in d.get("observations", []):
            o_dict = obs if isinstance(obs, dict) else (obs.to_dict() if hasattr(obs, "to_dict") else {})
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M1-OBS"),
                    source_module="sender_identity",
                    evidence_type="observation",
                    rule_id=o_dict.get("rule_id", "RULE-ID-OBSERVATION"),
                    severity=o_dict.get("severity", "informational"),
                    trust_state="observed",
                    description=o_dict.get("description", "Sender identity observation"),
                    entity_ids=[],
                    timestamp=None,
                    provenance=["sender_identity", o_dict.get("source_header", "header")],
                    supporting_fields=o_dict.get("evidence", {}),
                )
            )

        # Overall assessment
        ass = d.get("assessment")
        if ass and isinstance(ass, dict):
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M1-ASS"),
                    source_module="sender_identity",
                    evidence_type="assessment",
                    rule_id="RULE-M1-ASSESSMENT",
                    severity=ass.get("risk_level", "low"),
                    trust_state="inferred",
                    description=ass.get("reason", "Module 1 Sender Identity Assessment"),
                    entity_ids=[],
                    timestamp=None,
                    provenance=["sender_identity"],
                    supporting_fields={
                        "category": ass.get("category"),
                        "risk_level": ass.get("risk_level"),
                        "evidence_strength": ass.get("evidence_strength"),
                        "confidence": ass.get("confidence", 0.0),
                    },
                )
            )

        return ev_list

    def _normalize_module2(self, report: Any) -> List[NormalizedEvidence]:
        """Normalize Module 2 (Lookalike Domain Detection) findings."""
        ev_list: List[NormalizedEvidence] = []
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        # Direct lookalike indication
        if d.get("is_lookalike"):
            target_b = str(d.get("target_brand", "unknown"))
            q_dom = str(d.get("query_domain") or d.get("observed_domain", ""))
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M2-LOOKALIKE"),
                    source_module="lookalike_domain",
                    evidence_type="lookalike_signal",
                    rule_id="RULE-LOOKALIKE-MATCH",
                    severity="high",
                    trust_state="observed",
                    description=f"Domain '{q_dom}' is an identified lookalike of brand '{target_b}'",
                    entity_ids=[q_dom] if q_dom else [],
                    timestamp=None,
                    provenance=["lookalike_domain"],
                    supporting_fields={"target_brand": target_b, "query_domain": q_dom, "is_lookalike": True},
                )
            )

        # Positive lookalike indicators
        for obs in d.get("positive_evidence", []):
            o_dict = obs if isinstance(obs, dict) else (obs.to_dict() if hasattr(obs, "to_dict") else {})
            fact_t = o_dict.get("fact_type", "observed")
            trust = "observed" if fact_t == "observed" else "inferred"
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M2-POS"),
                    source_module="lookalike_domain",
                    evidence_type="lookalike_signal",
                    rule_id=o_dict.get("rule_id", "RULE-LOOKALIKE-MATCH"),
                    severity=o_dict.get("severity", "medium"),
                    trust_state=trust,
                    description=o_dict.get("description", "Lookalike domain similarity indicator"),
                    entity_ids=[d.get("observed_domain", "")] if d.get("observed_domain") else [],
                    timestamp=None,
                    provenance=["lookalike_domain"],
                    supporting_fields=o_dict.get("evidence", {}),
                )
            )

        # Negative / mitigating evidence
        for obs in d.get("negative_evidence", []):
            o_dict = obs if isinstance(obs, dict) else (obs.to_dict() if hasattr(obs, "to_dict") else {})
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M2-NEG"),
                    source_module="lookalike_domain",
                    evidence_type="lookalike_mitigation",
                    rule_id=o_dict.get("rule_id", "RULE-LOOKALIKE-MITIGATION"),
                    severity="informational",
                    trust_state="observed",
                    description=o_dict.get("description", "Mitigating domain evidence"),
                    entity_ids=[d.get("observed_domain", "")] if d.get("observed_domain") else [],
                    timestamp=None,
                    provenance=["lookalike_domain"],
                    supporting_fields=o_dict.get("evidence", {}),
                )
            )

        # Candidate score evidence
        if d.get("candidate_score", 0.0) > 0.0:
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M2-SCORE"),
                    source_module="lookalike_domain",
                    evidence_type="candidate_score",
                    rule_id="RULE-LOOKALIKE-SCORE",
                    severity="high" if d.get("candidate_score", 0.0) >= 0.70 else "medium",
                    trust_state="inferred",
                    description=f"Domain '{d.get('observed_domain')}' resembles reference '{d.get('reference_domain')}' (score: {d.get('candidate_score', 0.0):.2f})",
                    entity_ids=[d.get("observed_domain", ""), d.get("reference_domain", "")] if d.get("reference_domain") else [],
                    timestamp=None,
                    provenance=["lookalike_domain"],
                    supporting_fields={
                        "observed_domain": d.get("observed_domain"),
                        "reference_domain": d.get("reference_domain"),
                        "candidate_score": d.get("candidate_score"),
                    },
                )
            )

        return ev_list

    def _normalize_module3(self, report: Any) -> List[NormalizedEvidence]:
        """Normalize Module 3 (URL Analysis) findings."""
        ev_list: List[NormalizedEvidence] = []
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        # URL Observations
        for obs in d.get("observations", []):
            o_dict = obs if isinstance(obs, dict) else (obs.to_dict() if hasattr(obs, "to_dict") else {})
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M3-OBS"),
                    source_module="url_analysis",
                    evidence_type="url_observation",
                    rule_id=o_dict.get("rule_id", "RULE-URL-ANOMALY"),
                    severity=o_dict.get("severity", "informational"),
                    trust_state="observed",
                    description=o_dict.get("description", "URL forensic observation"),
                    entity_ids=[],
                    timestamp=None,
                    provenance=["url_analysis"],
                    supporting_fields=o_dict.get("evidence", {}),
                )
            )

        # Extracted URLs
        for url_item in d.get("urls", []):
            u_dict = url_item if isinstance(url_item, dict) else (url_item.to_dict() if hasattr(url_item, "to_dict") else {})
            norm_u = u_dict.get("normalized_url", u_dict.get("actual_url", ""))
            if norm_u:
                ev_list.append(
                    NormalizedEvidence(
                        evidence_id=self._next_id("M3-URL"),
                        source_module="url_analysis",
                        evidence_type="extracted_url",
                        rule_id="RULE-URL-EXTRACTED",
                        severity="informational",
                        trust_state="observed",
                        description=f"Extracted URL: {norm_u}",
                        entity_ids=[norm_u],
                        timestamp=None,
                        provenance=["url_analysis", u_dict.get("source", "body")],
                        supporting_fields=u_dict,
                    )
                )

        return ev_list

    def _normalize_module4(self, report: Any) -> List[NormalizedEvidence]:
        """Normalize Module 4 (Attachment Analysis) findings."""
        ev_list: List[NormalizedEvidence] = []
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        # Attachment Observations
        for obs in d.get("observations", []):
            o_dict = obs if isinstance(obs, dict) else (obs.to_dict() if hasattr(obs, "to_dict") else {})
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M4-OBS"),
                    source_module="attachment_analysis",
                    evidence_type="attachment_anomaly",
                    rule_id=o_dict.get("rule_id", "RULE-ATTACHMENT-ANOMALY"),
                    severity=o_dict.get("severity", "informational"),
                    trust_state="observed",
                    description=o_dict.get("description", "Attachment forensic observation"),
                    entity_ids=[o_dict.get("attachment_id", "")] if o_dict.get("attachment_id") else [],
                    timestamp=None,
                    provenance=["attachment_analysis"],
                    supporting_fields=o_dict.get("evidence", {}),
                )
            )

        # Extracted Attachments metadata
        for att in d.get("attachments", []):
            a_dict = att if isinstance(att, dict) else (att.to_dict() if hasattr(att, "to_dict") else {})
            fn = a_dict.get("filename", "")
            sha = a_dict.get("sha256", "")
            entities = [x for x in [fn, sha] if x]
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M4-ATT"),
                    source_module="attachment_analysis",
                    evidence_type="attachment_metadata",
                    rule_id="RULE-ATTACHMENT-EXTRACTED",
                    severity="informational",
                    trust_state="observed",
                    description=f"Attachment '{fn}' (SHA-256: {sha[:12]}...)" if sha else f"Attachment '{fn}'",
                    entity_ids=entities,
                    timestamp=None,
                    provenance=["attachment_analysis"],
                    supporting_fields=a_dict,
                )
            )

        return ev_list

    def _normalize_module5(self, report: Any) -> List[NormalizedEvidence]:
        """Normalize Module 5 (Origin & Infrastructure Reconstruction) findings."""
        ev_list: List[NormalizedEvidence] = []
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        # Observations
        for obs in d.get("observations", []):
            o_dict = obs if isinstance(obs, dict) else (obs.to_dict() if hasattr(obs, "to_dict") else {})
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=self._next_id("M5-OBS"),
                    source_module="origin_infrastructure",
                    evidence_type="routing_anomaly",
                    rule_id=o_dict.get("rule_id", "RULE-ORIGIN-OBSERVATION"),
                    severity=o_dict.get("severity", "informational"),
                    trust_state=o_dict.get("trust_state", "observed"),
                    description=o_dict.get("description", "Origin infrastructure observation"),
                    entity_ids=[],
                    timestamp=None,
                    provenance=["origin_infrastructure"],
                    supporting_fields=o_dict.get("evidence", {}),
                )
            )

        # Origin assessment
        orig_ass = d.get("origin_assessment")
        if orig_ass and isinstance(orig_ass, dict):
            peer = orig_ass.get("earliest_reliable_peer")
            if peer:
                ev_list.append(
                    NormalizedEvidence(
                        evidence_id=self._next_id("M5-PEER"),
                        source_module="origin_infrastructure",
                        evidence_type="origin_assessment",
                        rule_id="RULE-ORIGIN-EARLIEST-PEER",
                        severity="informational",
                        trust_state="inferred",
                        description=orig_ass.get("assessment_reason", f"Earliest reliable external peer: {peer}"),
                        entity_ids=[peer],
                        timestamp=None,
                        provenance=["origin_infrastructure"],
                        supporting_fields={
                            "earliest_reliable_peer": peer,
                            "source_visibility": orig_ass.get("source_visibility"),
                            "confidence": orig_ass.get("confidence", 0.0),
                        },
                    )
                )

        # Enriched peers location evidence
        for peer in d.get("enriched_peers", []):
            p_dict = peer if isinstance(peer, dict) else (peer.to_dict() if hasattr(peer, "to_dict") else {})
            ip = p_dict.get("ip", "")
            loc_ev = p_dict.get("location_evidence")
            if loc_ev and isinstance(loc_ev, dict):
                ev_list.append(
                    NormalizedEvidence(
                        evidence_id=self._next_id("M5-GEO"),
                        source_module="origin_infrastructure",
                        evidence_type="location_evidence",
                        rule_id="RULE-ORIGIN-LOCATION-EVIDENCE",
                        severity="informational",
                        trust_state="enriched",
                        description=f"Location evidence for IP {ip}: agreement={loc_ev.get('country_agreement')}, interpretation='{loc_ev.get('interpretation')}'",
                        entity_ids=[ip] if ip else [],
                        timestamp=None,
                        provenance=loc_ev.get("provenance", ["origin_infrastructure"]),
                        supporting_fields=loc_ev,
                    )
                )

        return ev_list
