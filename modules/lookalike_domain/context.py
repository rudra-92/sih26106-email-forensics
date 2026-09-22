"""Contextual validation and evidence correlation for lookalike domain detection.

Module 2 (Layer 3): Correlates Module 1 sender identity and authentication evidence
with Module 2 Layer 2 similarity candidate results to form an explainable investigative assessment.

Key Principles:
1. Investigative Assessment: Assesses suspicion in forensic context without claiming definitive attack proof.
2. Positive and Negative Evidence: Balances corroborating risk signals against mitigating contextual evidence.
3. No Double Counting: Correlated authentication checks (SPF/DKIM/DMARC) are evaluated as a cohesive cluster.
4. Valid Authentication Nuance: Passing SPF/DKIM does NOT clear a lookalike (evaluates registered lookalike domain hypothesis).
5. Explicitly Trusted Domains: Handled as explicit negative evidence rather than silent suppression.
6. Graph Validated Relationships: 'resembles' edge is emitted only when contextual evidence warrants it.
7. Bounded Confidence: Confidence scores are bounded (max 0.94) and represent heuristic evidence weight, not attack probability.
"""

from dataclasses import asdict, dataclass
from email.utils import parseaddr
import logging
from typing import Any, Dict, List, Optional, Set, Union

from .normalizer import extract_brand_from_display_name
from .similarity import CandidateResult

logger = logging.getLogger(__name__)

# Maximum bounded confidence (strictly < 1.0)
MAX_CONFIDENCE = 0.94


# =============================================================================
# Data Models
# =============================================================================


@dataclass(frozen=True)
class ContextualObservation:
    """Structured forensic finding generated during contextual correlation.

    Maintains strict provenance tracing back to Module 1 evidence and rule IDs.
    """
    observation_id: str
    rule_id: str
    source_module: str
    input_evidence_ids: List[str]
    description: str
    severity: str        # 'informational', 'low', 'medium', 'high'
    polarity: str        # 'positive' (threat indicator) or 'negative' (mitigating/contextual)
    fact_type: str       # 'observed', 'reported', 'inferred'
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HypothesisEvaluation:
    """Evaluation of a specific competing forensic explanation."""
    hypothesis: str
    supporting_observations: List[str]
    contradicting_observations: List[str]
    evidence_strength: str  # 'none', 'weak', 'moderate', 'strong'
    confidence: float       # Bounded float (0.0 to 0.94)
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis": self.hypothesis,
            "supporting_observations": self.supporting_observations,
            "contradicting_observations": self.contradicting_observations,
            "evidence_strength": self.evidence_strength,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ContextualAssessmentReport:
    """Final modular investigative assessment output for Module 2 Layer 3.

    Integrates Layer 2 candidate similarity metrics with Module 1 sender/auth evidence.
    """
    email_id: str
    observed_domain: str
    reference_domain: Optional[str]
    candidate_score: float
    category: str           # Leading hypothesis
    risk_level: str         # 'none', 'low', 'medium', 'high'
    evidence_strength: str  # 'none', 'weak', 'moderate', 'strong'
    confidence: float       # Bounded float (0.0 to 0.94)
    reason: str
    hypotheses: List[HypothesisEvaluation]
    positive_evidence: List[ContextualObservation]
    negative_evidence: List[ContextualObservation]
    validated_relationships: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email_id": self.email_id,
            "observed_domain": self.observed_domain,
            "reference_domain": self.reference_domain,
            "candidate_score": self.candidate_score,
            "category": self.category,
            "risk_level": self.risk_level,
            "evidence_strength": self.evidence_strength,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "positive_evidence": [o.to_dict() for o in self.positive_evidence],
            "negative_evidence": [o.to_dict() for o in self.negative_evidence],
            "validated_relationships": self.validated_relationships,
        }


# =============================================================================
# Helper Utilities: Safe Evidence Extraction from Module 1
# =============================================================================


def _extract_module1_evidence(sender_identity: Optional[Any]) -> Dict[str, Any]:
    """Safely extract identity, routing, and authentication fields from Module 1 output.

    Accepts SenderIdentityReport instance, dict, or None.
    """
    extracted: Dict[str, Any] = {
        "email_id": "E001",
        "from_domain": None,
        "reply_to_domain": None,
        "return_path_domain": None,
        "message_id_domain": None,
        "display_name": None,
        "spf_result": None,
        "dkim_result": None,
        "dmarc_result": None,
        "peer_ip": None,
        "m1_observation_ids": [],
        "m1_observations": [],
    }
    if sender_identity is None:
        return extracted

    # If sender_identity is a dict
    if isinstance(sender_identity, dict):
        extracted["email_id"] = sender_identity.get("email_id", "E001")
        if sender_identity.get("display_name"):
            extracted["display_name"] = str(sender_identity["display_name"]).strip()
        elif sender_identity.get("from_raw"):
            disp, _ = parseaddr(str(sender_identity["from_raw"]))
            if disp:
                extracted["display_name"] = disp.strip()

        # Extract observations
        obs_list = sender_identity.get("observations", [])
        extracted["m1_observations"] = obs_list
        extracted["m1_observation_ids"] = [
            o.get("observation_id") for o in obs_list if isinstance(o, dict) and "observation_id" in o
        ]
        # Extract entities for domain roles
        for ent in sender_identity.get("entities", []):
            if isinstance(ent, dict):
                t = ent.get("type")
                src = ent.get("source")
                val = ent.get("value")
                if t == "domain":
                    if src == "From" and not extracted["from_domain"]:
                        extracted["from_domain"] = val
                    elif src == "Reply-To" and not extracted["reply_to_domain"]:
                        extracted["reply_to_domain"] = val
                    elif src == "Return-Path" and not extracted["return_path_domain"]:
                        extracted["return_path_domain"] = val
                    elif src == "Message-ID" and not extracted["message_id_domain"]:
                        extracted["message_id_domain"] = val
                elif t == "ip" and ent.get("attributes", {}).get("role") == "peer_ip":
                    extracted["peer_ip"] = val

        # Extract auth and display results from observations if present
        for o in obs_list:
            if isinstance(o, dict):
                ev = o.get("evidence", {})
                if "reported_spf" in ev:
                    extracted["spf_result"] = str(ev.get("reported_spf")).lower()
                if "reported_dkim" in ev:
                    extracted["dkim_result"] = str(ev.get("reported_dkim")).lower()
                if "reported_dmarc" in ev:
                    extracted["dmarc_result"] = str(ev.get("reported_dmarc")).lower()
                if "spf" in ev and not extracted["spf_result"]:
                    extracted["spf_result"] = str(ev.get("spf")).lower()
                if "dkim" in ev and not extracted["dkim_result"]:
                    extracted["dkim_result"] = str(ev.get("dkim")).lower()
                if "dmarc" in ev and not extracted["dmarc_result"]:
                    extracted["dmarc_result"] = str(ev.get("dmarc")).lower()
                if "display_name" in ev and not extracted["display_name"]:
                    extracted["display_name"] = str(ev["display_name"]).strip()
                if "from_raw" in ev and not extracted["display_name"]:
                    disp, _ = parseaddr(str(ev["from_raw"]))
                    if disp:
                        extracted["display_name"] = disp.strip()

    # If sender_identity is an object (SenderIdentityReport)
    elif hasattr(sender_identity, "observations"):
        extracted["email_id"] = getattr(sender_identity, "email_id", "E001")
        if getattr(sender_identity, "display_name", None):
            extracted["display_name"] = str(sender_identity.display_name).strip()
        elif getattr(sender_identity, "from_raw", None):
            disp, _ = parseaddr(str(sender_identity.from_raw))
            if disp:
                extracted["display_name"] = disp.strip()

        obs_list = getattr(sender_identity, "observations", [])
        extracted["m1_observations"] = obs_list
        extracted["m1_observation_ids"] = [
            getattr(o, "observation_id", "") for o in obs_list if hasattr(o, "observation_id")
        ]
        entities = getattr(sender_identity, "entities", [])
        for ent in entities:
            t = getattr(ent, "type", None)
            src = getattr(ent, "source", None)
            val = getattr(ent, "value", None)
            attrs = getattr(ent, "attributes", {})
            if t == "domain":
                if src == "From" and not extracted["from_domain"]:
                    extracted["from_domain"] = val
                elif src == "Reply-To" and not extracted["reply_to_domain"]:
                    extracted["reply_to_domain"] = val
                elif src == "Return-Path" and not extracted["return_path_domain"]:
                    extracted["return_path_domain"] = val
                elif src == "Message-ID" and not extracted["message_id_domain"]:
                    extracted["message_id_domain"] = val
            elif t == "ip" and attrs.get("role") == "peer_ip":
                extracted["peer_ip"] = val

        for o in obs_list:
            ev = getattr(o, "evidence", {})
            if isinstance(ev, dict):
                if "reported_spf" in ev:
                    extracted["spf_result"] = str(ev.get("reported_spf")).lower()
                if "reported_dkim" in ev:
                    extracted["dkim_result"] = str(ev.get("reported_dkim")).lower()
                if "reported_dmarc" in ev:
                    extracted["dmarc_result"] = str(ev.get("reported_dmarc")).lower()
                if "spf" in ev and not extracted["spf_result"]:
                    extracted["spf_result"] = str(ev.get("spf")).lower()
                if "dkim" in ev and not extracted["dkim_result"]:
                    extracted["dkim_result"] = str(ev.get("dkim")).lower()
                if "dmarc" in ev and not extracted["dmarc_result"]:
                    extracted["dmarc_result"] = str(ev.get("dmarc")).lower()
                if "display_name" in ev and not extracted["display_name"]:
                    extracted["display_name"] = str(ev["display_name"]).strip()
                if "from_raw" in ev and not extracted["display_name"]:
                    disp, _ = parseaddr(str(ev["from_raw"]))
                    if disp:
                        extracted["display_name"] = disp.strip()

    return extracted


# =============================================================================
# Contextual Correlation & Validation Engine
# =============================================================================


def validate_candidate_context(
    candidate: Union[CandidateResult, Dict[str, Any]],
    sender_identity: Optional[Union[Any, Dict[str, Any]]] = None,
    trusted_domains: Optional[Union[Set[str], List[str]]] = None,
) -> ContextualAssessmentReport:
    """Correlate Layer 2 candidate similarity with Module 1 sender identity context.

    Evaluates competing hypotheses, balances positive and negative evidence,
    computes bounded risk metrics, and emits validated graph relationships.

    Args:
        candidate: CandidateResult instance or dict from Layer 2.
        sender_identity: Optional SenderIdentityReport or dict from Module 1.
        trusted_domains: Optional set of explicitly approved/known-vendor domains.

    Returns:
        ContextualAssessmentReport containing structured evidence, competing hypotheses,
        bounded assessment metrics, and validated graph edges.
    """
    # Normalize candidate fields
    if isinstance(candidate, dict):
        obs_domain = candidate.get("observed_domain", "")
        ref_domain = candidate.get("reference_domain", "")
        candidate_score = float(candidate.get("candidate_score", 0.0))
        is_candidate = bool(candidate.get("candidate", False))
        candidate_reason = candidate.get("reason", "")
        observed_token = candidate.get("observed_token")
        target_brand = candidate.get("target_brand")
        claimed_brand = candidate.get("claimed_brand")
    else:
        obs_domain = candidate.observed_domain
        ref_domain = candidate.reference_domain
        candidate_score = float(candidate.candidate_score)
        is_candidate = bool(candidate.candidate)
        candidate_reason = candidate.reason
        observed_token = getattr(candidate, "observed_token", None)
        target_brand = getattr(candidate, "target_brand", None)
        claimed_brand = getattr(candidate, "claimed_brand", None)

    trusted_set = set(d.lower() for d in trusted_domains) if trusted_domains else set()
    m1 = _extract_module1_evidence(sender_identity)
    email_id = m1["email_id"]

    # Deduce missing brand context if available from display name or domain labels
    if not claimed_brand and m1.get("display_name"):
        claimed_brand = extract_brand_from_display_name(m1["display_name"])
    if not target_brand and ref_domain:
        target_brand = ref_domain.split(".")[0]
    if not observed_token and obs_domain:
        observed_token = obs_domain.split(".")[0]

    pos_evidence: List[ContextualObservation] = []
    neg_evidence: List[ContextualObservation] = []
    obs_counter = 1

    def _next_obs_id() -> str:
        nonlocal obs_counter
        oid = f"OBS-LOOKALIKE-CTX-{obs_counter:03d}"
        obs_counter += 1
        return oid

    # Check 1: Low similarity / non-candidate short-circuit
    if not is_candidate or candidate_score < 0.70:
        hyp = HypothesisEvaluation(
            hypothesis="unlikely_domain_impersonation",
            supporting_observations=[],
            contradicting_observations=[],
            evidence_strength="none",
            confidence=0.10,
            reason="Observed domain shows low lexical resemblance to reference domains.",
        )
        return ContextualAssessmentReport(
            email_id=email_id,
            observed_domain=obs_domain,
            reference_domain=ref_domain,
            candidate_score=candidate_score,
            category="unlikely_domain_impersonation",
            risk_level="none",
            evidence_strength="none",
            confidence=0.10,
            reason=f"Observed domain '{obs_domain}' has low candidate resemblance score ({candidate_score:.2f}).",
            hypotheses=[hyp],
            positive_evidence=[],
            negative_evidence=[],
            validated_relationships=[],
        )

    # Record baseline candidate similarity observation preserving complete forensic provenance
    brand_desc = (
        f"Observed domain '{obs_domain}' (token '{observed_token}') resembles reference "
        f"brand '{target_brand}' ({ref_domain}) with candidate score {candidate_score:.4f} "
        f"({candidate_reason})."
    )
    base_obs = ContextualObservation(
        observation_id=_next_obs_id(),
        rule_id="RULE-LOOKALIKE-CANDIDATE-DETECTED",
        source_module="lookalike_domain",
        input_evidence_ids=[],
        description=brand_desc,
        severity="medium" if candidate_score < 0.85 else "high",
        polarity="positive",
        fact_type="inferred",
        evidence={
            "evidence_id": f"EVID-M2-{obs_domain}-{ref_domain}",
            "source_module": "lookalike_domain",
            "rule_id": "RULE-LOOKALIKE-CANDIDATE-DETECTED",
            "observed_domain": obs_domain,
            "observed_token": observed_token,
            "claimed_brand": claimed_brand,
            "reference_brand": target_brand,
            "reference_domain": ref_domain,
            "similarity_score": candidate_score,
            "candidate_state": is_candidate,
            "similarity_reason": candidate_reason,
            "trust_provenance": "bundled_reference_store",
        },
    )
    pos_evidence.append(base_obs)

    # -------------------------------------------------------------------------
    # Context Rule 0: Display Name Brand Alignment
    # -------------------------------------------------------------------------
    has_display_brand_alignment = False
    display_name = m1.get("display_name")
    if (
        claimed_brand
        and target_brand
        and (
            claimed_brand.lower() == target_brand.lower()
            or claimed_brand.lower() in target_brand.lower()
            or target_brand.lower() in claimed_brand.lower()
        )
    ):
        has_display_brand_alignment = True
        disp_m1_ids = [
            oid for oid in m1["m1_observation_ids"]
            if any(term in oid for term in ("DISPLAY", "FROM"))
        ]
        disp_obs = ContextualObservation(
            observation_id=_next_obs_id(),
            rule_id="RULE-LOOKALIKE-DISPLAY-NAME-BRAND-ALIGNMENT",
            source_module="lookalike_domain",
            input_evidence_ids=disp_m1_ids,
            description=(
                f"Sender display name '{display_name or claimed_brand}' claims brand '{claimed_brand}', "
                f"which aligns with protected reference brand '{target_brand}' ({ref_domain}) "
                f"resembled by observed token '{observed_token}' in domain '{obs_domain}'. "
                "Contextual evidence corroborates potential brand impersonation."
            ),
            severity="high" if candidate_score >= 0.80 else "medium",
            polarity="positive",
            fact_type="observed",
            evidence={
                "evidence_id": f"EVID-M2-CTX-DISPLAY-{obs_domain}",
                "source_module": "lookalike_domain",
                "rule_id": "RULE-LOOKALIKE-DISPLAY-NAME-BRAND-ALIGNMENT",
                "observed_domain": obs_domain,
                "observed_token": observed_token,
                "claimed_brand": claimed_brand,
                "display_name": display_name,
                "reference_brand": target_brand,
                "reference_domain": ref_domain,
                "similarity_score": candidate_score,
                "candidate_state": is_candidate,
                "trust_provenance": "header_from_display_name",
            },
        )
        pos_evidence.append(disp_obs)

    # -------------------------------------------------------------------------
    # Context Rule 1: Trusted / Known-Domain Exception
    # -------------------------------------------------------------------------
    is_trusted = (obs_domain.lower() in trusted_set)
    if is_trusted:
        trusted_obs = ContextualObservation(
            observation_id=_next_obs_id(),
            rule_id="RULE-LOOKALIKE-TRUSTED-EXCEPTION",
            source_module="lookalike_domain",
            input_evidence_ids=[],
            description=(
                f"Observed domain '{obs_domain}' is an explicitly configured trusted or partner domain. "
                f"Resemblance to '{ref_domain}' is evaluated as benign legitimate co-existence."
            ),
            severity="informational",
            polarity="negative",
            fact_type="observed",
            evidence={
                "observed_domain": obs_domain,
                "reference_domain": ref_domain,
                "trusted_status": "explicitly_trusted",
            },
        )
        neg_evidence.append(trusted_obs)

    # -------------------------------------------------------------------------
    # Context Rule 2: Correlated Authentication Cluster (No Double-Counting)
    # -------------------------------------------------------------------------
    # Group SPF, DKIM, DMARC reported failures into a single cohesive cluster
    spf = m1["spf_result"]
    dkim = m1["dkim_result"]
    dmarc = m1["dmarc_result"]

    auth_failures = []
    auth_passes = []
    if spf in ("fail", "softfail"):
        auth_failures.append(f"SPF ({spf})")
    elif spf == "pass":
        auth_passes.append("SPF (pass)")

    if dkim in ("fail",):
        auth_failures.append(f"DKIM ({dkim})")
    elif dkim == "pass":
        auth_passes.append("DKIM (pass)")

    if dmarc in ("fail",):
        auth_failures.append(f"DMARC ({dmarc})")
    elif dmarc == "pass":
        auth_passes.append("DMARC (pass)")

    # Trace input M1 observation IDs related to auth
    auth_m1_ids = [
        oid for oid in m1["m1_observation_ids"]
        if any(term in oid for term in ("AUTH", "SPF", "DKIM", "DMARC"))
    ]

    if auth_failures:
        # Case A: Correlated Authentication Failures
        num_fails = len(auth_failures)
        auth_fail_obs = ContextualObservation(
            observation_id=_next_obs_id(),
            rule_id="RULE-LOOKALIKE-AUTH-FAILURE-CLUSTER",
            source_module="lookalike_domain",
            input_evidence_ids=auth_m1_ids,
            description=(
                f"Receiving server reported authentication failures for '{obs_domain}' "
                f"resembling '{ref_domain}': {', '.join(auth_failures)}. "
                "Evaluated as a correlated authentication cluster."
            ),
            severity="high" if num_fails >= 2 else "medium",
            polarity="positive",
            fact_type="reported",
            evidence={
                "reported_failures": auth_failures,
                "num_failed_mechanisms": num_fails,
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
            },
        )
        pos_evidence.append(auth_fail_obs)

    elif len(auth_passes) >= 2 and not auth_failures:
        # Case B: Valid Authentication does NOT automatically clear the candidate!
        # Case of registered lookalike domain
        auth_valid_obs = ContextualObservation(
            observation_id=_next_obs_id(),
            rule_id="RULE-LOOKALIKE-AUTHENTICATED-DOMAIN",
            source_module="lookalike_domain",
            input_evidence_ids=auth_m1_ids,
            description=(
                f"Observed domain '{obs_domain}' resembles reference domain '{ref_domain}' "
                f"while authentication is valid for the observed domain ({', '.join(auth_passes)}). "
                "Represents a potential registered lookalike domain scenario."
            ),
            severity="medium",
            polarity="positive",
            fact_type="reported",
            evidence={
                "reported_passes": auth_passes,
                "spf": spf,
                "dkim": dkim,
                "dmarc": dmarc,
                "scenario": "possible_registered_lookalike",
            },
        )
        pos_evidence.append(auth_valid_obs)

        # Also preserve negative evidence that cryptographic signature and SPF matched
        neg_auth_obs = ContextualObservation(
            observation_id=_next_obs_id(),
            rule_id="RULE-LOOKALIKE-AUTH-PASS-NEGATIVE-EVIDENCE",
            source_module="lookalike_domain",
            input_evidence_ids=auth_m1_ids,
            description=(
                f"Authentication checks passed cryptographically for '{obs_domain}' "
                f"({', '.join(auth_passes)})."
            ),
            severity="informational",
            polarity="negative",
            fact_type="reported",
            evidence={"reported_passes": auth_passes},
        )
        neg_evidence.append(neg_auth_obs)

    # -------------------------------------------------------------------------
    # Context Rule 3: Reply-To Divergence
    # -------------------------------------------------------------------------
    reply_to_dom = m1["reply_to_domain"]
    from_dom = m1["from_domain"] or obs_domain

    reply_to_m1_ids = [
        oid for oid in m1["m1_observation_ids"]
        if "REPLY" in oid
    ]

    if reply_to_dom and from_dom and reply_to_dom.lower() != from_dom.lower():
        replyto_obs = ContextualObservation(
            observation_id=_next_obs_id(),
            rule_id="RULE-LOOKALIKE-REPLYTO-DIVERGENCE",
            source_module="lookalike_domain",
            input_evidence_ids=reply_to_m1_ids,
            description=(
                f"Reply-To domain '{reply_to_dom}' diverges from visible From domain '{from_dom}', "
                f"which resembles protected reference domain '{ref_domain}'."
            ),
            severity="high",
            polarity="positive",
            fact_type="observed",
            evidence={
                "from_domain": from_dom,
                "reply_to_domain": reply_to_dom,
                "reference_domain": ref_domain,
            },
        )
        pos_evidence.append(replyto_obs)

    # -------------------------------------------------------------------------
    # Context Rule 4: Return-Path & Message-ID Routing Inconsistency
    # -------------------------------------------------------------------------
    return_path_dom = m1["return_path_domain"]
    esp_indicators = ("sendgrid", "mailchimp", "sparkpost", "amazonses", "mailgun")

    if return_path_dom and from_dom and return_path_dom.lower() != from_dom.lower():
        is_esp = any(esp in return_path_dom.lower() for esp in esp_indicators)
        if is_esp:
            # Legitimate bulk ESP relay indicator -> negative/mitigating evidence
            esp_obs = ContextualObservation(
                observation_id=_next_obs_id(),
                rule_id="RULE-LOOKALIKE-ESP-RELAY-CONTEXT",
                source_module="lookalike_domain",
                input_evidence_ids=[],
                description=(
                    f"Return-Path '{return_path_dom}' indicates a recognized bulk email service provider (ESP), "
                    "which is common in legitimate third-party sending."
                ),
                severity="low",
                polarity="negative",
                fact_type="observed",
                evidence={"return_path_domain": return_path_dom, "esp_relay": True},
            )
            neg_evidence.append(esp_obs)
        else:
            routing_obs = ContextualObservation(
                observation_id=_next_obs_id(),
                rule_id="RULE-LOOKALIKE-ROUTING-MISMATCH",
                source_module="lookalike_domain",
                input_evidence_ids=[],
                description=(
                    f"Return-Path domain '{return_path_dom}' does not align with sender domain '{from_dom}'."
                ),
                severity="medium",
                polarity="positive",
                fact_type="observed",
                evidence={"from_domain": from_dom, "return_path_domain": return_path_dom},
            )
            pos_evidence.append(routing_obs)

    # -------------------------------------------------------------------------
    # Hypothesis Formulation & Competing Forensic Evaluation
    # -------------------------------------------------------------------------
    # 1. Hypothesis: possible_domain_impersonation
    # Supported by: high similarity + auth failures, reply-to mismatch, or display name brand alignment
    impers_supporting = [
        o.observation_id for o in pos_evidence
        if o.rule_id in (
            "RULE-LOOKALIKE-CANDIDATE-DETECTED",
            "RULE-LOOKALIKE-DISPLAY-NAME-BRAND-ALIGNMENT",
            "RULE-LOOKALIKE-AUTH-FAILURE-CLUSTER",
            "RULE-LOOKALIKE-REPLYTO-DIVERGENCE",
            "RULE-LOOKALIKE-ROUTING-MISMATCH",
        )
    ]
    impers_contradicting = [o.observation_id for o in neg_evidence]

    # Calculate confidence for possible_domain_impersonation
    has_auth_fail = any(o.rule_id == "RULE-LOOKALIKE-AUTH-FAILURE-CLUSTER" for o in pos_evidence)
    has_replyto_mismatch = any(o.rule_id == "RULE-LOOKALIKE-REPLYTO-DIVERGENCE" for o in pos_evidence)

    if is_trusted:
        conf_impers = 0.15
        strength_impers = "none"
        reason_impers = "Domain is explicitly configured as trusted."
    elif (has_auth_fail and has_replyto_mismatch) or (has_display_brand_alignment and (has_auth_fail or has_replyto_mismatch)):
        conf_impers = min(MAX_CONFIDENCE, 0.70 + (candidate_score * 0.15) + 0.08)
        strength_impers = "strong"
        reason_impers = "High domain similarity coupled with reported authentication failures, display name alignment, or Reply-To divergence."
    elif has_auth_fail or has_replyto_mismatch:
        conf_impers = min(MAX_CONFIDENCE, 0.65 + (candidate_score * 0.15))
        strength_impers = "moderate"
        reason_impers = "Domain similarity combined with authentication failure or identity inconsistency."
    elif has_display_brand_alignment:
        conf_impers = min(MAX_CONFIDENCE, 0.60 + (candidate_score * 0.15))
        strength_impers = "moderate"
        reason_impers = f"Domain token '{observed_token}' resembles protected brand '{target_brand}' with corroborating claimed brand '{claimed_brand}' in display name."
    else:
        conf_impers = 0.40
        strength_impers = "weak"
        reason_impers = "Resemblance exists, but corroborating identity or authentication failure is absent."

    hyp_impersonation = HypothesisEvaluation(
        hypothesis="possible_domain_impersonation",
        supporting_observations=impers_supporting,
        contradicting_observations=impers_contradicting,
        evidence_strength=strength_impers,
        confidence=conf_impers,
        reason=reason_impers,
    )

    # 2. Hypothesis: possible_authenticated_lookalike_domain
    # Supported by: high similarity + valid SPF/DKIM
    has_auth_pass_scenario = any(o.rule_id == "RULE-LOOKALIKE-AUTHENTICATED-DOMAIN" for o in pos_evidence)
    auth_lookalike_supporting = [
        o.observation_id for o in pos_evidence
        if o.rule_id in ("RULE-LOOKALIKE-CANDIDATE-DETECTED", "RULE-LOOKALIKE-AUTHENTICATED-DOMAIN")
    ]
    auth_lookalike_contradicting = [
        o.observation_id for o in pos_evidence
        if o.rule_id == "RULE-LOOKALIKE-AUTH-FAILURE-CLUSTER"
    ] + [o.observation_id for o in neg_evidence if o.rule_id == "RULE-LOOKALIKE-TRUSTED-EXCEPTION"]

    if is_trusted:
        conf_auth_lookalike = 0.15
        strength_auth_lookalike = "none"
        reason_auth_lookalike = "Domain is explicitly trusted."
    elif has_auth_pass_scenario and not has_auth_fail:
        conf_auth_lookalike = min(0.78, 0.50 + (candidate_score * 0.25))
        strength_auth_lookalike = "moderate"
        reason_auth_lookalike = (
            "Domain resembles protected brand while possessing valid cryptographic authentication, "
            "consistent with a registered lookalike domain."
        )
    else:
        conf_auth_lookalike = 0.20
        strength_auth_lookalike = "none"
        reason_auth_lookalike = "Authentication results do not fit an authenticated lookalike pattern."

    hyp_auth_lookalike = HypothesisEvaluation(
        hypothesis="possible_authenticated_lookalike_domain",
        supporting_observations=auth_lookalike_supporting,
        contradicting_observations=auth_lookalike_contradicting,
        evidence_strength=strength_auth_lookalike,
        confidence=conf_auth_lookalike,
        reason=reason_auth_lookalike,
    )

    # 3. Hypothesis: possible_legitimate_third_party_sender
    third_party_supporting = [o.observation_id for o in neg_evidence]
    third_party_contradicting = [
        o.observation_id for o in pos_evidence
        if o.rule_id in ("RULE-LOOKALIKE-AUTH-FAILURE-CLUSTER", "RULE-LOOKALIKE-REPLYTO-DIVERGENCE")
    ]
    if is_trusted:
        conf_third_party = 0.85
        strength_third_party = "strong"
        reason_third_party = "Domain is verified in trusted/partner domain configuration."
    elif any(o.rule_id == "RULE-LOOKALIKE-ESP-RELAY-CONTEXT" for o in neg_evidence):
        conf_third_party = 0.65
        strength_third_party = "moderate"
        reason_third_party = "Routing aligns with legitimate bulk ESP delegation patterns."
    else:
        conf_third_party = 0.20
        strength_third_party = "none"
        reason_third_party = "No positive indicators of recognized third-party delegation."

    hyp_third_party = HypothesisEvaluation(
        hypothesis="possible_legitimate_third_party_sender",
        supporting_observations=third_party_supporting,
        contradicting_observations=third_party_contradicting,
        evidence_strength=strength_third_party,
        confidence=conf_third_party,
        reason=reason_third_party,
    )

    # 4. Hypothesis: lookalike_candidate_without_strong_context
    if (not is_trusted and
        not has_auth_fail and
        not has_auth_pass_scenario and
        not has_replyto_mismatch):
        conf_no_context = min(0.68, 0.40 + (candidate_score * 0.25))
        strength_no_context = "moderate"
        reason_no_context = (
            "The observed domain resembles a trusted reference domain, "
            "but no strong additional sender-identity anomaly was observed."
        )
    else:
        conf_no_context = 0.25
        strength_no_context = "weak"
        reason_no_context = "Clear positive or negative context is present."

    hyp_no_context = HypothesisEvaluation(
        hypothesis="lookalike_candidate_without_strong_context",
        supporting_observations=[base_obs.observation_id],
        contradicting_observations=[],
        evidence_strength=strength_no_context,
        confidence=conf_no_context,
        reason=reason_no_context,
    )

    hypotheses = [
        hyp_impersonation,
        hyp_auth_lookalike,
        hyp_third_party,
        hyp_no_context,
    ]

    # Select leading hypothesis
    leading_hyp = max(hypotheses, key=lambda h: h.confidence)
    category = leading_hyp.hypothesis
    final_confidence = leading_hyp.confidence

    # Determine risk level and overall evidence strength
    if category == "possible_domain_impersonation":
        if final_confidence >= 0.75:
            risk_level = "high"
            evidence_strength = "strong"
        else:
            risk_level = "medium"
            evidence_strength = "moderate"
        overall_reason = leading_hyp.reason

    elif category == "possible_authenticated_lookalike_domain":
        risk_level = "medium"
        evidence_strength = "moderate"
        overall_reason = (
            f"The observed domain '{obs_domain}' resembles protected reference domain '{ref_domain}' "
            "while valid authentication was reported for the lookalike domain itself."
        )

    elif category == "possible_legitimate_third_party_sender":
        risk_level = "low"
        evidence_strength = "moderate" if is_trusted else "weak"
        overall_reason = leading_hyp.reason

    else:  # lookalike_candidate_without_strong_context
        risk_level = "medium"
        evidence_strength = "moderate"
        overall_reason = leading_hyp.reason

    # -------------------------------------------------------------------------
    # Graph Relationship Creation
    # -------------------------------------------------------------------------
    # 'resembles' edge is ONLY emitted if contextual evidence is substantiated
    # (i.e. not explicitly trusted and category indicates lookalike concern)
    validated_relationships: List[Dict[str, Any]] = []

    if (not is_trusted and
        candidate_score >= 0.75 and
        category in (
            "possible_domain_impersonation",
            "possible_authenticated_lookalike_domain",
            "lookalike_candidate_without_strong_context",
        )):
        supporting_obs_ids = [o.observation_id for o in pos_evidence]
        validated_relationships.append({
            "source": obs_domain,
            "relation": "resembles",
            "target": ref_domain,
            "evidence": {
                "candidate_score": candidate_score,
                "authentication_context": {
                    "spf": spf,
                    "dkim": dkim,
                    "dmarc": dmarc,
                },
                "supporting_observations": supporting_obs_ids,
            },
        })

    return ContextualAssessmentReport(
        email_id=email_id,
        observed_domain=obs_domain,
        reference_domain=ref_domain,
        candidate_score=candidate_score,
        category=category,
        risk_level=risk_level,
        evidence_strength=evidence_strength,
        confidence=final_confidence,
        reason=overall_reason,
        hypotheses=hypotheses,
        positive_evidence=pos_evidence,
        negative_evidence=neg_evidence,
        validated_relationships=validated_relationships,
    )
