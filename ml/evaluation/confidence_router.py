"""
confidence_router.py - Multi-Tier Decision & Forensic Routing for SIH26106.

Policy & Rationale:
- Ground-truth datasets cannot legitimately supply static labels for 'suspicious' or 'impersonated'.
- 'Suspicious' is an uncertainty/risk-margin tier: When model confidence is borderline
  or prediction entropy is high, the email is routed to 'suspicious' for human/sandbox review.
- 'Impersonated' is a multi-modal forensic fusion tier: When Module 1 (Sender Identity Spoofing)
  flags header authentication failures (SPF/DKIM/DMARC) or display-name spoofing,
  an otherwise ambiguous email is escalated to 'impersonated'.
"""

from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple
import numpy as np


@dataclass
class RoutingDecision:
    """Final multi-tier classification verdict and forensic rationale."""
    final_label: str
    confidence: float
    raw_model_prediction: str
    is_escalated: bool
    escalation_reason: Optional[str] = None


class ThreatConfidenceRouter:
    """
    Inference-time routing engine that integrates Model 1 probabilities with
    optional Module 1 forensic signals.
    """

    def __init__(
        self,
        high_confidence_threshold: float = 0.75,
        suspicious_lower_bound: float = 0.40,
        suspicious_upper_bound: float = 0.75
    ):
        self.high_confidence_threshold = high_confidence_threshold
        self.suspicious_lower_bound = suspicious_lower_bound
        self.suspicious_upper_bound = suspicious_upper_bound

    def route(
        self,
        class_probabilities: Dict[str, float],
        sender_identity_signals: Optional[Dict[str, Any]] = None
    ) -> RoutingDecision:
        """
        Routes an email based on Model 1 class probabilities and Module 1 identity signals.
        
        Args:
            class_probabilities: Dict mapping class names to predicted probabilities,
                                e.g. {'legitimate': 0.2, 'phishing': 0.65, 'fraud_related': 0.15}
            sender_identity_signals: Optional forensic dictionary from Module 1:
                                     {
                                         'spf_pass': bool,
                                         'dkim_pass': bool,
                                         'dmarc_pass': bool,
                                         'display_name_spoofed': bool,
                                         'lookalike_domain': bool
                                     }
        """
        # Find raw predicted class and probability
        sorted_probs = sorted(class_probabilities.items(), key=lambda x: x[1], reverse=True)
        top_class, top_prob = sorted_probs[0]

        # 1. Check Forensic Spoofing Integration (Module 1 escalation -> 'impersonated')
        if sender_identity_signals:
            display_name_spoofed = sender_identity_signals.get("display_name_spoofed", False)
            lookalike_domain = sender_identity_signals.get("lookalike_domain", False)
            auth_failed = not (
                sender_identity_signals.get("spf_pass", True) and
                sender_identity_signals.get("dkim_pass", True) and
                sender_identity_signals.get("dmarc_pass", True)
            )

            # If sender identity spoofing is detected AND text has non-trivial threat signals
            threat_prob = sum(prob for c, prob in class_probabilities.items() if c in ("phishing", "fraud_related", "spam"))
            if (display_name_spoofed or lookalike_domain or auth_failed) and threat_prob >= 0.30:
                reason = []
                if display_name_spoofed:
                    reason.append("display_name_spoofed")
                if lookalike_domain:
                    reason.append("lookalike_domain")
                if auth_failed:
                    reason.append("auth_failed")
                return RoutingDecision(
                    final_label="impersonated",
                    confidence=top_prob,
                    raw_model_prediction=top_class,
                    is_escalated=True,
                    escalation_reason=f"Escalated to impersonated via Module 1 signals: {','.join(reason)}"
                )

        # 2. Check Uncertainty / Ambiguity Margin -> 'suspicious'
        # If the top threat class is in the ambiguous band [0.40, 0.75]
        if top_class in ("phishing", "fraud_related") and (self.suspicious_lower_bound <= top_prob < self.suspicious_upper_bound):
            return RoutingDecision(
                final_label="suspicious",
                confidence=top_prob,
                raw_model_prediction=top_class,
                is_escalated=True,
                escalation_reason=f"Model threat confidence ({top_prob:.2f}) falls within ambiguous threshold [{self.suspicious_lower_bound}, {self.suspicious_upper_bound}]"
            )

        # 3. High-Confidence Direct Classification
        return RoutingDecision(
            final_label=top_class,
            confidence=top_prob,
            raw_model_prediction=top_class,
            is_escalated=False,
            escalation_reason=None
        )
