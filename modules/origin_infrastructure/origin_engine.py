"""Origin candidate selection and boundary engine for Origin & Infrastructure Reconstruction.

Identifies the earliest reliable external peer and observable origin infrastructure
by walking transmission hops backwards from the recipient's verified boundary.

Explicit constraint: Never designates an observed peer as a 'guaranteed attacker IP'.
Distinguishes between direct observable peers, mail provider relays, provider-masked
origins, and insufficient evidence.
"""

from typing import List, Optional, Tuple

from .models import (
    ArcAnalysisResult,
    OriginAssessment,
    OriginCandidate,
    ReconstructedHop,
    TemporalAnalysisResult,
)
from .received_parser import is_private_ip

# Known public cloud / webmail providers that mask client origin IPs
KNOWN_MAIL_RELAY_DOMAINS = {
    "google.com", "gmail.com", "googlemail.com", "outbound.protection.outlook.com",
    "microsoft.com", "outlook.com", "hotmail.com", "mail.protection.outlook.com",
    "amazonses.com", "sendgrid.net", "mailgun.org", "yahoo.com", "yahoodns.net",
    "zoho.com", "protonmail.ch", "proton.me", "mandrillapp.com",
}


def is_known_provider_hostname(hostname: Optional[str]) -> bool:
    """Check if a hostname belongs to a known public cloud mail relay or provider."""
    if not hostname:
        return False
    h = hostname.lower()
    return any(h == domain or h.endswith(f".{domain}") for domain in KNOWN_MAIL_RELAY_DOMAINS)


class OriginEngine:
    """Evaluates reconstructed hops to select the earliest reliable external peer."""

    def __init__(
        self,
        max_heuristic_confidence: float = 0.94,
    ) -> None:
        self.max_confidence = max_heuristic_confidence

    def evaluate(
        self,
        hops: List[ReconstructedHop],
        temporal_result: Optional[TemporalAnalysisResult] = None,
        arc_result: Optional[ArcAnalysisResult] = None,
    ) -> Tuple[List[OriginCandidate], OriginAssessment]:
        """Determine earliest reliable external peer candidates and overall origin assessment.

        Traverses hops in reverse order (from recipient's border gateway towards origin):
        - Sequential hops are indexed 1 (earliest) to N (latest / recipient).
        - We inspect from Hop N backwards to find the boundary crossing from external networks.
        - We then evaluate upstream hops to see if earlier reliable external peers exist.

        Args:
            hops: ReconstructedHop list ordered 1 (earliest) to N (latest).
            temporal_result: TemporalAnalysisResult (optional).
            arc_result: ArcAnalysisResult (optional).

        Returns:
            Tuple of (List[OriginCandidate], OriginAssessment).
        """
        if not hops:
            return [], OriginAssessment(
                earliest_reliable_peer=None,
                peer_hostname=None,
                source_visibility="insufficient_evidence",
                confidence=0.0,
                assessment_reason="No transmission hops available to analyze.",
            )

        candidates: List[OriginCandidate] = []
        boundary_hop: Optional[ReconstructedHop] = None

        # 1. Walk from latest hop (N) down to earliest hop (1) to identify external border gateway
        for hop in reversed(hops):
            source_is_priv = hop.is_source_private or is_private_ip(hop.source_ip)
            if hop.source_ip and not source_is_priv:
                if boundary_hop is None:
                    boundary_hop = hop
                break

        # 2. Case: No public source IP found anywhere in the chain
        if not boundary_hop or not boundary_hop.source_ip:
            assessment = OriginAssessment(
                earliest_reliable_peer=None,
                peer_hostname=None,
                source_visibility="insufficient_evidence",
                confidence=0.0,
                assessment_reason=(
                    "No public IP addresses found in the observable transmission path. "
                    "All hops are internal, private, or missing routable peer IPs."
                ),
            )
            return [], assessment

        # 3. Analyze candidate hops from hop 1 up to boundary_hop
        # Inspect for incomplete hops, contradictory evidence, and timestamp anomalies
        earliest_reliable_hop: Optional[ReconstructedHop] = None
        has_contradictory_evidence = False
        contradictory_reasons: List[str] = []

        # Find negative intervals or future timestamps by hop sequence
        negative_hop_seqs = set()
        if temporal_result and temporal_result.hop_delays_seconds:
            for idx, delay in enumerate(temporal_result.hop_delays_seconds):
                if delay is not None and delay < 0:
                    # Delay from hop idx+1 to idx+2 is negative
                    negative_hop_seqs.add(idx + 1)

        # Inspect candidate hops starting from earliest (hop 1) up to boundary_hop
        for hop in hops:
            if hop.hop_sequence_num > boundary_hop.hop_sequence_num:
                continue

            source_is_priv = hop.is_source_private or is_private_ip(hop.source_ip)
            if source_is_priv or not hop.source_ip:
                continue

            # Check if this hop is incomplete (missing both source and receiver host)
            if not hop.source_host and not hop.receiver_host:
                continue

            # Check for contradictory timestamp evidence on this hop
            if hop.hop_sequence_num in negative_hop_seqs:
                has_contradictory_evidence = True
                contradictory_reasons.append(
                    f"Hop {hop.hop_sequence_num} ({hop.source_ip}) has negative transit interval (chronology contradiction)."
                )
                continue

            # If no contradictory evidence, this is a candidate reliable external hop
            if earliest_reliable_hop is None:
                earliest_reliable_hop = hop

        # If all upstream hops had contradictory evidence or were incomplete, fall back to boundary_hop
        if earliest_reliable_hop is None:
            earliest_reliable_hop = boundary_hop

        earliest_ip = earliest_reliable_hop.source_ip or ""
        earliest_host = earliest_reliable_hop.source_host
        earliest_seq = earliest_reliable_hop.hop_sequence_num

        # Check if there are internal/private hops prior to the earliest public hop (hop 1 to earliest_seq - 1)
        prior_hops = [h for h in hops if h.hop_sequence_num < earliest_seq]
        has_prior_internal = any(
            h.source_ip and (h.is_source_private or is_private_ip(h.source_ip))
            for h in prior_hops
        )

        # Check if earliest public hop is a known webmail/cloud provider
        is_provider = is_known_provider_hostname(earliest_host)

        # Base confidence calculation
        confidence = 0.85

        # Factor in temporal consistency
        if temporal_result:
            if not temporal_result.chronology_consistent or temporal_result.negative_intervals > 0:
                confidence -= 0.15
            if temporal_result.future_timestamps > 0:
                confidence -= 0.10

        # Factor in ARC validation
        if arc_result and arc_result.is_chain_valid:
            confidence += 0.05

        confidence = max(0.20, min(self.max_confidence, confidence))

        # Determine role and visibility
        if is_provider and has_prior_internal:
            role = "mail_provider"
            source_visibility = "provider_masked"
            reasoning = (
                f"Hop {earliest_seq} connects via known mail provider infrastructure '{earliest_host or earliest_ip}'. "
                f"Upstream client origin is masked by provider internal hops. "
                "Represents earliest observable infrastructure supported by available evidence (unverified threat actor origin)."
            )
        elif is_provider and earliest_seq == 1:
            role = "mail_provider"
            source_visibility = "provider_masked"
            reasoning = (
                f"Earliest observable hop is known mail provider relay '{earliest_host or earliest_ip}'. "
                "True client source IP is not visible in transmission headers. "
                "Represents earliest observable infrastructure supported by available evidence (unverified threat actor origin)."
            )
        elif has_contradictory_evidence:
            role = "earliest_reliable_external_peer"
            source_visibility = "ambiguous"
            reasoning = (
                f"Hop {earliest_seq} is the earliest reliable external peer ({earliest_ip}) supported by consistent evidence. "
                f"Upstream headers contain contradictory timestamp evidence: {'; '.join(contradictory_reasons)}. "
                "Observable transport peer only (unverified threat actor origin)."
            )
        else:
            role = "earliest_reliable_external_peer"
            source_visibility = "visible"
            reasoning = (
                f"Hop {earliest_seq} represents the earliest reliable external peer ({earliest_ip}) "
                f"observable in the reconstructed transmission path. "
                "Identified as earliest externally observable infrastructure supported by available evidence (unverified threat actor origin)."
            )

        trust_state = (
            "trusted_configured"
            if earliest_reliable_hop.trust_state == "trusted_configured"
            else "inferred"
        )

        candidate = OriginCandidate(
            ip=earliest_ip,
            hostname=earliest_host,
            role=role,
            confidence=confidence,
            trust_state=trust_state,
            hop_sequence_num=earliest_seq,
            source_visibility=source_visibility,
            reasoning=reasoning,
        )
        candidates.append(candidate)

        # If boundary hop is different from earliest reliable hop, record it as upstream_relay candidate
        if boundary_hop.hop_sequence_num != earliest_seq and boundary_hop.source_ip:
            b_ip = boundary_hop.source_ip
            b_host = boundary_hop.source_host
            candidates.append(
                OriginCandidate(
                    ip=b_ip,
                    hostname=b_host,
                    role="upstream_relay",
                    confidence=min(self.max_confidence, confidence - 0.10),
                    trust_state=(
                        "trusted_configured"
                        if boundary_hop.trust_state == "trusted_configured"
                        else "inferred"
                    ),
                    hop_sequence_num=boundary_hop.hop_sequence_num,
                    source_visibility="visible",
                    reasoning=(
                        f"Intermediate border peer connecting to receiving gateway at hop {boundary_hop.hop_sequence_num}. "
                        "Observed transport infrastructure."
                    ),
                )
            )

        assessment = OriginAssessment(
            earliest_reliable_peer=earliest_ip,
            peer_hostname=earliest_host,
            source_visibility=source_visibility,
            confidence=confidence,
            assessment_reason=reasoning,
        )

        return candidates, assessment
