"""Competing origin hypothesis engine for Origin & Infrastructure Reconstruction.

Synthesizes transport hop evidence, authentication findings, temporal consistency,
and infrastructure classifications into competing heuristic hypotheses.

Explicit constraint: Confidence is heuristic and bounded (maximum 0.94).
Evaluates multiple competing hypotheses instead of forcing a singular speculative claim.
"""

from typing import List, Optional

from .models import (
    ArcAnalysisResult,
    EnrichedInfrastructure,
    OriginCandidate,
    OriginHypothesis,
    ReconstructedHop,
    TemporalAnalysisResult,
)


class OriginHypothesisEngine:
    """Evaluates multi-signal forensic evidence to produce competing origin hypotheses."""

    def __init__(self, max_confidence: float = 0.94) -> None:
        self.max_confidence = max_confidence

    def generate_hypotheses(
        self,
        candidates: List[OriginCandidate],
        hops: List[ReconstructedHop],
        enriched_peers: List[EnrichedInfrastructure],
        temporal_result: Optional[TemporalAnalysisResult] = None,
        arc_result: Optional[ArcAnalysisResult] = None,
        auth_spf_pass: bool = False,
        auth_dkim_pass: bool = False,
        auth_dmarc_pass: bool = False,
    ) -> List[OriginHypothesis]:
        """Generate competing hypotheses explaining observed email transmission."""
        hypotheses: List[OriginHypothesis] = []

        if not hops or not candidates:
            hypotheses.append(
                OriginHypothesis(
                    hypothesis_type="insufficient_origin_evidence",
                    confidence=0.85,
                    supporting_evidence=[
                        "No public transmission hops or external peers identified in Received headers.",
                        "Routing chain contains only private or unparseable headers.",
                    ],
                    contradicting_evidence=[],
                    trust_state="observed",
                    provenance={"hops_count": len(hops)},
                )
            )
            return hypotheses

        primary_cand = candidates[0]
        peer_ip = primary_cand.ip
        peer_role = primary_cand.role
        peer_vis = primary_cand.source_visibility

        # Find matching hop for timestamp provenance
        matching_hop = next((h for h in hops if h.hop_sequence_num == primary_cand.hop_sequence_num), None)
        relevant_timestamp = matching_hop.timestamp_utc if matching_hop else None

        # Find matching enrichment for primary peer
        peer_enrichment: Optional[EnrichedInfrastructure] = next(
            (e for e in enriched_peers if e.ip == peer_ip), None
        )
        infra_data = peer_enrichment.infrastructure if peer_enrichment else None

        # 1. Hypothesis: possible_provider_masking
        if peer_vis == "provider_masked" or peer_role == "mail_provider":
            supporting = [
                f"Earliest observable peer '{peer_ip}' is a recognized mail provider/relay.",
                f"Candidate role is '{peer_role}' with visibility '{peer_vis}'.",
            ]
            contradicting: List[str] = []
            if primary_cand.hop_sequence_num > 1:
                supporting.append(f"Private upstream hops exist prior to provider hop {primary_cand.hop_sequence_num}.")

            hypotheses.append(
                OriginHypothesis(
                    hypothesis_type="possible_provider_masking",
                    confidence=min(self.max_confidence, primary_cand.confidence),
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    trust_state="inferred",
                    provenance={
                        "rule_id": "HYPO-PROVIDER-MASKING",
                        "source_module": "origin_infrastructure",
                        "source_header": "Received",
                        "trust_state": "inferred",
                        "relevant_timestamp": relevant_timestamp,
                        "peer_ip": peer_ip,
                        "role": peer_role,
                    },
                )
            )

        # 2. Hypothesis: possible_direct_origin
        if peer_role == "earliest_reliable_external_peer" and peer_vis == "visible":
            supporting = [
                f"Hop {primary_cand.hop_sequence_num} is the earliest reliable external peer ({peer_ip}).",
                "Observable transmission path connects directly from this peer to recipient infrastructure.",
            ]
            contradicting = []
            if infra_data and infra_data.is_hosting:
                contradicting.append(f"Peer is hosted on cloud/datacenter infrastructure ({infra_data.provider_name or 'hosting'}).")
            if temporal_result and temporal_result.negative_intervals > 0:
                contradicting.append(f"Temporal analysis detected {temporal_result.negative_intervals} negative interval(s).")

            hyp_conf = primary_cand.confidence
            if infra_data and infra_data.is_hosting:
                hyp_conf -= 0.15

            hypotheses.append(
                OriginHypothesis(
                    hypothesis_type="possible_direct_origin",
                    confidence=max(0.30, min(self.max_confidence, hyp_conf)),
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    trust_state="inferred",
                    provenance={
                        "rule_id": "HYPO-DIRECT-ORIGIN",
                        "source_module": "origin_infrastructure",
                        "source_header": "Received",
                        "trust_state": "inferred",
                        "relevant_timestamp": relevant_timestamp,
                        "peer_ip": peer_ip,
                        "sequence": primary_cand.hop_sequence_num,
                    },
                )
            )

        # 3. Hypothesis: possible_cloud_infrastructure
        if infra_data and infra_data.is_hosting:
            supporting = [
                f"Peer IP '{peer_ip}' belongs to recognized cloud or hosting provider ({infra_data.provider_name or 'cloud'}).",
                f"Network classified as '{infra_data.classification}'.",
            ]
            contradicting = []
            if auth_spf_pass and auth_dkim_pass:
                contradicting.append("Valid SPF and DKIM pass reported for legitimate organizational domain.")

            hypotheses.append(
                OriginHypothesis(
                    hypothesis_type="possible_cloud_infrastructure",
                    confidence=min(self.max_confidence, 0.82),
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    trust_state="enriched",
                    provenance={
                        "rule_id": "HYPO-CLOUD-INFRA",
                        "source_module": "origin_infrastructure",
                        "source_header": "Received",
                        "trust_state": "enriched",
                        "enrichment_source": "local_infrastructure_provider",
                        "relevant_timestamp": relevant_timestamp,
                        "peer_ip": peer_ip,
                        "provider": infra_data.provider_name,
                    },
                )
            )

        # 4. Hypothesis: possible_anonymized_infrastructure (VPN / Tor / Proxy)
        if infra_data and (infra_data.is_tor or infra_data.is_vpn or infra_data.is_proxy):
            anonymizer_types = []
            if infra_data.is_tor:
                anonymizer_types.append("Tor exit node")
            if infra_data.is_vpn:
                anonymizer_types.append("VPN endpoint")
            if infra_data.is_proxy and not infra_data.is_tor and not infra_data.is_vpn:
                anonymizer_types.append("Proxy relay")

            supporting = [
                f"Observed peer IP '{peer_ip}' matches known {', '.join(anonymizer_types)} list.",
                "Origin network traffic routed through anonymization infrastructure.",
            ]
            contradicting = [
                "Anonymization indicator is a network transport property, not definitive attribution.",
            ]

            hypotheses.append(
                OriginHypothesis(
                    hypothesis_type="possible_anonymized_infrastructure",
                    confidence=min(self.max_confidence, 0.88),
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    trust_state="enriched",
                    provenance={
                        "rule_id": "HYPO-ANONYMIZED-INFRA",
                        "source_module": "origin_infrastructure",
                        "source_header": "Received",
                        "trust_state": "enriched",
                        "enrichment_source": "local_infrastructure_provider",
                        "relevant_timestamp": relevant_timestamp,
                        "peer_ip": peer_ip,
                        "anonymizers": anonymizer_types,
                    },
                )
            )

        # 5. Hypothesis: possible_compromised_account
        if (auth_spf_pass or auth_dkim_pass) and (peer_role in ("mail_provider", "upstream_relay") or (infra_data and infra_data.is_hosting)):
            supporting = [
                "Email successfully authenticated through legitimate cloud provider or organizational MTA.",
                "Message submitted through authorized mail relay infrastructure.",
            ]
            contradicting = [
                "Authentication pass may indicate legitimate business correspondence rather than compromise.",
            ]

            hypotheses.append(
                OriginHypothesis(
                    hypothesis_type="possible_compromised_account",
                    confidence=min(self.max_confidence, 0.55),
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    trust_state="inferred",
                    provenance={
                        "rule_id": "HYPO-COMPROMISED-ACCOUNT",
                        "source_module": "origin_infrastructure",
                        "source_header": "Authentication-Results",
                        "trust_state": "inferred",
                        "relevant_timestamp": relevant_timestamp,
                        "peer_ip": peer_ip,
                    },
                )
            )

        # 6. Hypothesis: possible_mail_relay
        if len(hops) >= 3 and primary_cand.hop_sequence_num < len(hops):
            supporting = [
                f"Multiple transit hops ({len(hops)}) recorded in Received header chain.",
                "Message routed through intermediate relays before arriving at boundary gateway.",
            ]
            contradicting = []
            if arc_result and not arc_result.is_chain_consistent:
                contradicting.append("Intermediate ARC chain is incomplete or inconsistent.")

            hypotheses.append(
                OriginHypothesis(
                    hypothesis_type="possible_mail_relay",
                    confidence=min(self.max_confidence, 0.75),
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    trust_state="inferred",
                    provenance={
                        "rule_id": "HYPO-MAIL-RELAY",
                        "source_module": "origin_infrastructure",
                        "source_header": "Received",
                        "trust_state": "inferred",
                        "relevant_timestamp": relevant_timestamp,
                        "total_hops": len(hops),
                    },
                )
            )

        # Ensure at least one hypothesis is always produced
        if not hypotheses:
            hypotheses.append(
                OriginHypothesis(
                    hypothesis_type="insufficient_origin_evidence",
                    confidence=0.50,
                    supporting_evidence=["Observable evidence is ambiguous or incomplete."],
                    contradicting_evidence=[],
                    trust_state="inferred",
                    provenance={
                        "rule_id": "HYPO-INSUFFICIENT-EVIDENCE",
                        "source_module": "origin_infrastructure",
                        "source_header": "Received",
                        "trust_state": "inferred",
                    },
                )
            )

        # Sort hypotheses descending by confidence
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses
