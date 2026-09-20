"""Top-level forensic analyzer for Origin & Infrastructure Reconstruction Engine (Module 5).

Orchestrates the end-to-end reconstruction pipeline:
1. Received Header Parsing (raw preservation, RFC 5321/5322 extraction)
2. Hop Sequence Reconstruction (origin-to-destination transport order)
3. Temporal Chronology & Delay Analysis (UTC normalization, negative intervals)
4. Authentication & ARC Correlation (SPF, DKIM, DMARC, ARC validation)
5. Earliest Reliable External Peer Detection (bounded confidence, provider-masking)
6. Offline Local Infrastructure Enrichment (GeoIP, ASN, Cloud/VPN/TOR indicators)
7. Cross-Case Temporal Correlation (recurring infrastructure)
8. Origin Hypothesis Generation (competing heuristic hypotheses <= 0.94)
9. Evidence Graph Construction (email, hop, ip, asn, country, infrastructure)
"""

from datetime import datetime
from email import message_from_bytes, message_from_string, policy
from email.message import EmailMessage, Message
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from modules.sender_identity.models import Entity, ParsedEmailEvidence, Relationship
from .authentication import AuthenticationCorrelator
from .correlation import CrossCaseCorrelator
from .enrichment import (
    BaseASNProvider,
    BaseGeoIPProvider,
    BaseInfrastructureProvider,
    CompositeEnrichmentProvider,
    LocalASNProvider,
    LocalGeoIPProvider,
    LocalInfrastructureProvider,
)
from .hop_reconstructor import HopReconstructor
from .hypotheses import OriginHypothesisEngine
from .models import (
    EnrichedInfrastructure,
    OriginInfrastructureReport,
    OriginObservation,
)
from .origin_engine import OriginEngine
from .received_parser import ReceivedHeaderParser
from .temporal import TemporalAnalyzer


class OriginInfrastructureAnalyzer:
    """Forensic engine for observable email transport reconstruction and origin analysis."""

    def __init__(
        self,
        geoip_provider: Optional[BaseGeoIPProvider] = None,
        asn_provider: Optional[BaseASNProvider] = None,
        infrastructure_provider: Optional[BaseInfrastructureProvider] = None,
        historical_cases: Optional[List[Dict[str, Any]]] = None,
        trusted_gateways: Optional[Union[List[str], Set[str]]] = None,
        max_heuristic_confidence: float = 0.94,
        reference_time: Optional[datetime] = None,
    ) -> None:
        self.received_parser = ReceivedHeaderParser()
        self.hop_reconstructor = HopReconstructor(trusted_gateways=trusted_gateways)
        self.temporal_analyzer = TemporalAnalyzer(reference_time=reference_time)
        self.auth_correlator = AuthenticationCorrelator()
        self.origin_engine = OriginEngine(max_heuristic_confidence=max_heuristic_confidence)
        self.hypothesis_engine = OriginHypothesisEngine(max_confidence=max_heuristic_confidence)
        self._reference_time = reference_time

        # Enrichment provider fallback to local offline providers
        g_prov = geoip_provider or LocalGeoIPProvider()
        a_prov = asn_provider or LocalASNProvider()
        i_prov = infrastructure_provider or LocalInfrastructureProvider()
        self.enrichment = CompositeEnrichmentProvider(
            geoip_provider=g_prov,
            asn_provider=a_prov,
            infrastructure_provider=i_prov,
        )

        self.correlator = CrossCaseCorrelator(historical_cases=historical_cases)

    def analyze(
        self,
        email_input: Union[EmailMessage, Message, bytes, str, Path, ParsedEmailEvidence, Dict[str, Any]],
        email_id: str = "E001",
        file_hash_sha256: Optional[str] = None,
        reference_time: Optional[datetime] = None,
    ) -> OriginInfrastructureReport:
        """Run full forensic origin & infrastructure reconstruction on input email.

        Args:
            email_input: Raw .eml bytes, str, Path, EmailMessage, or Module 1 ParsedEmailEvidence.
            email_id: Unique forensic case/email identifier.
            file_hash_sha256: Precomputed SHA-256 hash (optional).
            reference_time: Optional reference time for temporal analysis.

        Returns:
            OriginInfrastructureReport containing assessment, hops, hypotheses,
            enriched peers, observations, and graph entities/relationships.
        """
        msg, raw_bytes, parsed_evidence = self._resolve_input(email_input)

        calc_hash = file_hash_sha256 or (
            hashlib.sha256(raw_bytes).hexdigest() if raw_bytes else ""
        )
        if parsed_evidence and not calc_hash:
            calc_hash = parsed_evidence.file_hash_sha256

        all_observations: List[OriginObservation] = []
        obs_counter = 1

        # 1. Received Header Parsing
        parsed_hops = self.received_parser.parse_all(msg)

        # 2. Hop Reconstruction
        raw_reconstructed = self.hop_reconstructor.reconstruct(parsed_hops)

        # 3. Temporal Analysis
        date_header = msg.get("Date") if msg else (
            parsed_evidence.from_raw if parsed_evidence else None
        )
        effective_ref_time = reference_time or self._reference_time
        reconstructed_hops, temporal_result, time_obs = self.temporal_analyzer.analyze(
            raw_reconstructed,
            date_header_str=str(date_header) if date_header else None,
            obs_start_index=obs_counter,
            reference_time=effective_ref_time,
        )
        obs_counter += len(time_obs)
        all_observations.extend(time_obs)

        # 4. Authentication & ARC Correlation
        auth_ev = parsed_evidence.auth_results if parsed_evidence else None
        arc_result, auth_obs = self.auth_correlator.correlate(
            email_msg=msg,
            auth_results=auth_ev,
            obs_start_index=obs_counter,
        )
        obs_counter += len(auth_obs)
        all_observations.extend(auth_obs)

        # 5. Earliest Reliable Peer Detection
        candidates, origin_assessment = self.origin_engine.evaluate(
            hops=reconstructed_hops,
            temporal_result=temporal_result,
            arc_result=arc_result,
        )

        # 6. Local Infrastructure Enrichment
        enriched_peers: List[EnrichedInfrastructure] = []
        observed_ips_to_enrich: List[str] = []

        for cand in candidates:
            if cand.ip not in observed_ips_to_enrich:
                observed_ips_to_enrich.append(cand.ip)

        for hop in reconstructed_hops:
            if hop.source_ip and not hop.is_source_private and hop.source_ip not in observed_ips_to_enrich:
                observed_ips_to_enrich.append(hop.source_ip)

        for ip in observed_ips_to_enrich:
            enriched_peers.append(self.enrichment.enrich(ip))

        # 7. Cross-Case Temporal Correlation
        current_ts = reconstructed_hops[0].timestamp_raw if reconstructed_hops else str(date_header)
        observed_asns = [e.asn.asn for e in enriched_peers if e.asn and e.asn.asn]
        corr_matches, corr_obs = self.correlator.correlate(
            current_case_id=email_id,
            observed_ips=observed_ips_to_enrich,
            observed_asns=observed_asns,
            current_timestamp_str=current_ts,
            obs_start_index=obs_counter,
        )
        obs_counter += len(corr_obs)
        all_observations.extend(corr_obs)

        # 8. Origin Hypothesis Generation
        spf_pass = auth_ev.spf == "pass" if auth_ev else False
        dkim_pass = auth_ev.dkim == "pass" if auth_ev else False
        dmarc_pass = auth_ev.dmarc == "pass" if auth_ev else False

        hypotheses = self.hypothesis_engine.generate_hypotheses(
            candidates=candidates,
            hops=reconstructed_hops,
            enriched_peers=enriched_peers,
            temporal_result=temporal_result,
            arc_result=arc_result,
            auth_spf_pass=spf_pass,
            auth_dkim_pass=dkim_pass,
            auth_dmarc_pass=dmarc_pass,
        )

        # 9. Build Graph Entities & Relationships
        entities: List[Entity] = [
            Entity(type="email", value=email_id, source="origin_infrastructure")
        ]
        relationships: List[Relationship] = []

        # Graph nodes and edges for hops
        for hop in reconstructed_hops:
            hop_id = f"{email_id}:hop_{hop.hop_sequence_num}"
            entities.append(
                Entity(
                    type="hop",
                    value=hop_id,
                    source="origin_infrastructure",
                    attributes={
                        "sequence": hop.hop_sequence_num,
                        "source_host": hop.source_host,
                        "source_ip": hop.source_ip,
                        "receiver_host": hop.receiver_host,
                        "receiver_ip": hop.receiver_ip,
                        "timestamp_utc": hop.timestamp_utc,
                        "trust_state": hop.trust_state,
                    },
                )
            )
            relationships.append(
                Relationship(
                    source=email_id,
                    relation="has_hop",
                    target=hop_id,
                    evidence={"sequence": hop.hop_sequence_num},
                )
            )

        # Consecutive hop transmission edges
        for idx in range(len(reconstructed_hops) - 1):
            h_curr = f"{email_id}:hop_{reconstructed_hops[idx].hop_sequence_num}"
            h_next = f"{email_id}:hop_{reconstructed_hops[idx + 1].hop_sequence_num}"
            relationships.append(
                Relationship(
                    source=h_curr,
                    relation="transmitted_to",
                    target=h_next,
                )
            )

        # Graph nodes and edges for enriched peers and candidates
        for peer in enriched_peers:
            entities.append(
                Entity(
                    type="ip",
                    value=peer.ip,
                    source="origin_infrastructure",
                    attributes={
                        "classification": peer.infrastructure.classification,
                        "is_hosting": peer.infrastructure.is_hosting,
                        "provider_name": peer.infrastructure.provider_name,
                    },
                )
            )

            if peer.geolocation and peer.geolocation.status == "available" and peer.geolocation.country:
                entities.append(
                    Entity(
                        type="country",
                        value=peer.geolocation.country,
                        source="origin_infrastructure",
                    )
                )
                relationships.append(
                    Relationship(
                        source=peer.ip,
                        relation="located_in",
                        target=peer.geolocation.country,
                        evidence={"city": peer.geolocation.city, "source": peer.geolocation.source_dataset},
                    )
                )

            if peer.asn and peer.asn.status == "available" and peer.asn.asn:
                entities.append(
                    Entity(
                        type="asn",
                        value=peer.asn.asn,
                        source="origin_infrastructure",
                        attributes={"organization": peer.asn.organization},
                    )
                )
                relationships.append(
                    Relationship(
                        source=peer.ip,
                        relation="belongs_to_asn",
                        target=peer.asn.asn,
                        evidence={"organization": peer.asn.organization},
                    )
                )

        if origin_assessment.earliest_reliable_peer:
            relationships.append(
                Relationship(
                    source=email_id,
                    relation="observed_peer_ip",
                    target=origin_assessment.earliest_reliable_peer,
                    evidence={
                        "role": "earliest_reliable_external_peer",
                        "confidence": origin_assessment.confidence,
                        "visibility": origin_assessment.source_visibility,
                    },
                )
            )

        # 10. Provenance Tracking
        provenance = [
            {
                "email_id": email_id,
                "module": "origin_infrastructure",
                "parsed_hops_count": len(parsed_hops),
                "reconstructed_hops_count": len(reconstructed_hops),
                "earliest_peer": origin_assessment.earliest_reliable_peer,
                "source_visibility": origin_assessment.source_visibility,
                "confidence": origin_assessment.confidence,
                "has_arc": arc_result.has_arc,
            }
        ]

        return OriginInfrastructureReport(
            module="origin_infrastructure",
            email_id=email_id,
            file_hash_sha256=calc_hash,
            origin_assessment=origin_assessment,
            temporal_analysis=temporal_result,
            hops=reconstructed_hops,
            enriched_peers=enriched_peers,
            hypotheses=hypotheses,
            observations=all_observations,
            entities=entities,
            relationships=relationships,
            provenance=provenance,
        )

    def _resolve_input(
        self,
        email_input: Union[EmailMessage, Message, bytes, str, Path, ParsedEmailEvidence, Dict[str, Any]],
    ) -> Tuple[Optional[Message], Optional[bytes], Optional[ParsedEmailEvidence]]:
        """Resolve diverse email input representations into a Message and raw bytes."""
        msg: Optional[Message] = None
        raw_bytes: Optional[bytes] = None
        parsed_evidence: Optional[ParsedEmailEvidence] = None

        if isinstance(email_input, ParsedEmailEvidence):
            parsed_evidence = email_input
            # Reconstruct dummy message for header walking if needed
            msg = EmailMessage()
            for hop in parsed_evidence.received_hops:
                msg["Received"] = hop.raw_header
            return msg, None, parsed_evidence

        if isinstance(email_input, (EmailMessage, Message)):
            msg = email_input
            try:
                raw_bytes = msg.as_bytes()
            except Exception:
                pass
            return msg, raw_bytes, None

        if isinstance(email_input, bytes):
            raw_bytes = email_input
            msg = message_from_bytes(email_input, policy=policy.default)
            return msg, raw_bytes, None

        if isinstance(email_input, str):
            p = Path(email_input)
            if p.is_file():
                raw_bytes = p.read_bytes()
                msg = message_from_bytes(raw_bytes, policy=policy.default)
            else:
                raw_bytes = email_input.encode("utf-8", errors="surrogateescape")
                msg = message_from_string(email_input, policy=policy.default)
            return msg, raw_bytes, None

        if isinstance(email_input, Path):
            raw_bytes = email_input.read_bytes()
            msg = message_from_bytes(raw_bytes, policy=policy.default)
            return msg, raw_bytes, None

        if isinstance(email_input, dict) and "received_hops" in email_input:
            # Dictionary with pre-extracted received headers
            msg = EmailMessage()
            for h in email_input.get("received_hops", []):
                raw = h if isinstance(h, str) else h.get("raw_header", "")
                if raw:
                    msg["Received"] = raw
            return msg, None, None

        return None, None, None


def analyze_origin_infrastructure(
    email_input: Union[EmailMessage, Message, bytes, str, Path, ParsedEmailEvidence, Dict[str, Any]],
    email_id: str = "E001",
    file_hash_sha256: Optional[str] = None,
    historical_cases: Optional[List[Dict[str, Any]]] = None,
    trusted_gateways: Optional[Union[List[str], Set[str]]] = None,
) -> OriginInfrastructureReport:
    """Convenience entry point for Origin & Infrastructure Reconstruction analysis."""
    analyzer = OriginInfrastructureAnalyzer(
        historical_cases=historical_cases,
        trusted_gateways=trusted_gateways,
    )
    return analyzer.analyze(email_input, email_id=email_id, file_hash_sha256=file_hash_sha256)
