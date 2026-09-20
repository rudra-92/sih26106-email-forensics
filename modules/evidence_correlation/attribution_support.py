"""Attribution support engine for Module 6: Evidence Correlation & Attribution Support.

Produces forensic attribution support by synthesizing observable infrastructure,
probable origin routing context, recurring cross-case links, and explicit investigative boundaries.

CRITICAL FORENSIC GUARDRAIL:
Strictly produces attribution SUPPORT, never speculative identity claims:
- No attacker name
- No physical home address
- No guaranteed attacker location
- No guaranteed attacker IP
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import AttributionSupport, CampaignCluster, CorrelatedEntity, NormalizedEvidence


class AttributionSupportEngine:
    """Synthesizes observable infrastructure and campaign connections without speculative attribution."""

    DEFAULT_LIMITATIONS = [
        "Attribution represents technical infrastructure and observable patterns only.",
        "No human attacker identity, attacker home address, guaranteed attacker IP, or guaranteed physical attacker location is asserted or implied.",
        "Observed infrastructure geolocation represents network routing Point-of-Presence (PoP), NOT human attacker physical location.",
        "External machine learning predictions represent probabilistic inferences with trust_state = 'inferred', NOT deterministically observed facts.",
        "Infrastructure reuse across cases indicates potential operational or tooling correlation, NOT confirmed common ownership of infrastructure.",
        "Webmail interfaces, commercial cloud providers, and open proxies mask client origin endpoints, leaving only transport gateways observable.",
        "SPF, DKIM, and DMARC passes corroborate transport authorization on configured domains, not global message trustworthiness.",
    ]

    def build_attribution_support(
        self,
        entities: List[CorrelatedEntity],
        evidence_list: List[NormalizedEvidence],
        clusters: List[CampaignCluster],
        module5_report: Optional[Any] = None,
    ) -> AttributionSupport:
        """Construct structured attribution support adhering strictly to forensic boundaries."""
        observable_infra: List[Dict[str, Any]] = []
        probable_orig: Optional[Dict[str, Any]] = None
        recurring_infra: List[Dict[str, Any]] = []
        campaign_links: List[str] = []

        # 1. Observable infrastructure mapping
        ip_entities = [e for e in entities if e.type == "ip"]
        asn_entities = [e for e in entities if e.type == "asn"]
        domain_entities = [e for e in entities if e.type == "domain"]
        infra_entities = [e for e in entities if e.type == "infrastructure"]

        for ip_e in ip_entities:
            observable_infra.append({
                "entity_id": ip_e.entity_id,
                "type": "ip",
                "value": ip_e.value,
                "source_modules": ip_e.source_modules,
                "attributes": ip_e.attributes,
            })

        for asn_e in asn_entities:
            observable_infra.append({
                "entity_id": asn_e.entity_id,
                "type": "asn",
                "value": asn_e.value,
                "source_modules": asn_e.source_modules,
                "attributes": asn_e.attributes,
            })

        for dom_e in domain_entities:
            observable_infra.append({
                "entity_id": dom_e.entity_id,
                "type": "domain",
                "value": dom_e.value,
                "source_modules": dom_e.source_modules,
                "attributes": dom_e.attributes,
            })

        for inf_e in infra_entities:
            observable_infra.append({
                "entity_id": inf_e.entity_id,
                "type": "infrastructure_classification",
                "value": inf_e.value,
                "source_modules": inf_e.source_modules,
            })

        # 2. Probable origin extraction from Module 5
        if module5_report is not None:
            d5 = module5_report.to_dict() if hasattr(module5_report, "to_dict") else dict(module5_report)
            ass = d5.get("origin_assessment", {})
            peer_ip = ass.get("earliest_reliable_peer")
            if peer_ip:
                # Find matching peer details
                peer_detail: Dict[str, Any] = next(
                    (p for p in d5.get("enriched_peers", []) if isinstance(p, dict) and p.get("ip") == peer_ip),
                    {},
                )
                probable_orig = {
                    "earliest_reliable_peer_ip": peer_ip,
                    "peer_hostname": ass.get("peer_hostname"),
                    "source_visibility": ass.get("source_visibility"),
                    "confidence": ass.get("confidence", 0.0),
                    "assessment_reason": ass.get("assessment_reason"),
                    "infrastructure_classification": peer_detail.get("infrastructure", {}).get("classification"),
                    "asn": peer_detail.get("asn", {}).get("asn"),
                    "asn_organization": peer_detail.get("asn", {}).get("organization"),
                    "observed_infrastructure_location": peer_detail.get("geolocation", {}).get("city"),
                    "observed_infrastructure_country": peer_detail.get("geolocation", {}).get("country"),
                }

        # 3. Recurring infrastructure and campaign links from clusters
        for cl in clusters:
            campaign_links.append(f"{cl.cluster_id}: {cl.description} (Cases: {', '.join(cl.case_ids)})")
            for ent in cl.shared_entities:
                entry = {
                    "cluster_id": cl.cluster_id,
                    "type": ent.get("type"),
                    "value": ent.get("value"),
                    "occurrence_count": cl.occurrence_count,
                    "related_cases": cl.case_ids,
                }
                if entry not in recurring_infra:
                    recurring_infra.append(entry)

        return AttributionSupport(
            observable_infrastructure=observable_infra,
            probable_origin=probable_orig,
            recurring_infrastructure=recurring_infra,
            campaign_links=campaign_links,
            limitations=list(self.DEFAULT_LIMITATIONS),
        )
