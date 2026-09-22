"""Relationship correlation and graph edge engine for Module 6.

Normalizes, establishes, and merges evidence-bearing directed relationships connecting
resolved forensic entities (email, address, domain, URL, IP, ASN, attachment, hash).
Ensures no relationship is created without backing evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .entity_resolution import EntityResolver
from .models import CorrelatedRelationship, NormalizedEvidence


class RelationshipEngine:
    """Manages creation, de-duplication, and evidence linkage for graph relationships."""

    def __init__(self) -> None:
        # Keyed by (from_entity, relationship_type, to_entity)
        self._relationships: Dict[tuple[str, str, str], CorrelatedRelationship] = {}
        self._counter = 1

    def add_relationship(
        self,
        from_entity: str,
        relationship_type: str,
        to_entity: str,
        source_module: str,
        evidence_ids: Optional[List[str]] = None,
        trust_state: str = "observed",
        timestamp: Optional[str] = None,
        provenance: Optional[List[str]] = None,
    ) -> CorrelatedRelationship:
        """Add or update an evidence-bearing directed graph edge."""
        key = (from_entity, relationship_type, to_entity)

        if key in self._relationships:
            rel = self._relationships[key]
            if source_module not in rel.source_modules:
                rel.source_modules.append(source_module)
            for eid in (evidence_ids or []):
                if eid not in rel.evidence_ids:
                    rel.evidence_ids.append(eid)
            for prov in (provenance or []):
                if prov not in rel.provenance:
                    rel.provenance.append(prov)
            return rel

        rel_id = f"REL-{self._counter:04d}"
        self._counter += 1

        rel = CorrelatedRelationship(
            relationship_id=rel_id,
            from_entity=from_entity,
            to_entity=to_entity,
            relationship_type=relationship_type,
            evidence_ids=list(evidence_ids or []),
            source_modules=[source_module] if source_module else [],
            trust_state=trust_state,
            timestamp=timestamp,
            provenance=list(provenance or ([source_module] if source_module else [])),
        )
        self._relationships[key] = rel
        return rel

    def all_relationships(self) -> List[CorrelatedRelationship]:
        """Return all relationships sorted deterministically by relationship_id."""
        return sorted(self._relationships.values(), key=lambda r: r.relationship_id)

    def correlate_all(
        self,
        resolver: EntityResolver,
        email_id: str,
        case_id: str,
        evidence_list: List[NormalizedEvidence],
        module1_report: Optional[Any] = None,
        module2_report: Optional[Any] = None,
        module3_report: Optional[Any] = None,
        module4_report: Optional[Any] = None,
        module5_report: Optional[Any] = None,
        infrastructure_intelligence_report: Optional[Any] = None,
        timestamp: Optional[str] = None,
    ) -> List[CorrelatedRelationship]:
        """Correlate all domain, URL, IP, and attachment relationships across modules."""
        # Find matching evidence IDs by module
        m1_eids = [e.evidence_id for e in evidence_list if e.source_module == "sender_identity"]
        m2_eids = [e.evidence_id for e in evidence_list if e.source_module == "lookalike_domain"]
        m3_eids = [e.evidence_id for e in evidence_list if e.source_module == "url_analysis"]
        m4_eids = [e.evidence_id for e in evidence_list if e.source_module == "attachment_analysis"]
        m5_eids = [e.evidence_id for e in evidence_list if e.source_module == "origin_infrastructure"]
        infra_eids = [e.evidence_id for e in evidence_list if e.source_module == "infrastructure_intelligence"]

        email_eid = f"email:{email_id}"
        case_eid = f"case:{case_id}"

        # 0. Case contains email
        self.add_relationship(
            from_entity=case_eid,
            relationship_type="contains",
            to_entity=email_eid,
            source_module="evidence_correlation",
            evidence_ids=[evidence_list[0].evidence_id] if evidence_list else [],
            timestamp=timestamp,
        )

        # 1. Module 1: email -> sent_by -> email_address -> belongs_to -> domain
        if module1_report is not None:
            self._correlate_module1(module1_report, email_eid, m1_eids, timestamp)

        # 2. Module 2: domain -> resembles -> reference_domain
        if module2_report is not None:
            self._correlate_module2(module2_report, m2_eids, timestamp)

        # 3. Module 3: email -> contains_url -> url -> hosted_on -> ip/domain
        if module3_report is not None:
            self._correlate_module3(module3_report, email_eid, m3_eids, timestamp)

        # 4. Module 4: email -> contains_attachment -> attachment -> has_hash -> sha256
        if module4_report is not None:
            self._correlate_module4(module4_report, email_eid, m4_eids, timestamp)

        # 5. Module 5: email -> observed_from -> ip -> belongs_to -> asn / located_in -> country
        if module5_report is not None:
            self._correlate_module5(module5_report, email_eid, m5_eids, timestamp)

        # 6. Infrastructure Intelligence
        if infrastructure_intelligence_report is not None:
            self._correlate_infrastructure_intelligence(infrastructure_intelligence_report, infra_eids, timestamp)

        return self.all_relationships()

    def _correlate_module1(
        self,
        report: Any,
        email_eid: str,
        eids: List[str],
        timestamp: Optional[str],
    ) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        for ent in d.get("entities", []):
            e_dict = ent if isinstance(ent, dict) else (ent.to_dict() if hasattr(ent, "to_dict") else {})
            val = str(e_dict.get("value", "")).strip().lower()
            etype = e_dict.get("type")

            if etype == "email_address" and val:
                addr_eid = f"email_address:{val}"
                self.add_relationship(email_eid, "sent_by", addr_eid, "sender_identity", evidence_ids=eids, timestamp=timestamp)
                if "@" in val:
                    dom = val.split("@", 1)[1]
                    if dom:
                        dom_eid = f"domain:{dom.lower()}"
                        self.add_relationship(addr_eid, "belongs_to", dom_eid, "sender_identity", evidence_ids=eids, timestamp=timestamp)

            elif etype == "ip" and val:
                ip_eid = f"ip:{val}"
                self.add_relationship(email_eid, "observed_from", ip_eid, "sender_identity", evidence_ids=eids, timestamp=timestamp)

        # Fallback to header/envelope fields if entities list was empty
        if not d.get("entities"):
            for fld in ("header_from", "envelope_sender"):
                raw_sender = d.get(fld)
                if raw_sender and isinstance(raw_sender, str) and "@" in raw_sender:
                    val_clean = raw_sender.strip().lower()
                    addr_eid = f"email_address:{val_clean}"
                    self.add_relationship(email_eid, "sent_by", addr_eid, "sender_identity", evidence_ids=eids, timestamp=timestamp)
                    dom = val_clean.split("@", 1)[1]
                    if dom:
                        dom_eid = f"domain:{dom.lower()}"
                        self.add_relationship(addr_eid, "belongs_to", dom_eid, "sender_identity", evidence_ids=eids, timestamp=timestamp)
                    break

    def _correlate_module2(
        self,
        report: Any,
        eids: List[str],
        timestamp: Optional[str],
    ) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)
        obs_dom = str(d.get("observed_domain") or d.get("query_domain") or "").strip().lower()
        ref_dom = str(d.get("reference_domain") or d.get("target_brand") or "").strip().lower()

        is_cand = bool(d.get("candidate", False) or d.get("is_candidate", False) or d.get("is_lookalike", False))
        score = float(d.get("candidate_score", 0.0))
        is_rej = d.get("candidate") is False or d.get("is_candidate") is False or d.get("category") == "unlikely_domain_impersonation"

        if obs_dom and ref_dom and not is_rej and (is_cand or score >= 0.70 or d.get("is_lookalike")):
            self.add_relationship(
                from_entity=f"domain:{obs_dom}",
                relationship_type="resembles",
                to_entity=f"domain:{ref_dom}",
                source_module="lookalike_domain",
                evidence_ids=eids,
                trust_state="inferred",
                timestamp=timestamp,
            )

    def _correlate_module3(
        self,
        report: Any,
        email_eid: str,
        eids: List[str],
        timestamp: Optional[str],
    ) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        for u in d.get("urls", []):
            u_dict = u if isinstance(u, dict) else (u.to_dict() if hasattr(u, "to_dict") else {})
            raw_val = u_dict.get("normalized_url") or u_dict.get("actual_url") or ""
            norm_u = str(raw_val).strip()
            host = str(u_dict.get("hostname", "")).strip().lower()
            is_ip = u_dict.get("is_ip", False)

            if norm_u:
                url_eid = f"url:{norm_u}"
                self.add_relationship(email_eid, "contains_url", url_eid, "url_analysis", evidence_ids=eids, timestamp=timestamp)

                if host:
                    target_eid = f"ip:{host}" if is_ip else f"domain:{host}"
                    self.add_relationship(url_eid, "hosted_on", target_eid, "url_analysis", evidence_ids=eids, timestamp=timestamp)

    def _correlate_module4(
        self,
        report: Any,
        email_eid: str,
        eids: List[str],
        timestamp: Optional[str],
    ) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        for att in d.get("attachments", []):
            a_dict = att if isinstance(att, dict) else (att.to_dict() if hasattr(att, "to_dict") else {})
            fn = str(a_dict.get("filename", "")).strip()
            sha = str(a_dict.get("sha256", "")).strip()

            if fn:
                att_eid = f"attachment:{fn}"
                self.add_relationship(email_eid, "contains_attachment", att_eid, "attachment_analysis", evidence_ids=eids, timestamp=timestamp)

                if sha:
                    hash_eid = f"hash:{sha}"
                    self.add_relationship(att_eid, "has_hash", hash_eid, "attachment_analysis", evidence_ids=eids, timestamp=timestamp)

    def _correlate_module5(
        self,
        report: Any,
        email_eid: str,
        eids: List[str],
        timestamp: Optional[str],
    ) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        for peer in d.get("enriched_peers", []):
            p_dict = peer if isinstance(peer, dict) else (peer.to_dict() if hasattr(peer, "to_dict") else {})
            ip = str(p_dict.get("ip", "")).strip()
            if not ip:
                continue

            ip_eid = f"ip:{ip}"
            self.add_relationship(email_eid, "observed_from", ip_eid, "origin_infrastructure", evidence_ids=eids, timestamp=timestamp)

            asn_info = p_dict.get("asn", {})
            if isinstance(asn_info, dict) and asn_info.get("asn"):
                asn_val = str(asn_info["asn"]).strip()
                self.add_relationship(ip_eid, "belongs_to", f"asn:{asn_val}", "origin_infrastructure", evidence_ids=eids, timestamp=timestamp)

            geo = p_dict.get("geolocation", {})
            if isinstance(geo, dict) and geo.get("country"):
                c_val = str(geo["country"]).strip()
                self.add_relationship(ip_eid, "located_in", f"country:{c_val}", "origin_infrastructure", evidence_ids=eids, timestamp=timestamp)

            infra = p_dict.get("infrastructure", {})
            if isinstance(infra, dict) and infra.get("classification") and infra["classification"] != "unknown":
                inf_val = str(infra["classification"]).strip()
                self.add_relationship(ip_eid, "infrastructure_type", f"infrastructure:{inf_val}", "origin_infrastructure", evidence_ids=eids, timestamp=timestamp)

    def _correlate_infrastructure_intelligence(
        self,
        report: Any,
        eids: List[str],
        timestamp: Optional[str],
    ) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)
        target_ip = str(d.get("target_ip", "")).strip()
        target_domain = str(d.get("target_domain", "")).strip()

        rdap = d.get("rdap", {})
        # domain -> registered_with -> registrar
        if target_domain and rdap and rdap.get("registrar"):
            self.add_relationship(
                f"domain:{target_domain.lower()}",
                "registered_with",
                f"registrar:{rdap['registrar'].strip()}",
                "infrastructure_intelligence",
                evidence_ids=eids,
                timestamp=timestamp,
            )

        # domain -> mx_served_by -> mx_host
        mx = d.get("mx", {})
        if target_domain and mx:
            for r in mx.get("records", []):
                if isinstance(r, dict) and r.get("host"):
                    self.add_relationship(
                        f"domain:{target_domain.lower()}",
                        "mx_served_by",
                        f"hostname:{r['host'].strip().lower()}",
                        "infrastructure_intelligence",
                        evidence_ids=eids,
                        timestamp=timestamp,
                    )

        # ip -> allocated_in -> allocated_network
        if target_ip and rdap and (rdap.get("network_name") or rdap.get("cidr")):
            net_val = rdap.get("network_name") or rdap.get("cidr")
            self.add_relationship(
                f"ip:{target_ip}",
                "allocated_in",
                f"infrastructure:{str(net_val).strip()}",
                "infrastructure_intelligence",
                evidence_ids=eids,
                timestamp=timestamp,
            )

        # ip -> ptr_resolves_to -> hostname
        rdns = d.get("reverse_dns", {})
        if target_ip and rdns:
            for h in rdns.get("ptr_hostnames", []):
                self.add_relationship(
                    f"ip:{target_ip}",
                    "ptr_resolves_to",
                    f"hostname:{str(h).strip().lower()}",
                    "infrastructure_intelligence",
                    evidence_ids=eids,
                    timestamp=timestamp,
                )
