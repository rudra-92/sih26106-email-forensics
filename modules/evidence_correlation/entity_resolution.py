"""Entity resolution engine for Module 6: Evidence Correlation & Attribution Support.

Resolves, extracts, and merges equivalent atomic forensic entities across Modules 1–5,
including emails, sender addresses, domains, URLs, IPs, ASNs, attachments, hashes,
hostnames, countries, and infrastructure tags.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .models import CorrelatedEntity


class EntityResolver:
    """De-duplicates and resolves atomic forensic entities into canonical representations."""

    SUPPORTED_TYPES = (
        "email",
        "email_address",
        "domain",
        "url",
        "ip",
        "asn",
        "attachment",
        "hash",
        "message_id",
        "hostname",
        "country",
        "infrastructure",
        "case",
        "registrar",
    )

    def __init__(self) -> None:
        # Keyed by canonical entity_id: "{type}:{canonical_value}"
        self._entities: Dict[str, CorrelatedEntity] = {}

    def resolve_entity(
        self,
        entity_type: str,
        value: str,
        source_module: str,
        attributes: Optional[Dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> CorrelatedEntity:
        """Register or update an atomic entity, merging attributes and provenance."""
        clean_val = self._canonicalize_value(entity_type, value)
        if not clean_val:
            clean_val = "unknown"

        eid = f"{entity_type}:{clean_val}"

        if eid in self._entities:
            existing = self._entities[eid]
            if source_module not in existing.source_modules:
                existing.source_modules.append(source_module)
            if attributes:
                existing.attributes.update(attributes)
            if timestamp:
                if not existing.first_seen or timestamp < existing.first_seen:
                    existing.first_seen = timestamp
                if not existing.last_seen or timestamp > existing.last_seen:
                    existing.last_seen = timestamp
            return existing

        entity = CorrelatedEntity(
            entity_id=eid,
            type=entity_type,
            value=clean_val,
            source_modules=[source_module] if source_module else [],
            attributes=dict(attributes or {}),
            first_seen=timestamp,
            last_seen=timestamp,
        )
        self._entities[eid] = entity
        return entity

    def get_entity(self, entity_type: str, value: str) -> Optional[CorrelatedEntity]:
        """Retrieve resolved entity by type and value."""
        clean_val = self._canonicalize_value(entity_type, value)
        eid = f"{entity_type}:{clean_val}"
        return self._entities.get(eid)

    def all_entities(self) -> List[CorrelatedEntity]:
        """Return all resolved entities sorted deterministically by entity_id."""
        return sorted(self._entities.values(), key=lambda e: e.entity_id)

    def extract_and_resolve_all(
        self,
        email_id: str,
        module1_report: Optional[Any] = None,
        module2_report: Optional[Any] = None,
        module3_report: Optional[Any] = None,
        module4_report: Optional[Any] = None,
        module5_report: Optional[Any] = None,
        infrastructure_intelligence_report: Optional[Any] = None,
        case_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> List[CorrelatedEntity]:
        """Extract all entities across available module outputs and resolve them."""
        # 0. Case and email entities
        c_id = case_id or f"CASE-{email_id}"
        self.resolve_entity("case", c_id, "evidence_correlation", timestamp=timestamp)
        self.resolve_entity("email", email_id, "evidence_correlation", timestamp=timestamp)

        # 1. Module 1: Sender Identity
        if module1_report is not None:
            self._extract_from_module1(module1_report, timestamp)

        # 2. Module 2: Lookalike Domain
        if module2_report is not None:
            self._extract_from_module2(module2_report, timestamp)

        # 3. Module 3: URL Analysis
        if module3_report is not None:
            self._extract_from_module3(module3_report, timestamp)

        # 4. Module 4: Attachment Analysis
        if module4_report is not None:
            self._extract_from_module4(module4_report, timestamp)

        # 5. Module 5: Origin & Infrastructure
        if module5_report is not None:
            self._extract_from_module5(module5_report, timestamp)

        # 6. Infrastructure Intelligence Layer
        if infrastructure_intelligence_report is not None:
            self._extract_from_infrastructure_intelligence(infrastructure_intelligence_report, timestamp)

        return self.all_entities()

    def _canonicalize_value(self, entity_type: str, value: str) -> str:
        """Format and clean values consistently across modules."""
        s = str(value).strip()
        if entity_type in ("domain", "email_address", "hostname"):
            return s.lower()
        if entity_type == "url":
            # Normalise URL trailing slashes and lowercase domain component
            try:
                parsed = urlparse(s)
                netloc = parsed.netloc.lower()
                path = parsed.path if parsed.path else "/"
                return f"{parsed.scheme}://{netloc}{path}" + (f"?{parsed.query}" if parsed.query else "")
            except Exception:
                return s.strip()
        if entity_type in ("ip", "asn", "hash"):
            return s.strip()
        return s

    def _extract_from_module1(self, report: Any, default_ts: Optional[str]) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        # Ingest pre-constructed entities from Module 1
        for e in d.get("entities", []):
            e_dict = e if isinstance(e, dict) else (e.to_dict() if hasattr(e, "to_dict") else {})
            e_type = e_dict.get("type", "unknown")
            e_val = e_dict.get("value", "")
            if e_val and e_type in self.SUPPORTED_TYPES:
                self.resolve_entity(e_type, e_val, "sender_identity", attributes=e_dict.get("attributes"), timestamp=default_ts)

                # Derive child domain from email_address if applicable
                if e_type == "email_address" and "@" in e_val:
                    dom = e_val.split("@", 1)[1]
                    if dom:
                        self.resolve_entity("domain", dom, "sender_identity", timestamp=default_ts)

        # Ingest raw envelope/header email addresses
        for field in ("envelope_sender", "header_from", "header_reply_to"):
            addr = d.get(field)
            if addr and isinstance(addr, str) and "@" in addr:
                self.resolve_entity(
                    "email_address",
                    addr,
                    "sender_identity",
                    attributes={"field": field},
                    timestamp=default_ts,
                )
                dom = addr.split("@", 1)[1].strip()
                if dom:
                    self.resolve_entity("domain", dom, "sender_identity", timestamp=default_ts)

    def _extract_from_module2(self, report: Any, default_ts: Optional[str]) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)
        obs_dom = d.get("observed_domain") or d.get("query_domain")
        ref_dom = d.get("reference_domain")

        if obs_dom:
            self.resolve_entity(
                "domain",
                str(obs_dom),
                "lookalike_domain",
                attributes={"is_observed_domain": True, "target_brand": d.get("target_brand")},
                timestamp=default_ts,
            )
        if ref_dom and "." in str(ref_dom):
            self.resolve_entity(
                "domain",
                str(ref_dom),
                "lookalike_domain",
                attributes={"is_reference_domain": True},
                timestamp=default_ts,
            )

    def _extract_from_module3(self, report: Any, default_ts: Optional[str]) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        for e in d.get("entities", []):
            e_dict = e if isinstance(e, dict) else (e.to_dict() if hasattr(e, "to_dict") else {})
            e_type = e_dict.get("type", "unknown")
            e_val = e_dict.get("value", "")
            if e_val and e_type in self.SUPPORTED_TYPES:
                self.resolve_entity(e_type, e_val, "url_analysis", attributes=e_dict.get("attributes"), timestamp=default_ts)

        for u in d.get("urls", []):
            u_dict = u if isinstance(u, dict) else (u.to_dict() if hasattr(u, "to_dict") else {})
            norm_u = u_dict.get("normalized_url", u_dict.get("actual_url", ""))
            host = u_dict.get("hostname", "")
            if norm_u:
                self.resolve_entity("url", norm_u, "url_analysis", timestamp=default_ts)
            if host:
                # Distinguish whether host is an IP or a domain
                is_ip = u_dict.get("is_ip", False) or bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))
                if is_ip:
                    self.resolve_entity("ip", host, "url_analysis", timestamp=default_ts)
                else:
                    self.resolve_entity("domain", host, "url_analysis", timestamp=default_ts)
                    self.resolve_entity("hostname", host, "url_analysis", timestamp=default_ts)

    def _extract_from_module4(self, report: Any, default_ts: Optional[str]) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        for e in d.get("entities", []):
            e_dict = e if isinstance(e, dict) else (e.to_dict() if hasattr(e, "to_dict") else {})
            e_type = e_dict.get("type", "unknown")
            e_val = e_dict.get("value", "")
            if e_val and e_type in self.SUPPORTED_TYPES:
                self.resolve_entity(e_type, e_val, "attachment_analysis", attributes=e_dict.get("attributes"), timestamp=default_ts)

        for att in d.get("attachments", []):
            a_dict = att if isinstance(att, dict) else (att.to_dict() if hasattr(att, "to_dict") else {})
            fn = a_dict.get("filename", "")
            sha = a_dict.get("sha256", "")
            if fn:
                self.resolve_entity("attachment", fn, "attachment_analysis", attributes=a_dict, timestamp=default_ts)
            if sha:
                self.resolve_entity("hash", sha, "attachment_analysis", attributes={"hash_type": "sha256", "filename": fn}, timestamp=default_ts)

    def _extract_from_module5(self, report: Any, default_ts: Optional[str]) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        for e in d.get("entities", []):
            e_dict = e if isinstance(e, dict) else (e.to_dict() if hasattr(e, "to_dict") else {})
            e_type = e_dict.get("type", "unknown")
            e_val = e_dict.get("value", "")
            if e_val and e_type in self.SUPPORTED_TYPES:
                self.resolve_entity(e_type, e_val, "origin_infrastructure", attributes=e_dict.get("attributes"), timestamp=default_ts)

        # Enriched peers: IP, ASN, Country, Infrastructure
        for peer in d.get("enriched_peers", []):
            p_dict = peer if isinstance(peer, dict) else (peer.to_dict() if hasattr(peer, "to_dict") else {})
            ip = p_dict.get("ip", "")
            if ip:
                self.resolve_entity("ip", ip, "origin_infrastructure", timestamp=default_ts)

            asn_info = p_dict.get("asn", {})
            if isinstance(asn_info, dict) and asn_info.get("asn"):
                self.resolve_entity("asn", asn_info["asn"], "origin_infrastructure", attributes={"organization": asn_info.get("organization")}, timestamp=default_ts)

            geo = p_dict.get("geolocation", {})
            if isinstance(geo, dict) and geo.get("country"):
                self.resolve_entity("country", geo["country"], "origin_infrastructure", attributes={"city": geo.get("city")}, timestamp=default_ts)

            infra = p_dict.get("infrastructure", {})
            if infra and isinstance(infra, dict) and infra.get("classification") and infra["classification"] != "unknown":
                self.resolve_entity("infrastructure", infra["classification"], "origin_infrastructure", attributes=infra, timestamp=default_ts)

    def _extract_from_infrastructure_intelligence(self, report: Any, default_ts: Optional[str]) -> None:
        d = report.to_dict() if hasattr(report, "to_dict") else dict(report)

        # Registrar entity
        rdap = d.get("rdap", {})
        if rdap and rdap.get("registrar"):
            self.resolve_entity(
                "registrar",
                rdap["registrar"],
                "infrastructure_intelligence",
                attributes={"registrar_id": rdap.get("registrar_id")},
                timestamp=default_ts,
            )

        # Allocated network entity
        if rdap and (rdap.get("network_name") or rdap.get("cidr")):
            net_val = rdap.get("network_name") or rdap.get("cidr")
            self.resolve_entity(
                "infrastructure",
                str(net_val),
                "infrastructure_intelligence",
                attributes={"cidr": rdap.get("cidr"), "rir": rdap.get("rir")},
                timestamp=default_ts,
            )

        # MX host entities
        mx = d.get("mx", {})
        for r in mx.get("records", []):
            if isinstance(r, dict) and r.get("host"):
                self.resolve_entity(
                    "hostname",
                    r["host"],
                    "infrastructure_intelligence",
                    attributes={"preference": r.get("preference"), "primary_provider": mx.get("primary_provider")},
                    timestamp=default_ts,
                )

        # Reverse DNS / PTR hostname entities
        rdns = d.get("reverse_dns", {})
        for h in rdns.get("ptr_hostnames", []):
            self.resolve_entity(
                "hostname",
                h,
                "infrastructure_intelligence",
                attributes={"fcrdns_valid": rdns.get("fcrdns_valid")},
                timestamp=default_ts,
            )
