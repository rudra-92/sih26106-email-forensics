"""Forensic analyzer for sender identity inconsistencies and authentication.

Examines parsed email evidence for identity discrepancies, authentication
reports (SPF, DKIM, DMARC), display name impersonation, and routing hops.
Constructs graph-ready entities and relationships preserving explicit IP roles
and generates transparent, bounded forensic risk assessments.
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    Assessment,
    Entity,
    Observation,
    ParsedEmailEvidence,
    Relationship,
    SenderIdentityReport,
)


class SenderIdentityAnalyzer:
    """Performs structured forensic analysis on extracted sender identity evidence."""

    # Specific brand names that indicate high-risk targeted impersonation when
    # combined with an unaligned domain. Generic words like "support" or "admin"
    # are NOT in this list.
    SPECIFIC_BRAND_NAMES = {
        "microsoft",
        "google",
        "apple",
        "amazon",
        "paypal",
        "netflix",
        "meta",
        "facebook",
        "instagram",
        "chase",
        "wells fargo",
        "citibank",
        "irs",
    }

    # Public free webmail domains
    FREE_MAIL_DOMAINS = {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "icloud.com",
        "mail.com",
        "zoho.com",
        "protonmail.com",
        "proton.me",
        "yandex.com",
    }

    def __init__(self) -> None:
        self._obs_counter = 0

    def analyze(
        self, evidence: ParsedEmailEvidence, email_id: str = "E001"
    ) -> SenderIdentityReport:
        """Run all forensic checks, build graph artifacts, and generate assessment.

        Args:
            evidence: ParsedEmailEvidence from SenderIdentityParser.
            email_id: Logical identifier for the email being investigated.

        Returns:
            SenderIdentityReport ready for downstream graph or correlation engines.
        """
        self._obs_counter = 0
        observations: List[Observation] = []

        # 1. From vs Reply-To analysis
        self._check_from_vs_reply_to(evidence, observations)

        # 2. From vs Return-Path analysis
        self._check_from_vs_return_path(evidence, observations)

        # 3. Display name analysis (distinguish generic vs brand/embedded inconsistency)
        self._check_display_name_analysis(evidence, observations)

        # 4. Message-ID domain consistency
        self._check_message_id_domain(evidence, observations)

        # 5. SPF authentication report
        self._check_spf_report(evidence, observations)

        # 6. DKIM authentication report
        self._check_dkim_report(evidence, observations)

        # 7. DMARC authentication report
        self._check_dmarc_report(evidence, observations)

        # 8. Authentication & domain alignment
        self._check_auth_domain_alignment(evidence, observations)

        # 9. Received chain routing evidence
        self._check_received_chain(evidence, observations)

        # Build graph entities & relationships (preserving IP roles)
        entities = self._build_entities(evidence, email_id)
        relationships = self._build_relationships(evidence, email_id)

        # Compute transparent bounded risk assessment
        assessment = self._evaluate_assessment(evidence, observations)

        return SenderIdentityReport(
            module="sender_identity",
            email_id=email_id,
            file_hash_sha256=evidence.file_hash_sha256,
            entities=entities,
            observations=observations,
            relationships=relationships,
            assessment=assessment,
        )

    def _next_obs_id(self) -> str:
        self._obs_counter += 1
        return f"OBS-{self._obs_counter:03d}"

    def _domains_align(self, domain_a: Optional[str], domain_b: Optional[str]) -> bool:
        """Check if two domains match or share organizational parent domain."""
        if not domain_a or not domain_b:
            return False
        d1, d2 = domain_a.lower().strip(), domain_b.lower().strip()
        if d1 == d2:
            return True
        if d1.endswith(f".{d2}") or d2.endswith(f".{d1}"):
            return True
        return False

    def _check_from_vs_reply_to(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check A: Compare From identity with Reply-To."""
        from_addr = evidence.sender_address
        from_domain = evidence.sender_domain
        reply_addr = evidence.reply_to_address
        reply_domain = evidence.reply_to_domain

        if not reply_addr or not from_addr:
            return

        if reply_addr != from_addr:
            if from_domain and reply_domain and not self._domains_align(from_domain, reply_domain):
                observations.append(
                    Observation(
                        observation_id=self._next_obs_id(),
                        rule_id="RULE-REPLY-TO-DOMAIN-MISMATCH",
                        type="reply_to_domain_mismatch",
                        severity="medium",
                        description=(
                            "Reply-To domain differs from visible From domain "
                            "(contextual indicator: common in customer ticketing, CRM tools, "
                            "or third-party reply routing, but recorded as an identity divergence)."
                        ),
                        evidence={
                            "from_address": from_addr,
                            "reply_to_address": reply_addr,
                            "from_domain": from_domain,
                            "reply_to_domain": reply_domain,
                        },
                        source_header="Reply-To",
                    )
                )
            else:
                observations.append(
                    Observation(
                        observation_id=self._next_obs_id(),
                        rule_id="RULE-REPLY-TO-ADDR-MISMATCH",
                        type="reply_to_address_mismatch",
                        severity="low",
                        description=(
                            "Reply-To address differs from visible From address "
                            "within the same organizational domain."
                        ),
                        evidence={
                            "from_address": from_addr,
                            "reply_to_address": reply_addr,
                        },
                        source_header="Reply-To",
                    )
                )

    def _check_from_vs_return_path(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check B: Compare visible From domain with Return-Path (envelope sender)."""
        from_domain = evidence.sender_domain
        rp_domain = evidence.return_path_domain

        if not rp_domain or not from_domain:
            return

        if not self._domains_align(from_domain, rp_domain):
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-RETURN-PATH-DOMAIN-MISMATCH",
                    type="return_path_domain_mismatch",
                    severity="low",
                    description=(
                        "Return-Path domain differs from visible From domain "
                        "(contextual indicator: common with Email Service Providers, bounce processors, "
                        "or mailing lists; envelope sender mismatch)."
                    ),
                    evidence={
                        "from_address": evidence.sender_address or "",
                        "return_path_address": evidence.return_path_address or "",
                        "from_domain": from_domain,
                        "return_path_domain": rp_domain,
                    },
                    source_header="Return-Path",
                )
            )

    def _check_display_name_analysis(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check C: Analyze display name without treating generic words as spoofing."""
        disp_name = evidence.display_name
        sender_domain = evidence.sender_domain
        sender_addr = evidence.sender_address

        if not disp_name:
            return

        disp_lower = disp_name.lower().strip()

        # 1. Check for embedded email address in display name (e.g. "ceo@company.com <bad@evil.com>")
        email_match = re.search(r"[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}", disp_name)
        if email_match:
            embedded_email = email_match.group(0).lower()
            embedded_domain = embedded_email.split("@", 1)[1] if "@" in embedded_email else ""
            if not self._domains_align(sender_domain, embedded_domain):
                observations.append(
                    Observation(
                        observation_id=self._next_obs_id(),
                        rule_id="RULE-DISPLAY-NAME-EMBEDDED-EMAIL",
                        type="display_name_embedded_email_mismatch",
                        severity="high",
                        description="Display name contains an embedded email address from an inconsistent domain.",
                        evidence={
                            "display_name": disp_name,
                            "embedded_email": embedded_email,
                            "sender_address": sender_addr or "",
                            "sender_domain": sender_domain or "",
                        },
                        source_header="From",
                    )
                )
                return

        # 2. Check for specific corporate brand name impersonation
        for brand in self.SPECIFIC_BRAND_NAMES:
            # Word boundary check for the brand name
            if re.search(r"\b" + re.escape(brand) + r"\b", disp_lower):
                if sender_domain and brand not in sender_domain.lower():
                    observations.append(
                        Observation(
                            observation_id=self._next_obs_id(),
                            rule_id="RULE-DISPLAY-NAME-BRAND-MISMATCH",
                            type="display_name_brand_mismatch",
                            severity="medium",
                            description=(
                                f"Display name suggests a specific corporate brand ('{brand}') "
                                f"while the sender address domain is unaligned."
                            ),
                            evidence={
                                "display_name": disp_name,
                                "matched_brand": brand,
                                "sender_domain": sender_domain,
                                "sender_address": sender_addr or "",
                            },
                            source_header="From",
                        )
                    )
                    return

        # 3. If display name is present without suspicious brand/email anomalies, record context
        observations.append(
            Observation(
                observation_id=self._next_obs_id(),
                rule_id="RULE-DISPLAY-NAME-PRESENT",
                type="display_name_present",
                severity="informational",
                description="Display name is present and contains no contradictory brand or address tokens.",
                evidence={
                    "display_name": disp_name,
                    "sender_address": sender_addr or "",
                },
                source_header="From",
            )
        )

    def _check_message_id_domain(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check D: Compare Message-ID domain with sender domain."""
        msg_id_domain = evidence.message_id_domain
        sender_domain = evidence.sender_domain

        if not msg_id_domain or not sender_domain:
            return

        if not self._domains_align(msg_id_domain, sender_domain):
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-MESSAGE-ID-DOMAIN-MISMATCH",
                    type="message_id_domain_mismatch",
                    severity="low",
                    description=(
                        "Message-ID domain differs from visible From domain "
                        "(contextual indicator: common in outsourced SMTP relays or web application mailers)."
                    ),
                    evidence={
                        "message_id": evidence.message_id or "",
                        "message_id_domain": msg_id_domain,
                        "sender_domain": sender_domain,
                    },
                    source_header="Message-ID",
                )
            )

    def _check_spf_report(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check E: Evaluate SPF result reported in Authentication-Results."""
        spf_res = evidence.auth_results.spf
        if not spf_res:
            return

        spf_lower = spf_res.lower()
        if spf_lower == "fail":
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-AUTH-SPF-FAIL",
                    type="spf_authentication_failure",
                    severity="high",
                    description="Receiving server reported SPF failure.",
                    evidence={
                        "reported_result": spf_res,
                        "spf_domain": evidence.auth_results.spf_domain,
                        "raw_header": evidence.auth_results.raw_headers[0] if evidence.auth_results.raw_headers else "",
                    },
                    source_header="Authentication-Results",
                )
            )
        elif spf_lower == "softfail":
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-AUTH-SPF-SOFTFAIL",
                    type="spf_authentication_softfail",
                    severity="medium",
                    description="Receiving server reported SPF softfail.",
                    evidence={
                        "reported_result": spf_res,
                        "spf_domain": evidence.auth_results.spf_domain,
                        "raw_header": evidence.auth_results.raw_headers[0] if evidence.auth_results.raw_headers else "",
                    },
                    source_header="Authentication-Results",
                )
            )
        elif spf_lower in ("neutral", "none", "permerror", "temperror"):
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id=f"RULE-AUTH-SPF-{spf_lower.upper()}",
                    type=f"spf_{spf_lower}",
                    severity="low" if spf_lower != "none" else "informational",
                    description=f"Receiving server reported SPF {spf_lower}.",
                    evidence={
                        "reported_result": spf_res,
                        "spf_domain": evidence.auth_results.spf_domain,
                    },
                    source_header="Authentication-Results",
                )
            )
        elif spf_lower == "pass":
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-AUTH-SPF-PASS",
                    type="spf_authentication_pass",
                    severity="informational",
                    description="Receiving server reported SPF pass.",
                    evidence={
                        "reported_result": spf_res,
                        "spf_domain": evidence.auth_results.spf_domain,
                    },
                    source_header="Authentication-Results",
                )
            )

    def _check_dkim_report(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check F: Evaluate DKIM result reported in Authentication-Results."""
        dkim_res = evidence.auth_results.dkim
        if not dkim_res:
            return

        dkim_lower = dkim_res.lower()
        if dkim_lower in ("fail", "permerror"):
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-AUTH-DKIM-FAIL",
                    type="dkim_authentication_failure",
                    severity="high",
                    description="Receiving server reported DKIM authentication failure.",
                    evidence={
                        "reported_result": dkim_res,
                        "dkim_domain": evidence.auth_results.dkim_domain,
                    },
                    source_header="Authentication-Results",
                )
            )
        elif dkim_lower == "pass":
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-AUTH-DKIM-PASS",
                    type="dkim_authentication_pass",
                    severity="informational",
                    description="Receiving server reported DKIM pass.",
                    evidence={
                        "reported_result": dkim_res,
                        "dkim_domain": evidence.auth_results.dkim_domain,
                    },
                    source_header="Authentication-Results",
                )
            )
        elif dkim_lower in ("none", "neutral", "temperror"):
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id=f"RULE-AUTH-DKIM-{dkim_lower.upper()}",
                    type=f"dkim_{dkim_lower}",
                    severity="low" if dkim_lower != "none" else "informational",
                    description=f"Receiving server reported DKIM {dkim_lower}.",
                    evidence={
                        "reported_result": dkim_res,
                        "dkim_domain": evidence.auth_results.dkim_domain,
                    },
                    source_header="Authentication-Results",
                )
            )

    def _check_dmarc_report(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check G: Evaluate DMARC result reported in Authentication-Results."""
        dmarc_res = evidence.auth_results.dmarc
        if not dmarc_res:
            return

        dmarc_lower = dmarc_res.lower()
        if dmarc_lower in ("fail", "permerror"):
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-AUTH-DMARC-FAIL",
                    type="dmarc_authentication_failure",
                    severity="high",
                    description="Receiving server reported DMARC failure.",
                    evidence={
                        "reported_result": dmarc_res,
                        "dmarc_domain": evidence.auth_results.dmarc_domain,
                    },
                    source_header="Authentication-Results",
                )
            )
        elif dmarc_lower == "pass":
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id="RULE-AUTH-DMARC-PASS",
                    type="dmarc_authentication_pass",
                    severity="informational",
                    description="Receiving server reported DMARC pass.",
                    evidence={
                        "reported_result": dmarc_res,
                        "dmarc_domain": evidence.auth_results.dmarc_domain,
                    },
                    source_header="Authentication-Results",
                )
            )
        elif dmarc_lower in ("none", "temperror"):
            observations.append(
                Observation(
                    observation_id=self._next_obs_id(),
                    rule_id=f"RULE-AUTH-DMARC-{dmarc_lower.upper()}",
                    type=f"dmarc_{dmarc_lower}",
                    severity="informational",
                    description=f"Receiving server reported DMARC {dmarc_lower}.",
                    evidence={
                        "reported_result": dmarc_res,
                        "dmarc_domain": evidence.auth_results.dmarc_domain,
                    },
                    source_header="Authentication-Results",
                )
            )

    def _check_auth_domain_alignment(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check H: Identify whether authenticated domains align with visible From domain."""
        from_domain = evidence.sender_domain
        spf_domain = evidence.auth_results.spf_domain
        dkim_domain = evidence.auth_results.dkim_domain
        spf_res = evidence.auth_results.spf
        dkim_res = evidence.auth_results.dkim

        if not from_domain:
            return

        spf_aligned = self._domains_align(from_domain, spf_domain) if spf_domain else False
        dkim_aligned = self._domains_align(from_domain, dkim_domain) if dkim_domain else False

        has_auth = bool(spf_res or dkim_res)
        if has_auth and not spf_aligned and not dkim_aligned:
            if (spf_domain or dkim_domain) and (spf_res == "pass" or dkim_res == "pass"):
                observations.append(
                    Observation(
                        observation_id=self._next_obs_id(),
                        rule_id="RULE-AUTH-ALIGNMENT-MISMATCH",
                        type="authentication_domain_unaligned",
                        severity="medium",
                        description=(
                            "Authentication passed for third-party domain, but does not align with "
                            "the visible From domain (DMARC alignment requirement)."
                        ),
                        evidence={
                            "from_domain": from_domain,
                            "spf_domain": spf_domain,
                            "spf_aligned": spf_aligned,
                            "dkim_domain": dkim_domain,
                            "dkim_aligned": dkim_aligned,
                        },
                        source_header="Authentication-Results",
                    )
                )

    def _check_received_chain(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> None:
        """Check I: Preserve structured relay evidence without making attribution claims."""
        hops = evidence.received_hops
        all_ips: List[str] = []
        hop_summaries: List[Dict[str, Any]] = []

        for hop in hops:
            for ip in hop.all_ips:
                if ip not in all_ips:
                    all_ips.append(ip)
            hop_summaries.append({
                "hop_index": hop.hop_index,
                "from_host": hop.from_host,
                "from_ip": hop.from_ip,
                "by_host": hop.by_host,
                "by_ip": hop.by_ip,
                "timestamp": hop.timestamp,
            })

        observations.append(
            Observation(
                observation_id=self._next_obs_id(),
                rule_id="RULE-RECEIVED-CHAIN-SUMMARY",
                type="received_chain_evidence",
                severity="informational",
                description=(
                    f"Preserved {len(hops)} Received hop(s) with {len(all_ips)} unique IP address(es) "
                    "for downstream relay path reconstruction without attributing any IP as attacker."
                ),
                evidence={
                    "hop_count": len(hops),
                    "unique_ip_count": len(all_ips),
                    "observed_ips": all_ips,
                    "hops": hop_summaries,
                },
                source_header="Received",
            )
        )

    def _build_entities(
        self, evidence: ParsedEmailEvidence, email_id: str
    ) -> List[Entity]:
        """Construct graph-ready entities preserving forensic roles."""
        entities: List[Entity] = []
        seen_keys: Set[Tuple[str, str]] = set()

        def _add_entity(ent_type: str, value: Optional[str], source: str, **attrs: Any) -> None:
            if not value:
                return
            key = (ent_type, value.lower())
            if key not in seen_keys:
                seen_keys.add(key)
                entities.append(
                    Entity(
                        type=ent_type,
                        value=value,
                        source=source,
                        attributes=attrs if attrs else {},
                    )
                )

        # 1. Email Message entity
        _add_entity("email", email_id, "Parser", sha256=evidence.file_hash_sha256)

        # 2. Message-ID entity
        if evidence.message_id:
            _add_entity("message_id", evidence.message_id, "Message-ID")

        # 3. Email Addresses
        _add_entity("email_address", evidence.sender_address, "From")
        _add_entity("email_address", evidence.reply_to_address, "Reply-To")
        _add_entity("email_address", evidence.return_path_address, "Return-Path")

        # 4. Domains
        _add_entity("domain", evidence.sender_domain, "From")
        _add_entity("domain", evidence.reply_to_domain, "Reply-To")
        _add_entity("domain", evidence.return_path_domain, "Return-Path")
        _add_entity("domain", evidence.message_id_domain, "Message-ID")
        _add_entity("domain", evidence.auth_results.spf_domain, "Authentication-Results")
        _add_entity("domain", evidence.auth_results.dkim_domain, "Authentication-Results")
        _add_entity("domain", evidence.auth_results.dmarc_domain, "Authentication-Results")

        # 5. IP Addresses with explicit roles
        for hop in evidence.received_hops:
            if hop.from_ip:
                _add_entity(
                    "ip",
                    hop.from_ip,
                    "Received",
                    role="peer_ip",
                    hop_index=hop.hop_index,
                    from_host=hop.from_host,
                )
            if hop.by_ip:
                _add_entity(
                    "ip",
                    hop.by_ip,
                    "Received",
                    role="receiver_ip",
                    hop_index=hop.hop_index,
                    by_host=hop.by_host,
                )
            for other in hop.other_ips:
                _add_entity(
                    "ip",
                    other,
                    "Received",
                    role="observed_hop_ip",
                    hop_index=hop.hop_index,
                )

        return entities

    def _build_relationships(
        self, evidence: ParsedEmailEvidence, email_id: str
    ) -> List[Relationship]:
        """Construct graph-ready relationships preserving explicit forensic roles."""
        relationships: List[Relationship] = []
        seen: Set[Tuple[str, str, str]] = set()

        def _add_rel(
            src: Optional[str], rel: str, tgt: Optional[str], ev: Optional[Dict[str, Any]] = None
        ) -> None:
            if not src or not tgt:
                return
            key = (src.lower(), rel, tgt.lower())
            if key not in seen:
                seen.add(key)
                relationships.append(
                    Relationship(source=src, relation=rel, target=tgt, evidence=ev)
                )

        # Email -> sent_by -> sender_address
        if evidence.sender_address:
            _add_rel(email_id, "sent_by", evidence.sender_address, {"header": "From"})
            if evidence.sender_domain:
                _add_rel(evidence.sender_address, "belongs_to", evidence.sender_domain)

        # Email -> replies_to -> reply_to_address
        if evidence.reply_to_address:
            _add_rel(email_id, "replies_to", evidence.reply_to_address, {"header": "Reply-To"})
            if evidence.reply_to_domain:
                _add_rel(evidence.reply_to_address, "belongs_to", evidence.reply_to_domain)

        # Email -> returns_to -> return_path_address
        if evidence.return_path_address:
            _add_rel(email_id, "returns_to", evidence.return_path_address, {"header": "Return-Path"})
            if evidence.return_path_domain:
                _add_rel(evidence.return_path_address, "belongs_to", evidence.return_path_domain)

        # Email -> has_message_id -> message_id
        if evidence.message_id:
            _add_rel(email_id, "has_message_id", evidence.message_id, {"header": "Message-ID"})

        # Routing relationships preserving explicit roles:
        # observed_peer_ip (upstream sending peer observed by receiver)
        # observed_receiver_ip (server receiving that hop)
        for hop in evidence.received_hops:
            if hop.from_ip:
                _add_rel(
                    email_id,
                    "observed_peer_ip",
                    hop.from_ip,
                    {
                        "hop_index": hop.hop_index,
                        "from_host": hop.from_host,
                        "role": "peer_ip",
                    },
                )
            if hop.by_ip:
                _add_rel(
                    email_id,
                    "observed_receiver_ip",
                    hop.by_ip,
                    {
                        "hop_index": hop.hop_index,
                        "by_host": hop.by_host,
                        "role": "receiver_ip",
                    },
                )
            for other in hop.other_ips:
                _add_rel(
                    email_id,
                    "observed_ip",
                    other,
                    {
                        "hop_index": hop.hop_index,
                        "role": "observed_hop_ip",
                    },
                )

        return relationships

    def _evaluate_assessment(
        self, evidence: ParsedEmailEvidence, observations: List[Observation]
    ) -> Assessment:
        """Compute a transparent, bounded forensic risk evaluation.

        Distinguishes:
        - risk_level ('none', 'low', 'medium', 'high')
        - evidence_strength ('none', 'weak', 'moderate', 'strong')
        - confidence (strictly bounded float, never 1.0)
        - category and reason detailing the exact evidentiary justification
        """
        obs_types = {o.type: o for o in observations}

        # Signal weights for independent evidence accumulation
        signal_weights: Dict[str, float] = {
            "dmarc_authentication_failure": 0.45,
            "spf_authentication_failure": 0.35,
            "dkim_authentication_failure": 0.35,
            "display_name_embedded_email_mismatch": 0.40,
            "display_name_brand_mismatch": 0.25,
            "spf_authentication_softfail": 0.15,
            "authentication_domain_unaligned": 0.20,
            "reply_to_domain_mismatch": 0.15,
            "return_path_domain_mismatch": 0.10,
            "message_id_domain_mismatch": 0.08,
            "reply_to_address_mismatch": 0.04,
        }

        # Independent evidence accumulation: C = 1 - product(1 - w_i)
        combined_unconfidence = 1.0
        active_signals: List[Tuple[str, str, float]] = []

        for o_type, weight in signal_weights.items():
            if o_type in obs_types:
                obs = obs_types[o_type]
                combined_unconfidence *= (1.0 - weight)
                active_signals.append((o_type, obs.description, weight))

        raw_score = 1.0 - combined_unconfidence

        # Check for passing authentication
        has_spf_pass = "spf_authentication_pass" in obs_types
        has_dkim_pass = "dkim_authentication_pass" in obs_types
        has_dmarc_pass = "dmarc_authentication_pass" in obs_types

        # Check severe vs contextual signals
        has_dmarc_fail = "dmarc_authentication_failure" in obs_types
        has_spf_fail = "spf_authentication_failure" in obs_types
        has_dkim_fail = "dkim_authentication_failure" in obs_types
        has_brand_or_email_spoof = (
            "display_name_embedded_email_mismatch" in obs_types
            or "display_name_brand_mismatch" in obs_types
        )

        # Benign scenario: passing authentication without identity anomalies
        high_or_med_obs = [
            o for o in observations if o.severity in ("high", "medium")
        ]
        if not high_or_med_obs and (has_spf_pass or has_dkim_pass or has_dmarc_pass):
            return Assessment(
                category="legitimate_or_no_significant_identity_anomaly",
                risk_level="none",
                evidence_strength="none",
                confidence=0.0,
                reason="Sender identity and reported authentication results (SPF/DKIM/DMARC) are consistent.",
            )

        # Note: Confidence is a transparent heuristic/rule-based assessment score
        # and is not a statistically calibrated probability. SPF, DKIM, and DMARC
        # results can be correlated rather than strictly independent evidence.
        # Cap confidence at 0.94 to avoid claiming 100% certainty.
        MAX_CONFIDENCE = 0.94
        confidence = min(round(raw_score, 4), MAX_CONFIDENCE)

        # Determine evidence strength and risk level
        strong_auth_failures = has_dmarc_fail or (has_spf_fail and has_dkim_fail)

        if strong_auth_failures and (has_brand_or_email_spoof or "reply_to_domain_mismatch" in obs_types):
            category = "high_risk_sender_identity_anomaly"
            risk_level = "high"
            evidence_strength = "strong"
            summary = "Multiple authentication and identity inconsistencies were observed."
        elif strong_auth_failures or has_brand_or_email_spoof or (has_spf_fail and "reply_to_domain_mismatch" in obs_types):
            category = "possible_sender_impersonation"
            risk_level = "medium"
            evidence_strength = "moderate"
            summary = "Reported authentication anomalies and/or identity discrepancies suggest possible impersonation."
        elif active_signals:
            category = "contextual_identity_inconsistency"
            risk_level = "low"
            evidence_strength = "weak"
            summary = "Contextual identity differences observed (common in third-party senders, ticketing, or relays)."
            confidence = min(confidence, 0.35)
        else:
            category = "legitimate_or_no_significant_identity_anomaly"
            risk_level = "none"
            evidence_strength = "none"
            confidence = 0.0
            summary = "No significant sender identity anomalies observed."

        # Build detailed justification string
        reasons_list = [f"{desc} (weight: {w:.2f})" for _, desc, w in active_signals]
        full_reason = f"{summary} Details: " + "; ".join(reasons_list) if reasons_list else summary

        return Assessment(
            category=category,
            risk_level=risk_level,
            evidence_strength=evidence_strength,
            confidence=confidence,
            reason=full_reason,
        )
