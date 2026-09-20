"""Comprehensive test suite for Module 6: Evidence Correlation & Attribution Support.

Tests all 16 forensic requirements:
1. Normalization (conversion, provenance, trust state)
2. Entity Resolution (cross-module deduplication, separation)
3. Relationship Correlation (evidence backing, deduplication)
4. Cross-Module Corroboration (M1+M2, M2+M3, M4+M5, multi-signal)
5. Contradiction Detection (auth vs lookalike, geo conflict, ML vs deterministic)
6. ML Adapters (threat, BEC, URL risk, malformed inputs, trust_state='inferred')
7. Cross-Case & Temporal Correlation (recurring IP, shared hash, clustering)
8. Attribution Safety (no attacker identity, no physical home address, non-speculative wording)
"""

from __future__ import annotations

import unittest

from modules.evidence_correlation import (
    BECIntentModelAdapter,
    BecIntentClassifierAdapter,
    EmailThreatClassifierAdapter,
    EmailThreatModelAdapter,
    EXPECTED_MODULE3_FEATURES,
    EvidenceCorrelationAnalyzer,
    URLRiskModelAdapter,
    UrlRiskClassifierAdapter,
    correlate_evidence,
)
from modules.evidence_correlation.attribution_support import AttributionSupportEngine
from modules.evidence_correlation.contradiction import ContradictionEngine
from modules.evidence_correlation.corroboration import CorroborationEngine
from modules.evidence_correlation.entity_resolution import EntityResolver
from modules.evidence_correlation.hypothesis_engine import CaseHypothesisEngine
from modules.evidence_correlation.models import (
    CorrelatedEntity,
    InvestigationCase,
    MlPrediction,
    NormalizedEvidence,
)
from modules.evidence_correlation.normalizer import EvidenceNormalizer
from modules.evidence_correlation.relationship_engine import RelationshipEngine
from modules.evidence_correlation.temporal_correlation import CrossCaseCorrelator


class TestEvidenceCorrelation(unittest.TestCase):
    """Test suite verifying all Module 6 functionality and forensic guardrails."""

    def setUp(self) -> None:
        self.analyzer = EvidenceCorrelationAnalyzer()

    # =========================================================================
    # 1. Evidence Normalization Tests
    # =========================================================================

    def test_01_evidence_normalization_m1(self) -> None:
        """1. Verify Module 1 findings normalize into canonical NormalizedEvidence with observed trust state."""
        normalizer = EvidenceNormalizer(case_id="CASE-001")
        m1_dict = {
            "observations": [
                {
                    "observation_id": "OBS-001",
                    "rule_id": "RULE-ID-REPLY-TO-MISMATCH",
                    "severity": "medium",
                    "description": "Reply-To divergence detected",
                    "source_header": "Reply-To",
                    "evidence": {"from": "user@paypal.com", "reply_to": "user@paypa1.com"},
                }
            ],
            "assessment": {
                "category": "suspicious_sender",
                "risk_level": "medium",
                "evidence_strength": "moderate",
                "confidence": 0.75,
                "reason": "Unaligned routing",
            },
        }

        norm_ev = normalizer.normalize_all(module1_report=m1_dict)
        self.assertEqual(len(norm_ev), 2)
        obs_ev = norm_ev[0]
        self.assertEqual(obs_ev.source_module, "sender_identity")
        self.assertEqual(obs_ev.trust_state, "observed")
        self.assertEqual(obs_ev.rule_id, "RULE-ID-REPLY-TO-MISMATCH")
        self.assertEqual(obs_ev.severity, "medium")
        self.assertIn("sender_identity", obs_ev.provenance)

    def test_02_evidence_normalization_ml_inferred_trust(self) -> None:
        """2. Verify ML predictions ALWAYS receive trust_state='inferred' and are never marked observed."""
        normalizer = EvidenceNormalizer(case_id="CASE-001")
        preds = [
            MlPrediction(
                model="email_threat_classifier",
                model_version="1.0.0",
                label="phishing",
                confidence=0.94,
                input_reference="CASE-001",
            )
        ]
        norm_ev = normalizer.normalize_all(ml_predictions=preds)
        self.assertEqual(len(norm_ev), 1)
        ml_ev = norm_ev[0]
        self.assertEqual(ml_ev.trust_state, "inferred")
        self.assertNotEqual(ml_ev.trust_state, "observed")
        self.assertEqual(ml_ev.severity, "high")

    # =========================================================================
    # 2. Entity Resolution Tests
    # =========================================================================

    def test_03_cross_module_entity_resolution(self) -> None:
        """3. Verify equivalent domain, IP, and hash across modules resolve into unified entities."""
        resolver = EntityResolver()

        # M1 reports email and IP
        m1_dict = {
            "entities": [
                {"type": "email_address", "value": "billing@paypa1.com"},
                {"type": "ip", "value": "198.51.100.77"},
            ]
        }
        # M2 reports observed domain
        m2_dict = {
            "observed_domain": "paypa1.com",
            "reference_domain": "paypal.com",
        }
        # M3 reports URL on the same domain and IP
        m3_dict = {
            "urls": [
                {"normalized_url": "https://paypa1.com/login", "hostname": "paypa1.com", "is_ip": False},
                {"normalized_url": "http://198.51.100.77/auth", "hostname": "198.51.100.77", "is_ip": True},
            ]
        }
        # M4 reports attachment hash
        m4_dict = {
            "attachments": [
                {"filename": "invoice.pdf.exe", "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"}
            ]
        }
        # M5 reports same IP and an ASN
        m5_dict = {
            "enriched_peers": [
                {
                    "ip": "198.51.100.77",
                    "asn": {"asn": "AS24940", "organization": "Hetzner Online GmbH"},
                    "geolocation": {"country": "Germany", "city": "Frankfurt am Main"},
                }
            ]
        }

        entities = resolver.extract_and_resolve_all(
            email_id="E001",
            module1_report=m1_dict,
            module2_report=m2_dict,
            module3_report=m3_dict,
            module4_report=m4_dict,
            module5_report=m5_dict,
        )
        self.assertGreater(len(entities), 0)

        domain_ent = resolver.get_entity("domain", "paypa1.com")
        self.assertIsNotNone(domain_ent)
        assert domain_ent is not None
        # Merged provenance across M1, M2, and M3!
        self.assertIn("sender_identity", domain_ent.source_modules)
        self.assertIn("lookalike_domain", domain_ent.source_modules)
        self.assertIn("url_analysis", domain_ent.source_modules)

        ip_ent = resolver.get_entity("ip", "198.51.100.77")
        self.assertIsNotNone(ip_ent)
        assert ip_ent is not None
        # Merged provenance across M1, M3, and M5!
        self.assertIn("sender_identity", ip_ent.source_modules)
        self.assertIn("url_analysis", ip_ent.source_modules)
        self.assertIn("origin_infrastructure", ip_ent.source_modules)

        # Hash entity exists
        hash_ent = resolver.get_entity("hash", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        self.assertIsNotNone(hash_ent)

    def test_04_different_entities_remain_separate(self) -> None:
        """4. Verify distinct IPs and domains are never erroneously merged."""
        resolver = EntityResolver()
        e1 = resolver.resolve_entity("domain", "evil.com", "m1")
        e2 = resolver.resolve_entity("domain", "google.com", "m2")
        e3 = resolver.resolve_entity("ip", "1.1.1.1", "m3")
        e4 = resolver.resolve_entity("ip", "8.8.8.8", "m5")

        self.assertNotEqual(e1.entity_id, e2.entity_id)
        self.assertNotEqual(e3.entity_id, e4.entity_id)
        self.assertEqual(len(resolver.all_entities()), 4)

    # =========================================================================
    # 3. Relationship Engine Tests
    # =========================================================================

    def test_05_relationship_deduplication_and_evidence_backing(self) -> None:
        """5. Verify relationships merge duplicate reporting and preserve all backing evidence."""
        engine = RelationshipEngine()
        # Add relation from M1
        r1 = engine.add_relationship(
            from_entity="email:E001",
            relationship_type="observed_from",
            to_entity="ip:198.51.100.77",
            source_module="sender_identity",
            evidence_ids=["EV-001"],
        )
        # Add identical relation from M5 with new evidence
        r2 = engine.add_relationship(
            from_entity="email:E001",
            relationship_type="observed_from",
            to_entity="ip:198.51.100.77",
            source_module="origin_infrastructure",
            evidence_ids=["EV-005"],
        )

        self.assertEqual(r1.relationship_id, r2.relationship_id)
        self.assertEqual(len(engine.all_relationships()), 1)
        merged = engine.all_relationships()[0]
        self.assertIn("sender_identity", merged.source_modules)
        self.assertIn("origin_infrastructure", merged.source_modules)
        self.assertIn("EV-001", merged.evidence_ids)
        self.assertIn("EV-005", merged.evidence_ids)

    # =========================================================================
    # 4. Cross-Module Corroboration Tests
    # =========================================================================

    def test_06_corroborated_identity_deception(self) -> None:
        """6. Corroborate Module 1 (Reply-To mismatch) + Module 2 (lookalike candidate) + Module 3 (URL domain)."""
        normalizer = EvidenceNormalizer()
        m1_dict = {
            "observations": [
                {
                    "rule_id": "RULE-ID-REPLY-TO-MISMATCH",
                    "severity": "medium",
                    "description": "Reply-To divergence: user@paypa1.com vs user@paypal.com",
                    "evidence": {},
                }
            ]
        }
        m2_dict = {
            "observed_domain": "paypa1.com",
            "reference_domain": "paypal.com",
            "candidate_score": 0.88,
            "positive_evidence": [
                {
                    "rule_id": "RULE-LOOKALIKE-MATCH",
                    "severity": "high",
                    "description": "Domain paypa1.com resembles paypal.com",
                    "evidence": {},
                }
            ],
        }
        m3_dict = {
            "urls": [{"actual_url": "https://paypa1.com/login", "hostname": "paypa1.com"}]
        }

        evidence = normalizer.normalize_all(
            module1_report=m1_dict,
            module2_report=m2_dict,
            module3_report=m3_dict,
        )
        corroborator = CorroborationEngine()
        findings = corroborator.find_corroborations(evidence)

        id_find = next((f for f in findings if f.finding_type == "correlated_identity_deception"), None)
        self.assertIsNotNone(id_find)
        assert id_find is not None
        self.assertEqual(id_find.heuristic_support_strength, "critical")
        self.assertEqual(id_find.confidence_metric, "heuristic_non_calibrated_consensus")
        self.assertIn("sender_identity", id_find.source_modules)
        self.assertIn("lookalike_domain", id_find.source_modules)
        self.assertIn("url_analysis", id_find.source_modules)

    def test_07_corroborated_malware_delivery(self) -> None:
        """7. Corroborate Module 4 (macro attachment) + Module 5 (anonymized origin) + Threat ML (malware)."""
        normalizer = EvidenceNormalizer()
        m4_dict = {
            "observations": [
                {
                    "rule_id": "RULE-ATT-MACRO-CAPABLE",
                    "severity": "high",
                    "description": "Attachment contains macro executable scripts",
                    "evidence": {},
                }
            ]
        }
        m5_dict = {
            "observations": [
                {
                    "rule_id": "RULE-ORIGIN-TOR-EXIT",
                    "severity": "medium",
                    "description": "Origin infrastructure classified as anonymized Tor exit",
                    "evidence": {},
                }
            ]
        }
        ml_mal = [
            MlPrediction(
                model="email_threat_classifier",
                model_version="1.0",
                label="malware",
                confidence=0.92,
            )
        ]

        evidence = normalizer.normalize_all(
            module4_report=m4_dict,
            module5_report=m5_dict,
            ml_predictions=ml_mal,
        )
        findings = CorroborationEngine().find_corroborations(evidence, ml_predictions=ml_mal)

        mal_find = next((f for f in findings if f.finding_type == "correlated_malware_delivery"), None)
        self.assertIsNotNone(mal_find)
        assert mal_find is not None
        self.assertEqual(mal_find.heuristic_support_strength, "critical")
        self.assertIn("attachment_analysis", mal_find.source_modules)
        self.assertIn("origin_infrastructure", mal_find.source_modules)
        self.assertIn("external_ml", mal_find.source_modules)

    # =========================================================================
    # 5. Contradiction Detection Tests
    # =========================================================================

    def test_08_contradiction_spf_pass_vs_lookalike(self) -> None:
        """8. Verify conflict detection when SPF passes on an identified lookalike domain."""
        normalizer = EvidenceNormalizer()
        m1_dict = {
            "auth_results": {"spf": "pass", "spf_domain": "paypa1.com"},
            "observations": [
                {
                    "rule_id": "RULE-AUTH-SPF-PASS",
                    "severity": "informational",
                    "description": "SPF check passed for domain paypa1.com",
                    "evidence": {},
                }
            ],
        }
        m2_dict = {
            "observed_domain": "paypa1.com",
            "candidate_score": 0.85,
            "positive_evidence": [
                {
                    "rule_id": "RULE-LOOKALIKE-MATCH",
                    "severity": "high",
                    "description": "Domain paypa1.com resembles paypal.com",
                    "evidence": {},
                }
            ],
        }

        evidence = normalizer.normalize_all(module1_report=m1_dict, module2_report=m2_dict)
        contradictions = ContradictionEngine().find_contradictions(evidence, module1_report=m1_dict)

        auth_conflict = next((c for c in contradictions if c.conflict_type == "auth_vs_lookalike"), None)
        self.assertIsNotNone(auth_conflict)
        assert auth_conflict is not None
        self.assertEqual(auth_conflict.rule_id, "RULE-CORR-AUTH-LOOKALIKE-CONFLICT")
        self.assertIn("lookalike", auth_conflict.explanation)

    def test_09_contradiction_ml_benign_vs_deterministic_high_severity(self) -> None:
        """9. Verify conflict detection when ML predicts benign despite high-severity deterministic indicators."""
        normalizer = EvidenceNormalizer()
        m4_dict = {
            "observations": [
                {
                    "rule_id": "RULE-ATT-DOUBLE-EXT",
                    "severity": "high",
                    "description": "Dangerous double extension: invoice.pdf.exe",
                    "evidence": {},
                }
            ]
        }
        ml_benign = [
            MlPrediction(
                model="email_threat_classifier",
                model_version="2.0",
                label="benign",
                confidence=0.88,
            )
        ]

        evidence = normalizer.normalize_all(module4_report=m4_dict, ml_predictions=ml_benign)
        contradictions = ContradictionEngine().find_contradictions(evidence, ml_predictions=ml_benign)

        ml_conflict = next((c for c in contradictions if c.conflict_type == "ml_vs_deterministic"), None)
        self.assertIsNotNone(ml_conflict)
        assert ml_conflict is not None
        self.assertEqual(ml_conflict.rule_id, "RULE-CORR-ML-FORENSIC-CONFLICT")
        self.assertIn("email_threat_classifier", ml_conflict.explanation)
        self.assertIn("benign", ml_conflict.explanation)

    def test_10_contradiction_geographic_conflict(self) -> None:
        """10. Verify conflict detection when user_country != server_country."""
        normalizer = EvidenceNormalizer()
        m5_dict = {
            "enriched_peers": [
                {
                    "ip": "176.23.150.1",
                    "location_evidence": {
                        "country_agreement": False,
                        "interpretation": "country-level geographic evidence is inconsistent",
                        "user_country": {"country_code": "AU"},
                        "server_country": {"country_code": "US"},
                        "provenance": ["origin_infrastructure"],
                    },
                }
            ]
        }

        evidence = normalizer.normalize_all(module5_report=m5_dict)
        contradictions = ContradictionEngine().find_contradictions(evidence, module5_report=m5_dict)

        geo_conflict = next((c for c in contradictions if c.conflict_type == "user_vs_server_country"), None)
        self.assertIsNotNone(geo_conflict)
        assert geo_conflict is not None
        self.assertEqual(geo_conflict.rule_id, "RULE-CORR-GEOGRAPHIC-CONFLICT")
        self.assertIn("AU", geo_conflict.explanation)
        self.assertIn("US", geo_conflict.explanation)

    # =========================================================================
    # 6. ML Adapters Tests
    # =========================================================================

    def test_11_ml_adapters_valid_and_malformed(self) -> None:
        """11. Test all 3 ML adapters with valid, partial, and malformed inputs."""
        # 1. Threat model
        p1 = EmailThreatClassifierAdapter.parse({"model": "threat_net", "label": "phishing", "confidence": 0.93})
        self.assertIsNotNone(p1)
        assert p1 is not None
        self.assertEqual(p1.label, "phishing")
        self.assertEqual(p1.confidence, 0.93)
        self.assertEqual(p1.trust_state, "inferred")

        # 2. BEC model
        p2 = BecIntentClassifierAdapter.parse({"intent_label": "wire_fraud", "score": 0.85})
        self.assertIsNotNone(p2)
        assert p2 is not None
        self.assertEqual(p2.label, "wire_fraud")
        self.assertEqual(p2.confidence, 0.85)

        # 3. URL Risk model
        p3 = UrlRiskClassifierAdapter.parse({"risk_label": "high_risk", "risk_score": 0.99, "url": "http://bad.com"})
        self.assertIsNotNone(p3)
        assert p3 is not None
        self.assertEqual(p3.label, "high_risk")
        self.assertEqual(p3.confidence, 0.99)
        self.assertEqual(p3.input_reference, "http://bad.com")

        # 4. Malformed / None inputs
        self.assertIsNone(EmailThreatClassifierAdapter.parse(None))
        self.assertIsNone(BecIntentClassifierAdapter.parse("not-a-dict"))
        self.assertIsNone(UrlRiskClassifierAdapter.parse(12345))

        # 5. Out of bounds confidence clamped
        p_clamped = EmailThreatClassifierAdapter.parse({"label": "spam", "confidence": 1.5})
        assert p_clamped is not None
        self.assertEqual(p_clamped.confidence, 1.0)

    # =========================================================================
    # 7. Cross-Case & Temporal Correlation Tests
    # =========================================================================

    def test_12_cross_case_recurring_infrastructure(self) -> None:
        """12. Verify cross-case correlation of recurring IP/domain and repeated attachment hash."""
        correlator = CrossCaseCorrelator()

        # Historical Case 1: IP 198.51.100.77 + domain evil.com + hash HASH_A
        correlator.add_case({
            "case_id": "CASE-101",
            "timestamp": "2026-09-18T10:00:00+00:00",
            "entities": [
                {"type": "ip", "value": "198.51.100.77"},
                {"type": "domain", "value": "evil.com"},
                {"type": "hash", "value": "HASH_A"},
            ],
        })

        # Historical Case 2: Unrelated IP
        correlator.add_case({
            "case_id": "CASE-102",
            "timestamp": "2026-09-19T10:00:00+00:00",
            "entities": [
                {"type": "ip", "value": "10.0.0.1"},
            ],
        })

        # Current Case: shares IP 198.51.100.77 and hash HASH_A
        current_entities = [
            CorrelatedEntity(entity_id="ip:198.51.100.77", type="ip", value="198.51.100.77"),
            CorrelatedEntity(entity_id="hash:HASH_A", type="hash", value="HASH_A"),
            CorrelatedEntity(entity_id="domain:new-target.com", type="domain", value="new-target.com"),
        ]

        clusters = correlator.correlate_case(
            current_case_id="CASE-CURRENT",
            current_entities=current_entities,
            current_timestamp="2026-09-20T12:00:00+00:00",
        )

        self.assertEqual(len(clusters), 1)
        cluster = clusters[0]
        self.assertIn("CASE-101", cluster.case_ids)
        self.assertIn("CASE-CURRENT", cluster.case_ids)
        self.assertNotIn("CASE-102", cluster.case_ids)
        # Verify time delta calculated
        self.assertIsNotNone(cluster.inter_case_time_delta_seconds)
        self.assertGreater(cluster.inter_case_time_delta_seconds or 0, 0)
        # Verify strict non-attribution wording
        self.assertNotIn("same attacker", cluster.description.lower())
        self.assertIn("recurring", cluster.description.lower())

    # =========================================================================
    # 8. Attribution Safety & Guardrail Tests
    # =========================================================================

    def test_13_attribution_safety_boundaries(self) -> None:
        """13. Guarantee attribution support never claims human attacker identity, home address, or guaranteed attacker IP."""
        engine = AttributionSupportEngine()
        entities = [
            CorrelatedEntity(entity_id="ip:198.51.100.77", type="ip", value="198.51.100.77"),
            CorrelatedEntity(entity_id="asn:AS24940", type="asn", value="AS24940"),
        ]
        m5_dict = {
            "origin_assessment": {
                "earliest_reliable_peer": "198.51.100.77",
                "peer_hostname": "mail.gateway.com",
                "source_visibility": "visible",
                "confidence": 0.85,
                "assessment_reason": "Earliest reliable peer",
            },
            "enriched_peers": [
                {
                    "ip": "198.51.100.77",
                    "asn": {"asn": "AS24940", "organization": "Hetzner Online GmbH"},
                    "geolocation": {"country": "Germany", "city": "Frankfurt am Main"},
                    "infrastructure": {"classification": "cloud_hosting"},
                }
            ],
        }

        attr = engine.build_attribution_support(entities, [], [], module5_report=m5_dict)
        d = attr.to_dict()

        # Strict safety assertions
        self.assertNotIn("attacker_name", d)
        self.assertNotIn("attacker_home_address", d)
        self.assertNotIn("guaranteed_attacker_location", d)
        self.assertNotIn("guaranteed_attacker_ip", d)

        # Probable origin reflects observed infrastructure
        self.assertIsNotNone(attr.probable_origin)
        assert attr.probable_origin is not None
        self.assertEqual(attr.probable_origin["earliest_reliable_peer_ip"], "198.51.100.77")

        # Explicit disclaimers present
        self.assertTrue(any("NOT human attacker physical location" in lim for lim in attr.limitations))
        self.assertTrue(any("probabilistic inferences" in lim for lim in attr.limitations))

    # =========================================================================
    # 9. Case Hypothesis Evaluation Tests
    # =========================================================================

    def test_14_case_hypothesis_generation(self) -> None:
        """14. Verify case-level competing hypotheses are ranked with bounded heuristic confidence."""
        hypo_engine = CaseHypothesisEngine()
        ev_list = [
            NormalizedEvidence(
                evidence_id="EV-1",
                source_module="lookalike_domain",
                evidence_type="lookalike_signal",
                rule_id="RULE-LOOKALIKE-MATCH",
                severity="high",
                trust_state="inferred",
                description="Lookalike candidate paypa1.com",
            ),
            NormalizedEvidence(
                evidence_id="EV-2",
                source_module="url_analysis",
                evidence_type="url_observation",
                rule_id="RULE-URL-MISMATCH",
                severity="high",
                trust_state="observed",
                description="URL visible text mismatch",
            ),
        ]

        hypotheses = hypo_engine.evaluate_hypotheses(ev_list, [], [], [])
        self.assertGreater(len(hypotheses), 0)
        top = hypotheses[0]
        self.assertIn(top.hypothesis_type, ("possible_domain_impersonation", "possible_phishing"))
        self.assertLessEqual(top.heuristic_confidence, 0.94)
        self.assertEqual(top.confidence_metric, "heuristic_non_calibrated_consensus")

    # =========================================================================
    # 10. End-to-End Unified Pipeline Test
    # =========================================================================

    def test_15_end_to_end_pipeline(self) -> None:
        """15. Run full end-to-end evidence correlation across all 5 modules and 3 ML models."""
        case: InvestigationCase = correlate_evidence(
            email_id="EML-CASE-999",
            case_id="CASE-999",
            module1_report={
                "file_hash_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "entities": [{"type": "email_address", "value": "security@paypa1.com"}],
                "observations": [
                    {
                        "rule_id": "RULE-ID-REPLY-TO-MISMATCH",
                        "severity": "medium",
                        "description": "Reply-To mismatch",
                        "evidence": {},
                    }
                ],
                "auth_results": {"spf": "pass"},
            },
            module2_report={
                "observed_domain": "paypa1.com",
                "reference_domain": "paypal.com",
                "candidate_score": 0.89,
                "positive_evidence": [
                    {
                        "rule_id": "RULE-LOOKALIKE-MATCH",
                        "severity": "high",
                        "description": "paypa1.com mimics paypal.com",
                        "evidence": {},
                    }
                ],
            },
            module3_report={
                "urls": [{"actual_url": "https://paypa1.com/login", "hostname": "paypa1.com"}],
                "observations": [
                    {
                        "rule_id": "RULE-URL-MISMATCH",
                        "severity": "high",
                        "description": "Visible link target mismatch",
                        "evidence": {},
                    }
                ],
            },
            module4_report={
                "attachments": [
                    {
                        "filename": "statement.pdf.exe",
                        "sha256": "9999999999999999999999999999999999999999999999999999999999999999",
                    }
                ],
                "observations": [
                    {
                        "rule_id": "RULE-ATT-DOUBLE-EXT",
                        "severity": "high",
                        "description": "Double extension .pdf.exe",
                        "evidence": {},
                    }
                ],
            },
            module5_report={
                "origin_assessment": {
                    "earliest_reliable_peer": "185.220.101.5",
                    "confidence": 0.80,
                    "assessment_reason": "Earliest external hop",
                },
                "enriched_peers": [
                    {
                        "ip": "185.220.101.5",
                        "geolocation": {"country": "Germany", "city": "Frankfurt am Main"},
                        "asn": {"asn": "AS24940", "organization": "Hetzner"},
                        "infrastructure": {"classification": "tor_exit_node"},
                    }
                ],
            },
            ml_threat_prediction={"model": "email_threat_classifier", "label": "phishing", "confidence": 0.95},
            ml_bec_prediction={"model": "bec_intent_classifier", "intent_label": "credential_harvesting", "confidence": 0.88},
            ml_url_predictions=[{"model": "url_risk_classifier", "risk_label": "high_risk", "confidence": 0.92, "url": "https://paypa1.com/login"}],
            timestamp="2026-09-20T14:00:00+00:00",
        )

        self.assertEqual(case.case_id, "CASE-999")
        self.assertEqual(case.email_id, "EML-CASE-999")
        self.assertEqual(case.file_hash_sha256, "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

        # Verify normalized evidence
        self.assertGreater(len(case.evidence), 5)
        # Verify resolved entities
        entity_types = {e.type for e in case.entities}
        self.assertIn("domain", entity_types)
        self.assertIn("url", entity_types)
        self.assertIn("ip", entity_types)
        self.assertIn("attachment", entity_types)
        self.assertIn("hash", entity_types)

        # Verify relationships
        self.assertGreater(len(case.relationships), 0)
        rel_types = {r.relationship_type for r in case.relationships}
        self.assertIn("contains", rel_types)
        self.assertIn("resembles", rel_types)

        # Verify ML predictions normalized
        self.assertEqual(len(case.ml_predictions), 3)
        self.assertTrue(all(p.trust_state == "inferred" for p in case.ml_predictions))

        # Verify multi-module corroborations
        self.assertGreater(len(case.correlated_findings), 0)
        finding_types = {f.finding_type for f in case.correlated_findings}
        self.assertIn("correlated_identity_deception", finding_types)

        # Verify contradictions preserved (SPF pass on lookalike domain)
        self.assertGreater(len(case.contradictions), 0)
        conf_types = {c.conflict_type for c in case.contradictions}
        self.assertIn("auth_vs_lookalike", conf_types)

        # Verify hypotheses
        self.assertGreater(len(case.hypotheses), 0)
        self.assertLessEqual(case.hypotheses[0].heuristic_confidence, 0.94)

        # Verify serializability
        case_dict = case.to_dict()
        self.assertIsInstance(case_dict, dict)
        self.assertIn("attribution_support", case_dict)
        self.assertIn("limitations", case_dict["attribution_support"])

    def test_16_empty_reports_do_not_crash(self) -> None:
        """16. Verify pipeline degrades gracefully when all reports and models are empty."""
        case = correlate_evidence(email_id="EMPTY-001")
        self.assertEqual(case.email_id, "EMPTY-001")
        self.assertEqual(len(case.evidence), 0)
        self.assertEqual(len(case.contradictions), 0)
        self.assertEqual(len(case.correlated_findings), 0)
        self.assertEqual(len(case.hypotheses), 1)
        self.assertEqual(case.hypotheses[0].hypothesis_type, "insufficient_evidence")
        self.assertIsNotNone(case.to_dict())

    def test_17_ml_model_adapter_interfaces_and_contracts(self) -> None:
        """17. Verify ML adapter classes, expected concepts, and 14 Module 3 features contract."""
        # 1. Threat model concepts
        for concept in ("legitimate", "suspicious", "impersonated", "phishing", "fraud"):
            pred = EmailThreatModelAdapter.parse({"label": concept, "confidence": 0.85})
            self.assertIsNotNone(pred)
            assert pred is not None
            self.assertEqual(pred.label, concept)
            self.assertEqual(pred.trust_state, "inferred")
            self.assertEqual(pred.confidence_metric, "heuristic_non_calibrated_consensus")

        # 2. BEC Intent concepts
        for intent in ("payment_diversion", "fake_invoice", "credential_harvesting", "executive_impersonation"):
            pred = BECIntentModelAdapter.parse({"intent_label": intent, "score": 0.88})
            self.assertIsNotNone(pred)
            assert pred is not None
            self.assertEqual(pred.label, intent)
            self.assertEqual(pred.trust_state, "inferred")

        # 3. URL Risk contract: 14 required features
        self.assertEqual(len(EXPECTED_MODULE3_FEATURES), 14)
        expected_14 = (
            "url_length",
            "hostname_length",
            "path_length",
            "query_length",
            "subdomain_count",
            "special_character_count",
            "percent_encoded_count",
            "host_is_ip",
            "non_default_port",
            "userinfo_present",
            "login_token_present",
            "redirect_indicator",
            "visible_href_mismatch",
            "domain_similarity_score",
        )
        self.assertEqual(EXPECTED_MODULE3_FEATURES, expected_14)

        # 4. Feature extraction from Module 3 dict/object
        mock_m3_features = {
            "url": "https://secure-login.paypa1.com/auth",
            "url_length": 38,
            "hostname_length": 23,
            "path_length": 5,
            "query_length": 0,
            "subdomain_count": 2,
            "special_character_count": 4,
            "percent_encoded_count": 0,
            "host_is_ip": False,
            "non_default_port": False,
            "userinfo_present": False,
            "login_token_present": True,
            "redirect_indicator": False,
            "visible_href_mismatch": True,
            "domain_similarity_score": 0.92,
        }
        extracted = URLRiskModelAdapter.extract_features_from_module3(mock_m3_features)
        self.assertEqual(len(extracted), 14)
        for f in expected_14:
            self.assertIn(f, extracted)
            self.assertEqual(extracted[f], mock_m3_features[f])

    def test_18_framework_agnostic_output_ingestion(self) -> None:
        """18. Verify framework-agnostic output ingestion (sklearn, PyTorch/ONNX) and non-attribution."""
        # 1. Simulating sklearn predict_proba output (list of probabilities with class_labels)
        sklearn_probs = [0.03, 0.97]
        classes = ["legitimate", "phishing"]
        p_sklearn = EmailThreatModelAdapter.from_framework_output(
            sklearn_probs,
            class_labels=classes,
            features_used=["body_tfidf", "subject_intent"],
            top_features=["lookalike_domain"],
        )
        self.assertIsNotNone(p_sklearn)
        assert p_sklearn is not None
        self.assertEqual(p_sklearn.label, "phishing")
        self.assertEqual(p_sklearn.confidence, 0.97)
        self.assertEqual(p_sklearn.trust_state, "inferred")
        self.assertEqual(p_sklearn.features_used, ["body_tfidf", "subject_intent"])
        self.assertEqual(p_sklearn.top_features, ["lookalike_domain"])

        # 2. Simulating PyTorch/ONNX output tuple (label, confidence)
        p_tuple = BECIntentModelAdapter.from_framework_output(
            ("payment_diversion", 0.91),
            model_version="v2.1",
        )
        self.assertIsNotNone(p_tuple)
        assert p_tuple is not None
        self.assertEqual(p_tuple.label, "payment_diversion")
        self.assertEqual(p_tuple.confidence, 0.91)
        self.assertEqual(p_tuple.model_version, "v2.1")
        self.assertEqual(p_tuple.trust_state, "inferred")

        # 3. Disallowed attribution keys are stripped
        malformed_dict = {
            "label": "phishing",
            "confidence": 0.95,
            "attacker_name": "John Doe",
            "home_address": "123 Threat Lane",
            "attacker_location": "Moscow",
        }
        sanitized_pred = EmailThreatModelAdapter.parse(malformed_dict)
        self.assertIsNotNone(sanitized_pred)
        assert sanitized_pred is not None
        self.assertNotIn("attacker_name", sanitized_pred.raw_prediction)
        self.assertNotIn("home_address", sanitized_pred.raw_prediction)
        self.assertNotIn("attacker_location", sanitized_pred.raw_prediction)

    def test_19_future_real_prediction_pipeline_integration(self) -> None:
        """19. Verify future real model predictions integrate unchanged into the correlation pipeline."""
        # Wrap real model prediction outputs via the adapters
        threat_pred = EmailThreatModelAdapter.parse({
            "model": "email_threat_classifier",
            "model_version": "production-2026.09",
            "label": "phishing",
            "confidence": 0.91,
            "features_used": ["auth_alignment", "sender_entropy"],
            "top_features": ["lookalike_detected"],
            "input_reference": "E999",
        })
        bec_pred = BECIntentModelAdapter.parse({
            "model": "bec_intent_classifier",
            "model_version": "production-2026.09",
            "label": "fake_invoice",
            "confidence": 0.84,
            "input_reference": "E999",
        })
        url_pred = URLRiskModelAdapter.parse({
            "model": "url_risk_classifier",
            "risk_label": "high_risk",
            "confidence": 0.96,
            "url": "https://secure-login.paypa1.com/verify",
        })

        assert threat_pred is not None and bec_pred is not None and url_pred is not None

        # Pass directly into correlate_evidence() without altering engine
        case = correlate_evidence(
            email_id="E999",
            module1_report={
                "envelope_sender": "billing@paypa1.com",
                "header_from": "billing@paypa1.com",
                "auth_results": {"spf": {"result": "pass", "scope": "mfrom", "domain": "paypa1.com"}},
            },
            module2_report={"is_lookalike": True, "target_brand": "PayPal", "query_domain": "paypa1.com"},
            ml_predictions=[threat_pred, bec_pred, url_pred],
        )

        self.assertEqual(len(case.ml_predictions), 3)
        self.assertTrue(all(p.trust_state == "inferred" for p in case.ml_predictions))
        self.assertTrue(all(p.confidence_metric == "heuristic_non_calibrated_consensus" for p in case.ml_predictions))

        # Check that predictions are converted to normalized evidence
        ml_evidence = [e for e in case.evidence if e.source_module in (
            "email_threat_classifier", "bec_intent_classifier", "url_risk_classifier"
        )]
        self.assertEqual(len(ml_evidence), 3)
        self.assertTrue(all(e.trust_state == "inferred" for e in ml_evidence))

        # Check that case produces hypotheses and serializes cleanly
        self.assertGreater(len(case.hypotheses), 0)
        c_dict = case.to_dict()
        self.assertIsInstance(c_dict, dict)
        self.assertEqual(c_dict["case_id"], "CASE-E999")


if __name__ == "__main__":
    unittest.main()
