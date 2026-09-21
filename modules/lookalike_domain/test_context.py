"""Unit tests for Module 2 Layer 3: Contextual Validation & Evidence Correlation.

Covers the 10 specified test cases:
1. High similarity + SPF/DKIM/DMARC failures -> strong contextual evidence, high risk
2. High similarity + Reply-To mismatch -> stronger contextual evidence
3. High similarity + valid SPF/DKIM/DMARC -> candidate remains possible (not automatically safe)
4. High similarity + trusted/approved domain -> negative/contextual evidence preserved
5. Low similarity -> unlikely impersonation, no lookalike assessment
6. Legitimate third-party sender -> should not automatically become high-risk
7. Correlated authentication signals -> grouped into cohesive cluster, not double-counted
8. Graph relationship -> 'resembles' edge created only after contextual validation
9. Evidence provenance -> observation IDs trace rule IDs, source module, and inputs
10. Determinism -> repeated executions produce identical outputs
"""

import unittest

from modules.lookalike_domain import (
    compute_domain_similarity,
    validate_candidate_context,
)
from modules.sender_identity.models import (
    Entity,
    Observation,
    SenderIdentityReport,
)


class TestContextualValidation(unittest.TestCase):
    """Test suite for Module 2 Layer 3 contextual correlation."""

    def setUp(self):
        # High similarity candidate (paypa1.com vs paypal.com)
        self.high_cand = compute_domain_similarity("paypa1.com", "paypal.com")
        # Low similarity candidate (example.com vs microsoft.com)
        self.low_cand = compute_domain_similarity("example.com", "microsoft.com")

    def test_case_01_high_similarity_with_auth_failures(self):
        """Case 1: High similarity + SPF/DKIM/DMARC failures -> strong contextual evidence."""
        m1_report = SenderIdentityReport(
            email_id="E001",
            entities=[
                Entity(type="domain", value="paypa1.com", source="From"),
            ],
            observations=[
                Observation(
                    observation_id="OBS-AUTH-001",
                    rule_id="RULE-AUTH-FAILURE",
                    type="authentication_anomaly",
                    severity="high",
                    description="Receiving server reported SPF, DKIM, and DMARC failures",
                    evidence={"reported_spf": "fail", "reported_dkim": "fail", "reported_dmarc": "fail"},
                    source_header="Authentication-Results",
                )
            ],
        )

        report = validate_candidate_context(self.high_cand, m1_report)

        self.assertEqual(report.category, "possible_domain_impersonation")
        self.assertEqual(report.risk_level, "high")
        self.assertEqual(report.evidence_strength, "strong")
        self.assertGreaterEqual(report.confidence, 0.75)
        self.assertLessEqual(report.confidence, 0.94)

        # Confirm auth failure cluster was generated
        auth_obs = [o for o in report.positive_evidence if o.rule_id == "RULE-LOOKALIKE-AUTH-FAILURE-CLUSTER"]
        self.assertEqual(len(auth_obs), 1)
        self.assertIn("OBS-AUTH-001", auth_obs[0].input_evidence_ids)

    def test_case_02_high_similarity_with_replyto_divergence(self):
        """Case 2: High similarity + Reply-To mismatch -> stronger contextual evidence."""
        m1_report = SenderIdentityReport(
            email_id="E002",
            entities=[
                Entity(type="domain", value="paypa1.com", source="From"),
                Entity(type="domain", value="external-drop.net", source="Reply-To"),
            ],
            observations=[
                Observation(
                    observation_id="OBS-REPLYTO-001",
                    rule_id="RULE-REPLYTO-MISMATCH",
                    type="header_inconsistency",
                    severity="high",
                    description="Reply-To domain differs from From domain",
                    evidence={"from_domain": "paypa1.com", "reply_to_domain": "external-drop.net"},
                    source_header="Reply-To",
                )
            ],
        )

        report = validate_candidate_context(self.high_cand, m1_report)

        self.assertEqual(report.category, "possible_domain_impersonation")
        self.assertIn(report.risk_level, ("medium", "high"))
        replyto_obs = [o for o in report.positive_evidence if o.rule_id == "RULE-LOOKALIKE-REPLYTO-DIVERGENCE"]
        self.assertEqual(len(replyto_obs), 1)
        self.assertEqual(replyto_obs[0].evidence["reply_to_domain"], "external-drop.net")

    def test_case_03_high_similarity_with_valid_authentication(self):
        """Case 3: High similarity + valid SPF/DKIM/DMARC -> candidate remains possible (registered lookalike)."""
        m1_report = SenderIdentityReport(
            email_id="E003",
            entities=[
                Entity(type="domain", value="paypa1.com", source="From"),
            ],
            observations=[
                Observation(
                    observation_id="OBS-AUTH-PASS",
                    rule_id="RULE-AUTH-PASS",
                    type="authentication_success",
                    severity="informational",
                    description="SPF and DKIM passed for paypa1.com",
                    evidence={"reported_spf": "pass", "reported_dkim": "pass", "reported_dmarc": "pass"},
                    source_header="Authentication-Results",
                )
            ],
        )

        report = validate_candidate_context(self.high_cand, m1_report)

        # MUST NOT be marked automatically safe/legitimate!
        self.assertEqual(report.category, "possible_authenticated_lookalike_domain")
        self.assertEqual(report.risk_level, "medium")
        self.assertEqual(report.evidence_strength, "moderate")

        # Positive observation for potential registered lookalike
        auth_lookalike_obs = [o for o in report.positive_evidence if o.rule_id == "RULE-LOOKALIKE-AUTHENTICATED-DOMAIN"]
        self.assertEqual(len(auth_lookalike_obs), 1)

        # Negative observation preserving the fact that crypto passed
        neg_auth_obs = [o for o in report.negative_evidence if o.rule_id == "RULE-LOOKALIKE-AUTH-PASS-NEGATIVE-EVIDENCE"]
        self.assertEqual(len(neg_auth_obs), 1)

    def test_case_04_high_similarity_with_explicitly_trusted_domain(self):
        """Case 4: High similarity + explicitly trusted/approved domain -> negative evidence preserved."""
        # Suppose paypa1.com was explicitly whitelisted by organization
        report = validate_candidate_context(
            self.high_cand,
            sender_identity=None,
            trusted_domains={"paypa1.com"},
        )

        self.assertEqual(report.category, "possible_legitimate_third_party_sender")
        self.assertEqual(report.risk_level, "low")

        # Negative evidence preserved
        trusted_obs = [o for o in report.negative_evidence if o.rule_id == "RULE-LOOKALIKE-TRUSTED-EXCEPTION"]
        self.assertEqual(len(trusted_obs), 1)
        self.assertEqual(trusted_obs[0].polarity, "negative")

        # No 'resembles' graph edge emitted for explicitly trusted domains
        self.assertEqual(len(report.validated_relationships), 0)

    def test_case_05_low_similarity(self):
        """Case 5: Low similarity -> no lookalike assessment / unlikely impersonation."""
        report = validate_candidate_context(self.low_cand, sender_identity=None)

        self.assertEqual(report.category, "unlikely_domain_impersonation")
        self.assertEqual(report.risk_level, "none")
        self.assertEqual(report.evidence_strength, "none")
        self.assertEqual(report.confidence, 0.10)
        self.assertEqual(len(report.validated_relationships), 0)

    def test_case_06_legitimate_third_party_sender(self):
        """Case 6: Legitimate third-party sender -> should not automatically become high-risk."""
        m1_report = SenderIdentityReport(
            email_id="E006",
            entities=[
                Entity(type="domain", value="paypal.net", source="From"),
                Entity(type="domain", value="sendgrid.net", source="Return-Path"),
            ],
            observations=[
                Observation(
                    observation_id="OBS-ROUTING-001",
                    rule_id="RULE-RETURNPATH-ESP",
                    type="routing_context",
                    severity="low",
                    description="Return-path indicates recognized SendGrid relay",
                    evidence={"return_path_domain": "sendgrid.net"},
                    source_header="Return-Path",
                )
            ],
        )
        cand = compute_domain_similarity("paypal.net", "paypal.com")
        report = validate_candidate_context(cand, m1_report)

        # Should not be high risk
        self.assertNotEqual(report.risk_level, "high")
        esp_obs = [o for o in report.negative_evidence if o.rule_id == "RULE-LOOKALIKE-ESP-RELAY-CONTEXT"]
        self.assertEqual(len(esp_obs), 1)

    def test_case_07_correlated_authentication_signals_not_double_counted(self):
        """Case 7: Multiple correlated auth signals are grouped, not treated as independent multipliers."""
        m1_report = SenderIdentityReport(
            email_id="E007",
            entities=[Entity(type="domain", value="paypa1.com", source="From")],
            observations=[
                Observation(
                    observation_id="OBS-AUTH-SPF",
                    rule_id="RULE-SPF-FAIL",
                    type="authentication_anomaly",
                    severity="medium",
                    description="SPF fail",
                    evidence={"reported_spf": "fail"},
                    source_header="Authentication-Results",
                ),
                Observation(
                    observation_id="OBS-AUTH-DKIM",
                    rule_id="RULE-DKIM-FAIL",
                    type="authentication_anomaly",
                    severity="medium",
                    description="DKIM fail",
                    evidence={"reported_dkim": "fail"},
                    source_header="Authentication-Results",
                ),
                Observation(
                    observation_id="OBS-AUTH-DMARC",
                    rule_id="RULE-DMARC-FAIL",
                    type="authentication_anomaly",
                    severity="high",
                    description="DMARC fail",
                    evidence={"reported_dmarc": "fail"},
                    source_header="Authentication-Results",
                ),
            ],
        )

        report = validate_candidate_context(self.high_cand, m1_report)

        # Confirm there is exactly ONE cluster observation for auth failures
        auth_clusters = [o for o in report.positive_evidence if o.rule_id == "RULE-LOOKALIKE-AUTH-FAILURE-CLUSTER"]
        self.assertEqual(len(auth_clusters), 1)
        self.assertEqual(auth_clusters[0].evidence["num_failed_mechanisms"], 3)
        # Confidence must remain strictly bounded below 0.94
        self.assertLessEqual(report.confidence, 0.94)

    def test_case_08_graph_relationship_created_only_after_contextual_validation(self):
        """Case 8: 'resembles' edge is created only when contextual validation substantiates the lookalike."""
        # 8a: High candidate + auth failure -> substantiated, emits resembles edge
        m1_report = SenderIdentityReport(
            email_id="E008",
            entities=[Entity(type="domain", value="paypa1.com", source="From")],
            observations=[
                Observation(
                    observation_id="OBS-AUTH-008",
                    rule_id="RULE-AUTH-FAIL",
                    type="authentication_anomaly",
                    severity="high",
                    description="SPF fail",
                    evidence={"reported_spf": "fail"},
                    source_header="Authentication-Results",
                )
            ],
        )
        report_substantiated = validate_candidate_context(self.high_cand, m1_report)
        self.assertEqual(len(report_substantiated.validated_relationships), 1)
        rel = report_substantiated.validated_relationships[0]
        self.assertEqual(rel["source"], "paypa1.com")
        self.assertEqual(rel["relation"], "resembles")
        self.assertEqual(rel["target"], "paypal.com")
        self.assertIn("candidate_score", rel["evidence"])
        self.assertIn("authentication_context", rel["evidence"])

        # 8b: Low similarity -> NOT substantiated, no resembles edge
        report_unsubstantiated = validate_candidate_context(self.low_cand, m1_report)
        self.assertEqual(len(report_unsubstantiated.validated_relationships), 0)

    def test_case_09_evidence_provenance(self):
        """Case 9: All generated observations retain observation_id, rule_id, source_module, and input references."""
        m1_report = SenderIdentityReport(
            email_id="E009",
            entities=[
                Entity(type="domain", value="paypa1.com", source="From"),
                Entity(type="domain", value="suspicious-drop.com", source="Reply-To"),
            ],
            observations=[
                Observation(
                    observation_id="OBS-M1-REPLYTO",
                    rule_id="RULE-REPLYTO-MISMATCH",
                    type="header_inconsistency",
                    severity="high",
                    description="Reply-To mismatch",
                    evidence={"from_domain": "paypa1.com", "reply_to_domain": "suspicious-drop.com"},
                    source_header="Reply-To",
                )
            ],
        )

        report = validate_candidate_context(self.high_cand, m1_report)

        all_obs = report.positive_evidence + report.negative_evidence
        self.assertGreater(len(all_obs), 1)

        for obs in all_obs:
            self.assertTrue(obs.observation_id.startswith("OBS-LOOKALIKE-CTX-"))
            self.assertTrue(obs.rule_id.startswith("RULE-LOOKALIKE-"))
            self.assertEqual(obs.source_module, "lookalike_domain")
            self.assertIn(obs.severity, ("informational", "low", "medium", "high"))
            self.assertIn(obs.polarity, ("positive", "negative"))
            self.assertIn(obs.fact_type, ("observed", "reported", "inferred"))

    def test_case_10_determinism(self):
        """Case 10: Repeated execution with identical inputs produces identical assessments."""
        m1_report = SenderIdentityReport(
            email_id="E010",
            entities=[Entity(type="domain", value="paypa1.com", source="From")],
            observations=[
                Observation(
                    observation_id="OBS-AUTH-010",
                    rule_id="RULE-AUTH-FAIL",
                    type="authentication_anomaly",
                    severity="high",
                    description="SPF fail",
                    evidence={"reported_spf": "fail"},
                    source_header="Authentication-Results",
                )
            ],
        )

        run1 = validate_candidate_context(self.high_cand, m1_report)
        run2 = validate_candidate_context(self.high_cand, m1_report)

        self.assertEqual(run1.category, run2.category)
        self.assertEqual(run1.risk_level, run2.risk_level)
        self.assertEqual(run1.evidence_strength, run2.evidence_strength)
        self.assertEqual(run1.confidence, run2.confidence)
        self.assertEqual(run1.reason, run2.reason)
        self.assertEqual(run1.to_dict(), run2.to_dict())


if __name__ == "__main__":
    unittest.main()
