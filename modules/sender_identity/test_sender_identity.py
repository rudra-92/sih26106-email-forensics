"""Unit tests for Module 1: Sender Identity Spoofing & Authentication Analysis.

Tests all required forensic refinement scenarios:
1. One Received header containing both from_ip (peer) and by_ip (receiver)
2. Multiple Received headers preserving sequential chain and IP roles
3. IPv4 extraction and validation
4. IPv6 extraction (bracketed, IPv6-prefixed, and canonical tokens)
5. Legitimate Reply-To mismatch (treated as contextual/weak signal, not proof of attack)
6. Legitimate Return-Path mismatch (ESP/bounce handler contextual signal)
7. Generic display names such as "Support", "Admin", "Billing" (NOT flagged as spoofing)
8. Genuine suspicious display-name/address inconsistency (brand mismatch & embedded email)
9. Authentication-Results containing SPF/DKIM/DMARC failures (reported by receiving server)
10. Multiple simultaneous anomalies (compound threat, bounded confidence < 1.0, high risk)
"""

import hashlib
import unittest

from modules.sender_identity import (
    SenderIdentityAnalyzer,
    SenderIdentityParser,
    analyze_eml,
)


class TestSenderIdentityRefinedModule(unittest.TestCase):
    """Forensic verification test cases with refined role and risk models."""

    def setUp(self) -> None:
        self.parser = SenderIdentityParser()
        self.analyzer = SenderIdentityAnalyzer()

    # -------------------------------------------------------------------------
    # 1. One Received header containing both from_ip and by_ip
    # -------------------------------------------------------------------------
    def test_01_one_received_header_from_and_by_ip(self) -> None:
        """Distinguish from_ip (peer_ip) and by_ip (receiver_ip) in a single hop."""
        raw_eml = (
            b"From: <sender@source.com>\r\n"
            b"To: <victim@victim-enterprise.com>\r\n"
            b"Received: from rogue-host.info ([198.51.100.77])\r\n"
            b"    by relay.victim-enterprise.com ([203.0.113.15]) with ESMTP;\r\n"
            b"    Sun, 20 Sep 2026 02:30:00 +0000\r\n"
            b"Subject: Single Hop Role Distinction\r\n"
            b"\r\n"
            b"Testing IP role parsing."
        )

        evidence = self.parser.parse(raw_eml)
        self.assertEqual(len(evidence.received_hops), 1)
        hop = evidence.received_hops[0]

        # Check explicit hop roles
        self.assertEqual(hop.from_host, "rogue-host.info")
        self.assertEqual(hop.from_ip, "198.51.100.77")
        self.assertEqual(hop.by_host, "relay.victim-enterprise.com")
        self.assertEqual(hop.by_ip, "203.0.113.15")
        self.assertIn("198.51.100.77", hop.all_ips)
        self.assertIn("203.0.113.15", hop.all_ips)

        # Check graph relationships preserve roles
        report = self.analyzer.analyze(evidence, email_id="HOP-ROLES-01")
        rel_map = {(r.source, r.relation, r.target): r for r in report.relationships}

        self.assertIn(("HOP-ROLES-01", "observed_peer_ip", "198.51.100.77"), rel_map)
        self.assertIn(("HOP-ROLES-01", "observed_receiver_ip", "203.0.113.15"), rel_map)

        # Ensure neither IP is classified or claimed to be an attacker
        for entity in report.entities:
            if entity.type == "ip":
                self.assertNotIn("attacker", str(entity.attributes).lower())

    # -------------------------------------------------------------------------
    # 2. Multiple Received headers preserving sequence & raw headers
    # -------------------------------------------------------------------------
    def test_02_multiple_received_headers(self) -> None:
        """Preserve sequential relay chain and raw headers across multiple hops."""
        raw_eml = (
            b"From: <user@origin.net>\r\n"
            b"To: <final@destination.org>\r\n"
            b"Received: from hop2.internal.net ([10.0.0.2]) by mx.destination.org ([198.51.100.99]);\r\n"
            b"    Sun, 20 Sep 2026 03:02:00 +0000\r\n"
            b"Received: from hop1.edge.net ([192.0.2.50]) by hop2.internal.net ([10.0.0.1]);\r\n"
            b"    Sun, 20 Sep 2026 03:01:00 +0000\r\n"
            b"Received: from client.origin.net ([203.0.113.5]) by hop1.edge.net;\r\n"
            b"    Sun, 20 Sep 2026 03:00:00 +0000\r\n"
            b"Subject: Multi Hop Chain\r\n"
            b"\r\n"
            b"Three hops."
        )

        evidence = self.parser.parse(raw_eml)
        self.assertEqual(len(evidence.received_hops), 3)

        # Hop indices must preserve exact order
        self.assertEqual(evidence.received_hops[0].hop_index, 0)
        self.assertEqual(evidence.received_hops[0].from_ip, "10.0.0.2")
        self.assertEqual(evidence.received_hops[0].by_ip, "198.51.100.99")
        self.assertIn("hop2.internal.net", evidence.received_hops[0].raw_header)

        self.assertEqual(evidence.received_hops[1].hop_index, 1)
        self.assertEqual(evidence.received_hops[1].from_ip, "192.0.2.50")
        self.assertEqual(evidence.received_hops[1].by_ip, "10.0.0.1")

        self.assertEqual(evidence.received_hops[2].hop_index, 2)
        self.assertEqual(evidence.received_hops[2].from_ip, "203.0.113.5")
        self.assertIsNone(evidence.received_hops[2].by_ip)

    # -------------------------------------------------------------------------
    # 3. IPv4 extraction
    # -------------------------------------------------------------------------
    def test_03_ipv4_extraction(self) -> None:
        """Validate standard IPv4 address extraction."""
        raw_eml = (
            b"From: <sender@example.com>\r\n"
            b"Received: from mail.example.com ([198.51.100.1]) by mx.example.com ([198.51.100.2]);\r\n"
            b"    Sun, 20 Sep 2026 01:00:00 +0000\r\n"
            b"\r\n"
            b"IPv4 test."
        )
        evidence = self.parser.parse(raw_eml)
        self.assertEqual(evidence.received_hops[0].from_ip, "198.51.100.1")
        self.assertEqual(evidence.received_hops[0].by_ip, "198.51.100.2")

    # -------------------------------------------------------------------------
    # 4. IPv6 extraction
    # -------------------------------------------------------------------------
    def test_04_ipv6_extraction(self) -> None:
        """Validate IPv6 extraction including bracketed and IPv6-prefixed notations."""
        raw_eml = (
            b"From: <sender@ipv6.org>\r\n"
            b"Received: from mail.ipv6.org ([IPv6:2001:db8:85a3::8a2e:370:7334])\r\n"
            b"    by mx.target.net ([2001:db8:1::1]) with ESMTPS;\r\n"
            b"    Sun, 20 Sep 2026 02:25:00 +0000\r\n"
            b"\r\n"
            b"IPv6 dual role."
        )
        evidence = self.parser.parse(raw_eml)
        self.assertEqual(
            evidence.received_hops[0].from_ip, "2001:db8:85a3::8a2e:370:7334"
        )
        self.assertEqual(evidence.received_hops[0].by_ip, "2001:db8:1::1")

    # -------------------------------------------------------------------------
    # 5. Legitimate Reply-To mismatch (treated as contextual/weak signal)
    # -------------------------------------------------------------------------
    def test_05_legitimate_reply_to_mismatch(self) -> None:
        """Reply-To pointing to third-party CRM/ticketing must be contextual, not spoofing proof."""
        raw_eml = (
            b"From: \"Customer Support\" <support@legit-store.com>\r\n"
            b"Reply-To: <ticket-reply-99@zendesk-service.com>\r\n"
            b"To: <shopper@example.com>\r\n"
            b"Subject: Order #1234 Status\r\n"
            b"Authentication-Results: mx.shopper.com; "
            b"spf=pass smtp.mailfrom=legit-store.com; "
            b"dkim=pass header.d=legit-store.com; "
            b"dmarc=pass header.from=legit-store.com\r\n"
            b"\r\n"
            b"Your ticket has been updated."
        )

        report = analyze_eml(raw_eml, email_id="CRM-REPLYTO")
        obs_types = [o.type for o in report.observations]

        # Must record observation
        self.assertIn("reply_to_domain_mismatch", obs_types)
        obs = next(o for o in report.observations if o.type == "reply_to_domain_mismatch")
        self.assertEqual(obs.severity, "medium")
        self.assertEqual(obs.rule_id, "RULE-REPLY-TO-DOMAIN-MISMATCH")
        self.assertIn("contextual indicator", obs.description.lower())

        # Overall assessment must NOT call it high-risk or definite attack
        self.assertNotEqual(report.assessment.risk_level, "high")
        self.assertLess(report.assessment.confidence, 0.40)

    # -------------------------------------------------------------------------
    # 6. Legitimate Return-Path mismatch (ESP/bounce handler contextual signal)
    # -------------------------------------------------------------------------
    def test_06_legitimate_return_path_mismatch(self) -> None:
        """Return-Path from bulk ESP (e.g. SendGrid) must have low/contextual severity."""
        raw_eml = (
            b"From: \"Weekly Deals\" <newsletter@retailer.com>\r\n"
            b"Return-Path: <bounces+12345@sendgrid.net>\r\n"
            b"To: <subscriber@example.com>\r\n"
            b"Subject: This Week's Specials\r\n"
            b"Authentication-Results: mx.subscriber.com; "
            b"spf=pass smtp.mailfrom=sendgrid.net; "
            b"dkim=pass header.d=retailer.com; "
            b"dmarc=pass header.from=retailer.com\r\n"
            b"\r\n"
            b"Check out our catalog."
        )

        report = analyze_eml(raw_eml, email_id="ESP-NEWSLETTER")
        obs_types = [o.type for o in report.observations]

        self.assertIn("return_path_domain_mismatch", obs_types)
        obs = next(o for o in report.observations if o.type == "return_path_domain_mismatch")
        self.assertEqual(obs.severity, "low")
        self.assertEqual(obs.rule_id, "RULE-RETURN-PATH-DOMAIN-MISMATCH")
        self.assertIn("contextual indicator", obs.description.lower())

        # Low risk
        self.assertIn(report.assessment.risk_level, ("none", "low"))
        self.assertLess(report.assessment.confidence, 0.35)

    # -------------------------------------------------------------------------
    # 7. Generic display names such as "Support" (NOT flagged as spoofing)
    # -------------------------------------------------------------------------
    def test_07_generic_display_names_not_flagged(self) -> None:
        """Generic words like 'Support', 'Admin', 'Billing' must NOT trigger spoofing alerts."""
        generic_names = [
            b"From: \"Support\" <help@anydomain.com>\r\n\r\nTest",
            b"From: \"Billing Department\" <invoices@anydomain.com>\r\n\r\nTest",
            b"From: \"System Administrator\" <admin@anydomain.com>\r\n\r\nTest",
            b"From: \"Customer Security Team\" <security@anydomain.com>\r\n\r\nTest",
        ]

        for eml in generic_names:
            report = analyze_eml(eml, email_id="GENERIC-NAME")
            obs_types = [o.type for o in report.observations]
            # Must NOT flag brand mismatch or spoofing
            self.assertNotIn("display_name_brand_mismatch", obs_types)
            self.assertNotIn("display_name_embedded_email_mismatch", obs_types)
            # Should record presence as informational
            self.assertIn("display_name_present", obs_types)

    # -------------------------------------------------------------------------
    # 8. Genuine suspicious display-name/address inconsistency
    # -------------------------------------------------------------------------
    def test_08_genuine_suspicious_display_name(self) -> None:
        """Genuine display name inconsistency: embedded foreign email and brand mismatch."""
        # Case A: Embedded email
        raw_a = (
            b"From: \"paypal-alerts@paypal.com\" <hacker@shady-host.org>\r\n"
            b"Subject: Account Locked\r\n\r\nBody"
        )
        report_a = analyze_eml(raw_a, email_id="EMBED-DISP")
        self.assertTrue(
            any(o.type == "display_name_embedded_email_mismatch" for o in report_a.observations)
        )
        obs_a = next(
            o for o in report_a.observations if o.type == "display_name_embedded_email_mismatch"
        )
        self.assertEqual(obs_a.severity, "high")
        self.assertEqual(obs_a.rule_id, "RULE-DISPLAY-NAME-EMBEDDED-EMAIL")

        # Case B: Specific brand name with unaligned free-mail domain
        raw_b = (
            b"From: \"Microsoft Account Security\" <security-update99@gmail.com>\r\n"
            b"Subject: Password Alert\r\n\r\nBody"
        )
        report_b = analyze_eml(raw_b, email_id="BRAND-DISP")
        self.assertTrue(
            any(o.type == "display_name_brand_mismatch" for o in report_b.observations)
        )
        obs_b = next(
            o for o in report_b.observations if o.type == "display_name_brand_mismatch"
        )
        self.assertEqual(obs_b.severity, "medium")
        self.assertEqual(obs_b.rule_id, "RULE-DISPLAY-NAME-BRAND-MISMATCH")
        self.assertEqual(obs_b.evidence["matched_brand"], "microsoft")

    # -------------------------------------------------------------------------
    # 9. Authentication-Results containing SPF/DKIM/DMARC failures
    # -------------------------------------------------------------------------
    def test_09_auth_results_reported_failures(self) -> None:
        """Wording clearly states receiving server reported failures without claiming independent verification."""
        raw_eml = (
            b"From: <finance@victim.com>\r\n"
            b"Authentication-Results: mx.receiver.com; "
            b"spf=fail smtp.mailfrom=victim.com; "
            b"dkim=fail header.d=victim.com; "
            b"dmarc=fail (p=REJECT) header.from=victim.com\r\n"
            b"\r\n"
            b"Payroll notice."
        )

        report = analyze_eml(raw_eml, email_id="AUTH-REPORTED-FAIL")
        obs_dict = {o.type: o for o in report.observations}

        self.assertIn("spf_authentication_failure", obs_dict)
        self.assertIn("dkim_authentication_failure", obs_dict)
        self.assertIn("dmarc_authentication_failure", obs_dict)

        # Verify careful forensic wording
        self.assertEqual(
            obs_dict["spf_authentication_failure"].description,
            "Receiving server reported SPF failure.",
        )
        self.assertEqual(
            obs_dict["dkim_authentication_failure"].description,
            "Receiving server reported DKIM authentication failure.",
        )
        self.assertEqual(
            obs_dict["dmarc_authentication_failure"].description,
            "Receiving server reported DMARC failure.",
        )

    # -------------------------------------------------------------------------
    # 10. Multiple simultaneous anomalies (compound threat, bounded confidence)
    # -------------------------------------------------------------------------
    def test_10_multiple_simultaneous_anomalies(self) -> None:
        """Compound threat with bounded confidence (< 1.0) and distinguished risk/strength levels."""
        raw_eml = (
            b"From: \"Microsoft Support Team\" <billing-alert@fake-ms-portal.com>\r\n"
            b"To: <cfo@victim-enterprise.com>\r\n"
            b"Reply-To: <credential-drop@external-harvest.net>\r\n"
            b"Return-Path: <bounce@unregistered-relay.org>\r\n"
            b"Message-ID: <server99.sys@rogue-host.info>\r\n"
            b"Subject: Action Required: Your 365 Subscription Suspended\r\n"
            b"Authentication-Results: mx.victim-enterprise.com; "
            b"spf=fail smtp.mailfrom=fake-ms-portal.com; "
            b"dkim=fail header.d=fake-ms-portal.com; "
            b"dmarc=fail (p=REJECT) header.from=fake-ms-portal.com\r\n"
            b"Received: from rogue-host.info ([198.51.100.77]) "
            b"by relay.victim-enterprise.com ([203.0.113.15]) with ESMTP; "
            b"Sun, 20 Sep 2026 02:30:00 +0000\r\n"
            b"\r\n"
            b"Dear Customer, your subscription has failed."
        )

        report = analyze_eml(raw_eml, email_id="COMPOUND-001")
        assessment = report.assessment

        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.category, "high_risk_sender_identity_anomaly")
        self.assertEqual(assessment.risk_level, "high")
        self.assertEqual(assessment.evidence_strength, "strong")

        # Crucial requirement: Confidence must be bounded and strictly < 1.0 (never claims 100% certainty)
        self.assertLess(assessment.confidence, 1.0)
        self.assertGreaterEqual(assessment.confidence, 0.85)

        # Check provenance details
        for obs in report.observations:
            self.assertTrue(obs.rule_id.startswith("RULE-"))
            self.assertIn("evidence", obs.to_dict())
            self.assertTrue(obs.source_header)

        # Check SHA-256 calculation
        expected_sha = hashlib.sha256(raw_eml).hexdigest()
        self.assertEqual(report.file_hash_sha256, expected_sha)


if __name__ == "__main__":
    unittest.main()
