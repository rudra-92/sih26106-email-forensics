"""Comprehensive unit tests for Module 5: Origin & Infrastructure Reconstruction Engine.

Tests:
1. Received Header Parsing (IPv4, IPv6, hostname-only, malformed, multiple hops)
2. Hop Reconstruction (normal chain, incomplete chain, private IP handling, mixed IPv4/IPv6)
3. Temporal Analysis (normal chronology, negative intervals, timezone conversion, future/malformed timestamps, large delay, Date vs Received gap)
4. Authentication & ARC Correlation (SPF, DKIM, DMARC, ARC valid/inconsistent/absent)
5. Origin Candidate Selection (external peer, private hops before external peer, mail provider relay, ambiguous/insufficient chains)
6. Infrastructure Enrichment (successful lookup, unknown IP, missing database fallback, invalid input)
7. Cross-Case Temporal Correlation (recurring IP, recurring ASN, unrelated cases, time windows)
8. Origin Hypotheses (direct origin, provider masking, relay, cloud, anonymization, compromised account, insufficient evidence)
9. Invariants & Reliability (no attacker attribution, GeoIP is not attacker location, auth pass is not legitimate, missing enrichment does not crash)
"""

from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
import unittest

from modules.origin_infrastructure.analyzer import OriginInfrastructureAnalyzer
from modules.origin_infrastructure.authentication import AuthenticationCorrelator
from modules.origin_infrastructure.correlation import CrossCaseCorrelator
from modules.origin_infrastructure.enrichment import (
    CompositeEnrichmentProvider,
    LocalASNProvider,
    LocalGeoIPProvider,
    LocalInfrastructureProvider,
)
from modules.origin_infrastructure.hop_reconstructor import HopReconstructor
from modules.origin_infrastructure.hypotheses import OriginHypothesisEngine
from modules.origin_infrastructure.models import (
    OriginCandidate,
    ReconstructedHop,
)
from modules.origin_infrastructure.origin_engine import OriginEngine
from modules.origin_infrastructure.received_parser import ReceivedHeaderParser
from modules.origin_infrastructure.temporal import TemporalAnalyzer
from modules.sender_identity.models import AuthResults


class TestReceivedHeaderParsing(unittest.TestCase):
    """Test suite for RFC 5321/5322 Received header extraction."""

    def setUp(self):
        self.parser = ReceivedHeaderParser()

    def test_01_valid_ipv4_parsing(self):
        """1. Parse valid IPv4 source and receiver in Received header."""
        hdr = (
            "from mail.external-sender.com (mail.external-sender.com [198.51.100.77]) "
            "by mx1.victim-corp.com (Postfix) with ESMTPS id ABC12345 "
            "for <user@victim-corp.com>; Tue, 15 Sep 2026 10:00:00 +0000"
        )
        fields = self.parser.parse_single(hdr)
        self.assertEqual(fields.from_host, "mail.external-sender.com")
        self.assertEqual(fields.from_ip, "198.51.100.77")
        self.assertEqual(fields.by_host, "mx1.victim-corp.com")
        self.assertEqual(fields.with_protocol, "ESMTPS")
        self.assertEqual(fields.id_param, "ABC12345")
        self.assertEqual(fields.for_envelope_to, "user@victim-corp.com")
        self.assertEqual(fields.timestamp_raw, "Tue, 15 Sep 2026 10:00:00 +0000")
        self.assertEqual(fields.parser_confidence, "high")
        self.assertFalse(fields.is_source_private)

    def test_02_valid_ipv6_parsing(self):
        """2. Parse valid IPv6 source address in bracketed notation."""
        hdr = (
            "from mail.ipv6-domain.com ([IPv6:2001:db8:85a3::8a2e:370:7334]) "
            "by gateway.victim.com with ESMTP; Wed, 16 Sep 2026 12:00:00 +0000"
        )
        fields = self.parser.parse_single(hdr)
        self.assertEqual(fields.from_ip, "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(fields.from_host, "mail.ipv6-domain.com")
        self.assertEqual(fields.by_host, "gateway.victim.com")
        self.assertFalse(fields.is_source_private)

    def test_03_hostname_only_parsing(self):
        """3. Parse Received header containing only hostnames without IP addresses."""
        hdr = (
            "from internal-agent by mail-router.corp.local with local-smtp; "
            "Thu, 17 Sep 2026 08:30:00 -0400"
        )
        fields = self.parser.parse_single(hdr)
        self.assertEqual(fields.from_host, "internal-agent")
        self.assertIsNone(fields.from_ip)
        self.assertEqual(fields.by_host, "mail-router.corp.local")
        self.assertEqual(fields.parser_confidence, "medium")

    def test_04_malformed_received_header(self):
        """4. Tolerate malformed, empty, or truncated Received headers gracefully."""
        hdr = "gibberish with no standard syntax ; 1234 invalid date"
        fields = self.parser.parse_single(hdr)
        self.assertIsInstance(fields.parser_confidence, str)
        self.assertIsNone(fields.from_ip)

        empty_fields = self.parser.parse_single("")
        self.assertEqual(empty_fields.parser_confidence, "low")

    def test_05_multiple_received_hops_parsing(self):
        """5. Parse multiple Received headers preserving index and source references."""
        headers = [
            "from relay.net ([203.0.113.15]) by mx.victim.com; Sun, 20 Sep 2026 04:00:00 +0000",
            "from sender.org ([198.51.100.77]) by relay.net; Sun, 20 Sep 2026 03:59:00 +0000",
        ]
        hops = self.parser.parse_all(headers)
        self.assertEqual(len(hops), 2)
        self.assertEqual(hops[0].hop_index, 0)
        self.assertEqual(hops[0].source_header_ref, "Received[0]")
        self.assertEqual(hops[1].hop_index, 1)
        self.assertEqual(hops[1].source_header_ref, "Received[1]")


class TestHopReconstruction(unittest.TestCase):
    """Test suite for sequential hop reconstruction in transit order."""

    def setUp(self):
        self.parser = ReceivedHeaderParser()
        self.reconstructor = HopReconstructor()

    def test_06_normal_transmission_chain(self):
        """6. Invert SMTP Received stack so sequence 1 is earliest sender and sequence N is receiver."""
        headers = [
            # Top header (Received[0]): final hop to recipient
            "from relay.mta.com ([203.0.113.15]) by mx.recipient.com; Sun, 20 Sep 2026 12:05:00 +0000",
            # Bottom header (Received[1]): earliest hop from sender
            "from sender.com ([198.51.100.77]) by relay.mta.com; Sun, 20 Sep 2026 12:00:00 +0000",
        ]
        parsed = self.parser.parse_all(headers)
        reconstructed = self.reconstructor.reconstruct(parsed)

        self.assertEqual(len(reconstructed), 2)
        # Hop 1 should be the earliest hop (Received[1])
        self.assertEqual(reconstructed[0].hop_sequence_num, 1)
        self.assertEqual(reconstructed[0].original_header_index, 1)
        self.assertEqual(reconstructed[0].source_ip, "198.51.100.77")
        self.assertEqual(reconstructed[0].trust_state, "observed")

        # Hop 2 should be the final receiver hop (Received[0])
        self.assertEqual(reconstructed[1].hop_sequence_num, 2)
        self.assertEqual(reconstructed[1].original_header_index, 0)
        self.assertEqual(reconstructed[1].source_ip, "203.0.113.15")
        # Receiving gateway is observed by default (never verified merely for being hop 0)
        self.assertEqual(reconstructed[1].trust_state, "observed")

        # When configured with trusted_gateways, receiving gateway becomes trusted_configured
        reconstructed_trusted = self.reconstructor.reconstruct(
            parsed, trusted_gateways={"mx.recipient.com"}
        )
        self.assertEqual(reconstructed_trusted[1].trust_state, "trusted_configured")

    def test_07_private_ip_handling(self):
        """7. Accurately flag RFC 1918 and loopback private IPs in reconstructed hops."""
        headers = [
            "from mail.corp ([10.0.0.5]) by mail.corp ([192.168.1.1]); Sun, 20 Sep 2026 12:00:00 +0000"
        ]
        parsed = self.parser.parse_all(headers)
        reconstructed = self.reconstructor.reconstruct(parsed)
        self.assertTrue(reconstructed[0].is_source_private)
        self.assertTrue(reconstructed[0].is_receiver_private)

    def test_08_mixed_ipv4_and_ipv6_chain(self):
        """8. Reconstruct chain with both IPv4 and IPv6 hops seamlessly."""
        headers = [
            "from ipv6.net ([IPv6:2001:db8::1]) by mx.victim.com; Sun, 20 Sep 2026 12:02:00 +0000",
            "from ipv4.net ([198.51.100.77]) by ipv6.net; Sun, 20 Sep 2026 12:00:00 +0000",
        ]
        parsed = self.parser.parse_all(headers)
        reconstructed = self.reconstructor.reconstruct(parsed)
        self.assertEqual(reconstructed[0].source_ip, "198.51.100.77")
        self.assertEqual(reconstructed[1].source_ip, "2001:db8::1")


class TestTemporalAnalysis(unittest.TestCase):
    """Test suite for UTC normalization, negative intervals, delays, and clock skews."""

    def setUp(self):
        self.ref_time = datetime(2026, 9, 20, 16, 0, 0, tzinfo=timezone.utc)
        self.analyzer = TemporalAnalyzer(reference_time=self.ref_time)
        self.parser = ReceivedHeaderParser()
        self.reconstructor = HopReconstructor()

    def test_09_normal_chronology(self):
        """9. Evaluate normal forward chronology with positive hop delay."""
        headers = [
            "from b by c; Sun, 20 Sep 2026 12:01:30 +0000",
            "from a by b; Sun, 20 Sep 2026 12:00:00 +0000",
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        updated_hops, result, obs = self.analyzer.analyze(hops)

        self.assertTrue(result.chronology_consistent)
        self.assertEqual(result.negative_intervals, 0)
        self.assertEqual(result.total_transit_seconds, 90.0)
        self.assertEqual(len(obs), 0)

    def test_10_negative_interval_detection(self):
        """10. Detect negative hop interval (later hop timestamp is before earlier hop)."""
        headers = [
            "from b by c; Sun, 20 Sep 2026 11:50:00 +0000",  # Later hop timestamp: 11:50
            "from a by b; Sun, 20 Sep 2026 12:00:00 +0000",  # Earlier hop timestamp: 12:00
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        _, result, obs = self.analyzer.analyze(hops)

        self.assertFalse(result.chronology_consistent)
        self.assertEqual(result.negative_intervals, 1)
        neg_obs = next((o for o in obs if o.rule_id == "RULE-TIME-NEGATIVE-HOP"), None)
        self.assertIsNotNone(neg_obs)
        self.assertEqual(neg_obs.severity, "medium")

    def test_11_timezone_conversion_consistency(self):
        """11. Correctly normalize disparate timezones (-0400, +0530, +0000) to UTC."""
        # 12:00 -0400 is 16:00 UTC
        # 21:35 +0530 is 16:05 UTC (5 minutes later)
        headers = [
            "from b by c; Sun, 20 Sep 2026 21:35:00 +0530",
            "from a by b; Sun, 20 Sep 2026 12:00:00 -0400",
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        _, result, _ = self.analyzer.analyze(hops)

        self.assertTrue(result.chronology_consistent)
        self.assertEqual(result.total_transit_seconds, 300.0)

    def test_12_future_timestamp_detection(self):
        """12. Flag timestamp occurring in the future relative to reference time."""
        headers = [
            "from a by b; Sun, 25 Sep 2026 12:00:00 +0000",  # 5 days in future
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        _, result, obs = self.analyzer.analyze(hops)

        self.assertEqual(result.future_timestamps, 1)
        future_obs = next((o for o in obs if o.rule_id == "RULE-TIME-FUTURE"), None)
        self.assertIsNotNone(future_obs)
        self.assertEqual(future_obs.severity, "medium")

    def test_13_malformed_timestamp(self):
        """13. Safely record malformed timestamp without crashing."""
        headers = [
            "from a by b; invalid-date-string-1234",
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        _, result, obs = self.analyzer.analyze(hops)

        self.assertEqual(result.malformed_timestamps, 1)
        mal_obs = next((o for o in obs if o.rule_id == "RULE-TIME-MALFORMED"), None)
        self.assertIsNotNone(mal_obs)

    def test_14_excessive_transit_delay(self):
        """14. Emit observation when hop transit delay exceeds threshold."""
        headers = [
            "from b by c; Sun, 20 Sep 2026 15:00:00 +0000",  # 4 hours later
            "from a by b; Sun, 20 Sep 2026 11:00:00 +0000",
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        # Threshold: 3600 seconds (1 hour)
        _, result, obs = self.analyzer.analyze(hops)

        self.assertEqual(result.abnormal_delays, 1)
        delay_obs = next((o for o in obs if o.rule_id == "RULE-TIME-EXCESSIVE-DELAY"), None)
        self.assertIsNotNone(delay_obs)
        self.assertEqual(delay_obs.severity, "low")

    def test_15_date_vs_received_gap(self):
        """15. Flag large discrepancy between Date header and first Received hop."""
        headers = [
            "from a by b; Sun, 20 Sep 2026 12:00:00 +0000",
        ]
        # Date header is 3 days earlier
        date_hdr = "Thu, 17 Sep 2026 12:00:00 +0000"
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        _, result, obs = self.analyzer.analyze(hops, date_header_str=date_hdr)

        gap_obs = next((o for o in obs if o.rule_id == "RULE-TIME-DATE-RECEIVED-GAP"), None)
        self.assertIsNotNone(gap_obs)


class TestAuthenticationAndArcCorrelation(unittest.TestCase):
    """Test suite for SPF, DKIM, DMARC, and ARC chain correlation."""

    def setUp(self):
        self.correlator = AuthenticationCorrelator()

    def test_16_spf_dkim_dmarc_pass_evidence(self):
        """16. Ingest SPF/DKIM/DMARC pass findings as supporting evidence."""
        auth = AuthResults(
            spf="pass", spf_domain="example.com",
            dkim="pass", dkim_domain="example.com",
            dmarc="pass", dmarc_domain="example.com",
        )
        _, obs = self.correlator.correlate(auth_results=auth)
        self.assertEqual(len(obs), 3)
        self.assertTrue(all(o.severity == "informational" for o in obs))

    def test_17_authentication_failures(self):
        """17. Ingest authentication failures with appropriate severity."""
        auth = AuthResults(
            spf="fail", spf_domain="rogue.com",
            dkim="fail", dkim_domain="rogue.com",
            dmarc="fail", dmarc_domain="rogue.com",
        )
        _, obs = self.correlator.correlate(auth_results=auth)
        dmarc_obs = next((o for o in obs if o.rule_id == "RULE-AUTH-DMARC"), None)
        self.assertIsNotNone(dmarc_obs)
        self.assertEqual(dmarc_obs.severity, "high")

    def test_18_valid_arc_chain(self):
        """18. Validate complete and contiguous ARC chain across instances."""
        msg = EmailMessage()
        msg["ARC-Seal"] = "i=1; cv=none; d=relay1.com"
        msg["ARC-Message-Signature"] = "i=1; a=rsa-sha256; d=relay1.com"
        msg["ARC-Authentication-Results"] = "i=1; mx.google.com; spf=pass"

        msg["ARC-Seal"] = "i=2; cv=pass; d=relay2.com"
        msg["ARC-Message-Signature"] = "i=2; a=rsa-sha256; d=relay2.com"
        msg["ARC-Authentication-Results"] = "i=2; mx.google.com; dkim=pass"

        arc_res, obs = self.correlator.correlate(email_msg=msg)
        self.assertTrue(arc_res.has_arc)
        self.assertTrue(arc_res.is_chain_complete)
        self.assertTrue(arc_res.is_chain_consistent)
        self.assertTrue(arc_res.is_chain_valid)
        valid_obs = next((o for o in obs if o.rule_id == "RULE-ARC-STRUCTURE-VALID"), None)
        self.assertIsNotNone(valid_obs)
        self.assertEqual(valid_obs.trust_state, "reported")
        self.assertFalse(valid_obs.evidence.get("cryptographic_verification", True))
        self.assertIn("Cryptographic ARC signature verification is not implemented", valid_obs.description)

    def test_19_inconsistent_arc_chain(self):
        """19. Detect missing ARC headers or broken sequence continuity."""
        msg = EmailMessage()
        # Instance 1 is missing ARC-Message-Signature
        msg["ARC-Seal"] = "i=1; cv=none; d=relay1.com"
        msg["ARC-Authentication-Results"] = "i=1; mx.google.com; spf=pass"

        arc_res, obs = self.correlator.correlate(email_msg=msg)
        self.assertTrue(arc_res.has_arc)
        self.assertFalse(arc_res.is_chain_complete)
        inconsistent_obs = next((o for o in obs if o.rule_id == "RULE-ARC-INCONSISTENT"), None)
        self.assertIsNotNone(inconsistent_obs)

    def test_20_arc_absent(self):
        """20. Handle message with no ARC headers gracefully."""
        msg = EmailMessage()
        arc_res, obs = self.correlator.correlate(email_msg=msg)
        self.assertFalse(arc_res.has_arc)
        self.assertEqual(len(obs), 0)


class TestOriginCandidateSelection(unittest.TestCase):
    """Test suite for earliest reliable external peer selection."""

    def setUp(self):
        self.parser = ReceivedHeaderParser()
        self.reconstructor = HopReconstructor()
        self.engine = OriginEngine()

    def test_21_obvious_external_peer(self):
        """21. Identify obvious single external peer connecting to receiving gateway."""
        headers = [
            "from sender.com ([198.51.100.77]) by mx.victim.com; Sun, 20 Sep 2026 12:00:00 +0000"
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        candidates, assessment = self.engine.evaluate(hops)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].ip, "198.51.100.77")
        self.assertEqual(candidates[0].role, "earliest_reliable_external_peer")
        self.assertEqual(candidates[0].source_visibility, "visible")
        self.assertEqual(assessment.earliest_reliable_peer, "198.51.100.77")

    def test_22_private_hops_before_mail_provider(self):
        """22. Detect mail provider masking when private/LAN hops precede provider relay."""
        headers = [
            # Hop 2 (Received[0]): Google connecting to victim
            "from mail-wm1-f44.google.com ([203.0.113.15]) by mx.victim.com; Sun, 20 Sep 2026 12:02:00 +0000",
            # Hop 1 (Received[1]): Internal webmail client connecting to Google
            "from [10.0.0.99] by mail-wm1-f44.google.com with HTTP; Sun, 20 Sep 2026 12:00:00 +0000",
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        candidates, assessment = self.engine.evaluate(hops)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].ip, "203.0.113.15")
        self.assertEqual(candidates[0].role, "mail_provider")
        self.assertEqual(candidates[0].source_visibility, "provider_masked")
        self.assertEqual(assessment.source_visibility, "provider_masked")

    def test_23_multi_hop_upstream_relay_selection(self):
        """23. Distinguish earliest public peer from intermediate boundary relays."""
        headers = [
            # Final hop: intermediate cloud relay to victim
            "from relay.aws.com ([203.0.113.15]) by mx.victim.com; Sun, 20 Sep 2026 12:04:00 +0000",
            # Earliest public peer: external origin server to cloud relay
            "from source.corp ([198.51.100.77]) by relay.aws.com; Sun, 20 Sep 2026 12:00:00 +0000",
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        candidates, assessment = self.engine.evaluate(hops)

        self.assertEqual(len(candidates), 2)
        # Primary candidate is the earliest public peer
        self.assertEqual(candidates[0].ip, "198.51.100.77")
        self.assertEqual(candidates[0].role, "earliest_reliable_external_peer")
        # Secondary candidate is the intermediate border relay
        self.assertEqual(candidates[1].ip, "203.0.113.15")
        self.assertEqual(candidates[1].role, "upstream_relay")
        self.assertEqual(assessment.earliest_reliable_peer, "198.51.100.77")

    def test_24_insufficient_evidence_when_all_private(self):
        """24. Report insufficient_evidence when all hops are internal/private."""
        headers = [
            "from internal.local ([10.1.1.5]) by router.local ([10.1.1.1]); Sun, 20 Sep 2026 12:00:00 +0000"
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        candidates, assessment = self.engine.evaluate(hops)

        self.assertEqual(len(candidates), 0)
        self.assertIsNone(assessment.earliest_reliable_peer)
        self.assertEqual(assessment.source_visibility, "insufficient_evidence")

    def test_24b_ambiguous_origin_due_to_negative_transit_contradiction(self):
        """24b. Flag ambiguous origin when upstream hop contains contradictory timestamp."""
        headers = [
            # Hop 2 (Received[0]): Received at 12:00:00
            "from relay.mta.com ([203.0.113.15]) by mx.victim.com; Sun, 20 Sep 2026 12:00:00 +0000",
            # Hop 1 (Received[1]): Contradictory timestamp claiming 12:30:00 (after Hop 2!)
            "from source.corp ([198.51.100.77]) by relay.mta.com; Sun, 20 Sep 2026 12:30:00 +0000",
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        temp_analyzer = TemporalAnalyzer()
        hops, temp_result, _ = temp_analyzer.analyze(hops)

        candidates, assessment = self.engine.evaluate(hops, temporal_result=temp_result)

        self.assertEqual(assessment.source_visibility, "ambiguous")
        self.assertIn("contradictory timestamp evidence", assessment.assessment_reason)
        # Does not blindly crown uncorroborated contradictory hop 1
        self.assertEqual(assessment.earliest_reliable_peer, "203.0.113.15")

    def test_24c_incomplete_upstream_hop_skipped(self):
        """24c. Discard incomplete upstream hops lacking host and IP metadata."""
        headers = [
            # Hop 2: Complete external peer
            "from external.net ([203.0.113.15]) by mx.victim.com; Sun, 20 Sep 2026 12:02:00 +0000",
            # Hop 1: Corrupted / incomplete header without valid hosts
            "from unknown by unknown; Sun, 20 Sep 2026 12:00:00 +0000",
        ]
        parsed = self.parser.parse_all(headers)
        hops = self.reconstructor.reconstruct(parsed)
        candidates, assessment = self.engine.evaluate(hops)

        self.assertEqual(assessment.earliest_reliable_peer, "203.0.113.15")
        self.assertEqual(candidates[0].ip, "203.0.113.15")


# ==============================================================================
# TEST DATA ONLY: Deterministic fixtures for RFC 5737 synthetic unit tests.
# These values are test fixtures and NEVER exist in production modules.
# ==============================================================================
_TEST_DATA_GEOIP = {
    "198.51.100.77": {
        "country": "Germany",
        "country_code": "DE",
        "region": "Hesse",
        "city": "Frankfurt am Main",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "timezone": "Europe/Berlin",
    },
    "203.0.113.15": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Jose",
        "latitude": 37.3382,
        "longitude": -121.8863,
        "timezone": "America/Los_Angeles",
    },
    "192.0.2.45": {
        "country": "Finland",
        "country_code": "FI",
        "region": "Uusimaa",
        "city": "Helsinki",
        "latitude": 60.1699,
        "longitude": 24.9384,
        "timezone": "Europe/Helsinki",
    },
}

_TEST_DATA_ASN = {
    "198.51.100.77": {
        "asn": "AS24940",
        "organization": "Hetzner Online GmbH",
        "network_cidr": "198.51.100.0/24",
    },
    "203.0.113.15": {
        "asn": "AS15169",
        "organization": "Google LLC",
        "network_cidr": "203.0.113.0/24",
    },
    "192.0.2.45": {
        "asn": "AS16509",
        "organization": "Amazon.com, Inc.",
        "network_cidr": "192.0.2.0/24",
    },
}

_TEST_DATA_TOR_EXIT_IPS = {
    "185.220.101.5",
    "185.220.101.6",
    "192.42.116.16",
}

_TEST_DATA_VPN_IPS = {
    "198.51.100.200",
    "192.0.2.200",
}

_TEST_DATA_CLOUD_RANGES = [
    ("198.51.100.0/24", "Hetzner"),
    ("192.0.2.0/24", "AWS"),
    ("203.0.113.0/24", "Google Cloud / Workspace"),
]


class TestInfrastructureEnrichment(unittest.TestCase):
    """Test suite for offline adapter-based GeoIP, ASN, and infrastructure classification."""

    def setUp(self):
        # Deterministic unit test environment with mock DB paths and explicit TEST DATA fixtures
        self.geoip = LocalGeoIPProvider(db_path="/mock/nonexistent/geoip.mmdb", custom_lookup=_TEST_DATA_GEOIP)
        self.asn = LocalASNProvider(db_path="/mock/nonexistent/asn.mmdb", custom_lookup=_TEST_DATA_ASN)
        self.infra = LocalInfrastructureProvider(
            cloud_ranges=_TEST_DATA_CLOUD_RANGES,
            tor_exit_ips=_TEST_DATA_TOR_EXIT_IPS,
            vpn_ips=_TEST_DATA_VPN_IPS,
            tor_exit_list_path="/mock/nonexistent/tor.txt",
        )
        self.enrichment = CompositeEnrichmentProvider(
            geoip_provider=self.geoip,
            asn_provider=self.asn,
            infrastructure_provider=self.infra,
        )

    def test_25_successful_local_enrichment(self):
        """25. Enrich known test IP with geolocation, ASN, and hosting data."""
        res = self.enrichment.enrich("198.51.100.77")
        self.assertEqual(res.geolocation.status, "available")
        self.assertEqual(res.geolocation.country, "Germany")
        self.assertEqual(res.asn.status, "available")
        self.assertEqual(res.asn.asn, "AS24940")
        self.assertTrue(res.infrastructure.is_hosting)
        self.assertEqual(res.infrastructure.classification, "cloud_hosting")

    def test_26_unknown_ip_enrichment_fallback(self):
        """26. Unknown IP gracefully falls back to unavailable status without errors."""
        res = self.enrichment.enrich("100.64.0.1")
        self.assertEqual(res.geolocation.status, "unavailable")
        self.assertEqual(res.asn.status, "unavailable")

    def test_27_tor_exit_node_indicator(self):
        """27. Detect known Tor exit node IP address as tor_indicator."""
        res = self.enrichment.enrich("185.220.101.5")
        self.assertTrue(res.infrastructure.is_tor)
        self.assertEqual(res.infrastructure.classification, "tor_indicator")

    def test_28_missing_database_graceful_handling(self):
        """28. Non-existent database path gracefully reports unavailable without throwing."""
        empty_geoip = LocalGeoIPProvider(db_path="/path/does/not/exist/db.bin", custom_lookup={})
        geo_res = empty_geoip.lookup("198.51.100.77")
        self.assertEqual(geo_res.status, "unavailable")


class TestCrossCaseCorrelation(unittest.TestCase):
    """Test suite for cross-case infrastructure recurrence."""

    def test_29_recurring_ip_detection(self):
        """29. Detect recurring peer IP across historical cases."""
        past_cases = [
            {
                "case_id": "CASE-101",
                "ip": "198.51.100.77",
                "asn": "AS24940",
                "timestamp": "Sun, 20 Sep 2026 10:00:00 +0000",
            }
        ]
        correlator = CrossCaseCorrelator(historical_cases=past_cases)
        matches, obs = correlator.correlate(
            current_case_id="CASE-102",
            observed_ips=["198.51.100.77"],
            current_timestamp_str="Sun, 20 Sep 2026 12:00:00 +0000",
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["matched_case_id"], "CASE-101")
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].rule_id, "RULE-CORR-RECURRING-INFRASTRUCTURE")
        self.assertIn("Recurring infrastructure observed", obs[0].description)

    def test_30_unrelated_cases_no_match(self):
        """30. Confirm unrelated IPs produce zero false positive matches."""
        past_cases = [
            {"case_id": "CASE-200", "ip": "203.0.113.15"}
        ]
        correlator = CrossCaseCorrelator(historical_cases=past_cases)
        matches, obs = correlator.correlate(
            current_case_id="CASE-201",
            observed_ips=["198.51.100.77"],
        )
        self.assertEqual(len(matches), 0)
        self.assertEqual(len(obs), 0)


class TestOriginHypotheses(unittest.TestCase):
    """Test suite for competing origin hypotheses generation."""

    def setUp(self):
        self.engine = OriginHypothesisEngine()

    def test_31_direct_origin_hypothesis(self):
        """31. Generate possible_direct_origin hypothesis for visible external peer."""
        candidate = OriginCandidate(
            ip="198.51.100.77",
            hostname="mail.sender.com",
            role="earliest_reliable_external_peer",
            confidence=0.85,
            trust_state="inferred",
            hop_sequence_num=1,
            source_visibility="visible",
            reasoning="Direct external peer.",
        )
        hop = ReconstructedHop(
            hop_sequence_num=1, original_header_index=0,
            source_host="mail.sender.com", source_ip="198.51.100.77",
            receiver_host="mx.victim.com", receiver_ip=None,
            timestamp_raw=None, timestamp_utc=None, protocol=None,
            is_source_private=False, is_receiver_private=False,
        )
        hypotheses = self.engine.generate_hypotheses(
            candidates=[candidate],
            hops=[hop],
            enriched_peers=[],
        )
        types = [h.hypothesis_type for h in hypotheses]
        self.assertIn("possible_direct_origin", types)
        # Verify confidence is bounded <= 0.94
        self.assertTrue(all(h.confidence <= 0.94 for h in hypotheses))

    def test_32_provider_masking_hypothesis(self):
        """32. Generate possible_provider_masking hypothesis when origin is a mail provider."""
        candidate = OriginCandidate(
            ip="203.0.113.15",
            hostname="mail.google.com",
            role="mail_provider",
            confidence=0.85,
            trust_state="inferred",
            hop_sequence_num=1,
            source_visibility="provider_masked",
            reasoning="Mail provider relay.",
        )
        hop = ReconstructedHop(
            hop_sequence_num=1, original_header_index=0,
            source_host="mail.google.com", source_ip="203.0.113.15",
            receiver_host="mx.victim.com", receiver_ip=None,
            timestamp_raw=None, timestamp_utc=None, protocol=None,
            is_source_private=False, is_receiver_private=False,
        )
        hypotheses = self.engine.generate_hypotheses(
            candidates=[candidate],
            hops=[hop],
            enriched_peers=[],
        )
        types = [h.hypothesis_type for h in hypotheses]
        self.assertIn("possible_provider_masking", types)


class TestInvariantsAndReliability(unittest.TestCase):
    """Test suite ensuring strict semantic boundaries, safety invariants, and no false certainty."""

    def test_33_no_attacker_attribution_claim(self):
        """33. Verify report never claims an IP is the 'attacker IP'."""
        analyzer = OriginInfrastructureAnalyzer()
        eml = (
            b"From: sender@evil.com\r\n"
            b"Received: from evil.com ([198.51.100.77]) by mx.victim.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Body"
        )
        report = analyzer.analyze(eml)
        report_dict = report.to_dict()
        report_str = str(report_dict).lower()

        # Invariant checks:
        self.assertNotIn("attacker_ip", report_str)
        self.assertNotIn("guaranteed attacker", report_str)
        self.assertEqual(report.origin_assessment.earliest_reliable_peer, "198.51.100.77")
        self.assertTrue(report.origin_assessment.confidence <= 0.94)

    def test_34_geoip_is_not_attacker_location(self):
        """34. Geolocation explicitly denotes infrastructure location, NOT attacker physical location."""
        analyzer = OriginInfrastructureAnalyzer()
        eml = (
            b"Received: from evil.com ([198.51.100.77]) by mx.victim.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Body"
        )
        report = analyzer.analyze(eml)
        self.assertTrue(len(report.enriched_peers) > 0)
        peer = report.enriched_peers[0]
        self.assertIn("NOT human attacker physical location", peer.geolocation.semantic_note)

    def test_35_auth_pass_does_not_equal_legitimate(self):
        """35. Authentication PASS does not result in a 'legitimate' verdict."""
        analyzer = OriginInfrastructureAnalyzer()
        eml = (
            b"Authentication-Results: mx.victim.com; spf=pass; dkim=pass\r\n"
            b"Received: from sender.com ([198.51.100.77]) by mx.victim.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Body"
        )
        report = analyzer.analyze(eml)
        # Authentication findings are informational supporting evidence
        auth_obs = [o for o in report.observations if o.rule_id.startswith("RULE-AUTH-")]
        self.assertTrue(all(o.fact_type == "reported" for o in auth_obs))

    def test_36_missing_enrichment_does_not_crash(self):
        """36. Analysis executes completely when enrichment providers are empty/unavailable."""
        empty_enrichment = CompositeEnrichmentProvider()
        analyzer = OriginInfrastructureAnalyzer(
            geoip_provider=empty_enrichment.geoip_provider,
            asn_provider=empty_enrichment.asn_provider,
            infrastructure_provider=empty_enrichment.infrastructure_provider,
        )
        eml = (
            b"Received: from a.com ([198.51.100.77]) by mx.victim.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Body"
        )
        report = analyzer.analyze(eml)
        self.assertIsNotNone(report)
        self.assertEqual(report.origin_assessment.earliest_reliable_peer, "198.51.100.77")

    def test_37_graph_entities_and_relationships(self):
        """37. Verify evidence graph entities (email, hop, ip, country, asn) and relationships."""
        analyzer = OriginInfrastructureAnalyzer(
            geoip_provider=LocalGeoIPProvider(custom_lookup=_TEST_DATA_GEOIP),
            asn_provider=LocalASNProvider(custom_lookup=_TEST_DATA_ASN),
        )
        eml = (
            b"Received: from a.com ([198.51.100.77]) by mx.victim.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Body"
        )
        report = analyzer.analyze(eml, email_id="EML-100")
        entity_types = {e.type for e in report.entities}
        relation_types = {r.relation for r in report.relationships}

        self.assertIn("email", entity_types)
        self.assertIn("hop", entity_types)
        self.assertIn("ip", entity_types)
        self.assertIn("country", entity_types)
        self.assertIn("asn", entity_types)

        self.assertIn("has_hop", relation_types)
        self.assertIn("observed_peer_ip", relation_types)
        self.assertIn("located_in", relation_types)
        self.assertIn("belongs_to_asn", relation_types)

    def test_38_deterministic_output(self):
        """38. Ensure analysis is completely deterministic across multiple invocations."""
        ref = datetime(2026, 9, 20, 16, 0, 0, tzinfo=timezone.utc)
        analyzer = OriginInfrastructureAnalyzer(reference_time=ref)
        eml = (
            b"Received: from a.com ([198.51.100.77]) by mx.victim.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Body"
        )
        rep1 = analyzer.analyze(eml)
        rep2 = analyzer.analyze(eml)
        d1 = rep1.to_dict()
        d2 = rep2.to_dict()
        # Disregard wall-clock lookup timestamps between invocations
        for d in (d1, d2):
            for p in d.get("enriched_peers", []):
                p.get("geolocation", {}).pop("lookup_timestamp", None)
                p.get("observed_infrastructure_geolocation", {}).pop("lookup_timestamp", None)
                p.get("asn", {}).pop("lookup_timestamp", None)
        self.assertEqual(d1, d2)

    def test_39_adversarial_first_public_ip_never_claimed_as_attacker_ip(self):
        """39. Adversarial: First public IP is NEVER designated as a 'guaranteed attacker IP'."""
        analyzer = OriginInfrastructureAnalyzer()
        eml = (
            b"From: phish@spoofed.com\r\n"
            b"Received: from relay.com ([198.51.100.77]) by mx.target.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Phishing attack payload"
        )
        report = analyzer.analyze(eml)
        report_str = str(report.to_dict()).lower()
        self.assertNotIn("attacker_ip", report_str)
        self.assertNotIn("guaranteed attacker", report_str)
        self.assertEqual(report.origin_assessment.earliest_reliable_peer, "198.51.100.77")
        self.assertIn("unverified threat actor origin", report.origin_assessment.assessment_reason.lower())

    def test_40_adversarial_geoip_never_produces_attacker_physical_location(self):
        """40. Adversarial: GeoIP produces observed_infrastructure_geolocation, NEVER attacker_physical_location."""
        analyzer = OriginInfrastructureAnalyzer()
        eml = (
            b"Received: from foreign.net ([198.51.100.77]) by mx.target.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Content"
        )
        report = analyzer.analyze(eml)
        rep_dict = report.to_dict()

        # Must not have any field named attacker_physical_location
        self.assertNotIn("attacker_physical_location", rep_dict)
        self.assertNotIn("attacker_location", rep_dict)

        peer = report.enriched_peers[0]
        peer_dict = peer.to_dict()
        self.assertIn("observed_infrastructure_geolocation", peer_dict)
        self.assertNotIn("attacker_physical_location", peer_dict)
        self.assertIn("NOT human attacker physical location", peer.geolocation.semantic_note)

    def test_41_adversarial_vpn_tor_cloud_alone_does_not_imply_maliciousness(self):
        """41. Adversarial: VPN / Tor / Cloud indicator alone does NOT produce high severity or malicious finding."""
        analyzer = OriginInfrastructureAnalyzer()
        # IP 185.220.101.5 is a known Tor exit node in local test infrastructure dataset
        eml = (
            b"Received: from tor-node ([185.220.101.5]) by mx.target.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Routine message"
        )
        report = analyzer.analyze(eml)
        rep_str = str(report.to_dict()).lower()

        # Must not designate the message or IP as "malicious" by itself
        self.assertNotIn("'malicious'", rep_str)
        # Observations should not have "high" severity merely due to infrastructure type
        for obs in report.observations:
            if "tor" in obs.description.lower() or "vpn" in obs.description.lower():
                self.assertNotEqual(obs.severity, "high")

    def test_42_adversarial_spf_dkim_dmarc_pass_does_not_mark_legitimate(self):
        """42. Adversarial: SPF/DKIM/DMARC PASS does NOT mark the email as 'legitimate'."""
        analyzer = OriginInfrastructureAnalyzer()
        eml = (
            b"Authentication-Results: mx.target.com; spf=pass smtp.mailfrom=evil.com; "
            b"dkim=pass header.d=evil.com; dmarc=pass\r\n"
            b"Received: from evil.com ([198.51.100.77]) by mx.target.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Legitimate-looking phishing attack"
        )
        report = analyzer.analyze(eml)
        rep_dict = report.to_dict()
        rep_str = str(rep_dict).lower()

        # The system must not assign an overall "legitimate" verdict
        self.assertNotIn("verdict': 'legitimate'", rep_str)
        self.assertNotIn("is_legitimate", rep_str)

    def test_43_adversarial_structural_arc_does_not_claim_cryptographic_verification(self):
        """43. Adversarial: Structural ARC check emits RULE-ARC-STRUCTURE-VALID and denies crypto verification."""
        analyzer = OriginInfrastructureAnalyzer()
        eml = (
            b"ARC-Seal: i=1; cv=none; d=relay.org\r\n"
            b"ARC-Message-Signature: i=1; a=rsa-sha256; d=relay.org\r\n"
            b"ARC-Authentication-Results: i=1; mx.google.com; spf=pass\r\n"
            b"Received: from relay.org ([198.51.100.77]) by mx.target.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Body"
        )
        report = analyzer.analyze(eml)
        arc_obs = next((o for o in report.observations if "ARC" in o.rule_id), None)
        self.assertIsNotNone(arc_obs)
        self.assertEqual(arc_obs.rule_id, "RULE-ARC-STRUCTURE-VALID")
        self.assertNotEqual(arc_obs.rule_id, "RULE-ARC-VALID")
        self.assertEqual(arc_obs.trust_state, "reported")
        self.assertFalse(arc_obs.evidence.get("cryptographic_verification", True))

    def test_44_adversarial_gateway_not_marked_verified_without_configuration(self):
        """44. Adversarial: Receiving gateway is marked observed, NOT verified, unless explicitly configured."""
        analyzer_unconfigured = OriginInfrastructureAnalyzer()
        eml = (
            b"Received: from peer.com ([198.51.100.77]) by mx.target.com; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Body"
        )
        report1 = analyzer_unconfigured.analyze(eml)
        # Hop 1 in report is the only hop (Received[0])
        self.assertEqual(len(report1.hops), 1)
        self.assertEqual(report1.hops[0].trust_state, "observed")
        self.assertNotEqual(report1.hops[0].trust_state, "verified")

        # Now configure explicit trusted gateway
        analyzer_configured = OriginInfrastructureAnalyzer(trusted_gateways={"mx.target.com"})
        report2 = analyzer_configured.analyze(eml)
        self.assertEqual(report2.hops[0].trust_state, "trusted_configured")


class TestRealDBIPIntegration(unittest.TestCase):
    """Integration test suite exercising REAL local DB-IP Lite databases and Tor exit list."""

    @classmethod
    def setUpClass(cls):
        cls.city_db = Path("data/geoip/dbip-city-lite.mmdb")
        cls.asn_db = Path("data/geoip/dbip-asn-lite.mmdb")
        cls.tor_file = Path("data/geoip/tor_exit_nodes.txt")
        cls.has_real_dbs = cls.city_db.is_file() and cls.asn_db.is_file()

    def setUp(self):
        if not self.has_real_dbs:
            self.skipTest("Real DB-IP Lite databases not present in data/geoip/")
        self.geoip = LocalGeoIPProvider(db_path=str(self.city_db))
        self.asn = LocalASNProvider(db_path=str(self.asn_db))
        self.infra = LocalInfrastructureProvider(tor_exit_list_path=str(self.tor_file) if self.tor_file.is_file() else None)

    def tearDown(self):
        self.geoip.close()
        self.asn.close()

    def test_45_real_ipv4_lookup(self):
        """45. Real DB: Query public IPv4 (8.8.8.8) for City and ASN."""
        geo = self.geoip.lookup("8.8.8.8")
        self.assertEqual(geo.status, "available")
        self.assertEqual(geo.country, "United States")
        self.assertEqual(geo.country_code, "US")
        self.assertEqual(geo.region, "California")
        self.assertEqual(geo.city, "Mountain View")
        self.assertIsInstance(geo.latitude, float)
        self.assertIsInstance(geo.longitude, float)
        self.assertEqual(geo.source_dataset, "DB-IP Lite")
        self.assertEqual(geo.dataset_name, "DBIP-City-Lite")
        self.assertIsNotNone(geo.dataset_date)
        self.assertIsNotNone(geo.lookup_timestamp)
        self.assertTrue(geo.observed_infrastructure_geolocation)

        asn = self.asn.lookup("8.8.8.8")
        self.assertEqual(asn.status, "available")
        self.assertEqual(asn.asn, "AS15169")
        self.assertEqual(asn.organization, "Google LLC")
        self.assertEqual(asn.network_cidr, "8.8.8.0/24")
        self.assertEqual(asn.source_dataset, "DB-IP Lite")
        self.assertIn("DBIP-ASN-Lite", str(asn.dataset_name))
        self.assertIsNotNone(asn.dataset_date)
        self.assertIsNotNone(asn.lookup_timestamp)

    def test_46_real_ipv6_lookup(self):
        """46. Real DB: Query public IPv6 (2001:4860:4860::8888)."""
        geo = self.geoip.lookup("2001:4860:4860::8888")
        self.assertEqual(geo.status, "available")
        self.assertIsNotNone(geo.country)
        self.assertEqual(geo.source_dataset, "DB-IP Lite")

        asn = self.asn.lookup("2001:4860:4860::8888")
        self.assertEqual(asn.status, "available")
        self.assertEqual(asn.asn, "AS15169")
        self.assertEqual(asn.organization, "Google LLC")
        self.assertEqual(asn.source_dataset, "DB-IP Lite")

    def test_47_real_unknown_ip_in_db(self):
        """47. Real DB: Unknown / unrouted IP returns status='not_found'."""
        provider_no_fallback = LocalGeoIPProvider(db_path=str(self.city_db), custom_lookup={})
        geo = provider_no_fallback.lookup("100.64.0.1")
        self.assertEqual(geo.status, "not_found")
        self.assertEqual(geo.source_dataset, "DB-IP Lite")
        provider_no_fallback.close()

        asn_no_fallback = LocalASNProvider(db_path=str(self.asn_db), custom_lookup={})
        asn = asn_no_fallback.lookup("100.64.0.1")
        self.assertEqual(asn.status, "not_found")
        self.assertEqual(asn.source_dataset, "DB-IP Lite")
        asn_no_fallback.close()

    def test_48_real_invalid_ip_handling(self):
        """48. Real DB: Invalid IP syntax returns status='invalid_input'."""
        for bad_ip in ["invalid.ip.address", "999.999.999.999", "", "256.1.2.3"]:
            geo = self.geoip.lookup(bad_ip)
            self.assertEqual(geo.status, "invalid_input")
            asn = self.asn.lookup(bad_ip)
            self.assertEqual(asn.status, "invalid_input")

    def test_49_real_missing_and_malformed_database_path(self):
        """49. Real DB: Non-existent or malformed DB paths gracefully report status='unavailable'."""
        missing_geo = LocalGeoIPProvider(db_path="data/geoip/non_existent_file.mmdb", custom_lookup={})
        self.assertFalse(missing_geo.is_db_available)
        res = missing_geo.lookup("8.8.8.8")
        self.assertEqual(res.status, "unavailable")

        missing_asn = LocalASNProvider(db_path="data/geoip/non_existent_file.mmdb", custom_lookup={})
        self.assertFalse(missing_asn.is_db_available)
        res_asn = missing_asn.lookup("8.8.8.8")
        self.assertEqual(res_asn.status, "unavailable")

    def test_50_real_tor_exit_list_feed(self):
        """50. Real DB: Verify local Tor bulk exit list feed lookups."""
        if not self.tor_file.is_file():
            self.skipTest("Tor exit nodes file not present")
        # Sample known Tor exit IP from file
        infra_tor = self.infra.lookup("171.25.193.25")
        self.assertTrue(infra_tor.is_tor)
        self.assertEqual(infra_tor.tor_exit_indicator, "true")
        self.assertEqual(infra_tor.classification, "tor_indicator")
        self.assertIsNotNone(infra_tor.tor_feed_date)

        # Non-Tor public IP
        infra_clean = self.infra.lookup("8.8.8.8")
        self.assertFalse(infra_clean.is_tor)
        self.assertEqual(infra_clean.tor_exit_indicator, "false")

    def test_51_real_metadata_and_provenance_propagation(self):
        """51. Real DB: Composite enrichment preserves observed infrastructure metadata & provenance."""
        composite = CompositeEnrichmentProvider(
            geoip_provider=self.geoip,
            asn_provider=self.asn,
            infrastructure_provider=self.infra,
        )
        enriched = composite.enrich("8.8.8.8")
        d = enriched.to_dict()

        self.assertIn("observed_infrastructure_geolocation", d)
        geo_dict = d["geolocation"]
        self.assertEqual(geo_dict["source_dataset"], "DB-IP Lite")
        self.assertEqual(geo_dict["dataset_name"], "DBIP-City-Lite")
        self.assertIsNotNone(geo_dict["dataset_date"])
        self.assertIsNotNone(geo_dict["lookup_timestamp"])
        self.assertIn("Observed infrastructure geolocation, NOT human attacker physical location.", geo_dict["semantic_note"])

        asn_dict = d["asn"]
        self.assertEqual(asn_dict["source_dataset"], "DB-IP Lite")
        self.assertEqual(asn_dict["asn"], "AS15169")
        self.assertEqual(asn_dict["organization"], "Google LLC")

    def test_52_e2e_analyzer_with_real_databases(self):
        """52. Real DB: End-to-end email analysis using real local enrichment."""
        analyzer = OriginInfrastructureAnalyzer(
            geoip_provider=self.geoip,
            asn_provider=self.asn,
            infrastructure_provider=self.infra,
        )
        eml = (
            b"From: sender@external.com\r\n"
            b"To: victim@company.com\r\n"
            b"Subject: Test Real Enrichment\r\n"
            b"Received: from dns.google ([8.8.8.8]) by mx.target.com with ESMTPS; Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n"
            b"Hello world"
        )
        report = analyzer.analyze(eml)
        self.assertEqual(report.origin_assessment.earliest_reliable_peer, "8.8.8.8")
        peer_enriched = next((p for p in report.enriched_peers if p.ip == "8.8.8.8"), None)
        self.assertIsNotNone(peer_enriched)
        assert peer_enriched is not None
        self.assertEqual(peer_enriched.geolocation.country, "United States")
        self.assertEqual(peer_enriched.asn.asn, "AS15169")
        self.assertEqual(peer_enriched.asn.organization, "Google LLC")

    def test_53_real_dynamic_resolution_proof(self):
        """53. Prove dynamic local MMDB enrichment for multiple arbitrary IPv4 and IPv6 addresses."""
        test_ips = [
            ("8.8.8.8", "United States", "AS15169", "Google LLC"),
            ("1.1.1.1", "Australia", "AS13335", "Cloudflare, Inc."),
            ("171.25.193.25", "Sweden", "AS198093", "Foreningen for digitala fri- och rattigheter"),
            ("9.9.9.9", "United States", "AS19281", "Quad9"),
            ("2606:4700:4700::1111", "Canada", "AS13335", "Cloudflare, Inc."),
        ]

        # Verify none of these IPs are in test fixtures
        for ip_addr, _, _, _ in test_ips:
            self.assertNotIn(ip_addr, _TEST_DATA_GEOIP, f"{ip_addr} must not be hardcoded in _TEST_DATA_GEOIP")
            self.assertNotIn(ip_addr, _TEST_DATA_ASN, f"{ip_addr} must not be hardcoded in _TEST_DATA_ASN")

        # Query real dynamic providers (no custom lookup)
        dynamic_geoip = LocalGeoIPProvider(db_path=str(self.city_db), custom_lookup=None)
        dynamic_asn = LocalASNProvider(db_path=str(self.asn_db), custom_lookup=None)

        for ip_addr, expected_country, expected_asn, expected_org in test_ips:
            geo = dynamic_geoip.lookup(ip_addr)
            self.assertEqual(geo.status, "available", f"Expected available GeoIP for {ip_addr}")
            self.assertEqual(geo.country, expected_country, f"Expected country {expected_country} for {ip_addr}")
            self.assertEqual(geo.source_dataset, "DB-IP Lite")

            asn_res = dynamic_asn.lookup(ip_addr)
            self.assertEqual(asn_res.status, "available", f"Expected available ASN for {ip_addr}")
            self.assertEqual(asn_res.asn, expected_asn, f"Expected ASN {expected_asn} for {ip_addr}")
            self.assertEqual(asn_res.organization, expected_org, f"Expected org {expected_org} for {ip_addr}")
            self.assertEqual(asn_res.source_dataset, "DB-IP Lite")

        dynamic_geoip.close()
        dynamic_asn.close()

    def test_54_setup_geoip_expected_files_exist_and_valid(self):
        """54. Verify required local enrichment files (City, ASN, Tor feed) exist and pass validation."""
        from scripts.setup_geoip import validate_mmdb, validate_tor_feed

        self.assertTrue(self.city_db.is_file(), "data/geoip/dbip-city-lite.mmdb must exist")
        self.assertTrue(self.asn_db.is_file(), "data/geoip/dbip-asn-lite.mmdb must exist")
        self.assertTrue(self.tor_file.is_file(), "data/geoip/tor_exit_nodes.txt must exist")

        self.assertTrue(validate_mmdb(self.city_db, "city"), "dbip-city-lite.mmdb must be valid City MMDB")
        self.assertTrue(validate_mmdb(self.asn_db, "asn"), "dbip-asn-lite.mmdb must be valid ASN MMDB")
        self.assertTrue(validate_tor_feed(self.tor_file), "tor_exit_nodes.txt must contain valid IP feed")


class TestSecondaryPDDLEnrichment(unittest.TestCase):
    """Test suite for secondary PDDL geographic & ASN evidence providers (sapics/ip-location-db)."""

    @classmethod
    def setUpClass(cls):
        cls.user_mmdb = Path("benchmark/ip_location_db/user-country.mmdb")
        cls.server_mmdb = Path("benchmark/ip_location_db/server-country.mmdb")
        cls.origin_mmdb = Path("benchmark/ip_location_db/origin-asn.mmdb")
        cls.has_pddl = cls.user_mmdb.is_file() and cls.server_mmdb.is_file() and cls.origin_mmdb.is_file()

    def test_55_pddl_datasets_available(self):
        """55. Verify secondary PDDL providers query valid IPv4 when datasets are present."""
        from modules.origin_infrastructure.enrichment import (
            OriginASNProvider,
            ServerCountryProvider,
            UserCountryProvider,
        )

        u_prov = UserCountryProvider(db_path=str(self.user_mmdb) if self.has_pddl else None, custom_lookup={"49.37.154.164": {"country_code": "IN"}} if not self.has_pddl else None)
        s_prov = ServerCountryProvider(db_path=str(self.server_mmdb) if self.has_pddl else None, custom_lookup={"49.37.154.164": {"country_code": "IN"}} if not self.has_pddl else None)
        o_prov = OriginASNProvider(db_path=str(self.origin_mmdb) if self.has_pddl else None, custom_lookup={"49.37.154.164": {"asn": "AS55836", "organization": "Reliance Jio Infocomm Limited"}} if not self.has_pddl else None)

        u_res = u_prov.lookup("49.37.154.164")
        self.assertEqual(u_res.status, "available")
        self.assertEqual(u_res.country_code, "IN")
        self.assertEqual(u_res.trust_state, "enriched")
        self.assertIn("user-country", u_res.source_dataset)
        self.assertEqual(u_res.license, "PDDL-1.0")

        s_res = s_prov.lookup("49.37.154.164")
        self.assertEqual(s_res.status, "available")
        self.assertEqual(s_res.country_code, "IN")
        self.assertEqual(s_res.trust_state, "enriched")
        self.assertIn("server-country", s_res.source_dataset)

        o_res = o_prov.lookup("49.37.154.164")
        self.assertEqual(o_res.status, "available")
        self.assertEqual(o_res.asn, "AS55836")
        self.assertIn("Reliance Jio", str(o_res.organization))
        self.assertEqual(o_res.trust_state, "enriched")

        u_prov.close()
        s_prov.close()
        o_prov.close()

    def test_56_pddl_datasets_unavailable(self):
        """56. Verify secondary providers gracefully degrade to status='unavailable' when missing."""
        from modules.origin_infrastructure.enrichment import (
            OriginASNProvider,
            ServerCountryProvider,
            UserCountryProvider,
        )

        missing_u = UserCountryProvider(db_path="data/geoip/non_existent.mmdb", custom_lookup=None)
        missing_s = ServerCountryProvider(db_path="data/geoip/non_existent.mmdb", custom_lookup=None)
        missing_o = OriginASNProvider(db_path="data/geoip/non_existent.mmdb", custom_lookup=None)

        self.assertEqual(missing_u.lookup("8.8.8.8").status, "unavailable")
        self.assertEqual(missing_u.lookup("8.8.8.8").trust_state, "unknown")
        self.assertIsNone(missing_u.lookup("8.8.8.8").country_code)

        self.assertEqual(missing_s.lookup("8.8.8.8").status, "unavailable")
        self.assertEqual(missing_s.lookup("8.8.8.8").trust_state, "unknown")

        self.assertEqual(missing_o.lookup("8.8.8.8").status, "unavailable")
        self.assertEqual(missing_o.lookup("8.8.8.8").trust_state, "unknown")
        self.assertIsNone(missing_o.lookup("8.8.8.8").asn)

    def test_57_pddl_ipv4_and_ipv6(self):
        """57. Verify secondary providers handle both IPv4 and IPv6 lookups."""
        from modules.origin_infrastructure.enrichment import (
            OriginASNProvider,
            ServerCountryProvider,
            UserCountryProvider,
        )

        # Explicit test fixtures to test both IPv4 and IPv6
        fixtures_u = {
            "8.8.8.8": {"country_code": "US"},
            "2001:4860:4860::8888": {"country_code": "US"},
        }
        fixtures_o = {
            "8.8.8.8": {"asn": "AS15169", "organization": "Google LLC"},
            "2001:4860:4860::8888": {"asn": "AS15169", "organization": "Google LLC"},
        }
        u_prov = UserCountryProvider(custom_lookup=fixtures_u)
        s_prov = ServerCountryProvider(custom_lookup=fixtures_u)
        o_prov = OriginASNProvider(custom_lookup=fixtures_o)

        # IPv4
        self.assertEqual(u_prov.lookup("8.8.8.8").country_code, "US")
        self.assertEqual(s_prov.lookup("8.8.8.8").country_code, "US")
        self.assertEqual(o_prov.lookup("8.8.8.8").asn, "AS15169")

        # IPv6
        self.assertEqual(u_prov.lookup("2001:4860:4860::8888").country_code, "US")
        self.assertEqual(s_prov.lookup("2001:4860:4860::8888").country_code, "US")
        self.assertEqual(o_prov.lookup("2001:4860:4860::8888").asn, "AS15169")

        # Invalid IP
        self.assertEqual(u_prov.lookup("not-an-ip").status, "invalid_input")
        self.assertEqual(o_prov.lookup("").status, "invalid_input")

    def test_58_matching_user_and_server_country(self):
        """58. Verify country_agreement=True, interpretation='country-level evidence is consistent', but does NOT alone imply direct origin."""
        from modules.origin_infrastructure.enrichment import (
            CompositeEnrichmentProvider,
            LocalASNProvider,
            LocalGeoIPProvider,
            LocalInfrastructureProvider,
            OriginASNProvider,
            ServerCountryProvider,
            UserCountryProvider,
        )

        geo = LocalGeoIPProvider(custom_lookup={"49.37.154.164": {"country": "India", "country_code": "IN", "city": "Navi Mumbai"}})
        asn = LocalASNProvider(custom_lookup={"49.37.154.164": {"asn": "AS55836", "organization": "Reliance Jio Infocomm Limited"}})
        infra = LocalInfrastructureProvider()
        u_prov = UserCountryProvider(custom_lookup={"49.37.154.164": {"country_code": "IN"}})
        s_prov = ServerCountryProvider(custom_lookup={"49.37.154.164": {"country_code": "IN"}})
        o_prov = OriginASNProvider(custom_lookup={"49.37.154.164": {"asn": "AS55836", "organization": "Reliance Jio Infocomm Limited"}})

        composite = CompositeEnrichmentProvider(
            geoip_provider=geo,
            asn_provider=asn,
            infrastructure_provider=infra,
            user_country_provider=u_prov,
            server_country_provider=s_prov,
            origin_asn_provider=o_prov,
        )

        # A. Without broader hop context: country agreement alone does NOT declare direct_origin_infrastructure
        enriched_no_ctx = composite.enrich("49.37.154.164")
        self.assertIsNotNone(enriched_no_ctx.location_evidence)
        le_no_ctx = enriched_no_ctx.location_evidence
        assert le_no_ctx is not None
        self.assertEqual(le_no_ctx.country_agreement, True)
        self.assertEqual(le_no_ctx.interpretation, "country-level evidence is consistent")
        self.assertEqual(le_no_ctx.country_confidence, 0.95)
        self.assertEqual(le_no_ctx.location_type, "unknown", "Same country alone must NEVER infer direct origin")

        # B. Same country can still contain relays (e.g. hop_sequence_num = 2, role = upstream_relay)
        relay_ctx = {"role": "upstream_relay", "hop_sequence_num": 2, "trust_state": "observed"}
        enriched_relay = composite.enrich("49.37.154.164", hop_context=relay_ctx)
        le_relay = enriched_relay.location_evidence
        assert le_relay is not None
        self.assertEqual(le_relay.country_agreement, True)
        self.assertEqual(le_relay.location_type, "relay_infrastructure", "Same country can still contain relays")

        # C. With broader Module 5 evidence: earliest reliable external peer + verified trust state -> direct_origin_infrastructure
        origin_ctx = {"role": "earliest_reliable_external_peer", "hop_sequence_num": 1, "trust_state": "verified"}
        enriched_origin = composite.enrich("49.37.154.164", hop_context=origin_ctx)
        le_origin = enriched_origin.location_evidence
        assert le_origin is not None
        self.assertEqual(le_origin.location_type, "direct_origin_infrastructure")

    def test_59_differing_user_and_server_country(self):
        """59. Verify country_agreement=False, interpretation='country-level geographic evidence is inconsistent'."""
        from modules.origin_infrastructure.enrichment import (
            CompositeEnrichmentProvider,
            LocalASNProvider,
            LocalGeoIPProvider,
            LocalInfrastructureProvider,
            OriginASNProvider,
            ServerCountryProvider,
            UserCountryProvider,
        )

        # Cross-border relay / roaming IP (user in AU, server in US)
        ip = "176.23.150.1"
        geo = LocalGeoIPProvider(custom_lookup={ip: {"country": "Australia", "country_code": "AU", "city": "Sydney"}})
        asn = LocalASNProvider(custom_lookup={ip: {"asn": "AS40934", "organization": "Fortinet Inc."}})
        infra = LocalInfrastructureProvider()
        u_prov = UserCountryProvider(custom_lookup={ip: {"country_code": "AU"}})
        s_prov = ServerCountryProvider(custom_lookup={ip: {"country_code": "US"}})
        o_prov = OriginASNProvider(custom_lookup={ip: {"asn": "AS40934", "organization": "Fortinet Inc."}})

        composite = CompositeEnrichmentProvider(
            geoip_provider=geo,
            asn_provider=asn,
            infrastructure_provider=infra,
            user_country_provider=u_prov,
            server_country_provider=s_prov,
            origin_asn_provider=o_prov,
        )

        # Without broader hop context: country divergence alone does NOT set relay_infrastructure
        enriched = composite.enrich(ip)
        self.assertIsNotNone(enriched.location_evidence)
        le = enriched.location_evidence
        assert le is not None
        self.assertEqual(le.country_agreement, False)
        self.assertEqual(le.interpretation, "country-level geographic evidence is inconsistent")
        self.assertEqual(le.country_confidence, 0.45)  # Reduced heuristic confidence
        self.assertEqual(le.location_type, "unknown", "Disagreement alone must not set location_type")

        # With broader hop context (hop 2 upstream relay): different user/server country is corroborating relay evidence
        relay_ctx = {"role": "upstream_relay", "hop_sequence_num": 2, "trust_state": "observed"}
        enriched_relay = composite.enrich(ip, hop_context=relay_ctx)
        le_relay = enriched_relay.location_evidence
        assert le_relay is not None
        self.assertEqual(le_relay.location_type, "relay_infrastructure")

    def test_60_asn_agreement_and_disagreement(self):
        """60. Verify ASN agreement vs disagreement tracking between DB-IP ASN and origin-asn."""
        from modules.origin_infrastructure.enrichment import (
            CompositeEnrichmentProvider,
            LocalASNProvider,
            OriginASNProvider,
        )

        # Agreeing case
        ip1 = "8.8.8.8"
        asn1 = LocalASNProvider(custom_lookup={ip1: {"asn": "AS15169", "organization": "Google LLC"}})
        o_prov1 = OriginASNProvider(custom_lookup={ip1: {"asn": "AS15169", "organization": "Google LLC"}})
        c1 = CompositeEnrichmentProvider(asn_provider=asn1, origin_asn_provider=o_prov1)
        e1 = c1.enrich(ip1)
        self.assertEqual(e1.asn.asn, "AS15169")
        self.assertEqual(e1.location_evidence.origin_asn.get("asn"), "AS15169")  # type: ignore[union-attr]

        # Disagreeing / re-routed case
        ip2 = "192.0.2.1"
        asn2 = LocalASNProvider(custom_lookup={ip2: {"asn": "AS64500", "organization": "Old Org"}})
        o_prov2 = OriginASNProvider(custom_lookup={ip2: {"asn": "AS64501", "organization": "New BGP Route"}})
        c2 = CompositeEnrichmentProvider(asn_provider=asn2, origin_asn_provider=o_prov2)
        e2 = c2.enrich(ip2)
        self.assertEqual(e2.asn.asn, "AS64500")
        self.assertEqual(e2.location_evidence.origin_asn.get("asn"), "AS64501")  # type: ignore[union-attr]
        self.assertNotEqual(e2.asn.asn, e2.location_evidence.origin_asn.get("asn"))  # type: ignore[union-attr]

    def test_61_no_city_inference_from_country_datasets(self):
        """61. Ensure country datasets NEVER infer or populate city/coordinate data, DB-IP city remains infrastructure geolocation."""
        from modules.origin_infrastructure.enrichment import (
            CompositeEnrichmentProvider,
            LocalGeoIPProvider,
            ServerCountryProvider,
            UserCountryProvider,
        )

        geo = LocalGeoIPProvider(custom_lookup={"8.8.8.8": {"country": "United States", "country_code": "US", "city": "Mountain View", "latitude": 37.422, "longitude": -122.085}})
        u = UserCountryProvider(custom_lookup={"8.8.8.8": {"country_code": "US"}}).lookup("8.8.8.8")
        s = ServerCountryProvider(custom_lookup={"8.8.8.8": {"country_code": "US"}}).lookup("8.8.8.8")

        # user-country and server-country models must have only country_code, NO city or coords
        self.assertFalse(hasattr(u, "city"))
        self.assertFalse(hasattr(u, "latitude"))
        self.assertFalse(hasattr(s, "city"))
        self.assertFalse(hasattr(s, "longitude"))
        self.assertEqual(u.country_code, "US")
        self.assertEqual(s.country_code, "US")

        # Composite verification: DB-IP city remains the infrastructure geolocation
        comp = CompositeEnrichmentProvider(geoip_provider=geo, user_country_provider=UserCountryProvider(custom_lookup={"8.8.8.8": {"country_code": "US"}}))
        e = comp.enrich("8.8.8.8")
        self.assertEqual(e.geolocation.city, "Mountain View")
        assert e.location_evidence is not None
        self.assertEqual(e.location_evidence.dbip_infrastructure_location.get("city"), "Mountain View")

    def test_62_no_physical_attacker_location_claim(self):
        """62. Verify semantic rule: no physical attacker location claim is produced."""
        from modules.origin_infrastructure.enrichment import (
            CompositeEnrichmentProvider,
            UserCountryProvider,
        )

        u_prov = UserCountryProvider(custom_lookup={"8.8.8.8": {"country_code": "US"}})
        comp = CompositeEnrichmentProvider(user_country_provider=u_prov)
        enriched = comp.enrich("8.8.8.8")

        d = enriched.to_dict()
        # Ensure no key claims attacker location
        self.assertNotIn("attacker_location", d)
        self.assertNotIn("physical_location", d)
        self.assertIn("location_evidence", d)
        self.assertEqual(d["location_evidence"]["ip"], "8.8.8.8")
        self.assertNotIn("attacker", str(d["location_evidence"]).lower())


    def test_63_provenance_preservation(self):
        """63. Verify all contributing offline datasets are preserved in provenance."""
        from modules.origin_infrastructure.enrichment import (
            CompositeEnrichmentProvider,
            LocalASNProvider,
            LocalGeoIPProvider,
            OriginASNProvider,
            ServerCountryProvider,
            UserCountryProvider,
        )

        ip = "8.8.8.8"
        geo = LocalGeoIPProvider(custom_lookup={ip: {"country": "United States", "country_code": "US", "city": "Mountain View"}})
        asn = LocalASNProvider(custom_lookup={ip: {"asn": "AS15169", "organization": "Google LLC"}})
        u_prov = UserCountryProvider(custom_lookup={ip: {"country_code": "US"}})
        s_prov = ServerCountryProvider(custom_lookup={ip: {"country_code": "US"}})
        o_prov = OriginASNProvider(custom_lookup={ip: {"asn": "AS15169", "organization": "Google LLC"}})

        comp = CompositeEnrichmentProvider(
            geoip_provider=geo,
            asn_provider=asn,
            user_country_provider=u_prov,
            server_country_provider=s_prov,
            origin_asn_provider=o_prov,
        )

        e = comp.enrich(ip)
        assert e.location_evidence is not None
        prov = e.location_evidence.provenance
        self.assertTrue(any("DB-IP" in p for p in prov))
        self.assertTrue(any("user-country" in p for p in prov))
        self.assertTrue(any("server-country" in p for p in prov))
        self.assertTrue(any("origin-asn" in p for p in prov))

    def test_64_dbip_continues_working_when_secondary_unavailable(self):
        """64. Verify DB-IP and core pipeline continue operating without secondary providers."""
        from modules.origin_infrastructure.analyzer import OriginInfrastructureAnalyzer
        from modules.origin_infrastructure.enrichment import (
            LocalASNProvider,
            LocalGeoIPProvider,
            LocalInfrastructureProvider,
        )

        # Standard analyzer with only DB-IP and Tor providers
        geo = LocalGeoIPProvider(custom_lookup={"8.8.8.8": {"country": "United States", "country_code": "US", "city": "Mountain View"}})
        asn = LocalASNProvider(custom_lookup={"8.8.8.8": {"asn": "AS15169", "organization": "Google LLC"}})
        infra = LocalInfrastructureProvider()

        analyzer = OriginInfrastructureAnalyzer(
            geoip_provider=geo,
            asn_provider=asn,
            infrastructure_provider=infra,
            user_country_provider=None,
            server_country_provider=None,
            origin_asn_provider=None,
        )

        raw_eml = (
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Test\n"
            "Date: Wed, 10 Sep 2026 12:00:00 +0000\n"
            "Received: from mail.example.com (mail.example.com [8.8.8.8])\n"
            "    by mx.destination.com with ESMTP id xyz;\n"
            "    Wed, 10 Sep 2026 12:00:05 +0000\n\n"
            "Body content\n"
        )
        report = analyzer.analyze(raw_eml)
        self.assertEqual(report.origin_assessment.earliest_reliable_peer, "8.8.8.8")
        peer = next((p for p in report.enriched_peers if p.ip == "8.8.8.8"), None)
        self.assertIsNotNone(peer)
        assert peer is not None
        self.assertEqual(peer.geolocation.country, "United States")
        self.assertEqual(peer.asn.asn, "AS15169")
        # location_evidence is None when secondary providers are not configured
        self.assertIsNone(peer.location_evidence)

    def test_65_semantic_audit_geographic_invariants(self):
        """65. Comprehensive audit of PDDL geographic evidence semantic invariants.

        Enforces:
        1. NEVER infer: user_country == server_country -> direct_origin_infrastructure.
        2. NEVER infer: user_country == server_country -> no relay/proxy (domestic relays exist).
        3. user_country == server_country -> country_agreement=True, interpretation='country-level evidence is consistent'.
        4. user_country != server_country -> country_agreement=False, interpretation='country-level geographic evidence is inconsistent'.
        5. Neither agreement nor disagreement alone determines:
           direct_origin_infrastructure, relay_infrastructure, provider_infrastructure, anonymized_infrastructure.
        6. Origin location type determined ONLY using broader Module 5 evidence:
           hop position, trust state, temporal consistency, infrastructure classification,
           ASN, authentication context, country evidence, and cross-case evidence.
        7. Numeric confidence values are explicitly non-calibrated heuristic consensus metrics, NOT probabilities.
        8. Country evidence never establishes physical attacker location; DB-IP city remains infrastructure geolocation.
        """
        from modules.origin_infrastructure.enrichment import (
            CompositeEnrichmentProvider,
            LocalASNProvider,
            LocalGeoIPProvider,
            LocalInfrastructureProvider,
            OriginASNProvider,
            ServerCountryProvider,
            UserCountryProvider,
        )

        ip_same = "49.37.154.164"  # Same country: user=IN, server=IN
        ip_diff = "176.23.150.1"   # Diff country: user=AU, server=US

        geo = LocalGeoIPProvider(custom_lookup={
            ip_same: {"country": "India", "country_code": "IN", "city": "Navi Mumbai", "latitude": 19.033, "longitude": 73.029},
            ip_diff: {"country": "Australia", "country_code": "AU", "city": "Sydney", "latitude": -33.868, "longitude": 151.209},
        })
        asn = LocalASNProvider(custom_lookup={
            ip_same: {"asn": "AS55836", "organization": "Reliance Jio Infocomm Limited"},
            ip_diff: {"asn": "AS40934", "organization": "Fortinet Inc."},
        })
        infra = LocalInfrastructureProvider()
        u_prov = UserCountryProvider(custom_lookup={
            ip_same: {"country_code": "IN"},
            ip_diff: {"country_code": "AU"},
        })
        s_prov = ServerCountryProvider(custom_lookup={
            ip_same: {"country_code": "IN"},
            ip_diff: {"country_code": "US"},
        })
        o_prov = OriginASNProvider(custom_lookup={
            ip_same: {"asn": "AS55836", "organization": "Reliance Jio Infocomm Limited"},
            ip_diff: {"asn": "AS40934", "organization": "Fortinet Inc."},
        })

        composite = CompositeEnrichmentProvider(
            geoip_provider=geo,
            asn_provider=asn,
            infrastructure_provider=infra,
            user_country_provider=u_prov,
            server_country_provider=s_prov,
            origin_asn_provider=o_prov,
        )

        # Invariant 1 & 5: user_country == server_country alone does NOT determine direct_origin_infrastructure
        e_same_no_ctx = composite.enrich(ip_same)
        assert e_same_no_ctx.location_evidence is not None
        le_s1 = e_same_no_ctx.location_evidence
        self.assertEqual(le_s1.country_agreement, True)
        self.assertEqual(le_s1.interpretation, "country-level evidence is consistent")
        self.assertNotEqual(le_s1.location_type, "direct_origin_infrastructure")
        self.assertEqual(le_s1.location_type, "unknown")

        # Invariant 2 & 6: user_country == server_country can still contain relays (domestic relay)
        domestic_relay_ctx = {
            "role": "upstream_relay",
            "hop_sequence_num": 2,
            "trust_state": "observed",
            "temporal_consistent": True,
            "temporal_delay_anomaly": False,
            "auth_aligned": False,
            "is_recurring": False,
        }
        e_same_relay = composite.enrich(ip_same, hop_context=domestic_relay_ctx)
        assert e_same_relay.location_evidence is not None
        le_s2 = e_same_relay.location_evidence
        self.assertEqual(le_s2.country_agreement, True)
        self.assertEqual(le_s2.location_type, "relay_infrastructure")

        # Invariant 4 & 5: user_country != server_country alone does NOT determine relay_infrastructure
        e_diff_no_ctx = composite.enrich(ip_diff)
        assert e_diff_no_ctx.location_evidence is not None
        le_d1 = e_diff_no_ctx.location_evidence
        self.assertEqual(le_d1.country_agreement, False)
        self.assertEqual(le_d1.interpretation, "country-level geographic evidence is inconsistent")
        self.assertNotEqual(le_d1.location_type, "relay_infrastructure")
        self.assertEqual(le_d1.location_type, "unknown")

        # Invariant 6: Different user/server country corroborates relay when hop context indicates relay
        cross_border_relay_ctx = {
            "role": "upstream_relay",
            "hop_sequence_num": 3,
            "trust_state": "observed",
            "temporal_consistent": True,
            "temporal_delay_anomaly": False,
            "auth_aligned": False,
            "is_recurring": False,
        }
        e_diff_relay = composite.enrich(ip_diff, hop_context=cross_border_relay_ctx)
        assert e_diff_relay.location_evidence is not None
        le_d2 = e_diff_relay.location_evidence
        self.assertEqual(le_d2.country_agreement, False)
        self.assertEqual(le_d2.location_type, "relay_infrastructure")

        # Invariant 6: Broader evidence establishes direct_origin_infrastructure
        origin_ctx = {
            "role": "earliest_reliable_external_peer",
            "hop_sequence_num": 1,
            "trust_state": "verified",
            "temporal_consistent": True,
            "temporal_delay_anomaly": False,
            "auth_aligned": True,
            "is_recurring": False,
        }
        e_origin = composite.enrich(ip_same, hop_context=origin_ctx)
        assert e_origin.location_evidence is not None
        le_orig = e_origin.location_evidence
        self.assertEqual(le_orig.location_type, "direct_origin_infrastructure")

        # Invariant 6: Cross-case evidence establishes campaign_infrastructure
        campaign_ctx = {
            "role": "earliest_reliable_external_peer",
            "hop_sequence_num": 1,
            "trust_state": "verified",
            "temporal_consistent": True,
            "temporal_delay_anomaly": False,
            "auth_aligned": True,
            "is_recurring": True,
        }
        e_campaign = composite.enrich(ip_same, hop_context=campaign_ctx)
        assert e_campaign.location_evidence is not None
        self.assertEqual(e_campaign.location_evidence.location_type, "campaign_infrastructure")

        # Invariant 7: Numeric confidence values are heuristic consensus metrics, NOT probabilities
        self.assertEqual(le_s1.country_confidence, 0.95)
        self.assertEqual(le_s1.confidence_metric, "heuristic_non_calibrated_consensus")
        self.assertEqual(le_d1.country_confidence, 0.45)
        self.assertEqual(le_d1.confidence_metric, "heuristic_non_calibrated_consensus")
        dict_rep = le_s1.to_dict()
        self.assertEqual(dict_rep["confidence_metric"], "heuristic_non_calibrated_consensus")
        self.assertNotIn("probability", dict_rep)

        # Invariant 8: Country evidence NEVER establishes physical attacker location
        dict_s1 = le_s1.to_dict()
        self.assertNotIn("attacker_location", dict_s1)
        self.assertNotIn("physical_location", dict_s1)
        self.assertNotIn("attacker_ip", dict_s1)
        self.assertIn("NOT human attacker physical location", dict_s1["dbip_infrastructure_location"]["semantic_note"])

        # Invariant 8: DB-IP city remains infrastructure geolocation, never overwritten by country data
        self.assertIn("Navi Mumbai", str(e_same_no_ctx.geolocation.city))
        self.assertIn("Navi Mumbai", str(le_s1.dbip_infrastructure_location.get("city")))
        self.assertFalse(hasattr(u_prov.lookup(ip_same), "city"))
        self.assertFalse(hasattr(s_prov.lookup(ip_same), "city"))


if __name__ == "__main__":
    unittest.main()

