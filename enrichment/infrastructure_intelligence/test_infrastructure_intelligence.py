"""Comprehensive test suite for Infrastructure Intelligence Layer.

Validates deterministic behavior across:
1. Synthetic IP guard (RFC 5737, RFC 3849, RFC 1918, loopback)
2. Mock Spamhaus DROP matching (fixture MOCK_FEED_CIDR = '198.18.10.0/24')
3. Passive DNS (A, AAAA, CNAME, NS, TXT, SPF, DMARC, NXDOMAIN, timeout)
4. MX record resolution and neutral classification
5. Reverse DNS / FCrDNS match and mismatch
6. RDAP IP and domain response parsing, 404, timeout, malformed JSON
7. Neutral hosting classification and bulletproof source restrictions
8. Forensic trust semantics (observed vs inferred)
9. Evidence provenance tracking
10. Failure resilience and Module 6 InvestigationCase synthesis
"""

from __future__ import annotations

from typing import Any
import unittest
from unittest.mock import MagicMock, patch

from enrichment.infrastructure_intelligence.dispatcher import (
    is_rfc5737_documentation_ip,
    is_synthetic_or_private_ip,
    run_infrastructure_intelligence,
)
from enrichment.infrastructure_intelligence.fingerprinter import (
    classify_hosting,
)
from enrichment.infrastructure_intelligence.models import (
    HostingFingerprintData,
    InfrastructureIntelligenceReport,
    MxRecordData,
    PassiveDnsData,
    RdapRegistrationData,
    ReverseDnsData,
    ThreatFeedMatch,
)
from enrichment.infrastructure_intelligence.passive_dns import (
    resolve_mx_records,
    resolve_passive_dns,
)
from enrichment.infrastructure_intelligence.rdap_client import RdapClient
from enrichment.infrastructure_intelligence.reverse_dns import (
    resolve_reverse_dns,
)
from enrichment.infrastructure_intelligence.threat_feeds import (
    LocalThreatFeedMatcher,
)
from modules.evidence_correlation.analyzer import EvidenceCorrelationAnalyzer
from modules.evidence_correlation.normalizer import EvidenceNormalizer

# Benchmark and unit-test mock fixture CIDR (RFC 2544 benchmark network)
# Explicitly local-only; NOT RFC 5737, RFC 3849, or RFC 1918.
MOCK_FEED_CIDR = "198.18.10.0/24"


# =============================================================================
# 1. Synthetic IP Guard Tests
# =============================================================================
class TestSyntheticIPGuard(unittest.TestCase):
    """Validate RFC 5737, RFC 3849, RFC 1918, and loopback interception."""

    def test_synthetic_ip_detection(self) -> None:
        ips = [
            ("198.51.100.99", True),
            ("192.0.2.1", True),
            ("203.0.113.50", True),
            ("2001:db8::1", True),
            ("10.0.0.1", False),
            ("172.16.1.1", False),
            ("192.168.1.100", False),
            ("127.0.0.1", False),
            ("::1", False),
        ]
        for ip_str, is_doc in ips:
            with self.subTest(ip=ip_str):
                self.assertTrue(is_synthetic_or_private_ip(ip_str))
                if is_doc:
                    self.assertTrue(is_rfc5737_documentation_ip(ip_str))

    @patch(
        "enrichment.infrastructure_intelligence.dispatcher.resolve_reverse_dns"
    )
    @patch(
        "enrichment.infrastructure_intelligence.dispatcher.resolve_passive_dns"
    )
    def test_synthetic_ip_zero_network_calls(
        self, mock_dns: MagicMock, mock_rdns: MagicMock
    ) -> None:
        """Target 198.51.100.99 must produce zero network and zero lookups."""
        report = run_infrastructure_intelligence(
            target_ip="198.51.100.99",
            target_domain="example.com",
        )

        mock_dns.assert_not_called()
        mock_rdns.assert_not_called()

        self.assertTrue(report.is_documentation_ip)
        self.assertTrue(report.is_synthetic_test)
        self.assertEqual(report.threat_feed.status, "synthetic_test")
        self.assertFalse(report.threat_feed.is_listed)
        self.assertEqual(report.rdap.status, "synthetic_test")
        self.assertEqual(report.dns.status, "synthetic_test")
        self.assertEqual(report.mx.status, "synthetic_test")
        self.assertEqual(report.mx.mx_status, "synthetic_test")
        self.assertEqual(report.reverse_dns.status, "synthetic_test")
        self.assertEqual(len(report.observations), 1)
        self.assertIn(
            report.observations[0]["rule_id"],
            ("RULE-INFRA-SYNTHETIC-BYPASS", "RULE-ORIGIN-SYNTHETIC-IP"),
        )

    def test_synthetic_ip_strict_zero_socket_and_urllib_calls(self) -> None:
        """Strict counter ensuring socket/urllib never called for test IPs."""
        network_calls: list[str] = []

        def fail_socket(*args: Any, **kwargs: Any) -> Any:
            network_calls.append("socket")
            raise AssertionError("Unexpected socket call for synthetic IP!")

        def fail_urlopen(*args: Any, **kwargs: Any) -> Any:
            network_calls.append("urlopen")
            raise AssertionError("Unexpected urlopen call for synthetic IP!")

        with patch("socket.socket", side_effect=fail_socket), \
             patch("urllib.request.urlopen", side_effect=fail_urlopen):
            report = run_infrastructure_intelligence(
                target_ip="198.51.100.99",
                target_domain="example.com",
            )

        self.assertEqual(len(network_calls), 0)
        self.assertTrue(report.is_documentation_ip)
        self.assertTrue(report.is_synthetic_test)
        self.assertEqual(report.threat_feed.status, "synthetic_test")


# =============================================================================
# 2. Local Threat Feed Matcher Tests
# =============================================================================
class TestLocalThreatFeedMatcher(unittest.TestCase):
    """Validate offline Spamhaus DROP / DROPv6 matching and mock fixture."""

    def test_mock_feed_cidr_match(self) -> None:
        matcher = LocalThreatFeedMatcher(
            extra_cidrs=[(MOCK_FEED_CIDR, "TEST-MOCK-DROP")]
        )
        match = matcher.lookup("198.18.10.50")

        self.assertEqual(match.status, "available")
        self.assertTrue(match.is_listed)
        self.assertEqual(match.matched_cidr, MOCK_FEED_CIDR)
        self.assertEqual(match.feed_name, "Spamhaus DROP")
        self.assertEqual(
            match.provider_attribution,
            "The Spamhaus Project (Local Public Feed)",
        )
        self.assertFalse(hasattr(match, "reputation_score"))
        self.assertFalse(hasattr(match, "abuse_score"))

    def test_mock_feed_cidr_non_match(self) -> None:
        matcher = LocalThreatFeedMatcher(
            extra_cidrs=[(MOCK_FEED_CIDR, "TEST-MOCK-DROP")]
        )
        match = matcher.lookup("198.18.11.1")

        self.assertEqual(match.status, "available")
        self.assertFalse(match.is_listed)
        self.assertIsNone(match.matched_cidr)

    def test_feed_missing_returns_unavailable_not_clean(self) -> None:
        """Missing feed files must yield unavailable without clean infer."""
        matcher = LocalThreatFeedMatcher(
            drop_v4_path="nonexistent_v4.txt",
            drop_v6_path="nonexistent_v6.txt",
        )
        match = matcher.lookup("198.18.10.1")
        self.assertEqual(match.status, "unavailable")
        self.assertFalse(match.is_listed)


# =============================================================================
# 3. Passive DNS Tests
# =============================================================================
class TestPassiveDns(unittest.TestCase):
    """Validate RFC 1035 UDP queries for A, AAAA, CNAME, NS, TXT, SPF."""

    @patch("enrichment.infrastructure_intelligence.passive_dns._query_dns_udp")
    def test_passive_dns_record_extraction(
        self, mock_query: MagicMock
    ) -> None:
        def side_effect(
            qname: str, qtype: int, *args: Any, **kwargs: Any
        ) -> tuple[str, list[Any]]:
            if qtype == 1:  # A
                return "available", ["93.184.216.34"]
            elif qtype == 28:  # AAAA
                return "available", ["2606:2800:220:1:248:1893:25c8:1946"]
            elif qtype == 5:  # CNAME
                return "available", ["alias.example.com"]
            elif qtype == 2:  # NS
                return "available", ["ns1.example.com", "ns2.example.com"]
            elif qtype == 16:  # TXT
                if "_dmarc" in qname:
                    return (
                        "available",
                        ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
                    )
                return (
                    "available",
                    [
                        "v=spf1 include:_spf.example.com ~all",
                        "other_txt=123",
                    ],
                )
            return "not_found", []

        mock_query.side_effect = side_effect

        dns_data = resolve_passive_dns("example.com")
        self.assertEqual(dns_data.status, "available")
        self.assertIn("93.184.216.34", dns_data.a_records)
        self.assertIn(
            "2606:2800:220:1:248:1893:25c8:1946", dns_data.aaaa_records
        )
        self.assertIn("alias.example.com", dns_data.cname_records)
        self.assertIn("ns1.example.com", dns_data.ns_records)
        self.assertEqual(
            dns_data.spf_record, "v=spf1 include:_spf.example.com ~all"
        )
        self.assertEqual(
            dns_data.dmarc_record,
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        )

    @patch("enrichment.infrastructure_intelligence.passive_dns._query_dns_udp")
    def test_passive_dns_nxdomain(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("not_found", [])
        dns_data = resolve_passive_dns("nxdomain-does-not-exist-123.com")
        self.assertEqual(dns_data.status, "not_found")

    @patch("enrichment.infrastructure_intelligence.passive_dns._query_dns_udp")
    def test_passive_dns_timeout(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("unavailable", [])
        dns_data = resolve_passive_dns("timeout.example.com")
        self.assertEqual(dns_data.status, "unavailable")


# =============================================================================
# 4. MX Record Resolution Tests
# =============================================================================
class TestMxRecords(unittest.TestCase):
    """Validate MX resolution and neutral provider classification."""

    @patch("enrichment.infrastructure_intelligence.passive_dns._query_dns_udp")
    def test_mx_google_classification(self, mock_query: MagicMock) -> None:
        mock_query.return_value = (
            "available",
            [
                {"host": "aspmx.l.google.com", "preference": 1},
                {"host": "alt1.aspmx.l.google.com", "preference": 5},
            ],
        )
        mx_data = resolve_mx_records("example.com")
        self.assertEqual(mx_data.status, "available")
        self.assertEqual(mx_data.primary_provider, "google_workspace")
        self.assertEqual(len(mx_data.records), 2)
        self.assertEqual(mx_data.records[0]["preference"], 1)

    @patch("enrichment.infrastructure_intelligence.passive_dns._query_dns_udp")
    def test_mx_microsoft_classification(self, mock_query: MagicMock) -> None:
        mock_query.return_value = (
            "available",
            [
                {
                    "host": "example-com.mail.protection.outlook.com",
                    "preference": 10,
                }
            ],
        )
        mx_data = resolve_mx_records("example.com")
        self.assertEqual(mx_data.status, "available")
        self.assertEqual(mx_data.primary_provider, "microsoft_365")

    @patch("enrichment.infrastructure_intelligence.passive_dns._query_dns_udp")
    def test_mx_rfc7505_null_mx(self, mock_query: MagicMock) -> None:
        """RFC 7505 Null MX: preference=0, host='' represents no-mail."""
        mock_query.return_value = (
            "available",
            [{"host": "", "preference": 0}],
        )
        mx_data = resolve_mx_records("example.com")
        self.assertEqual(mx_data.status, "available")
        self.assertTrue(mx_data.is_null_mx)
        self.assertEqual(mx_data.mx_status, "null_mx")
        self.assertEqual(mx_data.primary_provider, "null_mx")
        self.assertNotEqual(mx_data.primary_provider, "malicious")

    @patch("enrichment.infrastructure_intelligence.passive_dns._query_dns_udp")
    def test_mx_no_mx_distinction(self, mock_query: MagicMock) -> None:
        """Distinguish clean domain with no MX from Null MX and failures."""
        mock_query.return_value = ("not_found", [])
        mx_data = resolve_mx_records("no-mx-domain.example.com")
        self.assertEqual(mx_data.status, "not_found")
        self.assertFalse(mx_data.is_null_mx)
        self.assertEqual(mx_data.mx_status, "no_mx")
        self.assertEqual(mx_data.primary_provider, "none")

    @patch("enrichment.infrastructure_intelligence.passive_dns._query_dns_udp")
    def test_mx_failure(self, mock_query: MagicMock) -> None:
        mock_query.return_value = ("unavailable", [])
        mx_data = resolve_mx_records("example.com")
        self.assertEqual(mx_data.status, "unavailable")
        self.assertEqual(mx_data.mx_status, "unavailable")


# =============================================================================
# 5. Reverse DNS and FCrDNS Verification Tests
# =============================================================================
class TestReverseDns(unittest.TestCase):
    """Validate PTR resolution, FCrDNS matching, and mismatch generation."""

    @patch("socket.getaddrinfo")
    @patch("socket.gethostbyaddr")
    def test_fcrdns_valid_match(
        self, mock_ptr: MagicMock, mock_fwd: MagicMock
    ) -> None:
        mock_ptr.return_value = ("mail.example.com", [], ["8.8.8.8"])
        mock_fwd.return_value = [(2, 1, 6, "", ("8.8.8.8", 0))]

        rdns_data, observations = resolve_reverse_dns(
            "8.8.8.8", helo_name="mail.example.com"
        )
        self.assertEqual(rdns_data.status, "available")
        self.assertTrue(rdns_data.fcrdns_valid)
        self.assertTrue(rdns_data.helo_ptr_match)
        self.assertEqual(len(observations), 0)

    @patch("socket.getaddrinfo")
    @patch("socket.gethostbyaddr")
    def test_fcrdns_mismatch_creates_contextual_observation(
        self, mock_ptr: MagicMock, mock_fwd: MagicMock
    ) -> None:
        mock_ptr.return_value = ("claimed-host.example.com", [], ["1.2.3.4"])
        mock_fwd.return_value = [(2, 1, 6, "", ("5.6.7.8", 0))]

        rdns_data, observations = resolve_reverse_dns(
            "1.2.3.4", helo_name="unrelated.com"
        )
        self.assertEqual(rdns_data.status, "available")
        self.assertFalse(rdns_data.fcrdns_valid)
        self.assertFalse(rdns_data.helo_ptr_match)
        self.assertEqual(len(observations), 1)
        obs = observations[0]
        self.assertEqual(obs["rule_id"], "RULE-ORIGIN-FCRDNS-MISMATCH")
        self.assertEqual(obs["severity"], "medium")
        self.assertEqual(obs["trust_state"], "observed")
        self.assertIn("not proof of spoofing", obs["description"].lower())


# =============================================================================
# 6. RDAP Client Tests (RFC 9082/9083/9224)
# =============================================================================
class TestRdapClient(unittest.TestCase):
    """Validate RDAP IP/domain separation, error, and redacted handling."""

    @patch.object(RdapClient, "_fetch_rdap_json")
    def test_rdap_ip_parsing_separation(self, mock_fetch: MagicMock) -> None:
        """IP RDAP response must populate network fields not registrar."""
        mock_fetch.return_value = (
            "available",
            {
                "handle": "NET-8-8-8-0-1",
                "name": "GOGL",
                "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "2014-03-14T00:00:00Z",
                    }
                ],
                "entities": [
                    {
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [
                                ["version", {}, "text", "4.0"],
                                ["email", {}, "text", "abuse@google.com"],
                            ],
                        ],
                    }
                ],
            },
            None,
        )

        client = RdapClient(timeout=2.0)
        data = client.lookup_ip("8.8.8.8")

        self.assertEqual(data.status, "available")
        self.assertEqual(data.query_type, "ip")
        self.assertEqual(data.network_name, "GOGL")
        self.assertEqual(data.cidr, "8.8.8.0/24")
        self.assertEqual(data.handle, "NET-8-8-8-0-1")
        self.assertEqual(data.abuse_contact_email, "abuse@google.com")
        self.assertEqual(data.creation_date, "2014-03-14T00:00:00Z")
        self.assertIsNone(data.registrar)
        self.assertIsNone(data.registrar_id)
        self.assertEqual(data.nameservers, [])

    @patch.object(RdapClient, "_fetch_rdap_json")
    def test_rdap_domain_parsing_separation(
        self, mock_fetch: MagicMock
    ) -> None:
        """Domain RDAP response must populate registrar fields not network."""
        mock_fetch.return_value = (
            "available",
            {
                "ldhName": "example.com",
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "1995-08-14T04:00:00Z",
                    },
                    {
                        "eventAction": "expiration",
                        "eventDate": "2028-08-13T04:00:00Z",
                    },
                ],
                "nameservers": [
                    {"ldhName": "a.iana-servers.net"},
                    {"ldhName": "b.iana-servers.net"},
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "publicIds": [
                            {"type": "IANA Registrar ID", "identifier": "376"}
                        ],
                        "vcardArray": [
                            "vcard",
                            [
                                ["version", {}, "text", "4.0"],
                                [
                                    "fn",
                                    {},
                                    "text",
                                    "Reserved Domain Registry",
                                ],
                            ],
                        ],
                    }
                ],
            },
            None,
        )

        client = RdapClient(timeout=2.0)
        data = client.lookup_domain("example.com")

        self.assertEqual(data.status, "available")
        self.assertEqual(data.query_type, "domain")
        self.assertEqual(data.registrar, "Reserved Domain Registry")
        self.assertEqual(data.registrar_id, "376")
        self.assertEqual(data.creation_date, "1995-08-14T04:00:00Z")
        self.assertEqual(data.expiration_date, "2028-08-13T04:00:00Z")
        self.assertIsNotNone(data.domain_age_days)
        self.assertTrue(
            data.domain_age_days is not None and data.domain_age_days > 10000
        )
        self.assertIn("a.iana-servers.net", data.nameservers)
        self.assertIsNone(data.network_name)
        self.assertIsNone(data.cidr)
        self.assertIsNone(data.rir)

    @patch.object(RdapClient, "_fetch_rdap_json")
    def test_rdap_404_handling(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = ("not_found", {}, "HTTP 404: Not Found")
        client = RdapClient(timeout=2.0)
        data = client.lookup_domain("nonexistent-domain-404.com")
        self.assertEqual(data.status, "not_found")

    @patch.object(RdapClient, "_fetch_rdap_json")
    def test_rdap_timeout_handling(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = ("unavailable", {}, "Lookup error: timeout")
        client = RdapClient(timeout=2.0)
        data = client.lookup_ip("1.1.1.1")
        self.assertEqual(data.status, "unavailable")

    def test_iana_bootstrap_discovery_all_rirs_and_domains(self) -> None:
        """Verify dynamic discovery for all 5 RIRs and domain TLDs."""
        client = RdapClient(timeout=2.0)

        # 1. ARIN (e.g. 8.8.8.8)
        arin_eps = client.discover_endpoints_for_ip("8.8.8.8")
        self.assertEqual(arin_eps[0][0], "ARIN")
        self.assertIn("rdap.arin.net", arin_eps[0][1])

        # 2. APNIC (e.g. 1.1.1.1)
        apnic_eps = client.discover_endpoints_for_ip("1.1.1.1")
        self.assertEqual(apnic_eps[0][0], "APNIC")
        self.assertIn("rdap.apnic.net", apnic_eps[0][1])

        # 3. RIPE (e.g. 193.0.0.1)
        ripe_eps = client.discover_endpoints_for_ip("193.0.0.1")
        self.assertEqual(ripe_eps[0][0], "RIPE")
        self.assertIn("rdap.db.ripe.net", ripe_eps[0][1])

        # 4. LACNIC (e.g. 200.0.0.1)
        lacnic_eps = client.discover_endpoints_for_ip("200.0.0.1")
        self.assertEqual(lacnic_eps[0][0], "LACNIC")
        self.assertIn("rdap.lacnic.net", lacnic_eps[0][1])

        # 5. AFRINIC (e.g. 41.0.0.1)
        afrinic_eps = client.discover_endpoints_for_ip("41.0.0.1")
        self.assertEqual(afrinic_eps[0][0], "AFRINIC")
        self.assertIn("rdap.afrinic.net", afrinic_eps[0][1])

        # 6. Domain bootstrap discovery (VeriSign for com/net, PIR for org)
        com_eps = client.discover_endpoints_for_domain("example.com")
        self.assertEqual(com_eps[0][0], "VeriSign")
        self.assertIn("rdap.verisign.com", com_eps[0][1])

        org_eps = client.discover_endpoints_for_domain("example.org")
        self.assertEqual(org_eps[0][0], "PIR")
        self.assertIn("publicinterestregistry.org", org_eps[0][1])


# =============================================================================
# 7. Neutral Hosting Classification Tests
# =============================================================================
class TestHostingClassification(unittest.TestCase):
    """Validate objective classification into neutral roles."""

    def test_cloud_classification(self) -> None:
        hp = classify_hosting(
            asn_str="AS16509",
            org_name="Amazon.com, Inc.",
            rdap_network_name="AMAZON-CF",
        )
        self.assertEqual(hp.classification, "cloud_infrastructure")
        self.assertIn("AWS", hp.provider_name or "")
        self.assertFalse(hp.is_bulletproof_reported)

    def test_vps_classification(self) -> None:
        hp = classify_hosting(
            asn_str="AS24940", org_name="Hetzner Online GmbH"
        )
        self.assertEqual(hp.classification, "vps_infrastructure")
        self.assertIn("Hetzner", hp.provider_name or "")

    def test_enterprise_mail_classification(self) -> None:
        hp = classify_hosting(
            org_name="Microsoft Corporation",
            ptr_hosts=["mail-protection.outlook.com"],
        )
        self.assertEqual(hp.classification, "enterprise_mail_infrastructure")

    def test_unknown_classification(self) -> None:
        hp = classify_hosting(asn_str="AS99999", org_name="Generic Small ISP")
        self.assertEqual(hp.classification, "unknown")

    def test_explicit_bulletproof_registry_match(self) -> None:
        hp = classify_hosting(asn_str="AS210558", org_name="Biterika LLC")
        self.assertEqual(
            hp.classification, "reported_bulletproof_infrastructure"
        )
        self.assertTrue(hp.is_bulletproof_reported)
        self.assertIsNotNone(hp.bulletproof_source)

    def test_drop_match_alone_does_not_imply_bulletproof(self) -> None:
        """Spamhaus DROP match alone MUST NOT classify as bulletproof."""
        threat_match = ThreatFeedMatch(
            status="available",
            is_listed=True,
            feed_name="Spamhaus DROP",
            matched_cidr="198.18.10.0/24",
        )
        hp = classify_hosting(
            asn_str="AS12345",
            org_name="Generic Host",
            threat_match=threat_match,
        )
        self.assertNotEqual(
            hp.classification, "reported_bulletproof_infrastructure"
        )
        self.assertFalse(hp.is_bulletproof_reported)

    def test_google_public_dns_primary(self) -> None:
        """A. 8.8.8.8 must be public_dns_infrastructure, NOT mail."""
        hp = classify_hosting(
            asn_str="AS15169",
            org_name="Google LLC",
            ptr_hosts=["dns.google"],
            ip_str="8.8.8.8",
        )
        self.assertEqual(hp.provider_name, "Google")
        self.assertEqual(hp.provider, "Google")
        self.assertEqual(hp.classification, "public_dns_infrastructure")
        self.assertEqual(
            hp.infrastructure_role, "public_dns_infrastructure"
        )
        self.assertNotEqual(
            hp.infrastructure_role, "enterprise_mail_infrastructure"
        )
        self.assertNotEqual(
            hp.classification, "enterprise_mail_infrastructure"
        )

    def test_google_public_dns_secondary(self) -> None:
        """B. 8.8.4.4 must be public_dns_infrastructure."""
        hp = classify_hosting(
            asn_str="AS15169",
            org_name="Google LLC",
            ptr_hosts=["dns.google"],
            ip_str="8.8.4.4",
        )
        self.assertEqual(hp.provider_name, "Google")
        self.assertEqual(
            hp.infrastructure_role, "public_dns_infrastructure"
        )

    def test_google_workspace_mail_infrastructure(self) -> None:
        """C. Legitimate Google Workspace MX is enterprise_mail."""
        hp = classify_hosting(
            asn_str="AS15169",
            org_name="Google LLC",
            ptr_hosts=["aspmx.l.google.com"],
        )
        self.assertEqual(hp.provider_name, "Google")
        self.assertEqual(
            hp.infrastructure_role, "enterprise_mail_infrastructure"
        )
        self.assertEqual(
            hp.classification, "enterprise_mail_infrastructure"
        )

    def test_provider_vs_role_separation(self) -> None:
        """D. Provider Google does not auto-infer mail infrastructure."""
        hp = classify_hosting(
            asn_str="AS15169",
            org_name="Google LLC",
        )
        self.assertEqual(hp.provider_name, "Google")
        self.assertNotEqual(
            hp.infrastructure_role, "enterprise_mail_infrastructure"
        )
        self.assertNotEqual(
            hp.classification, "enterprise_mail_infrastructure"
        )

    def test_iana_example_com_neutral_role(self) -> None:
        """E. IANA / example.com infrastructure is neutral unknown."""
        hp = classify_hosting(
            org_name="RESERVED-Internet Assigned Numbers Authority",
            rdap_network_name="IANA",
        )
        self.assertEqual(hp.infrastructure_role, "unknown")
        self.assertEqual(hp.classification, "unknown")
        self.assertNotEqual(
            hp.infrastructure_role, "enterprise_mail_infrastructure"
        )
        self.assertNotEqual(
            hp.infrastructure_role, "commercial_hosting"
        )


# =============================================================================
# 8. Trust Semantics and Provenance Tests
# =============================================================================
class TestTrustSemanticsAndProvenance(unittest.TestCase):
    """Verify trust state assignment ('observed' vs 'inferred')."""

    def test_normalizer_trust_states_and_provenance(self) -> None:
        normalizer = EvidenceNormalizer(case_id="CASE-TRUST-001")
        mock_report = InfrastructureIntelligenceReport(
            target_ip="198.18.10.50",
            target_domain="test.example.com",
            threat_feed=ThreatFeedMatch(
                status="available",
                is_listed=True,
                feed_name="Spamhaus DROP",
                matched_cidr=MOCK_FEED_CIDR,
                download_timestamp="2026-09-01T00:00:00Z",
                source_url="https://www.spamhaus.org/drop/drop.txt",
            ),
            reverse_dns=ReverseDnsData(
                status="available",
                ptr_hostnames=["mismatch.com"],
                fcrdns_valid=False,
                forward_ips=["1.1.1.1"],
                lookup_timestamp="2026-09-01T00:00:00Z",
            ),
            rdap=RdapRegistrationData(
                status="available",
                query="test.example.com",
                domain_age_days=10,
                creation_date="2026-08-22T00:00:00Z",
                lookup_timestamp="2026-09-01T00:00:00Z",
            ),
            hosting_fingerprint=HostingFingerprintData(
                classification="cloud_infrastructure",
                provider_name="AWS",
                evidence_basis=["Matches hyperscale cloud"],
                lookup_timestamp="2026-09-01T00:00:00Z",
            ),
        )

        evidence_list = normalizer.normalize_all(
            infrastructure_intelligence_report=mock_report
        )

        # Check Threat Feed evidence
        drop_ev = next(
            e for e in evidence_list if e.rule_id == "RULE-ORIGIN-DROP-MATCH"
        )
        self.assertEqual(drop_ev.trust_state, "observed")
        self.assertEqual(
            drop_ev.source_module, "infrastructure_intelligence"
        )
        self.assertIn("threat_feeds", drop_ev.provenance)

        # Check FCrDNS evidence
        fcrdns_ev = next(
            e for e in evidence_list
            if e.rule_id == "RULE-ORIGIN-FCRDNS-MISMATCH"
        )
        self.assertEqual(fcrdns_ev.trust_state, "observed")
        self.assertEqual(fcrdns_ev.severity, "medium")
        self.assertIn("reverse_dns", fcrdns_ev.provenance)

        # Check Domain Age evidence
        age_ev = next(
            e for e in evidence_list if e.rule_id == "RULE-ORIGIN-DOMAIN-AGE"
        )
        self.assertEqual(age_ev.trust_state, "observed")
        self.assertEqual(age_ev.severity, "low")
        self.assertIn("rdap", age_ev.provenance)

        # Check Hosting classification evidence
        host_ev = next(
            e for e in evidence_list
            if e.rule_id == "RULE-ORIGIN-HOSTING-CLASSIFICATION"
        )
        self.assertEqual(host_ev.trust_state, "inferred")
        self.assertEqual(host_ev.severity, "informational")
        self.assertIn("fingerprinter", host_ev.provenance)


# =============================================================================
# 9. Failure Resilience & Module 6 End-to-End Synthesis
# =============================================================================
class TestFailureResilienceAndModule6Integration(unittest.TestCase):
    """Verify that full pipeline tolerates worker failures."""

    def test_pipeline_with_all_workers_unavailable(self) -> None:
        """Module 6 must return InvestigationCase even when workers fail."""
        analyzer = EvidenceCorrelationAnalyzer()
        unavailable_report = InfrastructureIntelligenceReport(
            target_ip="1.2.3.4",
            target_domain="broken.example.com",
            rdap=RdapRegistrationData(status="unavailable"),
            dns=PassiveDnsData(status="unavailable"),
            mx=MxRecordData(status="unavailable"),
            reverse_dns=ReverseDnsData(status="unavailable"),
            threat_feed=ThreatFeedMatch(status="unavailable"),
            hosting_fingerprint=HostingFingerprintData(
                classification="unknown"
            ),
        )

        case = analyzer.correlate(
            email_id="TEST-FAIL-001",
            infrastructure_intelligence_report=unavailable_report,
        )
        self.assertIsNotNone(case)
        self.assertEqual(case.email_id, "TEST-FAIL-001")
        self.assertIsInstance(case.to_dict(), dict)

    def test_module6_entities_and_relationships_from_infra(self) -> None:
        """Verify registrar, MX, and network graph entities/relationships."""
        analyzer = EvidenceCorrelationAnalyzer()
        mock_report = InfrastructureIntelligenceReport(
            target_ip="8.8.8.8",
            target_domain="example.com",
            rdap=RdapRegistrationData(
                status="available",
                query="example.com",
                registrar="MarkMonitor Inc.",
                registrar_id="292",
                network_name="GOOGLE-NET",
                cidr="8.8.8.0/24",
            ),
            mx=MxRecordData(
                status="available",
                records=[{"host": "aspmx.l.google.com", "preference": 1}],
                primary_provider="google_workspace",
            ),
            reverse_dns=ReverseDnsData(
                status="available",
                ptr_hostnames=["dns.google"],
                fcrdns_valid=True,
            ),
            threat_feed=ThreatFeedMatch(
                status="available",
                is_listed=True,
                feed_name="Spamhaus DROP",
                matched_cidr=MOCK_FEED_CIDR,
            ),
        )

        case = analyzer.correlate(
            email_id="TEST-INFRA-002",
            infrastructure_intelligence_report=mock_report,
        )

        entity_ids = [e.entity_id for e in case.entities]
        has_registrar = any(
            "markmonitor" in eid.lower() for eid in entity_ids
        )
        self.assertTrue(has_registrar)
        self.assertTrue(any("aspmx.l.google.com" in eid for eid in entity_ids))
        self.assertTrue(any("dns.google" in eid for eid in entity_ids))

        rel_types = [r.relationship_type for r in case.relationships]
        self.assertIn("registered_with", rel_types)
        self.assertIn("mx_served_by", rel_types)
        self.assertIn("allocated_in", rel_types)
        self.assertIn("ptr_resolves_to", rel_types)

    def test_correlate_threat_feed_with_auth_failure(self) -> None:
        """Threat feed match + auth failure yields infrastructure_abuse."""
        analyzer = EvidenceCorrelationAnalyzer()

        m1_mock = {
            "entities": [],
            "auth_results": {
                "spf": {"result": "fail", "domain": "spoofed.com"}
            },
        }
        infra_mock = InfrastructureIntelligenceReport(
            target_ip="198.18.10.50",
            threat_feed=ThreatFeedMatch(
                status="available",
                is_listed=True,
                feed_name="Spamhaus DROP",
                matched_cidr=MOCK_FEED_CIDR,
            ),
        )

        case = analyzer.correlate(
            email_id="TEST-ABUSE-001",
            module1_report=m1_mock,
            infrastructure_intelligence_report=infra_mock,
        )

        finding_types = [f.finding_type for f in case.correlated_findings]
        self.assertIn("correlated_infrastructure_abuse", finding_types)

    def test_cloud_and_young_domain_never_produces_malicious_hypothesis(
        self,
    ) -> None:
        """Cloud + young domain ALONE must NEVER produce malicious hyp."""
        analyzer = EvidenceCorrelationAnalyzer()

        infra_mock = InfrastructureIntelligenceReport(
            target_ip="54.239.28.85",
            target_domain="brand-new-cloud-startup.com",
            rdap=RdapRegistrationData(
                status="available",
                query="brand-new-cloud-startup.com",
                domain_age_days=5,
            ),
            hosting_fingerprint=HostingFingerprintData(
                classification="cloud_infrastructure",
                provider_name="Amazon Web Services (AWS)",
            ),
        )

        case = analyzer.correlate(
            email_id="TEST-BENIGN-CLOUD-001",
            infrastructure_intelligence_report=infra_mock,
        )

        for h in case.hypotheses:
            self.assertNotIn(
                h.hypothesis_type,
                (
                    "possible_domain_impersonation",
                    "possible_credential_harvesting",
                    "possible_malware_distribution",
                    "possible_anonymized_infrastructure",
                ),
            )
