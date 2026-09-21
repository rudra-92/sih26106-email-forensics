"""Unit tests for Module 3: Static URL Forensic Analysis.

Tests:
1. Plain-text URL extraction
2. HTML anchor href extraction
3. HTML visible text + href extraction
4. Visible text itself contains a URL (mismatch preservation)
5. Multiple URLs in single message
6. Deduplication while preserving provenance
7. Malformed / non-URL content handling
8. URL normalization (HTTP vs HTTPS, path, query, fragment)
9. Port extraction (default vs non-default)
10. Userinfo extraction and credentials parsing
11. IP-based hostname detection (IPv4 and IPv6)
12. Excessive subdomains detection
13. Length thresholds (URL, hostname, path, query)
14. Percent encoding and nested/double encoding detection
15. Host/userinfo ambiguity spoofing (paypal.com@evil.example)
16. Sensitive path keywords (/login, /verify, /auth, etc.)
17. Open redirect query parameter detection
18. Visible vs actual href mismatch (URL vs URL)
19. Visible text brand vs actual destination mismatch (text vs URL)
20. Module 2 lookalike domain integration on URL hostname
21. Observation provenance (rule IDs, source module, fact types)
22. Graph-ready entities and relationships (contains_url, hosted_on)
23. Tabular ML features extraction
24. Bounded structural assessment
25. Determinism across repeated executions
"""

import unittest

from modules.url_analysis import (
    analyze_urls,
    extract_urls,
    normalize_url,
)


class TestUrlExtraction(unittest.TestCase):
    """Test URL extraction across plain text and HTML formats."""

    def test_plain_text_single_url(self):
        text = "Please login at https://example.com/login to proceed."
        extracted = extract_urls(text)
        self.assertEqual(len(extracted), 1)
        self.assertEqual(extracted[0].actual_url, "https://example.com/login")
        self.assertEqual(extracted[0].source, "plain_text")

    def test_plain_text_multiple_urls(self):
        text = "Visit https://example.com/a and https://example.com/b for details."
        extracted = extract_urls(text)
        self.assertEqual(len(extracted), 2)
        urls = [u.actual_url for u in extracted]
        self.assertIn("https://example.com/a", urls)
        self.assertIn("https://example.com/b", urls)

    def test_plain_text_trailing_punctuation_stripping(self):
        text = "Check this: https://example.com/page. And this: (https://example.com/faq)!"
        extracted = extract_urls(text)
        self.assertEqual(len(extracted), 2)
        self.assertEqual(extracted[0].actual_url, "https://example.com/page")
        self.assertEqual(extracted[1].actual_url, "https://example.com/faq")

    def test_html_anchor_extraction(self):
        html = '<p>Click <a href="https://evil.example/login">here</a> to sign in.</p>'
        extracted = extract_urls(html)
        self.assertEqual(len(extracted), 1)
        self.assertEqual(extracted[0].actual_url, "https://evil.example/login")
        self.assertEqual(extracted[0].source, "html_href")
        self.assertEqual(extracted[0].visible_text, "here")

    def test_html_visible_text_contains_url(self):
        html = '<a href="https://evil.example/login">https://paypal.com/login</a>'
        extracted = extract_urls(html)
        # Should extract the href link and the visible text link
        sources = {u.source: u.actual_url for u in extracted}
        self.assertIn("html_href", sources)
        self.assertEqual(sources["html_href"], "https://evil.example/login")
        self.assertIn("html_visible_text", sources)
        self.assertEqual(sources["html_visible_text"], "https://paypal.com/login")

    def test_duplicate_url_deduplication(self):
        text = "https://example.com https://example.com https://example.com"
        extracted = extract_urls(text)
        self.assertEqual(len(extracted), 1)

    def test_malformed_and_empty_content(self):
        self.assertEqual(extract_urls(""), [])
        self.assertEqual(extract_urls("No links here whatsoever! Just regular text."), [])
        self.assertEqual(extract_urls(None), [])


class TestUrlNormalization(unittest.TestCase):
    """Test URL component decomposition and standardization."""

    def test_standard_https_url(self):
        norm = normalize_url("https://EXAMPLE.COM:443/login?id=123#abc")
        self.assertEqual(norm.scheme, "https")
        self.assertEqual(norm.port, 443)
        self.assertNotIn(":443", norm.normalized_url)  # Default port stripped in canonical URL
        self.assertEqual(norm.path, "/login")
        self.assertEqual(norm.query, "id=123")
        self.assertEqual(norm.query_params, {"id": ["123"]})
        self.assertEqual(norm.fragment, "abc")
        self.assertFalse(norm.is_ip)

    def test_non_default_port(self):
        norm = normalize_url("http://example.com:8080/api")
        self.assertEqual(norm.scheme, "http")
        self.assertEqual(norm.port, 8080)
        self.assertIn(":8080", norm.normalized_url)

    def test_userinfo_extraction(self):
        norm = normalize_url("https://admin:secret@example.com/dashboard")
        self.assertEqual(norm.username, "admin")
        self.assertEqual(norm.password, "secret")
        self.assertEqual(norm.hostname, "example.com")

    def test_missing_scheme_default(self):
        norm = normalize_url("example.com/test")
        self.assertEqual(norm.scheme, "http")
        self.assertEqual(norm.hostname, "example.com")
        self.assertEqual(norm.path, "/test")

    def test_ipv4_address_hostname(self):
        norm = normalize_url("http://192.0.2.10:80/index.html")
        self.assertTrue(norm.is_ip)
        self.assertEqual(norm.hostname, "192.0.2.10")

    def test_ipv6_address_hostname(self):
        norm = normalize_url("http://[2001:db8::1]:8080/index.html")
        self.assertTrue(norm.is_ip)
        self.assertEqual(norm.hostname, "2001:db8::1")


class TestStaticStructuralAnalysis(unittest.TestCase):
    """Test static structural anomaly indicators and obfuscation detection."""

    def test_ip_address_hostname_rule(self):
        report = analyze_urls("http://192.0.2.10/login")
        ip_obs = [o for o in report.observations if o.rule_id == "RULE-URL-IP-HOST"]
        self.assertEqual(len(ip_obs), 1)
        self.assertEqual(ip_obs[0].severity, "high")
        self.assertTrue(report.ml_features[0]["host_is_ip"])

    def test_excessive_subdomains(self):
        report = analyze_urls("https://login.security.verify.account.example.com/auth")
        sub_obs = [o for o in report.observations if o.rule_id == "RULE-URL-EXCESSIVE-SUBDOMAINS"]
        self.assertEqual(len(sub_obs), 1)
        self.assertGreaterEqual(report.ml_features[0]["subdomain_count"], 3)

    def test_non_default_port(self):
        report = analyze_urls("https://example.com:8443/login")
        port_obs = [o for o in report.observations if o.rule_id == "RULE-URL-NON-DEFAULT-PORT"]
        self.assertEqual(len(port_obs), 1)
        self.assertTrue(report.ml_features[0]["non_default_port"])

    def test_excessive_length(self):
        long_url = "https://example.com/" + ("a" * 150)
        report = analyze_urls(long_url)
        len_obs = [o for o in report.observations if o.rule_id == "RULE-URL-EXCESSIVE-LENGTH"]
        self.assertEqual(len(len_obs), 1)
        self.assertGreater(report.ml_features[0]["url_length"], 120)

    def test_percent_encoding_and_nested_encoding(self):
        # Nested encoding e.g. %252F
        report = analyze_urls("https://example.com/test%252Fpayload%20encoded%20string%20here%20extra%20data%20test")
        nested_obs = [o for o in report.observations if o.rule_id == "RULE-URL-NESTED-ENCODING"]
        self.assertEqual(len(nested_obs), 1)
        self.assertEqual(nested_obs[0].severity, "high")

    def test_userinfo_ambiguity_spoofing(self):
        # paypal.com@evil.example
        report = analyze_urls("https://paypal.com@evil.example/login")
        userinfo_obs = [o for o in report.observations if o.rule_id == "RULE-URL-USERINFO-AMBIGUITY"]
        self.assertEqual(len(userinfo_obs), 1)
        self.assertEqual(userinfo_obs[0].severity, "high")
        self.assertTrue(report.ml_features[0]["userinfo_present"])
        self.assertEqual(userinfo_obs[0].evidence["actual_hostname"], "evil.example")

    def test_sensitive_path_keywords(self):
        report = analyze_urls("https://example.com/auth/login/verify")
        path_obs = [o for o in report.observations if o.rule_id == "RULE-URL-SENSITIVE-PATH-KEYWORD"]
        self.assertEqual(len(path_obs), 1)
        self.assertTrue(report.ml_features[0]["login_token_present"])

    def test_open_redirect_parameter(self):
        report = analyze_urls("https://example.com/redirect?url=https://attacker.net/harvest")
        redir_obs = [o for o in report.observations if o.rule_id == "RULE-URL-REDIRECT-PARAMETER"]
        self.assertEqual(len(redir_obs), 1)
        self.assertTrue(report.ml_features[0]["redirect_indicator"])


class TestVisibleHrefMismatch(unittest.TestCase):
    """Test visible destination vs actual href destination mismatch detection."""

    def test_visible_url_mismatch(self):
        html = '<a href="https://paypa1-login.com/auth">https://paypal.com/login</a>'
        report = analyze_urls(html)
        mismatch_obs = [o for o in report.observations if o.rule_id == "RULE-URL-VISIBLE-HREF-MISMATCH"]
        self.assertEqual(len(mismatch_obs), 1)
        self.assertEqual(mismatch_obs[0].severity, "high")
        self.assertEqual(mismatch_obs[0].evidence["visible_hostname"], "paypal.com")
        self.assertEqual(mismatch_obs[0].evidence["actual_hostname"], "paypa1-login.com")
        self.assertTrue(report.ml_features[0]["visible_href_mismatch"])

    def test_brand_text_mismatch(self):
        html = '<a href="https://evil.example/login">Microsoft Login Portal</a>'
        report = analyze_urls(html)
        text_obs = [o for o in report.observations if o.rule_id == "RULE-URL-VISIBLE-TEXT-MISMATCH"]
        self.assertEqual(len(text_obs), 1)
        self.assertEqual(text_obs[0].evidence["visible_text"], "Microsoft Login Portal")


class TestModule2DomainIntegration(unittest.TestCase):
    """Verify URL hostname integrates with Module 2 without duplicating logic."""

    def test_hostname_lookalike_detection(self):
        # paypa1.com resembles paypal.com from Module 2 reference store
        report = analyze_urls("https://paypa1.com/login")
        lookalike_obs = [o for o in report.observations if o.rule_id == "RULE-URL-HOST-LOOKALIKE-CANDIDATE"]
        self.assertEqual(len(lookalike_obs), 1)
        self.assertEqual(lookalike_obs[0].severity, "medium")
        self.assertEqual(lookalike_obs[0].type, "lookalike_hostname_candidate")
        self.assertEqual(lookalike_obs[0].evidence["reference_domain"], "paypal.com")
        self.assertGreaterEqual(lookalike_obs[0].evidence["candidate_score"], 0.80)
        self.assertGreaterEqual(report.ml_features[0]["domain_similarity_score"], 0.80)


class TestGraphEntitiesAndProvenance(unittest.TestCase):
    """Verify graph entity/relationship emission and observation provenance."""

    def test_graph_entities_and_relations(self):
        report = analyze_urls("https://example.com/test", email_id="EML-999")

        # Check Entities: email, url, domain
        ent_types = {e.type: e.value for e in report.entities}
        self.assertIn("email", ent_types)
        self.assertEqual(ent_types["email"], "EML-999")
        self.assertIn("url", ent_types)
        self.assertIn("domain", ent_types)
        self.assertEqual(ent_types["domain"], "example.com")

        # Check Relationships: contains_url, hosted_on
        rel_types = {(r.relation, r.source, r.target) for r in report.relationships}
        self.assertIn(("contains_url", "EML-999", "https://example.com/test"), rel_types)
        self.assertIn(("hosted_on", "https://example.com/test", "example.com"), rel_types)

    def test_observation_provenance(self):
        report = analyze_urls("http://192.0.2.10/login")
        for obs in report.observations:
            self.assertTrue(obs.observation_id.startswith("OBS-URL-"))
            self.assertTrue(obs.rule_id.startswith("RULE-URL-"))
            self.assertEqual(obs.source_module, "url_analysis")
            self.assertIn(obs.fact_type, ("observed", "inferred", "reported"))


class TestMlFeaturesAndDeterminism(unittest.TestCase):
    """Verify ML feature schema completeness and deterministic repeatability."""

    def test_ml_features_schema(self):
        report = analyze_urls("https://example.com/login?id=1")
        self.assertEqual(len(report.ml_features), 1)
        feat = report.ml_features[0]

        required_keys = [
            "url", "url_length", "hostname_length", "path_length", "query_length",
            "subdomain_count", "special_character_count", "percent_encoded_count",
            "host_is_ip", "non_default_port", "userinfo_present", "login_token_present",
            "redirect_indicator", "visible_href_mismatch", "domain_similarity_score"
        ]
        for key in required_keys:
            self.assertIn(key, feat)

    def test_determinism(self):
        content = '<a href="https://paypa1.com@evil.example:8443/login?redirect=true">https://paypal.com/login</a>'
        run1 = analyze_urls(content, email_id="E001")
        run2 = analyze_urls(content, email_id="E001")

        self.assertEqual(run1.assessment.to_dict(), run2.assessment.to_dict())
        self.assertEqual(run1.ml_features, run2.ml_features)
        self.assertEqual(
            [o.to_dict() for o in run1.observations],
            [o.to_dict() for o in run2.observations]
        )

    def test_assessment_count_exact_match(self):
        """Regression test verifying that the count in assessment reason matches observations exactly."""
        content = '<a href="https://paypal.com@evil.example:8443/login?redirect=true">https://paypal.com/login</a>'
        report = analyze_urls(content, email_id="E001")

        high_sev = [o for o in report.observations if o.severity == "high"]
        med_sev = [o for o in report.observations if o.severity == "medium"]

        if high_sev:
            expected_prefix = f"URL structural analysis detected {len(high_sev)} high-severity anomaly indicator(s)"
            self.assertIn(expected_prefix, report.assessment.reason)
            # Verify each included high-severity observation is actually present in the reason
            for obs in high_sev:
                self.assertIn(obs.description, report.assessment.reason)
        elif med_sev:
            expected_prefix = f"URL structural analysis detected {len(med_sev)} moderate-severity anomaly indicator(s)"
            self.assertIn(expected_prefix, report.assessment.reason)
            for obs in med_sev:
                self.assertIn(obs.description, report.assessment.reason)


if __name__ == "__main__":
    unittest.main()
