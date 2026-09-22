"""Unit tests for Module 2 Layer 1: Lookalike domain normalization and reference store.

Tests:
- Basic domain canonicalization (casing, whitespace, trailing root dots)
- Subdomain preservation without lossy reduction
- Safe failure on malformed/invalid inputs
- IDN/Unicode Punycode conversion and deterministic representations
- Reference domains loading, deduplication, sorting, and error handling
- Module 1 forensic Entity integration
- Graph edge generation (compared_with)
"""

import json
import os
import tempfile
import unittest

from modules.lookalike_domain import (
    DomainNormalizationError,
    create_domain_comparison_edge,
    load_reference_domains,
    normalize_domain,
)
from modules.sender_identity.models import Entity


class TestDomainNormalizationBasic(unittest.TestCase):
    """Test standard normalization rules."""

    def test_uppercase_domain(self):
        result = normalize_domain("PAYPAL.COM")
        self.assertEqual(result.normalized, "paypal.com")
        self.assertEqual(result.original, "PAYPAL.COM")
        self.assertEqual(result.ascii_form, "paypal.com")
        self.assertEqual(result.unicode_form, "paypal.com")

    def test_mixed_case_domain(self):
        result = normalize_domain("Paypal.Com")
        self.assertEqual(result.normalized, "paypal.com")
        self.assertEqual(result.original, "Paypal.Com")

    def test_trailing_root_dot(self):
        result = normalize_domain("paypal.com.")
        self.assertEqual(result.normalized, "paypal.com")
        self.assertEqual(result.original, "paypal.com.")

    def test_surrounding_whitespace(self):
        result = normalize_domain(" paypal.com ")
        self.assertEqual(result.normalized, "paypal.com")
        self.assertEqual(result.original, " paypal.com ")

    def test_combined_whitespace_casing_trailing_dot(self):
        result = normalize_domain("  PAYPAL.COM.  ")
        self.assertEqual(result.normalized, "paypal.com")


class TestSubdomainPreservation(unittest.TestCase):
    """Verify that subdomains are preserved and not collapsed to parent domains."""

    def test_single_subdomain(self):
        result = normalize_domain("login.paypal.com")
        self.assertEqual(result.normalized, "login.paypal.com")
        self.assertEqual(result.labels, ("login", "paypal", "com"))
        # Ensure it does NOT collapse to paypal.com
        self.assertNotEqual(result.normalized, "paypal.com")

    def test_nested_subdomain(self):
        result = normalize_domain("secure.login.paypal.com")
        self.assertEqual(result.normalized, "secure.login.paypal.com")
        self.assertEqual(result.labels, ("secure", "login", "paypal", "com"))

    def test_subdomain_with_mixed_case_and_root_dot(self):
        result = normalize_domain("Login.PayPal.Com.")
        self.assertEqual(result.normalized, "login.paypal.com")
        self.assertEqual(result.labels, ("login", "paypal", "com"))


class TestInvalidInputHandling(unittest.TestCase):
    """Verify that malformed or invalid inputs fail safely and predictably."""

    def test_empty_string(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("")

    def test_whitespace_only(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("   ")

    def test_none_input(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain(None)

    def test_url_scheme_http(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("http://paypal.com")

    def test_url_with_path(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("paypal.com/login")

    def test_email_address_format(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("user@paypal.com")

    def test_port_number(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("paypal.com:443")

    def test_spaces_inside_domain(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("paypal com")

    def test_leading_dot(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain(".paypal.com")

    def test_consecutive_dots(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("paypal..com")

    def test_single_dot(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain(".")

    def test_single_label_domain(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("paypal")

    def test_hyphen_at_start_of_label(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("-paypal.com")

    def test_hyphen_at_end_of_label(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("paypal-.com")

    def test_all_numeric_tld(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain("paypal.123")

    def test_unsupported_type(self):
        with self.assertRaises(DomainNormalizationError):
            normalize_domain(12345)


class TestIDNUnicodeHandling(unittest.TestCase):
    """Test deterministic handling of internationalized domain names (IDN)."""

    def test_unicode_domain_conversion(self):
        result = normalize_domain("bücher.de")
        self.assertEqual(result.ascii_form, "xn--bcher-kva.de")
        self.assertEqual(result.unicode_form, "bücher.de")
        self.assertEqual(result.normalized, "xn--bcher-kva.de")
        self.assertTrue(result.is_idn)

    def test_punycode_input_conversion(self):
        result = normalize_domain("xn--bcher-kva.de")
        self.assertEqual(result.ascii_form, "xn--bcher-kva.de")
        self.assertEqual(result.unicode_form, "bücher.de")
        self.assertEqual(result.normalized, "xn--bcher-kva.de")
        self.assertTrue(result.is_idn)

    def test_mixed_case_unicode(self):
        result = normalize_domain("Bücher.DE.")
        self.assertEqual(result.ascii_form, "xn--bcher-kva.de")
        self.assertEqual(result.unicode_form, "bücher.de")
        self.assertEqual(result.normalized, "xn--bcher-kva.de")

    def test_ascii_is_not_flagged_as_idn(self):
        result = normalize_domain("paypal.com")
        self.assertFalse(result.is_idn)
        self.assertEqual(result.ascii_form, "paypal.com")
        self.assertEqual(result.unicode_form, "paypal.com")

    def test_non_malicious_representation(self):
        # Verify that IDN processing only normalizes representation without
        # attributing malicious intent or similarity scores.
        result = normalize_domain("münchen.de")
        as_dict = result.to_dict()
        self.assertIn("normalized", as_dict)
        self.assertIn("ascii_form", as_dict)
        self.assertIn("unicode_form", as_dict)
        self.assertNotIn("is_malicious", as_dict)
        self.assertNotIn("similarity_score", as_dict)


class TestReferenceDomains(unittest.TestCase):
    """Test loading, normalization, deduplication, and error modes for reference domains."""

    def test_load_default_reference_domains(self):
        domains = load_reference_domains()
        self.assertIsInstance(domains, list)
        self.assertGreaterEqual(len(domains), 4)
        normalized_names = [d.normalized for d in domains]
        self.assertIn("paypal.com", normalized_names)
        self.assertIn("microsoft.com", normalized_names)
        self.assertIn("google.com", normalized_names)
        self.assertIn("amazon.com", normalized_names)
        self.assertNotIn("example.com", normalized_names)

    def test_deterministic_sorting(self):
        domains = load_reference_domains()
        normalized_names = [d.normalized for d in domains]
        self.assertEqual(normalized_names, sorted(normalized_names))

    def test_deduplication_and_normalization_on_custom_file(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            json.dump({
                "trusted_domains": [
                    "PAYPAL.COM",
                    "paypal.com.",
                    " paypal.com ",
                    "google.com",
                    "Apple.Com",
                ]
            }, tf)
            temp_path = tf.name

        try:
            domains = load_reference_domains(temp_path)
            normalized_names = [d.normalized for d in domains]
            # Should deduplicate paypal.com and sort deterministically
            self.assertEqual(normalized_names, ["apple.com", "google.com", "paypal.com"])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_invalid_reference_entry_raise_mode(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            json.dump({
                "trusted_domains": [
                    "valid.com",
                    "invalid..com",
                ]
            }, tf)
            temp_path = tf.name

        try:
            with self.assertRaises(DomainNormalizationError):
                load_reference_domains(temp_path, on_error="raise")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_invalid_reference_entry_skip_mode(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            json.dump({
                "trusted_domains": [
                    "valid.com",
                    "invalid..com",
                    "another-valid.org",
                ]
            }, tf)
            temp_path = tf.name

        try:
            domains = load_reference_domains(temp_path, on_error="skip")
            normalized_names = [d.normalized for d in domains]
            self.assertEqual(normalized_names, ["another-valid.org", "valid.com"])
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_missing_reference_file(self):
        with self.assertRaises(FileNotFoundError):
            load_reference_domains("non_existent_reference_file_12345.json")

    def test_malformed_json_reference_file(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json") as tf:
            tf.write("NOT_VALID_JSON{")
            temp_path = tf.name

        try:
            with self.assertRaises(ValueError):
                load_reference_domains(temp_path)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestModule1EntityIntegration(unittest.TestCase):
    """Test consuming sender domain entities produced by Module 1."""

    def test_consume_module1_entity(self):
        entity = Entity(
            type="domain",
            value="Login.PayPal.Com.",
            source="From",
            attributes={"role": "sender_domain"},
        )
        result = normalize_domain(entity)
        self.assertEqual(result.normalized, "login.paypal.com")
        self.assertEqual(result.original, "Login.PayPal.Com.")

    def test_reject_non_domain_entity(self):
        entity = Entity(
            type="email_address",
            value="user@paypal.com",
            source="From",
        )
        with self.assertRaises(DomainNormalizationError):
            normalize_domain(entity)

    def test_consume_dict_entity(self):
        entity_dict = {"type": "domain", "value": "MAIL.GOOGLE.COM"}
        result = normalize_domain(entity_dict)
        self.assertEqual(result.normalized, "mail.google.com")


class TestGraphBoundary(unittest.TestCase):
    """Verify graph relationship creation for future lookalike comparison."""

    def test_comparison_edge_structure(self):
        obs = normalize_domain("login.paypal.com")
        ref = normalize_domain("paypal.com")
        edge = create_domain_comparison_edge(obs, ref)

        self.assertEqual(edge["source"], "login.paypal.com")
        self.assertEqual(edge["relation"], "compared_with")
        self.assertEqual(edge["target"], "paypal.com")

        # Explicitly verify that no 'resembles' relationship is created in this layer
        self.assertNotEqual(edge["relation"], "resembles")

    def test_comparison_edge_from_strings(self):
        edge = create_domain_comparison_edge("Login.PayPal.Com.", "PAYPAL.COM")
        self.assertEqual(edge["source"], "login.paypal.com")
        self.assertEqual(edge["relation"], "compared_with")
        self.assertEqual(edge["target"], "paypal.com")


class TestSerialization(unittest.TestCase):
    """Verify serialization to dictionary and string conversion."""

    def test_to_dict_and_str(self):
        norm = normalize_domain("Login.PayPal.Com")
        self.assertEqual(str(norm), "login.paypal.com")
        d = norm.to_dict()
        self.assertEqual(d["original"], "Login.PayPal.Com")
        self.assertEqual(d["normalized"], "login.paypal.com")
        self.assertEqual(d["ascii_form"], "login.paypal.com")
        self.assertEqual(d["unicode_form"], "login.paypal.com")
        self.assertEqual(d["labels"], ["login", "paypal", "com"])
        self.assertFalse(d["is_idn"])
        # Ensure json serializable
        serialized = json.dumps(d)
        self.assertIn("login.paypal.com", serialized)


if __name__ == "__main__":
    unittest.main()
