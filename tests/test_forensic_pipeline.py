"""
test_forensic_pipeline.py - Unit Test Suite for Model 2 Forensic Feature Extraction Pipeline.

Tests all 20 required forensic parser and analyzer components:
1. From/Reply-To mismatch
2. Display-name mismatch
3. Received header parsing
4. IPv4 extraction
5. IPv6 extraction
6. Public/private IP detection
7. SPF parsing
8. DKIM parsing
9. DMARC parsing
10. URL extraction
11. IP-based URL detection
12. Punycode detection
13. Homoglyph/lookalike detection
14. Double-extension detection
15. PE static analysis
16. Office macro analysis
17. PDF active content analysis
18. YARA integration
19. Model 1 probability integration
20. Missing-field handling (NaN preservation)
"""

import os
import sys
import unittest
import numpy as np

# Ensure workspace root in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.forensic.email_parser import ParsedEmail
from ml.forensic.header_analyzer import HeaderAnalyzer
from ml.forensic.auth_analyzer import AuthAnalyzer
from ml.forensic.received_analyzer import ReceivedAnalyzer
from ml.forensic.ip_analyzer import IPAnalyzer
from ml.forensic.url_analyzer import URLAnalyzer
from ml.forensic.domain_analyzer import DomainAnalyzer
from ml.forensic.attachment_analyzer import AttachmentAnalyzer
from ml.forensic.pe_analyzer import PEAnalyzer
from ml.forensic.document_analyzer import DocumentAnalyzer
from ml.forensic.pdf_analyzer import PDFAnalyzer
from ml.forensic.yara_scanner import YaraScanner
from ml.forensic.feature_pipeline import ForensicFeaturePipeline


class TestForensicPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.pipeline = ForensicFeaturePipeline()

    # 1. From / Reply-To Mismatch
    def test_from_replyto_mismatch(self):
        analyzer = HeaderAnalyzer()
        email_obj = ParsedEmail(
            from_header="Alice <alice@company.com>",
            reply_to_header="Evil <attacker@evil.com>"
        )
        feats, ev = analyzer.analyze(email_obj)
        self.assertEqual(feats["from_replyto_mismatch"], 1)
        self.assertEqual(feats["sender_domain_replyto_domain_mismatch"], 1)

    # 2. Display Name Mismatch
    def test_display_name_mismatch(self):
        analyzer = HeaderAnalyzer()
        email_obj = ParsedEmail(
            from_header='"support@paypal.com" <attacker@phishing-server.com>',
            reply_to_header=""
        )
        feats, ev = analyzer.analyze(email_obj)
        self.assertEqual(feats["display_name_email_mismatch"], 1)

    # 3. Received Header Parsing (Hop Chain)
    def test_received_header_parsing(self):
        analyzer = ReceivedAnalyzer()
        email_obj = ParsedEmail(
            received_headers=[
                "from relay.mta.com (relay.mta.com [93.184.216.34]) by mail.victim.com with ESMTP id 123; Tue, 15 Oct 2024 10:05:00 +0000",
                "from origin.host.org (origin.host.org [104.244.42.1]) by relay.mta.com with ESMTP id 456; Tue, 15 Oct 2024 10:00:00 +0000"
            ]
        )
        feats, ev = analyzer.analyze(email_obj)
        self.assertEqual(feats["received_hop_count"], 2)
        self.assertIn("93.184.216.34", ev["all_extracted_ips"])
        self.assertEqual(feats["public_ip_count"], 2)

    # 4. IPv4 Extraction
    def test_ipv4_extraction(self):
        analyzer = IPAnalyzer()
        text = "Contact server at 203.0.113.195 or 10.0.0.1 for details."
        ips = analyzer.extract_ips_from_text(text)
        self.assertIn("203.0.113.195", ips)
        self.assertIn("10.0.0.1", ips)

    # 5. IPv6 Extraction
    def test_ipv6_extraction(self):
        analyzer = IPAnalyzer()
        text = "MTA routed via 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ips = analyzer.extract_ips_from_text(text)
        self.assertIn("2001:db8:85a3::8a2e:370:7334", ips)

    # 6. Public vs Private IP Detection
    def test_public_private_ip_detection(self):
        analyzer = IPAnalyzer()
        email_obj = ParsedEmail(body_plain="Internal: 192.168.1.1, External: 93.184.216.34")
        feats, ev = analyzer.analyze(email_obj)
        self.assertGreaterEqual(feats["private_ip_count"], 1)
        self.assertGreaterEqual(feats["public_ip_count"], 1)

    # 7. SPF Parsing
    def test_spf_parsing(self):
        analyzer = AuthAnalyzer()
        email_obj = ParsedEmail(
            auth_results_headers=["mx.google.com; spf=pass (google.com: domain of user@sender.com designates 192.0.2.1)"]
        )
        feats, ev = analyzer.analyze(email_obj, sender_domain="sender.com")
        self.assertEqual(feats["spf_present"], 1)
        self.assertEqual(feats["spf_pass"], 1)
        self.assertEqual(feats["spf_fail"], 0)

    # 8. DKIM Parsing
    def test_dkim_parsing(self):
        analyzer = AuthAnalyzer()
        email_obj = ParsedEmail(
            auth_results_headers=["mx.google.com; dkim=fail (bad signature) header.d=evil.com"]
        )
        feats, ev = analyzer.analyze(email_obj, sender_domain="target.com")
        self.assertEqual(feats["dkim_present"], 1)
        self.assertEqual(feats["dkim_fail"], 1)
        self.assertEqual(feats["dkim_pass"], 0)

    # 9. DMARC Parsing
    def test_dmarc_parsing(self):
        analyzer = AuthAnalyzer()
        email_obj = ParsedEmail(
            auth_results_headers=["mx.google.com; dmarc=fail (p=reject action=reject) header.from=brand.com"]
        )
        feats, ev = analyzer.analyze(email_obj, sender_domain="brand.com")
        self.assertEqual(feats["dmarc_present"], 1)
        self.assertEqual(feats["dmarc_fail"], 1)
        self.assertEqual(feats["dmarc_policy_reject"], 1)

    # 10. URL Extraction
    def test_url_extraction(self):
        analyzer = URLAnalyzer()
        text = "Visit https://secure.bank.com/login and http://update.portal.org/home"
        urls = analyzer.extract_urls(text_plain=text)
        self.assertEqual(len(urls), 2)
        self.assertIn("https://secure.bank.com/login", urls)

    # 11. IP-based URL Detection
    def test_ip_based_url_detection(self):
        analyzer = URLAnalyzer()
        feats, ev = analyzer.analyze(text_plain="Click here: http://198.51.100.42:8080/session/verify")
        self.assertEqual(feats["ip_based_url_count"], 1)
        self.assertEqual(feats["has_ip_as_hostname"], 1)
        self.assertEqual(feats["url_with_port_count"], 1)

    # 12. Punycode Detection
    def test_punycode_detection(self):
        analyzer = DomainAnalyzer()
        metrics = analyzer.extract_domain_metrics("xn--pypal-4ve.com")
        self.assertEqual(metrics["punycode_flag"], 1)

    # 13. Homoglyph and Lookalike Domain Detection
    def test_homoglyph_lookalike_detection(self):
        analyzer = DomainAnalyzer()
        # "paypa1.com" substitutes '1' for 'l'
        feats, ev = analyzer.analyze(sender_domain="paypa1.com")
        self.assertEqual(feats["lookalike_domain_candidate"], 1)
        self.assertLessEqual(feats["target_domain_min_distance_ratio"], 0.25)

    # 14. Double Extension Detection
    def test_double_extension_detection(self):
        analyzer = AttachmentAnalyzer()
        att = {"filename": "invoice_october.pdf.exe", "content_bytes": b"MZ\x00\x00test", "mime_type": "application/octet-stream"}
        feats, ev = analyzer.analyze_single_attachment(att)
        self.assertEqual(feats["double_extension"], 1)
        self.assertEqual(feats["executable_extension"], 1)

    # 15. PE Static Analysis
    def test_pe_static_analysis(self):
        analyzer = PEAnalyzer()
        pe_bytes = bytearray(512)
        pe_bytes[0:2] = b"MZ"
        pe_bytes[0x3C:0x40] = (0x80).to_bytes(4, byteorder="little")
        pe_bytes[0x80:0x84] = b"PE\x00\x00"
        pe_bytes[0x84:0x86] = (0x014C).to_bytes(2, byteorder="little")
        pe_bytes[0x86:0x88] = (1).to_bytes(2, byteorder="little")
        feats, ev = analyzer.analyze_bytes(bytes(pe_bytes))
        self.assertEqual(feats["is_pe"], 1)

    # 16. Office Macro Analysis
    def test_office_macro_analysis(self):
        analyzer = DocumentAnalyzer()
        data = b"\xd0\xcf\x11\xe0" + b"\x00" * 500 + b"Sub AutoOpen()\n  Shell(\"calc.exe\")\nEnd Sub"
        feats, ev = analyzer.analyze_bytes("test_macro.docm", data)
        self.assertEqual(feats["has_macro"], 1)
        self.assertEqual(feats["suspicious_macro_indicator"], 1)

    # 17. PDF Active Content Analysis
    def test_pdf_analysis(self):
        analyzer = PDFAnalyzer()
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R /JavaScript 3 0 R >>\nendobj\n%%EOF"
        feats, ev = analyzer.analyze_bytes(pdf_bytes)
        self.assertEqual(feats["pdf_has_javascript"], 1)
        self.assertEqual(feats["pdf_has_openaction"], 1)

    # 18. YARA Scanner Integration
    def test_yara_scanner(self):
        scanner = YaraScanner()
        # Test scan on PE stub
        pe_stub = b"MZ" + b"\x00" * 126 + b"PE\x00\x00"
        feats, ev = scanner.scan_bytes(pe_stub)
        self.assertIn("yara_match_count", feats)
        self.assertIsInstance(ev.get("yara_rule_names"), list)

    # 19. Model 1 Probability Integration (Real Model Artifact)
    def test_model1_probability_integration(self):
        m1_lr = "ml/models/model1d_word_char_filtered_lr.joblib"
        m1_vec = "ml/models/model1d_word_char_filtered_vectorizer.joblib"
        if not (os.path.exists(m1_lr) and os.path.exists(m1_vec)):
            self.skipTest("Model 1 artifacts not present; skipping real-model inference test.")

        probs = self.pipeline.predict_model1_probabilities("URGENT: Verify your PayPal account password now!")
        self.assertIn("nlp_prob_legitimate", probs)
        self.assertIn("nlp_prob_phishing", probs)
        self.assertIn("nlp_prob_fraud", probs)
        self.assertIn("nlp_prob_spam", probs)
        # Should sum approximately to 1.0 (for 3 classes)
        total_prob = probs["nlp_prob_legitimate"] + probs["nlp_prob_phishing"] + probs["nlp_prob_fraud"]
        self.assertAlmostEqual(total_prob, 1.0, delta=0.05)

    def test_model1_uninitialized_default_probabilities(self):
        """When Model 1 artifacts are absent, pipeline must return explicit default NaN state."""
        if self.pipeline.model1_model is None or self.pipeline.model1_vectorizer is None:
            probs = self.pipeline.predict_model1_probabilities("Any test message")
            self.assertTrue(np.isnan(probs["nlp_prob_legitimate"]))
            self.assertTrue(np.isnan(probs["nlp_prob_phishing"]))
            self.assertTrue(np.isnan(probs["nlp_prob_fraud"]))
            self.assertEqual(probs["nlp_prob_spam"], 0.0)

    def test_model1_probability_output_mapping_with_stub(self):
        """Verify probability output mapping contract using an in-memory test stub."""
        from unittest.mock import MagicMock
        stub_pipeline = ForensicFeaturePipeline()
        mock_model = MagicMock()
        mock_model.classes_ = np.array(["fraud_related", "legitimate", "phishing", "spam"])
        mock_model.predict_proba.return_value = np.array([[0.10, 0.20, 0.65, 0.05]])
        mock_vectorizer = MagicMock()
        mock_vectorizer.transform.return_value = [[1, 2, 3]]

        stub_pipeline.model1_model = mock_model
        stub_pipeline.model1_vectorizer = mock_vectorizer
        stub_pipeline.model1_classes = list(mock_model.classes_)

        probs = stub_pipeline.predict_model1_probabilities("URGENT: Verify password")
        self.assertEqual(probs["nlp_prob_fraud"], 0.10)
        self.assertEqual(probs["nlp_prob_legitimate"], 0.20)
        self.assertEqual(probs["nlp_prob_phishing"], 0.65)
        self.assertEqual(probs["nlp_prob_spam"], 0.05)
        total_prob = probs["nlp_prob_legitimate"] + probs["nlp_prob_phishing"] + probs["nlp_prob_fraud"]
        self.assertAlmostEqual(total_prob, 0.95, delta=0.01)

    # 20. Missing Field Handling (NaN Preservation)
    def test_missing_field_handling(self):
        raw_email = {"subject": "Hello", "body": "Plain message without headers"}
        feats, ev = self.pipeline.extract_features(raw_email)
        # Verify missing headers do not fabricate false values
        self.assertTrue(np.isnan(feats["from_replyto_mismatch"]))
        self.assertTrue(np.isnan(feats["spf_alignment_issue"]))
        self.assertEqual(feats["spf_present"], 0)
        self.assertEqual(feats["spf_fail"], 0)  # Absence != failure!


if __name__ == "__main__":
    unittest.main()
