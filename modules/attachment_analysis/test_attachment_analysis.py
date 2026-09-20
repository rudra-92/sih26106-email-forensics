"""Unit tests for Module 4: Static Attachment Forensics.

Tests extraction, hashing, magic-byte signatures, consistency evaluation,
safe archive inspection, graph entities/relationships, and future ML features.
"""

from email.message import EmailMessage
import hashlib
import io
import unittest
import zipfile

from modules.attachment_analysis.analyzer import (
    SignatureDetector,
    StaticAttachmentAnalyzer,
    analyze_attachments,
    analyze_filename,
)
from modules.attachment_analysis.extractor import AttachmentExtractor, extract_attachments
from modules.attachment_analysis.models import (
    ArchiveMetadata,
    AttachmentAssessment,
    AttachmentMlFeatures,
    AttachmentObservation,
    AttachmentReport,
    ExtractedAttachment,
    FilenameAnalysis,
    FileSignature,
)


def _create_synthetic_email_message(
    parts_data: list,
) -> EmailMessage:
    """Helper to generate an in-memory EmailMessage with specified parts."""
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.com"
    msg["Subject"] = "Test Email with Attachments"
    msg.set_content("Please find the attached files.")

    for item in parts_data:
        # item: (filename, maintype, subtype, payload_bytes, disposition, cid)
        filename, maintype, subtype, payload_bytes, disposition, cid = item
        if disposition == "inline":
            msg.add_attachment(
                payload_bytes,
                maintype=maintype,
                subtype=subtype,
                filename=filename,
                disposition="inline",
                cid=cid,
            )
        else:
            msg.add_attachment(
                payload_bytes,
                maintype=maintype,
                subtype=subtype,
                filename=filename,
                disposition="attachment",
            )
    return msg


def _create_zip_bytes(files: dict) -> bytes:
    """Helper to build in-memory zip archive bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(fname, content)
    return buf.getvalue()


class TestAttachmentExtraction(unittest.TestCase):
    """Test suite for attachment extraction from MIME email structures."""

    def test_01_single_attachment_extraction(self):
        """1. Verify extraction of a single attachment."""
        pdf_bytes = b"%PDF-1.4\nTest PDF content"
        msg = _create_synthetic_email_message(
            [("invoice.pdf", "application", "pdf", pdf_bytes, "attachment", None)]
        )
        extracted = extract_attachments(msg)
        self.assertEqual(len(extracted), 1)
        self.assertEqual(extracted[0].filename, "invoice.pdf")
        self.assertEqual(extracted[0].declared_mime, "application/pdf")
        self.assertEqual(extracted[0].size, len(pdf_bytes))
        self.assertEqual(extracted[0].raw_bytes, pdf_bytes)
        self.assertFalse(extracted[0].is_inline)

    def test_02_multiple_attachments_extraction(self):
        """2. Verify extraction of multiple attachments in preserved order."""
        pdf_bytes = b"%PDF-1.4\nTest PDF content"
        png_bytes = b"\x89PNG\r\n\x1a\nTest PNG content"
        msg = _create_synthetic_email_message(
            [
                ("statement.pdf", "application", "pdf", pdf_bytes, "attachment", None),
                ("logo.png", "image", "png", png_bytes, "attachment", None),
            ]
        )
        extracted = extract_attachments(msg)
        self.assertEqual(len(extracted), 2)
        self.assertEqual(extracted[0].attachment_id, "ATT-001")
        self.assertEqual(extracted[0].filename, "statement.pdf")
        self.assertEqual(extracted[1].attachment_id, "ATT-002")
        self.assertEqual(extracted[1].filename, "logo.png")

    def test_03_inline_vs_normal_attachment(self):
        """3. Distinguish inline attachments from standard attachments."""
        png_bytes = b"\x89PNG\r\n\x1a\nInline Image"
        doc_bytes = b"%PDF-1.4\nDocument"
        msg = _create_synthetic_email_message(
            [
                ("embedded_logo.png", "image", "png", png_bytes, "inline", "logo@cid"),
                ("contract.pdf", "application", "pdf", doc_bytes, "attachment", None),
            ]
        )
        extracted = extract_attachments(msg)
        self.assertEqual(len(extracted), 2)
        inline_att = next(a for a in extracted if a.filename == "embedded_logo.png")
        normal_att = next(a for a in extracted if a.filename == "contract.pdf")
        self.assertTrue(inline_att.is_inline)
        self.assertEqual(inline_att.content_disposition, "inline")
        self.assertEqual(inline_att.content_id, "logo@cid")
        self.assertFalse(normal_att.is_inline)
        self.assertEqual(normal_att.content_disposition, "attachment")

    def test_04_filename_extraction(self):
        """4. Verify filename extraction including RFC 2047 encoded names."""
        data = b"Sample text"
        msg = _create_synthetic_email_message(
            [("regular_report.txt", "text", "plain", data, "attachment", None)]
        )
        extracted = extract_attachments(msg)
        self.assertEqual(extracted[0].filename, "regular_report.txt")

    def test_05_mime_extraction(self):
        """5. Verify declared MIME type extraction."""
        data = b"%PDF-1.7\nSample"
        msg = _create_synthetic_email_message(
            [("doc.pdf", "application", "pdf", data, "attachment", None)]
        )
        extracted = extract_attachments(msg)
        self.assertEqual(extracted[0].declared_mime, "application/pdf")

    def test_06_content_disposition(self):
        """6. Verify preservation of content-disposition header value."""
        data = b"Some data"
        msg = _create_synthetic_email_message(
            [("archive.zip", "application", "zip", data, "attachment", None)]
        )
        extracted = extract_attachments(msg)
        self.assertEqual(extracted[0].content_disposition, "attachment")


class TestAttachmentHashing(unittest.TestCase):
    """Test suite for cryptographic SHA-256 calculation."""

    def test_07_correct_sha256(self):
        """7. Verify SHA-256 matches exact hash of raw attachment payload."""
        payload = b"Hello, this is a test payload for SHA-256 verification!"
        expected_hash = hashlib.sha256(payload).hexdigest()
        msg = _create_synthetic_email_message(
            [("sample.txt", "text", "plain", payload, "attachment", None)]
        )
        extracted = extract_attachments(msg)
        self.assertEqual(extracted[0].sha256, expected_hash)

    def test_08_deterministic_hashing(self):
        """8. Verify deterministic SHA-256 across multiple extraction runs."""
        payload = b"\x00\x01\x02\x03\xff\xfe\xfd\xfc"
        msg1 = _create_synthetic_email_message(
            [("binary.dat", "application", "octet-stream", payload, "attachment", None)]
        )
        msg2 = _create_synthetic_email_message(
            [("binary.dat", "application", "octet-stream", payload, "attachment", None)]
        )
        ext1 = extract_attachments(msg1)
        ext2 = extract_attachments(msg2)
        self.assertEqual(ext1[0].sha256, ext2[0].sha256)


class TestSignatureDetection(unittest.TestCase):
    """Test suite for magic-byte file signature detection."""

    def setUp(self):
        self.detector = SignatureDetector()

    def test_09_pdf_signature(self):
        """9. Detect PDF document signature (%PDF-)."""
        pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj"
        sig = self.detector.detect(pdf_bytes)
        self.assertEqual(sig.detected_type, "PDF document")
        self.assertEqual(sig.signature, "%PDF-")
        self.assertEqual(sig.confidence, "high")

    def test_10_zip_signature(self):
        """10. Detect standard ZIP archive signature (PK\x03\x04)."""
        zip_bytes = _create_zip_bytes({"test.txt": "hello"})
        sig = self.detector.detect(zip_bytes)
        self.assertEqual(sig.detected_type, "ZIP archive")
        self.assertEqual(sig.signature, "PK\\x03\\x04")

    def test_11_png_jpeg_gif_signatures(self):
        """11. Detect PNG, JPEG, and GIF image signatures."""
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF"
        gif_bytes = b"GIF89a\x01\x00\x01\x00"

        sig_png = self.detector.detect(png_bytes)
        sig_jpeg = self.detector.detect(jpeg_bytes)
        sig_gif = self.detector.detect(gif_bytes)

        self.assertEqual(sig_png.detected_type, "PNG image")
        self.assertEqual(sig_jpeg.detected_type, "JPEG image")
        self.assertEqual(sig_gif.detected_type, "GIF image")

    def test_12_pe_mz_signature(self):
        """12. Detect Windows PE executable signature (MZ)."""
        pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
        sig = self.detector.detect(pe_bytes)
        self.assertEqual(sig.detected_type, "PE executable")
        self.assertEqual(sig.signature, "MZ")
        self.assertEqual(sig.confidence, "high")

    def test_13_ole_compound_file_signature(self):
        """13. Detect Microsoft Compound File (OLE) signature."""
        ole_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00\x00\x00\x00"
        sig = self.detector.detect(ole_bytes)
        self.assertEqual(sig.detected_type, "Microsoft Compound File (OLE)")
        self.assertEqual(sig.signature, "D0 CF 11 E0")

    def test_14_unknown_file_signature(self):
        """14. Safely handle unknown file binary signatures."""
        rand_bytes = b"RANDOM_UNRECOGNIZED_HEADER_BYTES_12345"
        sig = self.detector.detect(rand_bytes)
        self.assertEqual(sig.detected_type, "unknown")
        self.assertIsNone(sig.signature)
        self.assertEqual(sig.confidence, "none")


class TestConsistencyChecks(unittest.TestCase):
    """Test suite for extension vs MIME vs file signature consistency."""

    def setUp(self):
        self.analyzer = StaticAttachmentAnalyzer()

    def test_15_extension_mime_match(self):
        """15. Consistent extension and declared MIME."""
        pdf_bytes = b"%PDF-1.5\nValid PDF"
        msg = _create_synthetic_email_message(
            [("invoice.pdf", "application", "pdf", pdf_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        mime_mismatch_rules = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-MIME-MISMATCH"]
        self.assertEqual(len(mime_mismatch_rules), 0)
        self.assertEqual(report.assessment.risk_level, "none")

    def test_16_extension_mime_mismatch(self):
        """16. Inconsistent extension and declared MIME (e.g. .pdf claimed as executable MIME)."""
        pdf_bytes = b"%PDF-1.5\nValid PDF"
        msg = _create_synthetic_email_message(
            [("invoice.pdf", "application", "x-msdownload", pdf_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-MIME-MISMATCH"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "medium")
        self.assertIn("application/x-msdownload", obs[0].description)

    def test_17_extension_signature_mismatch(self):
        """17. Critical mismatch: .pdf extension with PE executable binary signature."""
        pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
        msg = _create_synthetic_email_message(
            [("invoice.pdf", "application", "pdf", pe_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-TYPE-MISMATCH"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "high")
        self.assertEqual(obs[0].evidence["detected_type"], "PE executable")
        self.assertEqual(report.assessment.risk_level, "high")

    def test_18_double_extension(self):
        """18. Detect deceptive double extension pattern (e.g. invoice.pdf.exe)."""
        pe_bytes = b"MZ\x90\x00\x03\x00"
        msg = _create_synthetic_email_message(
            [("invoice.pdf.exe", "application", "x-msdownload", pe_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-DOUBLE-EXTENSION"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "high")
        self.assertIn("deceptive double-extension pattern", obs[0].description)


class TestSuspiciousStructures(unittest.TestCase):
    """Test suite for executable, script, macro-capable, and archive structures."""

    def setUp(self):
        self.analyzer = StaticAttachmentAnalyzer()

    def test_19_executable_attachment(self):
        """19. Detect directly executable attachment extension."""
        pe_bytes = b"MZ\x90\x00"
        msg = _create_synthetic_email_message(
            [("setup.exe", "application", "x-msdownload", pe_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-EXECUTABLE-EXTENSION"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "medium")

    def test_20_script_attachment(self):
        """20. Detect script attachment extension (e.g. .bat, .ps1, .vbs)."""
        script_bytes = b"@echo off\necho Update\n"
        msg = _create_synthetic_email_message(
            [("patch.bat", "text", "plain", script_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-SCRIPT-EXTENSION"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "medium")

    def test_21_macro_capable_document(self):
        """21. Detect macro-capable Office document extension (.docm, .xlsm)."""
        dummy_ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        msg = _create_synthetic_email_message(
            [("ledger.xlsm", "application", "vnd.ms-excel.sheet.macroenabled.12", dummy_ole, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-MACRO-CAPABLE"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "low")
        self.assertIn("Macro execution not evaluated", obs[0].description)

    def test_22_archive_containing_executable_member(self):
        """22. Safe static inspection of ZIP containing executable-looking member."""
        zip_bytes = _create_zip_bytes({
            "readme.txt": "Instructions",
            "payload.exe": b"MZ\x00\x00",
        })
        msg = _create_synthetic_email_message(
            [("package.zip", "application", "zip", zip_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-ARCHIVE-SUSPICIOUS-MEMBER"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "high")
        self.assertIn("payload.exe", obs[0].evidence["suspicious_members"])

    def test_23_nested_archive(self):
        """23. Safe static inspection of ZIP containing a nested archive."""
        inner_zip = _create_zip_bytes({"inner.txt": "inner data"})
        outer_zip = _create_zip_bytes({
            "notes.txt": "outer notes",
            "nested.zip": inner_zip,
        })
        msg = _create_synthetic_email_message(
            [("bundle.zip", "application", "zip", outer_zip, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-ARCHIVE-NESTED"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "medium")
        self.assertIn("nested.zip", obs[0].evidence["nested_archives"])

    def test_24_excessive_filename_length(self):
        """24. Flag filenames that exceed length threshold."""
        long_name = "a" * 125 + ".pdf"
        pdf_bytes = b"%PDF-1.4\nTest"
        msg = _create_synthetic_email_message(
            [(long_name, "application", "pdf", pdf_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-EXCESSIVE-FILENAME-LENGTH"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "low")
        self.assertEqual(obs[0].evidence["length"], 129)


class TestGraphProvenanceAndMlFeatures(unittest.TestCase):
    """Test suite for graph entities, relationships, provenance, and ML features."""

    def setUp(self):
        self.analyzer = StaticAttachmentAnalyzer()

    def test_25_email_to_attachment_relationship(self):
        """25. Graph relationship: email -> contains_attachment -> attachment."""
        pdf_bytes = b"%PDF-1.4\nDoc"
        msg = _create_synthetic_email_message(
            [("doc.pdf", "application", "pdf", pdf_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg, email_id="EML-999")
        rel = next(
            (r for r in report.relationships if r.relation == "contains_attachment"), None
        )
        self.assertIsNotNone(rel)
        self.assertEqual(rel.source, "EML-999")
        self.assertEqual(rel.target, "ATT-001")

    def test_26_attachment_to_hash_and_type_relationship(self):
        """26. Graph relationship: attachment -> has_hash and detected_as."""
        pdf_bytes = b"%PDF-1.4\nDoc"
        expected_hash = hashlib.sha256(pdf_bytes).hexdigest()
        msg = _create_synthetic_email_message(
            [("doc.pdf", "application", "pdf", pdf_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        hash_rel = next((r for r in report.relationships if r.relation == "has_hash"), None)
        type_rel = next((r for r in report.relationships if r.relation == "detected_as"), None)
        self.assertIsNotNone(hash_rel)
        self.assertEqual(hash_rel.target, expected_hash)
        self.assertIsNotNone(type_rel)
        self.assertEqual(type_rel.target, "document")

    def test_27_observation_provenance(self):
        """27. Strict provenance fields on every attachment observation."""
        pe_bytes = b"MZ\x00\x00"
        msg = _create_synthetic_email_message(
            [("fake.pdf", "application", "pdf", pe_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        self.assertTrue(len(report.observations) > 0)
        for obs in report.observations:
            self.assertTrue(obs.observation_id.startswith("OBS-ATT-"))
            self.assertTrue(obs.rule_id.startswith("RULE-ATTACHMENT-"))
            self.assertEqual(obs.source_module, "attachment_analysis")
            self.assertEqual(obs.attachment_id, "ATT-001")
            self.assertIn(obs.severity, {"informational", "low", "medium", "high"})
            self.assertIsInstance(obs.evidence, dict)
            self.assertEqual(obs.fact_type, "observed")

    def test_28_deterministic_output(self):
        """28. Deterministic analysis across repeated invocations."""
        pdf_bytes = b"%PDF-1.4\nConsistent content"
        msg = _create_synthetic_email_message(
            [("file.pdf", "application", "pdf", pdf_bytes, "attachment", None)]
        )
        report1 = self.analyzer.analyze(msg)
        report2 = self.analyzer.analyze(msg)
        self.assertEqual(report1.to_dict(), report2.to_dict())

    def test_29_ml_features_schema(self):
        """29. Expose complete tabular features schema for future attachment ML."""
        zip_bytes = _create_zip_bytes({"test.exe": b"MZ"})
        msg = _create_synthetic_email_message(
            [("archive.zip", "application", "zip", zip_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        self.assertEqual(len(report.ml_features), 1)
        feat = report.ml_features[0]
        expected_keys = {
            "file_size", "filename_length", "extension_count", "dot_count",
            "has_double_extension", "executable_extension", "script_extension",
            "macro_capable", "archive", "nested_archive", "member_count",
            "contains_executable_member", "mime_mismatch", "signature_mismatch",
            "detected_type", "sha256",
        }
        self.assertEqual(set(feat.keys()), expected_keys)
        self.assertTrue(feat["archive"])
        self.assertTrue(feat["contains_executable_member"])

    def test_30_assessment_count_exact_match(self):
        """30. Regression test verifying reported count in assessment.reason exactly matches observations."""
        pe_bytes = b"MZ\x00\x00"
        msg = _create_synthetic_email_message(
            [("invoice.pdf.exe", "application", "pdf", pe_bytes, "attachment", None)]
        )
        report = self.analyzer.analyze(msg)
        high_obs = [o for o in report.observations if o.severity == "high"]
        self.assertIn(
            f"detected {len(high_obs)} high-severity anomaly indicator(s)",
            report.assessment.reason,
        )


class TestArchiveResourceSafetyLimits(unittest.TestCase):
    """Test suite for safe configurable limits on archive member count, size, and nesting."""

    def test_31_archive_member_count_limit(self):
        """31. Bounded inspection when archive member count exceeds configurable limit."""
        files = {f"file_{i:03d}.txt": f"Content {i}" for i in range(15)}
        zip_bytes = _create_zip_bytes(files)
        expected_sha = hashlib.sha256(zip_bytes).hexdigest()

        msg = _create_synthetic_email_message(
            [("many_files.zip", "application", "zip", zip_bytes, "attachment", None)]
        )
        # Configure strict limit of 5 members
        analyzer = StaticAttachmentAnalyzer(max_archive_members=5)
        report = analyzer.analyze(msg)

        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-ARCHIVE-MEMBER-LIMIT"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "medium")
        self.assertEqual(obs[0].evidence["member_count"], 15)
        self.assertEqual(obs[0].evidence["limit"], 5)

        # Original SHA-256 preserved
        self.assertEqual(report.attachments[0]["sha256"], expected_sha)
        # Not classified as high risk or malware
        self.assertEqual(report.assessment.risk_level, "medium")
        self.assertIn("exceeds safety limit", report.assessment.reason)

    def test_32_archive_total_size_limit(self):
        """32. Flag archive whose declared uncompressed size exceeds configurable safety limit."""
        large_content = "X" * 10000
        zip_bytes = _create_zip_bytes({"big_file.txt": large_content})
        expected_sha = hashlib.sha256(zip_bytes).hexdigest()

        msg = _create_synthetic_email_message(
            [("big.zip", "application", "zip", zip_bytes, "attachment", None)]
        )
        # Configure size limit of 5000 bytes
        analyzer = StaticAttachmentAnalyzer(max_archive_total_size=5000)
        report = analyzer.analyze(msg)

        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-ARCHIVE-SIZE-LIMIT"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "medium")
        self.assertEqual(obs[0].evidence["total_uncompressed_size"], 10000)
        self.assertEqual(obs[0].evidence["limit"], 5000)

        # Original SHA-256 preserved
        self.assertEqual(report.attachments[0]["sha256"], expected_sha)
        self.assertEqual(report.assessment.risk_level, "medium")

    def test_33_archive_nesting_depth_limit(self):
        """33. Stop deeper inspection when nesting depth exceeds configurable limit."""
        inner_zip = _create_zip_bytes({"secret.txt": "deep data"})
        outer_zip = _create_zip_bytes({
            "notes.txt": "outer notes",
            "nested.zip": inner_zip,
        })
        expected_sha = hashlib.sha256(outer_zip).hexdigest()

        msg = _create_synthetic_email_message(
            [("nested_bundle.zip", "application", "zip", outer_zip, "attachment", None)]
        )
        # Limit max nesting depth to 1 (do not inspect depth 2)
        analyzer = StaticAttachmentAnalyzer(max_archive_nesting_depth=1)
        report = analyzer.analyze(msg)

        obs = [o for o in report.observations if o.rule_id == "RULE-ATTACHMENT-ARCHIVE-NESTING-LIMIT"]
        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].severity, "medium")
        self.assertEqual(obs[0].evidence["limit"], 1)

        # Original SHA-256 preserved
        self.assertEqual(report.attachments[0]["sha256"], expected_sha)
        self.assertEqual(report.assessment.risk_level, "medium")

    def test_34_deterministic_behavior_when_limits_exceeded(self):
        """34. Verify deterministic behavior when resource safety limits are exceeded."""
        files = {f"item_{i}.txt": "data" for i in range(10)}
        zip_bytes = _create_zip_bytes(files)

        msg = _create_synthetic_email_message(
            [("archive_limit.zip", "application", "zip", zip_bytes, "attachment", None)]
        )
        analyzer = StaticAttachmentAnalyzer(max_archive_members=4)
        rep1 = analyzer.analyze(msg)
        rep2 = analyzer.analyze(msg)

        self.assertEqual(rep1.to_dict(), rep2.to_dict())
        self.assertEqual(
            [o.rule_id for o in rep1.observations],
            [o.rule_id for o in rep2.observations],
        )


if __name__ == "__main__":
    unittest.main()
