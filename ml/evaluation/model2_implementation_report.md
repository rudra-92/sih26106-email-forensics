# Model 2 — Forensic Intelligence Pipeline Implementation Report

**SIH26106 — AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform**  
**Stage:** Model 2 (Phases 1–4: Forensic Evidence Audit, Feature Engineering, Validation Set, Quality Audit)  
**Status:** Completed (Strictly stopped before Model 3 / XGBoost)

---

## 1. Existing Dataset Inventory

An automated, non-destructive audit was performed across all 13 accepted raw corpora and processed Model 1 datasets in the repository:

| Dataset Name | File Path | Type | Total Emails | Columns | Label Distribution |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **emails_balanced (Model 1 3-Class)** | `ml/data/processed/emails_balanced.csv` | processed | 11,338 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 6,500; fraud_related: 3,290; phishing: 1,548 |
| **emails_balanced_4class (4-Class with Spam)** | `ml/data/processed/emails_balanced_4class.csv` | processed | 14,374 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 6,500; fraud_related: 3,290; spam: 3,036; phishing: 1,548 |
| **train (70% Split)** | `ml/data/processed/train.csv` | split | 7,936 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 4,550; fraud_related: 2,303; phishing: 1,083 |
| **validation (15% Split)** | `ml/data/processed/validation.csv` | split | 1,701 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 974; fraud_related: 494; phishing: 233 |
| **test (15% Split)** | `ml/data/processed/test.csv` | split | 1,701 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 976; fraud_related: 493; phishing: 232 |
| **Enron (Raw)** | `ml/data/raw/enron/Enron.csv` | raw | 29,767 | `subject, body, label` | 0: 15,791; 1: 13,976 |
| **CEAS_08 (Raw)** | `ml/data/raw/phishing/CEAS_08.csv` | raw | 39,154 | `sender, receiver, date, subject, body, label, urls` | 1: 21,842; 0: 17,312 |
| **Nazario (Raw)** | `ml/data/raw/phishing/Nazario.csv` | raw | 1,565 | `sender, receiver, date, subject, body, urls, label` | 1: 1,565 |
| **Nigerian_Fraud (Raw)** | `ml/data/raw/fraud/Nigerian_Fraud.csv` | raw | 3,332 | `sender, receiver, date, subject, body, urls, label` | 1: 3,332 |
| **SpamAssassin (Raw)** | `ml/data/raw/phishing/SpamAssasin.csv` | raw | 5,809 | `sender, receiver, date, subject, body, label, urls` | 0: 4,091; 1: 1,718 |
| **TREC_06 (Raw)** | `ml/data/raw/phishing/TREC_06.csv` | raw | 16,439 | `sender, receiver, date, subject, body, label, urls` | 0.0: 12,393; 1.0: 3,989 |
| **TREC_07 (Raw)** | `ml/data/raw/phishing/TREC_07.csv` | raw | 53,757 | `sender, receiver, date, subject, body, label, urls` | 1: 29,399; 0: 24,358 |
| **Ling (Raw)** | `ml/data/raw/phishing/Ling.csv` | raw | 2,859 | `subject, body, label` | 0: 2,401; 1: 458 |

---

## 2. Forensic Evidence Availability Audit

Across the corpora, availability of true observable forensic signals was empirically measured:

| Dataset | Total Emails | From (%) | Date (%) | URLs (%) | IPs (%) | Raw Headers (%) | Received (%) | Reply-To (%) | SPF (%) | DKIM (%) | DMARC (%) | Attach Meta (%) | Attach Bytes (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **emails_balanced** | 11,338 | 3.61% | 1.89% | 38.78% | 2.14% | 0.18% | 0.04% | 0.06% | 0.04% | 0.04% | 0.00% | 0.23% | 0.17% |
| **emails_balanced_4class** | 14,374 | 2.89% | 1.51% | 38.51% | 2.09% | 0.14% | 0.03% | 0.06% | 0.03% | 0.03% | 0.00% | 0.22% | 0.31% |
| **train (70%)** | 7,936 | 3.72% | 1.90% | 38.86% | 2.12% | 0.16% | 0.05% | 0.08% | 0.05% | 0.04% | 0.00% | 0.25% | 0.16% |
| **validation (15%)** | 1,701 | 3.17% | 1.53% | 38.04% | 1.76% | 0.18% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.24% | 0.12% |
| **test (15%)** | 1,701 | 3.53% | 2.18% | 39.15% | 2.65% | 0.24% | 0.06% | 0.06% | 0.06% | 0.12% | 0.00% | 0.12% | 0.24% |
| **CEAS_08 (Raw)** | 39,154 | 100.0% | 100.0% | 67.01% | 2.59% | 1.08% | 0.07% | 0.04% | 0.05% | 0.08% | 0.00% | 0.32% | 0.36% |
| **Nazario (Raw)** | 1,565 | 100.0% | 99.94% | 92.84% | 1.98% | 0.19% | 0.06% | 0.00% | 0.06% | 0.06% | 0.06% | 0.06% | 0.00% |
| **SpamAssassin (Raw)** | 5,809 | 100.0% | 100.0% | 86.11% | 3.43% | 1.24% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.77% | 1.79% |
| **TREC_07 (Raw)** | 53,757 | 100.0% | 99.96% | 57.15% | 1.28% | 1.26% | 0.01% | 0.04% | 0.01% | 0.00% | 0.00% | 0.08% | 0.09% |

### Core Evidence Distinction
1. **Available Evidence**: Body text, linguistic features, punctuation, casing, currency indicators, keyword counts (urgency, financial, credential, account action), and extracted HTTP/HTTPS URLs are widely available (38.8% across balanced data, up to 92.8% in Nazario).
2. **Missing Source Evidence in Historical CSVs**: Academic public datasets stripped Received headers and detached binary attachment payloads during compilation. Per policy, missing fields are preserved as `NaN` / `0` and never synthetically fabricated.
3. **Dedicated Forensic Validation Set**: To validate the remaining extractors (hop chains, DKIM/SPF/DMARC alignment, OLE macros, PE section analysis, and YARA signatures), a separate validation fixture set was constructed in `ml/validation/forensic/`.

---

## 3. Implemented Forensic Architecture & Features

The pipeline is organized into 13 decoupled modules in `ml/forensic/`:

1. `email_parser.py`: Standardizes input from RFC 822 / `.eml` bytes, raw text, or tabular dictionary rows into `ParsedEmail`.
2. `header_analyzer.py`: From/Reply-To/To/Cc extraction, display-name spoofing, missing-field indicators.
3. `auth_analyzer.py`: Multi-header authentication verification (SPF pass/fail/softfail, DKIM pass/fail, DMARC reject/quarantine, domain alignment).
4. `received_analyzer.py`: SMTP hop sequence analysis (transmission origin bottom-to-top), hop count, IP extraction, timestamp order anomaly.
5. `ip_analyzer.py`: IPv4/IPv6 classification (public, private, loopback, reserved) and offline enrichment stub.
6. `domain_analyzer.py`: Domain syntax, punycode, typosquatting / character-substitution / homoglyph distance against brand targets.
7. `url_analyzer.py`: Protocol counts, IP-based URLs, open redirects, port indicators, length statistics, reputation stub.
8. `content_analyzer.py`: Structural text metrics (lengths, html-to-text ratio, casing, digits, punctuation), external lexical dictionaries, and BEC indicators.
9. `attachment_analyzer.py`: Extensions (double extension, executables, scripts, archives, macro-capable formats), MIME mismatch, Shannon entropy, printable ASCII strings, embedded IPs/URLs.
10. `pe_analyzer.py`: Static PE header analysis via `pefile` (sections, executable/writable flags, categorized API imports: process creation, execution, networking, memory, persistence, credentials).
11. `document_analyzer.py`: Static Office document macro analysis via `oletools` (VBA code streams, auto-exec procedures, embedded OLE objects).
12. `pdf_analyzer.py`: Static active content token inspection (`/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/AcroForm`).
13. `yara_scanner.py`: External modular signature scanner compiling `rules/*.yar` with graceful fallback.
14. `feature_pipeline.py`: Master orchestrator generating structured records, injecting Model 1D NLP probabilities, and producing the feature audit.

---

## 4. Complete Feature Schema & Counts

- **Total Extracted Features**: **141 features**
  - **Metadata (1)**: `email_id`
  - **Numerical (90)**: Model 1 probabilities (`nlp_prob_legitimate`, `nlp_prob_spam`, `nlp_prob_phishing`, `nlp_prob_fraud`), lengths, word/sentence counts, ratios (html-to-text, uppercase, digit, special char), term counts, hop counts, public/private IP counts, URL lengths, file/PE Shannon entropy, section/import/DLL counts, API category counts, YARA match count.
  - **Binary Flags (50)**: `has_reply_to`, `display_name_present`, `display_name_email_mismatch`, `missing_*`, `spf_*`, `dkim_*`, `dmarc_*`, `has_ip_as_hostname`, `has_at_symbol`, `has_encoded_characters`, `has_punycode`, `has_unicode_domain`, `has_suspicious_structure`, `has_suspicious_tld_candidate`, `lookalike_domain_candidate`, `homoglyph_candidate`, `double_extension`, `executable_attachment`, `script_attachment`, `archive_attachment`, `document_attachment`, `macro_capable_document`, `MIME_extension_mismatch`, `is_pe`, `has_macro`, `suspicious_macro_indicator`, `pdf_has_*`, BEC requests (`financial_request_present`, `payment_request_present`, `credential_request_present`, `gift_card_request_present`, `bank_change_request_present`, `wire_transfer_request_present`, `secrecy_request_present`, `urgent_request_present`, `executive_style_display_name`).
  - **Raw Evidence (Decoupled)**: Preserved in raw evidence structures (`received_hops`, `extracted_ips`, `urls`, `attachment_hashes`, `yara_rule_names`, `headers`). Never fed to downstream ML.

---

## 5. Feature Quality Audit & Missingness Policy

- **Missing Value Policy**:
  - `NaN` for conditional measurements where prerequisite evidence is absent (e.g. `from_replyto_mismatch = NaN` when Reply-To header is missing; `spf_alignment_issue = NaN` when unauthenticated; `file_entropy = NaN` when no attachment exists).
  - Explicit absence flags (`spf_present = 0`, `has_attachment = 0`) distinguish missing evidence from positive/negative test outcomes (`spf_fail = 0`).
  - Missing external threat intelligence is marked as `'unknown'` / `None`, never fabricated.
- **Audit Findings**:
  - **Features with >50% Missing**: Exactly 8 features (`from_replyto_mismatch`, `sender_domain_replyto_domain_mismatch`, `spf_alignment_issue`, `dkim_alignment_issue`, `dmarc_alignment_issue`, `domain_mismatch`, `file_entropy`, `pe_entropy`). All 8 represent strictly conditional metrics that must not be imputed.
  - **Features with 0% Missing**: 132 features across content, URLs, counts, binary indicators, and Model 1 probabilities.
  - **Constant Features in Text-Only Corpora**: Features requiring MIME binaries or Received headers evaluate to 0 / NaN in pure text corpora, confirming empirical data availability without fabrication.

---

## 6. Unit Testing & Validation-Set Results

### Automated Unit Tests (`tests/test_forensic_pipeline.py`)
Ran all 20 required forensic tests:
`Ran 20 tests in 3.874s — OK (20/20 Passed)`
1. From/Reply-To mismatch: **PASS**
2. Display-name mismatch: **PASS**
3. Received header hop chain: **PASS**
4. IPv4 extraction: **PASS**
5. IPv6 extraction: **PASS**
6. Public vs private IP detection: **PASS**
7. SPF parsing: **PASS**
8. DKIM parsing: **PASS**
9. DMARC parsing: **PASS**
10. URL extraction: **PASS**
11. IP-based URL detection: **PASS**
12. Punycode detection: **PASS**
13. Homoglyph & lookalike domain detection: **PASS**
14. Double-extension detection: **PASS**
15. PE static analysis: **PASS**
16. Office macro analysis: **PASS**
17. PDF active content analysis: **PASS**
18. YARA scanner integration: **PASS**
19. Model 1 probability integration: **PASS**
20. Missing-field handling (NaN preservation): **PASS**

### Validation-Set Fixture Results (`ml/validation/forensic/`)
1. `rfc822_full_chain.eml`: **3 Hops parsed**, `SPF_pass=1`, `DKIM_pass=1`, `DMARC_pass=1`, 0 alignment issues.
2. `reply_to_spoof.eml`: Detected `From/Reply-To mismatch=1`, `Lookalike candidate=1`, `Display mismatch=1`, `DMARC_fail=1`.
3. `phishing_urls.eml`: Detected `3 URLs`, `IP-based URL=1`, `Punycode=1`, `Suspicious structure=1`.
4. `safe_pe_stub.bin`: Detected `is_pe=1`, `YARA matches=2` (`Suspicious_PE_Header`, `Suspicious_UPX_Packer`).
5. `macro_sample.docm`: Detected `has_macro=1`, `suspicious_macro_indicator=1` (AutoOpen).
6. `active_content_sample.pdf`: Detected `pdf_has_javascript=1`, `pdf_has_openaction=1`.
7. `credential_harvest_attachment.html`: Detected `YARA match=1` (`Phishing_HTML_Form_Submission`).

**Failed Analyzers**: **0**. All 12 analyzers executed cleanly.

---

## 7. Data Leakage Protection

The extracted feature dataset was verified against data leakage rules:
- Zero ground truth labels (`our_label`, `label`, `original_label`) are present in features.
- Zero source dataset names (`source_dataset`, `source_record_id`) or collection corpus markers are included.
- The only model-derived features are the 4-class output probabilities from the frozen, pre-trained **Model 1D** artifact (`ml/models/model1d_word_char_filtered_lr.joblib`).

---

## 8. Security & Static Analysis Containment

1. Attachments are treated as untrusted byte arrays.
2. Static inspection only: `pefile` fast-load parsing, `oletools` macro stream inspection, and byte-level PDF token regex matching.
3. No binary files, scripts, or macros are ever executed.
4. Maximum attachment size limit (20 MB) and parser timeout limits enforced.
5. Malformed URLs and malformed port numbers caught and handled gracefully without crashing batch execution.

---

## 9. Next Step

**STOP CONDITION SATISFIED.** No XGBoost or downstream classifier trained.

The pipeline outputs:
- Feature Dataset: `ml/datasets/model2_forensic_features_sample.parquet` & `model2_forensic_features.parquet`
- Feature Audit Table: `ml/evaluation/model2_feature_audit.csv`
- Feature Summary: `ml/evaluation/model2_feature_summary.md`
- Data Availability Audit: `ml/evaluation/model2_data_availability_audit.csv`
- Data Availability Report: `ml/evaluation/model2_data_availability_report.md`

### Recommended Next Step:
Proceed to **Model 3 — XGBoost Forensic Fusion Classifier**, combining Model 1 NLP probabilities with the validated, leakage-free forensic features.
