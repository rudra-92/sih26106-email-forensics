# Model 2 — Forensic Evidence Availability Audit Report

## Executive Summary

Before extracting features or training any downstream models, a thorough forensic evidence availability audit was performed across all accepted raw corpora and processed Model 1 datasets. This establishes the **true observable baseline** for each forensic feature group without synthetic data fabrication or false label imputation.

## Forensic Evidence Availability Table

| Dataset | Total Emails | From (%) | Date (%) | URLs (%) | IPs (%) | Raw Headers (%) | Received (%) | Reply-To (%) | SPF (%) | DKIM (%) | DMARC (%) | Attach Meta (%) | Attach Bytes (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **emails_balanced (Model 1 3-Class)** | 11,338 | 3.61% | 1.89% | 38.78% | 2.14% | 0.18% | 0.04% | 0.06% | 0.04% | 0.04% | 0.0% | 0.23% | 0.17% |
| **emails_balanced_4class (Model 1 4-Class with Spam)** | 14,374 | 2.89% | 1.51% | 38.51% | 2.09% | 0.14% | 0.03% | 0.06% | 0.03% | 0.03% | 0.0% | 0.22% | 0.31% |
| **train (70% Split)** | 7,936 | 3.72% | 1.9% | 38.86% | 2.12% | 0.16% | 0.05% | 0.08% | 0.05% | 0.04% | 0.0% | 0.25% | 0.16% |
| **validation (15% Split)** | 1,701 | 3.17% | 1.53% | 38.04% | 1.76% | 0.18% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.24% | 0.12% |
| **test (15% Split)** | 1,701 | 3.53% | 2.18% | 39.15% | 2.65% | 0.24% | 0.06% | 0.06% | 0.06% | 0.12% | 0.0% | 0.12% | 0.24% |
| **Enron (Raw)** | 29,767 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| **CEAS_08 (Raw)** | 39,154 | 100.0% | 100.0% | 67.01% | 2.59% | 1.08% | 0.07% | 0.04% | 0.05% | 0.08% | 0.0% | 0.32% | 0.36% |
| **Nazario (Raw)** | 1,565 | 100.0% | 99.94% | 92.84% | 1.98% | 0.19% | 0.06% | 0.0% | 0.06% | 0.06% | 0.06% | 0.06% | 0.0% |
| **Nigerian_Fraud (Raw)** | 3,332 | 90.07% | 85.53% | 34.84% | 1.2% | 0.12% | 0.0% | 0.15% | 0.0% | 0.0% | 0.0% | 0.03% | 0.0% |
| **SpamAssassin (Raw)** | 5,809 | 100.0% | 100.0% | 86.11% | 3.43% | 1.24% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.77% | 1.79% |
| **TREC_06 (Raw)** | 16,439 | 98.38% | 97.01% | 41.12% | 3.54% | 0.97% | 0.0% | 0.01% | 0.0% | 0.0% | 0.0% | 0.26% | 0.49% |
| **TREC_07 (Raw)** | 53,757 | 100.0% | 99.96% | 57.15% | 1.28% | 1.26% | 0.01% | 0.04% | 0.01% | 0.0% | 0.0% | 0.08% | 0.09% |
| **Ling (Raw)** | 2,859 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |

## Dataset Inventory & Label Distribution

| Dataset | File Path | Type | Row Count | Columns | Label Distribution |
| :--- | :--- | :---: | :---: | :--- | :--- |
| **emails_balanced (Model 1 3-Class)** | `ml\data\processed\emails_balanced.csv` | processed | 11,338 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 6500; fraud_related: 3290; phishing: 1548 |
| **emails_balanced_4class (Model 1 4-Class with Spam)** | `ml\data\processed\emails_balanced_4class.csv` | processed | 14,374 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 6500; fraud_related: 3290; spam: 3036; phishing: 1548 |
| **train (70% Split)** | `ml\data\processed\train.csv` | split | 7,936 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 4550; fraud_related: 2303; phishing: 1083 |
| **validation (15% Split)** | `ml\data\processed\validation.csv` | split | 1,701 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 974; fraud_related: 494; phishing: 233 |
| **test (15% Split)** | `ml\data\processed\test.csv` | split | 1,701 | `record_id, source_dataset, source_record_id, original_label, our_label, subject, body, clean_text, clean_subject, clean_body, text_hash` | legitimate: 976; fraud_related: 493; phishing: 232 |
| **Enron (Raw)** | `ml\data\raw\enron\Enron.csv` | raw | 29,767 | `subject, body, label` | 0: 15791; 1: 13976 |
| **CEAS_08 (Raw)** | `ml\data\raw\phishing\CEAS_08.csv` | raw | 39,154 | `sender, receiver, date, subject, body, label, urls` | 1: 21842; 0: 17312 |
| **Nazario (Raw)** | `ml\data\raw\phishing\Nazario.csv` | raw | 1,565 | `sender, receiver, date, subject, body, urls, label` | 1: 1565 |
| **Nigerian_Fraud (Raw)** | `ml\data\raw\fraud\Nigerian_Fraud.csv` | raw | 3,332 | `sender, receiver, date, subject, body, urls, label` | 1: 3332 |
| **SpamAssassin (Raw)** | `ml\data\raw\phishing\SpamAssasin.csv` | raw | 5,809 | `sender, receiver, date, subject, body, label, urls` | 0: 4091; 1: 1718 |
| **TREC_06 (Raw)** | `ml\data\raw\phishing\TREC_06.csv` | raw | 16,439 | `sender, receiver, date, subject, body, label, urls` | 0.0: 12393; 1.0: 3989 |
| **TREC_07 (Raw)** | `ml\data\raw\phishing\TREC_07.csv` | raw | 53,757 | `sender, receiver, date, subject, body, label, urls` | 1: 29399; 0: 24358 |
| **Ling (Raw)** | `ml\data\raw\phishing\Ling.csv` | raw | 2,859 | `subject, body, label` | 0: 2401; 1: 458 |

## Key Forensic Findings & Empirical Constraints

1. **Content & URL Richness**: Body text, linguistic features, and URLs are widely available across processed and raw datasets (35% - 85% of emails contain extracted URLs, and 100% contain subjects and bodies).
2. **Headers in Raw Corpora vs Processed Tabular CSVs**:
   - Raw corpora (`CEAS_08`, `Nazario`, `SpamAssassin`, `Nigerian_Fraud`, `TREC_06`, `TREC_07`) include explicit header fields (`sender`, `receiver`, `date`, `urls`).
   - `Nazario` contains full raw RFC 822 headers in its body text for multiple records (including `Received:`, `Message-ID:`, `Authentication-Results:`).
   - The preprocessed `emails_balanced.csv` preserved `subject`, `body`, and `clean_text`. Header extraction is applied to available header strings and raw lines.
3. **Attachment Bytes & RFC 822 Received Hops Absence in Static CSVs**:
   - Most historical academic public datasets (Enron, Ling, SpamAssassin CSV exports) stripped raw Received header blocks and detached binary payloads to preserve storage.
   - As mandated by **Phase 3**, missing evidence must NOT be fabricated. Instead, a dedicated **Forensic Validation Set** (`ml/validation/forensic/`) will be established containing real, provenance-tracked RFC 822 emails, complete Received hop chains, DKIM/SPF/DMARC authentication, and safe static PE/Office/PDF attachments to test and validate the feature extractors.
