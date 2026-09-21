# SIH26106 — Data Preprocessing Pipeline

This directory contains the data preprocessing pipeline for **Model 1: Email Threat Classification** in SIH26106.

The pipeline ingests accepted raw email corpora, executes deterministic security-aware text cleaning, filters low-quality and non-email records with full audit trails, removes cross-dataset duplicates while preserving provenance, and emits canonical datasets for downstream feature extraction.

---

## 1. Directory Structure

```text
ml/preprocessing/
├── __init__.py          # Preprocessing package exports
├── clean_text.py        # Security-aware text cleaning & normalization
├── quality_filter.py    # Data quality evaluation & quarantine flagging
├── deduplicate.py       # Cross-dataset & intra-dataset deduplication
├── build_dataset.py     # Master end-to-end pipeline orchestrator
└── README.md            # This documentation
```

---

## 2. Core Modules & Responsibilities

### `clean_text.py`
Provides deterministic, security-aware text cleaning functions.
- **`clean_email_text(subject, body, source)`**: Creates canonical `clean_text` (`subject + "\n" + body`).
- **`normalize_encoding(text)`**: Decodes HTML entities (`&amp;`, `&quot;`, etc.), replaces non-breaking spaces (`\xa0`), strips zero-width characters and BOMs, and unifies typographic quotes.
- **`normalize_whitespace(text)`**: Unifies line breaks (`\r\n` / `\r` -> `\n`), collapses multi-space runs per line, and caps consecutive blank lines at 2.
- **`strip_source_artifacts(text, source)`**: Removes documented, verified collector/listserv artifacts without broad regexes:
  - Ling-Spam leading `content - length : <num>` lines.
  - SpamAssassin Yahoo! Groups / eGroups unsubscribe boilerplate.
  - Residual top-of-body `Date:/From:/Message-ID:` transport headers in SpamAssassin.
  - Debian listmaster and Mailman mailing-list automated footers in TREC_06/07.
  - CEAS-08 testbed tracking parameters (`?e=<hash>@gvc.ceas-challenge.cc`).
  - Nazario top-of-body mbox envelope lines (`From <addr> <date>`) and dumped local delivery headers.
- **Preserved Security Signals**: Explicitly preserves all URLs, domains, email addresses, IP addresses, dollar amounts, phone numbers, urgency phrases, credential terms, and attachment names.
- **Does NOT**: Lowercase everything, tokenize, stem, lemmatize, remove stopwords, or calculate TF-IDF.

### `quality_filter.py`
Audits records against quality and forensic criteria. Borderline or defective records are flagged and routed to `emails_quarantine.csv` with specific failure codes:
- `missing_subject_and_body`: Both fields empty.
- `missing_body`: Body is empty or whitespace-only (insufficient context for threat classification).
- `extremely_short_text_len_<N>`: Cleaned text shorter than 20 characters (e.g., single-word messages).
- `non_email_folder_internal_data`: Mail server / mbox state records (e.g. `FOLDER INTERNAL DATA` in Nazario).
- `contains_null_bytes` / `high_unprintable_character_ratio`: Binary corruption.
- `unsupported_label`: Records outside the trusted three classes (`legitimate`, `phishing`, `fraud_related`).

### `deduplicate.py`
Executes deduplication strictly **after** text normalization:
- Computes SHA-256 exact text hash (`exact_hash`) and conservative normalized hash (`norm_hash`).
- When duplicate content is detected across corpora with the same label, a deterministic hierarchy is applied:
  `Nazario` (100) = `Nigerian_Fraud` (100) > `Enron` (90) > `SpamAssassin` (85) > `TREC_07` (80) > `TREC_06` (75) > `CEAS_08` (70) > `Ling` (65).
- If identical text appears under **conflicting labels** (e.g. legitimate vs. phishing), both records are flagged for quarantine to prevent label poisoning.
- Every duplicate action is logged to `ml/data/processed/deduplication_log.csv` (`kept_record`, `duplicate_record`, `source`, `reason`).

### `build_dataset.py`
Master execution script that orchestrates ingestion, cleaning, quality filtering, deduplication, and file generation.

---

## 3. Trusted Classes & Accepted Sources

Model 1 v1 strictly targets **three classes** under the **ZERO LABEL MANUFACTURING** policy:
1. **`legitimate`**: Enron (label 0), CEAS-08 (label 0), SpamAssassin (label 0), TREC_06 (label 0), TREC_07 (label 0), Ling-Spam (label 0).
2. **`phishing`**: Jose Nazario Curated Phishing Corpus (label 1).
3. **`fraud_related`**: Radev CLAIR 419 Fraudulent E-mail Corpus (label 1).

### Excluded Datasets & Records
- **Quarantined Spam**: All label 1 records from Enron, CEAS-08, SpamAssassin, TREC_06, TREC_07, and Ling-Spam (71,382 records) are excluded because they represent generic spam, not verified phishing or fraud.
- **TREC_05**: Excluded due to label corruption, high null rate, and 86.9% Enron content overlap.
- **Nazario_5 / Nigerian_5**: Excluded because they are 100% duplicates of our existing phishing and fraud corpora with recycled ham.
- **Derivative Aggregates**: HuggingFace/Kaggle aggregates rejected during the audit.

---

## 4. Pipeline Outputs

Running the pipeline populates `ml/data/processed/` and `ml/data/metadata/`:

| Output File | Destination | Description |
| :--- | :--- | :--- |
| **`emails_cleaned.csv`** | `ml/data/processed/` | Canonical usable dataset containing `record_id`, `source_dataset`, `source_record_id`, `original_label`, `our_label`, `subject`, `body`, `clean_text`, `clean_subject`, `clean_body`, `text_hash`. |
| **`emails_quarantine.csv`** | `ml/data/processed/` | Borderline/defective records with `quarantine_category` and `exclusion_reason`. |
| **`deduplication_log.csv`** | `ml/data/processed/` | Full audit log of all duplicate removals with `kept_record`, `duplicate_record`, `source`, `reason`. |
| **`preprocessing_report.md`** | `ml/data/metadata/` | Comprehensive report documenting pipeline execution, counts, rules, and quality metrics. |

---

## 5. Usage

To run the complete data preprocessing pipeline from the repository root:

```bash
python ml/preprocessing/build_dataset.py
```

Or using module invocation:

```bash
python -m ml.preprocessing.build_dataset
```
