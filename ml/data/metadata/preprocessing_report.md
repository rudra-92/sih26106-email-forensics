# SIH26106 — Data Preprocessing Pipeline Report

## 1. Executive Summary

This report documents the end-to-end execution of the security-aware data preprocessing pipeline for SIH26106 Model 1. The pipeline standardizes disparate email corpora into a canonical, auditable representation while adhering to the **ZERO LABEL MANUFACTURING** policy.

- **Total Candidate Records Ingested:** 81,243
- **Total Usable Records Accepted:** 80,784
- **Total Records Quarantined (Quality Checks):** 12
- **Total Duplicate Records Removed:** 447
- **Pipeline Execution Time:** 152.87 seconds

---

## 2. Usable Dataset Breakdown

### 2.1 Final Usable Count per Class

| Target Class | Usable Records | Percentage of Usable Corpus | Provenance Sources |
| :--- | :---: | :---: | :--- |
| **`legitimate`** | **75,946** | 94.01% | Enron, CEAS_08, TREC_06, SpamAssassin, TREC_07, Ling |
| **`phishing`** | **1,548** | 1.92% | Nazario |
| **`fraud_related`** | **3,290** | 4.07% | Nigerian_Fraud |
| **Total** | **80,784** | 100.00% | 8 Accepted Corpora |

### 2.2 Final Usable Count per Accepted Source

| Source Dataset | Class | Ingested | Quarantined | Duplicates Removed | Final Usable |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `Enron` | `legitimate` | 15,791 | 2 | 317 | **15,472** |
| `CEAS_08` | `legitimate` | 17,312 | 0 | 30 | **17,282** |
| `Nazario` | `phishing` | 1,565 | 4 | 13 | **1,548** |
| `Nigerian_Fraud` | `fraud_related` | 3,332 | 1 | 41 | **3,290** |
| `SpamAssassin` | `legitimate` | 4,091 | 0 | 1 | **4,090** |
| `TREC_06` | `legitimate` | 12,393 | 2 | 30 | **12,361** |
| `TREC_07` | `legitimate` | 24,358 | 3 | 14 | **24,341** |
| `Ling` | `legitimate` | 2,401 | 0 | 1 | **2,400** |

---

## 3. Data Quality & Quarantine Audit

Under the SIH26106 data integrity policy, records failing quality criteria are **quarantined with an auditable reason code** rather than silently destroyed.

| Failure Reason Code | Quarantine Category | Occurrences | Detailed Rationale |
| :--- | :--- | :---: | :--- |
| `extremely_short_text_len_17` | `extremely_short` | 1 | Cleaned text contains fewer than 20 characters (e.g. single words/punctuation). |
| `extremely_short_text_len_16` | `extremely_short` | 2 | Cleaned text contains fewer than 20 characters (e.g. single words/punctuation). |
| `non_email_folder_internal_data` | `non_email_metadata` | 2 | UW-IMAP / Pine server mbox folder internal metadata records. |
| `missing_body` | `missing_body` | 5 | Record contains subject only without body content. |
| `extremely_short_text_len_12` | `extremely_short` | 1 | Cleaned text contains fewer than 20 characters (e.g. single words/punctuation). |
| `extremely_short_text_len_9` | `extremely_short` | 1 | Cleaned text contains fewer than 20 characters (e.g. single words/punctuation). |

All quarantined records are safely archived in `ml/data/processed/emails_quarantine.csv`.

---

## 4. Cross-Dataset Deduplication Analysis

Deduplication was performed after text cleaning and normalization using exact SHA-256 text hashing and conservative normalized text hashing (whitespace-collapsed, case-folded). When identical content occurred across sources, provenance was preserved using a deterministic source hierarchy.

- **Total duplicate records removed:** 447
Full audit trail recorded in `ml/data/processed/deduplication_log.csv`.

---

## 5. Security-Aware Cleaning Rules Applied

The cleaning function (`clean_text.py`) applies deterministic transformations strictly without degrading threat signals:

1. **Encoding Normalization:** Decodes HTML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#39;`), normalizes `\xa0` non-breaking spaces, strips zero-width spaces (`\u200b`), and converts typographic curly quotes to ASCII.
2. **Whitespace Normalization:** Unifies line endings (`\r\n` / `\r` -> `\n`), normalizes multiple horizontal spaces, and caps consecutive blank lines at 2.
3. **Mailing List Disclaimer Stripping:** Removes automated Yahoo Groups / eGroups unsubscribe footers (`SpamAssassin`), Debian listmaster footers (`TREC_07`), and Mailman disclaimers without altering email bodies.
4. **Source Artifact Removal:** Strips synthetic `content - length : <num>` lines from Ling-Spam, strips residual transport headers (`Date:/From:/Message-ID:`) dumped into SpamAssassin bodies, and removes CEAS testbed tracking parameters (`?e=@gvc.ceas-challenge.cc`).
5. **Threat Signal Preservation:** Explicitly retains all URLs, domain names, IP addresses, currency figures ($/€/£), telephone numbers, urgency tokens, and recipient identifiers.

---

## 6. Known Limitations & Next Steps

1. **Severe Class Imbalance:** Legitimate email comprises >93% of the usable corpus. Downsampling or class-weighted loss will be required during Model 1 training.
2. **Excluded Spam Quarantines:** All 71,382 generic spam records remain excluded from Model 1 v1 to prevent contaminating the `phishing` boundary.
3. **Zero Label Manufacturing:** No synthetic samples or inferred labels were introduced.
