# SIH26106 — Pre-Training Verification Report

## Executive Summary

Before initiating any feature extraction, TF-IDF calculation, or ML model training, this verification audit was conducted to validate the integrity, provenance, deduplication, and class balances of the active training dataset ([`ml/data/processed/emails_balanced.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/emails_balanced.csv)).

All checks passed with **zero inconsistencies**. No synthetic data, no LLM-generated labels, and no ungrounded class inferences exist in the corpus.

---

## 1. Explanation of the Legitimate-Count Difference

### High-Level Summary
- **Previous Audit Count:** `76,346` raw legitimate records (across 6 accepted corpora)
- **Cleaned Available Count:** `75,946` unique quality-passed records
- **Total Difference:** **`400` records**
- **Explanation:** Exactly accounted for by **`7` quality quarantines** + **`393` duplicate removals** ($7 + 393 = 400$).

### Breakdown by Source and Reason

```text
previous_count: 76,346
cleaned_count:  75,946
difference:     400
reason:         7 records quarantined (quality failure) + 393 duplicate records removed
```

| Source Dataset | Previous Raw Count | Cleaned Usable | Difference | Quarantined (Quality) | Duplicates Removed | Accounting Verified |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`Enron`** | 15,791 | 15,472 | **319** | 2 | 317 | ✅ $2 + 317 = 319$ |
| **`CEAS_08`** | 17,312 | 17,282 | **30** | 0 | 30 | ✅ $0 + 30 = 30$ |
| **`TREC_07`** | 24,358 | 24,341 | **17** | 3 | 14 | ✅ $3 + 14 = 17$ |
| **`TREC_06`** | 12,393 | 12,361 | **32** | 2 | 30 | ✅ $2 + 30 = 32$ |
| **`SpamAssassin`** | 4,091 | 4,090 | **1** | 0 | 1 | ✅ $0 + 1 = 1$ |
| **`Ling`** | 2,401 | 2,400 | **1** | 0 | 1 | ✅ $0 + 1 = 1$ |
| **Total** | **76,346** | **75,946** | **400** | **7** | **393** | ✅ **100.0% Verified** |

### Specific Exclusion Reasons for the 7 Quarantined Records
All 7 quarantined legitimate records are archived in [`ml/data/processed/emails_quarantine.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/emails_quarantine.csv):
1. `Enron_8077`: `extremely_short_text_len_17` (subject: *"elena chilkina"*, body: *"hi"*)
2. `Enron_16691`: `extremely_short_text_len_16` (subject: *"geir ' s goals"*, body: *")"*)
3. `TREC_06_1130`: `extremely_short_text_len_12` (subject: *"Re: test"*, body: *"test"*)
4. `TREC_06_3051`: `extremely_short_text_len_16` (subject: *"Re: plan9"*, body: *"thanks"*)
5. `TREC_07_5391`: `missing_body` (subject only, empty body)
6. `TREC_07_12892`: `missing_body` (subject only, empty body)
7. `TREC_07_18402`: `extremely_short_text_len_9` (subject: *"test"*, body: *"ok"*)

---

## 2. Verification of the Balanced Dataset

### Confirmation of Legitimate Count
The final balanced dataset contains **exactly 6,500 legitimate records**:

| Source Dataset | Cleaned Available | Downsampled Allocation | Proportion of Legitimate Class |
| :--- | :---: | :---: | :---: |
| **`TREC_07`** | 24,341 | **2,083** | 32.05% |
| **`CEAS_08`** | 17,282 | **1,479** | 22.75% |
| **`Enron`** | 15,472 | **1,324** | 20.37% |
| **`TREC_06`** | 12,361 | **1,058** | 16.28% |
| **`SpamAssassin`** | 4,090 | **350** | 5.38% |
| **`Ling`** | 2,400 | **206** | 3.17% |
| **Total Legitimate** | **75,946** | **6,500** | **100.00%** |

### Sampling Order Verification
- **Verified:** Sampling was performed **strictly after** text normalization, artifact cleaning, quality filtering, and deduplication.
- 100% of the 6,500 record IDs in the balanced file exist in `emails_cleaned.csv`. No raw or uncleaned records bypassed the pipeline.

---

## 3. Verification of All Three ML Classes

### Exact Class Distribution
```text
legitimate:    6,500  (57.33%)
fraud_related: 3,290  (29.02%)
phishing:      1,548  (13.65%)
Total:        11,338 (100.00%)
```

### Policy Confirmations
- **No spam mapped to phishing:** 100% of phishing records ($n = 1,548$) are strictly from the Jose Nazario verified phishing corpus with original label `1.0`. All 71,382 raw spam records remain in quarantine.
- **No artificial suspicious labels:** Count of `suspicious` in dataset = **`0`**.
- **No artificial impersonation labels:** Count of `impersonated` in dataset = **`0`**.
- **No LLM-generated labels:** All labels originate from the primary source publications (Nazario 2005-2015, Radev ACL 2008, Enron CMU, CEAS 2008, TREC 2006/2007, SpamAssassin, Ling-Spam).

---

## 4. Verification of Provenance Fields

Every single record in [`ml/data/processed/emails_balanced.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/emails_balanced.csv) retains complete, unbroken provenance:

| Column Name | Status in Balanced Dataset | Null Count | Description |
| :--- | :---: | :---: | :--- |
| **`record_id`** | Present | **0** | Deterministic ID (e.g., `Enron_0`, `Nazario_14`) |
| **`source_dataset`** | Present | **0** | Name of origin corpus |
| **`source_record_id`** | Present | **0** | Row index in original raw file |
| **`original_label`** | Present | **0** | Raw label from dataset author (`0.0` or `1.0`) |
| **`our_label`** | Present | **0** | Target ML class (`legitimate`, `phishing`, `fraud_related`) |
| **`subject`** | Present | 72 | Raw subject string (72 blank in raw email) |
| **`body`** | Present | **0** | Raw body string |
| **`clean_text`** | Present | **0** | Canonical normalized text (`clean_subject + "\n" + clean_body`) |

---

## 5. Duplicate Handling Verification

### Deduplication Execution Summary
- **Exact text hash duplicates removed:** **84**
- **Normalized near-duplicate matches removed:** **363** (362 direct matches + 1 superseded by higher-priority source)
- **Total duplicates removed across corpus:** **447**
- **Remaining duplicates in balanced dataset:** **`0`** (both exact `clean_text` duplicates and `text_hash` duplicates = 0).
- **Global Cross-Dataset Matching:** Deduplication checked across all corpora simultaneously. A total of **115 duplicate pairs** were detected and resolved across different source files.

### Representative Duplicate Provenance Examples

```text
Example 1 (Cross-Dataset Priority Resolution):
  Kept Record:      TREC_06_7618 (Source: TREC_06, Priority: 75)
  Duplicate Record: CEAS_08_31634 (Source: CEAS_08, Priority: 70)
  Reason:           normalized_near_duplicate_match_superseded_by_higher_priority_source_TREC_06

Example 2 (Cross-Dataset Exact Match):
  Kept Record:      SpamAssassin_4028 (Source: SpamAssassin)
  Duplicate Record: TREC_06_11118 (Source: TREC_06)
  Reason:           exact_text_hash_match (identical text broadcast to multiple listservs)

Example 3 (Intra-Dataset Enron Near-Duplicate):
  Kept Record:      Enron_134 (Source: Enron)
  Duplicate Record: Enron_409 (Source: Enron)
  Reason:           normalized_near_duplicate_match (repeated corporate meeting notification)

Example 4 (Intra-Dataset CEAS Exact Match):
  Kept Record:      CEAS_08_2360 (Source: CEAS_08)
  Duplicate Record: CEAS_08_2421 (Source: CEAS_08)
  Reason:           exact_text_hash_match (automated subscription receipt)

Example 5 (Intra-Dataset Fraud Exact Match):
  Kept Record:      Nigerian_Fraud_237 (Source: Nigerian_Fraud)
  Duplicate Record: Nigerian_Fraud_557 (Source: Nigerian_Fraud)
  Reason:           exact_text_hash_match (identical 419 scam solicitation broadcast to multiple addresses)
```

All 447 removed duplicates are permanently audited in [`ml/data/processed/deduplication_log.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/deduplication_log.csv).

---

## 6. Verification of the Final Training Dataset

### Exact File Location
- **Path:** [`ml/data/processed/emails_balanced.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/emails_balanced.csv)
- **File Size:** ~23.4 MB
- **Total Row Count:** **`11,338`**

### Field Completeness Metrics
- **Total Columns (11):** `record_id`, `source_dataset`, `source_record_id`, `original_label`, `our_label`, `subject`, `body`, `clean_text`, `clean_subject`, `clean_body`, `text_hash`
- **Missing Subject Count:** 72 (0.63% — legitimate raw messages with no subject header; safely handled in `clean_text`)
- **Missing Body Count:** **0** (0.00%)
- **Empty `clean_text` Count:** **0** (0.00%)

### Distribution Summary

```text
Class Distribution:
  legitimate:      6,500 (57.33%)
  fraud_related:   3,290 (29.02%)
  phishing:        1,548 (13.65%)
  Total:          11,338

Source Distribution:
  Nigerian_Fraud:  3,290 (29.02%)
  TREC_07:         2,083 (18.37%)
  Nazario:         1,548 (13.65%)
  CEAS_08:         1,479 (13.04%)
  Enron:           1,324 (11.68%)
  TREC_06:         1,058  (9.33%)
  SpamAssassin:      350  (3.09%)
  Ling:              206  (1.82%)
  Total:          11,338
```

---

## 7. Architecture Boundary Definition

In strict accordance with the updated SIH26106 system design:

1. **Learned ML Classifier Boundaries (Model 1):**
   - Model 1 is strictly a **3-class text classifier**:
     - `legitimate`
     - `phishing`
     - `fraud_related`
   - Neither `suspicious` nor `impersonated` are trained as machine learning classes.
   - The probability interval $0.40 \le P \le 0.75$ is **not** a learned class; it represents an **inference-time escalation policy** for routing borderline predictions to human/sandbox review.

2. **Forensic Fusion Investigation Layer (Post-Classification):**
   - Header authentication failures (SPF/DKIM/DMARC) and display-name mismatches from Module 1 are **investigative evidence**, not deterministic proof of impersonation.
   - The downstream fusion layer will ingest independent forensic signals:
     ```text
     - authentication_failure: bool
     - display_name_mismatch:  bool
     - lookalike_domain:       bool
     - threat_probability:     float
     ```
   - These signals will be combined at the decision engine level after Model 1 evaluation.

---

## 8. Conclusion

The dataset [`ml/data/processed/emails_balanced.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/emails_balanced.csv) is **100% verified, clean, auditable, and ready** for feature engineering and model training under the strict 3-class architecture.
