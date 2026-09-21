# Comprehensive Dataset Audit Report

**Project:** SIH26106 — Email Threat Classification (Model 1)  
**Date of Audit:** 2026-09-20  
**Audit Scope:** Pre-processing inventory, data hygiene, label grounding, and leakage assessment for downloaded raw corpora in `ml/data/raw/`.  
**Governing Rule:** Absolute label integrity and provenance. No synthetic generation, no LLM auto-labeling, and zero modification of raw files or `modules/sender_identity/`.

---

## Executive Summary

An exhaustive technical audit of the four raw datasets downloaded into `ml/data/raw/` revealed crucial findings regarding dataset composition, source leakage, and label integrity:

1. **Total Records Audited:** 73,818 raw messages across 4 corpora.
2. **Strictly Usable Records:** 38,000 messages (51.48% of total downloaded data).
3. **Quarantined / Unmapped Records:** 35,818 messages (48.52% of total data), consisting of external commercial spam (`Enron.csv` Label 1: 13,976) and challenge spam (`CEAS_08.csv` Label 1: 21,842). In accordance with the project policy, generic spam is **not** converted into phishing or suspicious.
4. **Current Usable Class Distribution:**
   - **`legitimate`:** 33,103 messages (87.11% of usable data)
   - **`fraud_related`:** 3,332 messages (8.77% of usable data)
   - **`phishing`:** 1,565 messages (4.12% of usable data)
   - **`suspicious`:** 0 messages (deferred; no organic ground truth exists)
   - **`impersonated`:** 0 messages (deferred; requires Module 1 forensic authentication)
5. **Severe Source Leakage Detected:** Domain artifacts and collection infrastructure tokens are embedded directly in headers and bodies across all datasets:
   - `Enron`: 24.14% of messages explicitly contain the token `"enron"`.
   - `Nazario`: 66.01% of headers and 39.62% of message texts contain `"monkey.org"`.
   - `CEAS_08`: 61.22% of headers contain `"ceas-challenge"`.
   - `Nigerian_Fraud`: 5.43% of headers contain `"webmaster@aclweb.org"`.
   - *Implication:* A naive text classifier trained directly on raw headers and text will overfit to collection artifacts rather than authentic threat patterns.

---

## 1. Dataset-by-Dataset Audit

### 1.1 Enron Email Corpus (`ml/data/raw/enron/Enron.csv`)

- **Dataset Role:** Primary baseline for the `legitimate` class.
- **Provenance:** Carnegie Mellon University (CMU) / CALO Project / Federal Energy Regulatory Commission (FERC) public investigation record, curated in Zenodo Record 8339691.
- **Original Source URL:** `https://www.cs.cmu.edu/~enron/`
- **Total Records:** 29,767
- **Schema / Columns:** `['subject', 'body', 'label']`
- **Field Completeness:**
  - `subject`: 29,569 populated, 198 null (0.67% null rate)
  - `body`: 29,767 populated, 0 null (0.00% null rate)
  - `label`: 29,767 populated, 0 null (0.00% null rate)
  - Headers: Structured sender/receiver headers are **not** present in this CSV subset; body contains forwarded mail routing headers in plain text.
  - Raw `.eml`: Available in the original 1.7 GB CMU maildir archive, but flattened into CSV in this curated distribution.

#### Label Breakdown & Grounding
- **Original Label `0` (15,791 records - 53.05%):** Authentic corporate correspondence between Enron senior management, energy trading desks, and external partners. Mapped strictly to **`legitimate`**.
- **Original Label `1` (13,976 records - 46.95%):** Commercial spam emails (unsolicited software offers, stock pitches, adult entertainment) appended during external benchmark compilation.
- **Audit Finding & Policy:** Label `1` messages are **NOT Enron organizational emails** and are **NOT documented phishing**. Mapping Label `1` to `phishing` or `suspicious` is strictly rejected. All 13,976 records are **quarantined and excluded**.

#### Text Quality & Statistics
- **Empty Body:** 0 (0.00%)
- **Empty Subject:** 198 (0.67%)
- **Very Short Body (< 20 chars):** 133 (0.45%) — mostly meeting acceptances, acknowledgments ("ok", "thanks").
- **Very Long Body (> 10,000 chars):** 255 (0.86%) — long legal agreements, forwarded contracts.
- **Body Length Distribution:** Median: 694 characters, Mean: 1,464.6 characters, Max: 228,353 characters.
- **HTML Content:** 0 messages contain raw HTML tags; text has been normalized to plain ASCII.
- **Duplicates:** Exact full duplicates: 0 (0.00%); Normalized text duplicates: 22 (0.07%).

#### Source Leakage Risk
- `"enron"` appears in **7,186** messages (24.14% of the entire file).
- Models trained on raw text will associate "enron", "hou/ect", or "vince kaminski" with legitimacy, creating artificial accuracy that collapses on modern email.

---

### 1.2 Nazario Phishing Corpus (`ml/data/raw/phishing/Nazario.csv`)

- **Dataset Role:** Ground-truth training data for the `phishing` class.
- **Provenance:** Jose Nazario Phishing Archive (`monkey.org/~jose/phishing/`), curated in Zenodo Record 8339691.
- **Original Source URL:** `https://monkey.org/~jose/phishing/`
- **Total Records:** 1,565
- **Schema / Columns:** `['sender', 'receiver', 'date', 'subject', 'body', 'urls', 'label']`
- **Field Completeness:**
  - `sender`: 1,565 populated, 0 null (0.00% null rate)
  - `receiver`: 1,469 populated, 96 null (6.13% null rate)
  - `date`: 1,564 populated, 1 null (0.06% null rate)
  - `subject`: 1,561 populated, 4 null (0.26% null rate)
  - `body`: 1,563 populated, 2 null/empty (0.13% null rate)
  - `urls`: 1,565 populated, 0 null (0.00% null rate)
  - `label`: 1,565 populated, 0 null (0.00% null rate)
  - Headers: Sender, receiver, and date headers are explicitly present.
  - Raw `.eml`: Originally Unix mbox format; extracted into structured fields with preserved URLs.

#### Label Breakdown & Grounding
- **Original Label `1` (1,565 records - 100.0%):** Hand-verified phishing campaigns collected from active honeypots, mail traps, and user reports.
- **Audit Finding & Policy:** Every record represents genuine phishing (spoofed banking alerts, eBay/PayPal credential harvesting, urgent account suspension threats). Mapped strictly to **`phishing`**.

#### Text Quality & Statistics
- **Empty Body:** 2 (0.13%) — malformed records with empty payloads.
- **Empty Subject:** 4 (0.26%)
- **Very Short Body (< 20 chars):** 9 (0.58%)
- **Very Long Body (> 10,000 chars):** 7 (0.45%)
- **Body Length Distribution:** Median: 720 characters, Mean: 4,730.0 characters, Max: 4,599,644 characters (outlier containing encoded attachment dump).
- **HTML Content:** Plain text representations, but 100% of rows contain extracted malicious URL listings.
- **Duplicates:** Exact full duplicates: 0 (0.00%); Normalized text duplicates: 1 (0.06%).

#### Source Leakage Risk (CRITICAL)
- `"monkey.org"` appears in **620** message bodies (39.62%) and in **1,033** sender/receiver headers (66.01%).
- *Root Cause:* Jose Nazario hosted the archive on `monkey.org`. The local mail delivery system injected `MAILER-DAEMON@monkey.org` and internal routing headers into the mbox files.
- *Mitigation Requirement:* Headers containing `monkey.org` must **never** be exposed as text features to the classifier.

---

### 1.3 CEAS-08 Anti-Spam Challenge (`ml/data/raw/phishing/CEAS_08.csv`)

- **Dataset Role:** Auxiliary source for `legitimate` (Label 0); quarantine source for Label 1.
- **Provenance:** 2008 Conference on Email and Anti-Spam Challenge Evaluation Corpus, curated in Zenodo Record 8339691.
- **Original Source URL:** `http://www.ceas.cc/2008/`
- **Total Records:** 39,154
- **Schema / Columns:** `['sender', 'receiver', 'date', 'subject', 'body', 'label', 'urls']`
- **Field Completeness:**
  - `sender`: 39,154 populated, 0 null (0.00% null rate)
  - `receiver`: 38,692 populated, 462 null (1.18% null rate)
  - `date`: 39,154 populated, 0 null (0.00% null rate)
  - `subject`: 39,126 populated, 28 null (0.07% null rate)
  - `body`: 39,154 populated, 0 null (0.00% null rate)
  - `label`: 39,154 populated, 0 null (0.00% null rate)
  - `urls`: 39,154 populated, 0 null (0.00% null rate)

#### Label Breakdown & Grounding
- **Original Label `0` (17,312 records - 44.22%):** Genuine non-spam ("ham") messages collected across academic, corporate, and private environments to evaluate false-alarm rates. Mapped strictly to **`legitimate`**.
- **Original Label `1` (21,842 records - 55.78%):** Challenge spam submissions. Contains generic unsolicited bulk email (pharmaceutical marketing, financial spam, replicas) alongside phishing.
- **Audit Finding & Policy:** Because CEAS-08 documentation evaluates broad spam rather than isolating phishing, mapping `1 → phishing` violates the no-inference rule. All 21,842 records are **quarantined and excluded**.

#### Text Quality & Statistics
- **Empty Body:** 0 (0.00%)
- **Empty Subject:** 28 (0.07%)
- **Very Short Body (< 20 chars):** 9 (0.02%)
- **Very Long Body (> 10,000 chars):** 593 (1.51%)
- **Body Length Distribution:** Median: 570 characters, Mean: 1,571.1 characters, Max: 143,996 characters.
- **HTML Content:** 2 records retain unparsed HTML blocks.
- **Duplicates:** Exact full duplicates: 0 (0.00%); Normalized text duplicates: 54 (0.14%).

#### Source Leakage Risk (CRITICAL)
- `"ceas"` or `"ceas-challenge"` appears in **23,970** sender/receiver headers (61.22%) and in **4,074** message bodies (10.41%).
- *Root Cause:* Synthetic delivery addresses (e.g., `user4@gvc.ceas-challenge.cc`) were generated for the live competition testbed.
- *Mitigation Requirement:* The recipient domain `ceas-challenge.cc` is an artificial artifact that must be stripped prior to any tokenization.

---

### 1.4 Fraudulent E-mail Corpus (`ml/data/raw/fraud/Nigerian_Fraud.csv`)

- **Dataset Role:** Ground-truth training data for the `fraud_related` class.
- **Provenance:** Dragomir Radev (2008), CLAIR collection of fraud email, ACL Data and Code Repository `ADCR2008T001`; mirrored on Kaggle (`rtatman/fraudulent-email-corpus`) and Zenodo Record 8339691.
- **Original Source URL:** `https://www.kaggle.com/datasets/rtatman/fraudulent-email-corpus`
- **Total Records:** 3,332
- **Schema / Columns:** `['sender', 'receiver', 'date', 'subject', 'body', 'urls', 'label']`
- **Field Completeness:**
  - `sender`: 3,001 populated, 331 null (9.93% null rate)
  - `receiver`: 2,008 populated, 1,324 null (39.74% null rate)
  - `date`: 2,850 populated, 482 null (14.47% null rate)
  - `subject`: 3,293 populated, 39 null (1.17% null rate)
  - `body`: 3,331 populated, 1 null/empty (0.03% null rate)
  - `urls`: 3,332 populated, 0 null (0.00% null rate)
  - `label`: 3,332 populated, 0 null (0.00% null rate)

#### Label Breakdown & Grounding
- **Original Label `1` (3,332 records - 100.0%):** Genuine 419 / advance-fee fraud solicitations.
- **Audit Finding & Policy:** Sourced from public submissions of scam correspondence. Mapped strictly to **`fraud_related`**.

#### Text Quality & Usability for `fraud_related`
- **Is there enough usable body and subject content?**
  - **YES, exceptionally rich text.** The median body length is **2,547 characters** (mean: 2,644.4 characters), which is more than 3.5× longer than Enron and Nazario messages.
  - Advance-fee fraud relies heavily on narrative deception, complex backstories (foreign dignitaries, oil contracts, unclaimed inheritances, escrow transfers), and specific psychological urgency cues.
  - Key vocabulary frequencies:
    - `"deceased"`: 609 messages (18.28%)
    - `"transfer"`: 1,942 messages (58.28%)
    - `"bank"`: 1,811 messages (54.35%)
    - `"assistance"`: 1,234 messages (37.03%)
    - `"funds"` / `"fund"`: 2,105 messages (63.18%)
- **Empty Body:** 1 (0.03%)
- **Empty Subject:** 39 (1.17%)
- **Very Short Body (< 20 chars):** 1 (0.03%)
- **Very Long Body (> 10,000 chars):** 17 (0.51%)
- **HTML Content:** 5 records contain HTML tags.
- **Duplicates:** Exact full duplicates: 0 (0.00%); Normalized text duplicates: 16 (0.48%).

#### Source Leakage Risk
- `"webmaster@aclweb.org"` appears in **181** sender/receiver fields (5.43%), and `"aclweb.org"` in **190** records (5.70%).
- *Root Cause:* The collector (Dragomir Radev) served as the ACL webmaster, and scam emails were harvested from forwarding rules to `webmaster@aclweb.org`.
- *Mitigation Requirement:* Must strip `aclweb.org` from header strings during feature extraction.

---

## 2. Cross-Dataset Overlap & Leakage Assessment

A pairwise cross-dataset matching audit was executed to evaluate whether identical or duplicate messages exist across the 4 corpora:

| Dataset Pair | Identical (Subject + Body) Matches | Shared Subject Lines | Sample Shared Subject Topics |
| :--- | :---: | :---: | :--- |
| **Enron ↔ Nazario** | **0** | 13 | `"hello"`, `"meeting"`, `"update"`, `"thank you"` |
| **Enron ↔ CEAS_08** | **0** | 30 | `"presentation"`, `"contract"`, `"schedule"`, `"invoice"` |
| **Enron ↔ Nigerian_Fraud** | **0** | 115 *(109 from Enron spam; only 23 from Enron ham)* | `"business proposal"`, `"confidential"`, `"urgent"`, `"assistance"` |
| **Nazario ↔ CEAS_08** | **0** | 6 | `"security alert"`, `"account verification"`, `"notice"` |
| **Nazario ↔ Nigerian_Fraud** | **0** | 5 | `"urgent notification"`, `"claim your prize"` |
| **CEAS_08 ↔ Nigerian_Fraud** | **0** | 13 | `"partnership"`, `"business transaction"`, `"urgent"` |

### Key Finding on Cross-Corpora Overlap
There are **zero exact text duplicates** between any of the four datasets. The shared subject strings represent universal email tropes rather than duplicated messages. Crucially, 109 of the 115 shared subjects between Enron and Nigerian Fraud occurred exclusively in Enron's **Label 1 (spam)** subset, reinforcing the necessity of quarantining Enron Label 1.

---

## 3. Data Quality & Distribution Summary

### Data Quality Summary Table
*(Generated in [data_quality_report.csv](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/metadata/data_quality_report.csv))*

| Dataset | Total Records | Empty Subject | Empty Body | Exact Duplicates | Malformed Records | Very Short (<20 chars) | Very Long (>10k chars) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Enron** | 29,767 | 198 | 0 | 0 | 0 | 133 | 255 |
| **Nazario** | 1,565 | 4 | 2 | 0 | 2 | 9 | 7 |
| **CEAS_08** | 39,154 | 28 | 0 | 0 | 0 | 9 | 593 |
| **Nigerian_Fraud** | 3,332 | 39 | 1 | 0 | 1 | 1 | 17 |
| **Total** | **73,818** | **269** | **3** | **0** | **3** | **152** | **872** |

### Usable Class Distribution Table
*(Generated in [class_distribution.csv](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/metadata/class_distribution.csv))*

| Class | Source Dataset & Split | Count | % of Usable Pool | % of Total Downloaded |
| :--- | :--- | :---: | :---: | :---: |
| **`legitimate`** | Enron (Label `0`) | 15,791 | 41.56% | 21.39% |
| **`legitimate`** | CEAS_08 (Label `0`) | 17,312 | 45.56% | 23.45% |
| **`phishing`** | Nazario (Label `1`) | 1,565 | 4.12% | 2.12% |
| **`fraud_related`** | Nigerian_Fraud (Label `1`) | 3,332 | 8.77% | 4.51% |
| **Total Usable** | — | **38,000** | **100.00%** | **51.48%** |
| *QUARANTINED* | Enron (Label `1` - Spam) | 13,976 | — | 18.93% |
| *QUARANTINED* | CEAS_08 (Label `1` - Spam) | 21,842 | — | 29.59% |
| **Total Quarantined**| — | **35,818** | — | **48.52%** |

---

## 4. Licenses and Research Terms Review

| Dataset | Stated License / Terms | Commercial Use | Educational / Student Project | Attribution Requirement |
| :--- | :--- | :---: | :---: | :--- |
| **Enron Email Corpus** | Public Domain (FERC investigation record; CALO project) | Permitted | **Fully Permitted** | Required (cite CMU Enron / CALO) |
| **Nazario Phishing Corpus** | Public Research Archive / CC-BY 4.0 (Zenodo Record 8339691) | Permitted | **Fully Permitted** | Required (cite Jose Nazario) |
| **CEAS-08 Challenge** | Open Benchmark / CC-BY 4.0 (Zenodo Record 8339691) | Permitted | **Fully Permitted** | Required (cite CEAS 2008 Conference) |
| **Fraudulent E-mail Corpus** | Creative Commons Attribution-ShareAlike (CC BY-SA 3.0 / 4.0) | Permitted with ShareAlike | **Fully Permitted** | Required (cite D. Radev, ACL ADCR2008T001) |

All four datasets are legally and ethically permissible for academic research, hackathons, and student software development.

---

## 5. Audit Recommendations & Retention Verdicts

| Dataset | Retention Verdict | Recommended Role in Pipeline | Operational Directives |
| :--- | :---: | :--- | :--- |
| **Enron Email Corpus** | **PARTIALLY RETAINED** | Primary baseline for `legitimate` | Filter strictly on `label == 0` (15,791 records). Completely drop `label == 1`. Clean `enron.com` domain artifacts during text preprocessing. |
| **Nazario Phishing Corpus** | **RETAINED** | Ground truth for `phishing` | Retain all 1,565 records. Exclude header text containing `monkey.org` to prevent severe training leakage. |
| **CEAS-08 Challenge** | **PARTIALLY RETAINED** | Evaluation baseline for `legitimate` | Retain `label == 0` (17,312 records) for evaluation/holdout testing. Discard `label == 1` challenge spam. Strip `ceas-challenge.cc` recipient addresses. |
| **Fraudulent E-mail Corpus** | **RETAINED** | Ground truth for `fraud_related` | Retain all 3,332 records. Highly suitable text length. Strip `webmaster@aclweb.org` from headers. |

---

## 6. Target Class Readiness & Missing Information Assessment

| Target Class | Reliable Data Available? | Current Sample Size | Readiness Assessment | Missing Information / Action Required |
| :--- | :---: | :---: | :---: | :--- |
| **`legitimate`** | **YES** | 33,103 | **Production Ready** | Sufficient volume. Need domain neutralization to prevent Enron-specific memorization. |
| **`phishing`** | **PARTIALLY** | 1,565 | **Viable for Baseline, but Underrepresented** | Ratio is 1:21 against legitimate mail. Need data augmentation or complementary verified phishing sets (e.g., IWSPA-AP full-header sets or modern APWG feeds). |
| **`fraud_related`** | **YES** | 3,332 | **Ready for Baseline** | Excellent semantic signal (419 advance-fee schemes). Needs modern BEC invoice fraud examples for broader coverage. |
| **`suspicious`** | **NO** | 0 | **Not Ready (Deferred by Policy)** | No natural ground truth exists. Must be implemented downstream via prediction confidence thresholds, not static training labels. |
| **`impersonated`** | **NO** | 0 | **Not Ready (Deferred by Policy)** | Cannot be classified by text alone. Strictly dependent on Module 1 (`modules/sender_identity/`) forensic authentication features (SPF/DKIM alignment, display name mismatch). |
