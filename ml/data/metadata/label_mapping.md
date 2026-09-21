# Dataset Label Mapping Specification

**Project:** SIH26106 — Email Threat Classification (Model 1)  
**Task:** Machine Learning Dataset Audit & Grounding  
**Policy:** Absolute provenance integrity. Original labels must have explicit source documentation supporting their mapping. No speculative, synthetic, or generalized label conversions.

---

## 1. Summary of Label Mappings

| Dataset | Original Label | Record Count | Our Mapped Label | Mapping Status | Primary Justification |
| :--- | :---: | :---: | :--- | :---: | :--- |
| **Enron Email Corpus** | `0` | 15,791 | **`legitimate`** | **MAPPED** | Authentic corporate emails from Enron management released during FERC investigation. Represents genuine organizational correspondence. |
| **Enron Email Corpus** | `1` | 13,976 | **`NOT MAPPED`** | **QUARANTINED** | Commercial spam injected into this benchmark subset during external compilation. Does not represent Enron emails, nor is it documented phishing. Cannot be mapped to `phishing`, `legitimate`, or `suspicious`. |
| **Nazario Phishing Corpus** | `1` | 1,565 | **`phishing`** | **MAPPED** | Curated cybersecurity repository of confirmed phishing and credential-harvesting attacks collected by Jose Nazario. Explicitly documented ground-truth phishing. |
| **CEAS-08 Challenge** | `0` | 17,312 | **`legitimate`** | **MAPPED** | Verified non-spam ("ham") messages curated for the 2008 Conference on Email and Anti-Spam competition. Genuine benign communication. |
| **CEAS-08 Challenge** | `1` | 21,842 | **`NOT MAPPED`** | **QUARANTINED** | Heterogeneous challenge spam collection (unsolicited commercial emails, generic ads, spam). The CEAS documentation does not differentiate targeted phishing from generic bulk spam. Relabeling spam → phishing is strictly prohibited by policy. |
| **Fraudulent E-mail Corpus** | `1` | 3,332 | **`fraud_related`** | **MAPPED** | CLAIR collection (ACL ADCR2008T001) / Kaggle collection of Nigerian 419 advance-fee fraud solicitations. Ground truth is explicitly documented as fraudulent schemes (lottery, inheritance, funds transfer). Not generalized to generic spam. |

---

## 2. Detailed Dataset-by-Dataset Mapping Rationale

### 2.1 Enron Email Corpus (`ml/data/raw/enron/Enron.csv`)

#### Mapping: `0 → legitimate`
- **Original Meaning:** Ham / Benign communication from Enron employees and management.
- **Justification:** Sourced from the historical FERC investigation public release and curated by the CALO project (SRI/CMU). Represents real-world internal and B2B corporate correspondence.
- **Action:** Retain all 15,791 records as the primary training baseline for the `legitimate` class.

#### Mapping: `1 → NOT MAPPED`
- **Original Meaning:** Spam messages included in benchmark distributions (e.g., promotional flyers, software sales, stock touts).
- **Justification:** The dataset documentation explicitly identifies these as external unsolicited spam, not Enron correspondence. Converting bulk spam to `phishing` would corrupt the phishing feature space with generic marketing signals. Converting it to `suspicious` would manufacture an unverified intermediate category.
- **Action:** Quarantine all 13,976 records. Exclude from Model 1 training and evaluation.

---

### 2.2 Nazario Phishing Corpus (`ml/data/raw/phishing/Nazario.csv`)

#### Mapping: `1 → phishing`
- **Original Meaning:** Verified phishing email samples.
- **Justification:** Hand-curated by cybersecurity researcher Jose Nazario between 2005 and 2019 specifically to study social engineering, spear-phishing lures, spoofed banking pages, and credential interception.
- **Action:** Retain all 1,565 records for the `phishing` class.

---

### 2.3 CEAS-08 Anti-Spam Challenge (`ml/data/raw/phishing/CEAS_08.csv`)

#### Mapping: `0 → legitimate`
- **Original Meaning:** Verified legitimate ("ham") email messages collected for the 2008 challenge.
- **Justification:** Represents real benign email traffic used to evaluate false-positive rates of commercial and academic spam filters.
- **Action:** Retain 17,312 records as auxiliary legitimate data (monitoring for challenge header leakage).

#### Mapping: `1 → NOT MAPPED`
- **Original Meaning:** Challenge spam submissions.
- **Justification:** The CEAS 2008 challenge evaluated general spam filtering, meaning label `1` contains pharmaceutical ads, product pitches, chain letters, and random spam alongside potential phishing attacks. Because there is no granular breakdown distinguishing phishing from benign bulk spam, mapping `1 → phishing` directly violates the project's strict labeling rule:
  > *"Do not convert spam → phishing unless the dataset documentation explicitly supports that interpretation."*
- **Action:** Quarantine all 21,842 records. Exclude from Model 1 training.

---

### 2.4 Fraudulent E-mail Corpus (`ml/data/raw/fraud/Nigerian_Fraud.csv`)

#### Mapping: `1 → fraud_related`
- **Original Meaning:** Fraudulent 419 / advance-fee scam emails.
- **Justification:** Registered in the ACL Data and Code Repository under ID `ADCR2008T001` (Dragomir Radev, 2008). Every record represents an advance-fee fraud solicitation (e.g., Nigerian prince, deceased banker, foreign lottery payout, contract over-invoicing).
- **Action:** Retain all 3,332 records as the ground-truth training set for `fraud_related`.

---

## 3. Policy on Deferred Target Classes

1. **`suspicious`:**
   - Status: **`NOT MAPPED` (0 records assigned)**
   - Rationale: None of the audited datasets contain an organic, researcher-verified "suspicious" ground-truth label. Labeling low-confidence spam or ambiguous text as "suspicious" would constitute subjective label manufacturing. In production, this class will be defined dynamically through prediction entropy or forensic conflict bands.

2. **`impersonated`:**
   - Status: **`NOT MAPPED` (0 records assigned)**
   - Rationale: Executive and sender impersonation requires forensic header verification (SPF/DKIM alignment, display name spoofing, cousin domains) handled by Module 1. Text-only datasets cannot reliably establish impersonation without introducing severe synthetic bias.
