# Model 1 Labeling Policy & Class Grounding Specification

**Project:** SIH26106 — Email Threat Classification (Model 1)  
**Status:** Phase 1 Training Data Curation  
**Governing Rule:** Absolute label integrity and provenance. No synthetic generation, no LLM auto-labeling, and no arbitrary class coercion.

---

## 1. Confidently Supported Classes (Phase 1)

At this initial phase, only three target classes are grounded in authentic, verified public corpora with researcher-assigned ground truth:

| Class | Primary Data Sources | Ground Truth Basis | Scope & Definition |
| :--- | :--- | :--- | :--- |
| **`legitimate`** | **Enron Email Corpus** (`Enron.csv`, Label `0`: 15,791 msgs)<br>**CEAS-08 Corpus** (`CEAS_08.csv`, Label `0`: 17,312 msgs) | Authentic corporate email from FERC public investigation & human-verified ham from CEAS challenge | Benign organizational, operational, and interpersonal communications free of deceptive intent, malicious payloads, or scam solicitations. |
| **`phishing`** | **Nazario Phishing Corpus** (`Nazario.csv`, Label `1`: 1,565 msgs) | Curated security archive of verified credential harvesting and malicious link campaigns | Emails constructed to deceive recipients into entering credentials, clicking malicious links, or disclosing sensitive corporate/banking information. |
| **`fraud_related`** | **CLAIR Fraudulent Email Corpus** (`Nigerian_Fraud.csv`, Label `1`: 3,332 msgs) | ACL Data Repository (ADCR2008T001) / Kaggle collection of 419 advance-fee fraud | Explicitly fraudulent communications involving advance-fee schemes, fake lottery wins, inheritance scams, or unauthorized funds transfer requests. |

---

## 2. Policy on Deferred Classes: Why `suspicious` and `impersonated` Are Excluded at This Stage

### 2.1 Why We DO NOT Manufacture `suspicious`
1. **Lack of Objective Ground Truth:** No natural public email corpus contains an authentic, human-labeled "suspicious" category. In real-world security operations, "suspicious" is not an inherent email category; rather, it is a **policy triage verdict** or **confidence boundary** (e.g., model prediction confidence between $0.40$ and $0.70$, or emails triggering partial heuristics).
2. **Harm of Synthetic Manufacture:** Arbitrarily labeling noisy spam, newsletters, or ambiguous emails as "suspicious" injects severe label noise and damages model calibration.
3. **Future Implementation Strategy:**
   - In subsequent development, `suspicious` will be derived through **calibrated prediction uncertainty** and **multi-signal triage** (e.g., when NLP text probabilities conflict with forensic header flags from Module 1), rather than forcing noisy training labels into a fixed bucket.

### 2.2 Why We DO NOT Manufacture `impersonated`
1. **Dependency on Forensic Headers:** Impersonation (CEO fraud, display name spoofing, cousin-domain spoofing, lookalike domains) cannot be determined reliably from subject and body text alone. An email reading *"Please process the attached invoice immediately"* is only impersonated if the envelope sender, display name, and SPF/DKIM/DMARC authentication fail to align with the authentic executive or vendor.
2. **Independence from Module 1:** Module 1 (`modules/sender_identity/`) specifically specializes in Sender Identity Spoofing analysis. Generating or guessing "impersonated" labels without Module 1 forensic signals would create invalid artifacts, merge conflicts, and ungrounded data.
3. **Absence of Clean Public Real-World Corpora:** Public datasets containing authentic corporate executive impersonation are nearly nonexistent due to strict NDA and enterprise privacy constraints; existing public attempts rely on synthetic Faker templates which introduce severe synthetic bias.
4. **Future Implementation Strategy:**
   - The `impersonated` category will be integrated once Module 1 forensic features (display name mismatch, header anomaly scores, domain similarity metrics) are formally combined with Model 1 text features.

---

## 3. Strict Dataset Mapping Rules

1. **`spam != phishing`**: Generic bulk spam (promotional marketing, unsolicited pharmaceuticals, non-targeted newsletters) must **never** be relabeled as `phishing`. The 13,976 spam messages in `Enron.csv` (Label `1`) and the 21,842 challenge spam messages in `CEAS_08.csv` (Label `1`) are strictly quarantined and excluded from `phishing`.
2. **`ham == legitimate` with Validation**: Only emails from verified organizational contexts (Enron corporate archives) or human-cleared ham splits are assigned to `legitimate`.
3. **`419 scam == fraud_related`**: advance-fee scams are classified as `fraud_related` solely because the dataset is explicitly documented and validated as fraudulent by academic researchers (CLAIR/ACL). This label is not extended to general spam.
4. **Original Raw Data Preservation**: All original files in `ml/data/raw/` remain bit-for-bit unchanged.
