# SIH26106 — Dataset Split & Data Leakage Audit Report

## 1. Split Configuration & Methodology

- **Source Dataset:** [`ml/data/processed/emails_balanced.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/emails_balanced.csv)
- **Total Population:** **11,338** records
- **Split Ratios:** 70% Train, 15% Validation, 15% Test
- **Random Seed:** `random_state=42`
- **Stratification Strategy:** Stratified on the composite key `our_label + "_" + source_dataset`. This ensures that every individual data source (Enron, CEAS, TREC-06, TREC-07, SpamAssassin, Ling, Nazario, Nigerian Fraud) maintains proportional representation across all three partitions.

---

## 2. Partition Summary & Counts

| Partition | Record Count | Proportion of Corpus | File Location |
| :--- | :---: | :---: | :--- |
| **Train Set** | **7,936** | 69.99% | [`ml/data/processed/train.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/train.csv) |
| **Validation Set** | **1,701** | 15.00% | [`ml/data/processed/validation.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/validation.csv) |
| **Test Set** | **1,701** | 15.00% | [`ml/data/processed/test.csv`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/data/processed/test.csv) |
| **Total** | **11,338** | 100.00% | — |

---

## 3. Data Leakage Audit

Before training, the partitions were verified against both exact and near-duplicate leakage:

| Leakage Test | Train $\leftrightarrow$ Validation | Train $\leftrightarrow$ Test | Validation $\leftrightarrow$ Test | Status |
| :--- | :---: | :---: | :---: | :---: |
| **Exact `text_hash` Overlap** | **0** | **0** | **0** | ✅ Clean (0% Leakage) |
| **Normalized Text Overlap** (whitespace-collapsed, lowercase) | **0** | **0** | **0** | ✅ Clean (0% Leakage) |
| **Record ID Overlap** | **0** | **0** | **0** | ✅ Clean (0% Leakage) |

---

## 4. Class Distribution Across Splits

The multi-class balance is preserved across partitions:

| Class | Train ($n=7,936$) | Validation ($n=1,701$) | Test ($n=1,701$) | Target Share |
| :--- | :---: | :---: | :---: | :---: |
| **`legitimate`** | 4,550 (57.33%) | 974 (57.26%) | 976 (57.38%) | ~57.3% |
| **`fraud_related`** | 2,303 (29.02%) | 494 (29.04%) | 493 (28.98%) | ~29.0% |
| **`phishing`** | 1,083 (13.65%) | 233 (13.70%) | 232 (13.64%) | ~13.7% |

---

## 5. Source Distribution Across Splits

Every individual origin corpus is distributed in proportion across splits:

| Source Dataset | Class | Train ($n=7,936$) | Validation ($n=1,701$) | Test ($n=1,701$) | Total in Corpus |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`Nigerian_Fraud`** | `fraud_related` | 2,303 (29.02%) | 494 (29.04%) | 493 (28.98%) | 3,290 |
| **`TREC_07`** | `legitimate` | 1,458 (18.37%) | 312 (18.34%) | 313 (18.40%) | 2,083 |
| **`Nazario`** | `phishing` | 1,083 (13.65%) | 233 (13.70%) | 232 (13.64%) | 1,548 |
| **`CEAS_08`** | `legitimate` | 1,035 (13.04%) | 222 (13.05%) | 222 (13.05%) | 1,479 |
| **`Enron`** | `legitimate` | 927 (11.68%) | 199 (11.70%) | 198 (11.64%) | 1,324 |
| **`TREC_06`** | `legitimate` | 741 (9.34%) | 158 (9.29%) | 159 (9.35%) | 1,058 |
| **`SpamAssassin`** | `legitimate` | 245 (3.09%) | 52 (3.06%) | 53 (3.12%) | 350 |
| **`Ling`** | `legitimate` | 144 (1.81%) | 31 (1.82%) | 31 (1.82%) | 206 |
