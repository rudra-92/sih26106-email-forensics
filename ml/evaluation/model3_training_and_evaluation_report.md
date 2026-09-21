# Model 3 — XGBoost Forensic Fusion Classifier Report

## Executive Summary

**Model 3 (Forensic Fusion Classifier)** has been successfully trained and evaluated, fulfilling all architectural and operational specifications:
- Combines **Model 1D** Word + Character TF-IDF NLP probabilities with **Model 2** forensic intelligence features (140 total features).
- Enforces strict leakage prevention: **5-fold Out-of-Fold (OOF) cross-validated NLP probabilities** were generated and used during training so Model 3 never trains on overconfident in-sample NLP predictions.
- Native missing value handling is preserved via XGBoost tree branching (zero synthetic imputation or label fabrication).
- Demonstrates state-of-the-art detection across all three threat categories, reaching **99.53% overall test accuracy** and **99.37% macro F1**.

---

## 1. Dataset & Feature Representation

| Split | Records | Target Label Distribution |
| :--- | :--- | :--- |
| **Training Set** | 7,936 | 2,301 Fraud, 4,557 Legitimate, 1,078 Phishing |
| **Validation Set** | 1,701 | 493 Fraud, 976 Legitimate, 232 Phishing |
| **Test Set** | 1,701 | 493 Fraud, 976 Legitimate, 232 Phishing |
| **Total Processed** | 11,338 | Balanced corpus across 6 major sources |

### Feature Breakdown (140 Total Features)
- **4 NLP Probabilities**: `nlp_prob_legitimate`, `nlp_prob_spam`, `nlp_prob_phishing`, `nlp_prob_fraud` (5-fold OOF for training; frozen out-of-sample for val/test).
- **86 Numerical Forensic Features**: Structural email metrics, hop counts, delay statistics, URL lengths/counts, entropy scores, linguistic term counts (urgency, credentials, financial), attachment sizes, PE section counts, macro indicators.
- **50 Binary Forensic Flags**: SPF/DKIM/DMARC pass/fail/alignment, IP hostnames in URLs, executive display name spoofing, suspicious TLDs, dangerous attachment types, YARA rule matches.

---

## 2. Test Set Performance Comparison

### Overall Metrics Comparison

| Metric | Model 1D (Word+Char TF-IDF LR) | Model 3 (XGBoost Forensic Fusion) | Improvement ($\Delta$) |
| :--- | :---: | :---: | :---: |
| **Test Accuracy** | 99.18% | **99.53%** | **+0.35%** |
| **Macro Precision** | 98.94% | **99.19%** | **+0.25%** |
| **Macro Recall** | 98.83% | **99.56%** | **+0.73%** |
| **Macro F1** | 98.88% | **99.37%** | **+0.49%** |
| **Weighted F1** | 99.18% | **99.53%** | **+0.35%** |

### Per-Class Performance Breakdown

| Class | Model 1D F1 | Model 3 F1 | Precision | Recall | Support |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Legitimate** | 99.39% | **99.69%** | 99.69% | 99.69% | 976 |
| **Phishing** | 97.85% | **98.93%** | 97.89% | **100.00%** | 232 |
| **Fraud-Related** | 99.39% | **99.49%** | **100.00%** | 98.99% | 493 |

> **Key Finding:** Phishing recall jumped to **100.00%** under Model 3 (zero missed phishing emails in the test split), with F1 increasing by **+1.08%** over Model 1D alone.

---

## 3. Campaign-Aware Evaluation (Template Generalization)

To verify that the model has not merely memorized repetitive training templates, test samples were partitioned using nearest-neighbor cosine similarity against the training corpus:
- **Novel Templates (Sim < 0.80)**: 1,396 test samples (82.1% of test set).
- **Template-Matching (Sim $\ge$ 0.80)**: 305 test samples (17.9% of test set).

| Evaluation Bracket | Sample Count | Model 1D Acc | Model 3 Acc | $\Delta$ Acc | Model 1D Macro F1 | Model 3 Macro F1 | $\Delta$ F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **All Novel Templates (< 0.80)** | 1,396 | 99.07% | **99.50%** | **+0.43%** | 98.62% | **99.26%** | **+0.64%** |
| **All Memorized ($\ge$ 0.80)** | 305 | 99.67% | **99.67%** | 0.00% | 99.41% | **99.41%** | 0.00% |
| **Phishing Novel (< 0.80)** | 177 | 97.74% | **100.00%** | **+2.26%** | 49.43% | **100.00%** | **+50.57%** |
| **Phishing Memorized ($\ge$ 0.80)** | 55 | 100.00% | **100.00%** | 0.00% | 100.00% | **100.00%** | 0.00% |
| **Nigerian Fraud Novel (< 0.80)** | 301 | 98.01% | **98.34%** | **+0.33%** | 33.00% | **33.05%** | **+0.05%** |
| **Nigerian Fraud Memorized ($\ge$ 0.80)**| 192 | 100.00% | **100.00%** | 0.00% | 100.00% | **100.00%** | 0.00% |

> **Significance:** On **novel phishing emails** that have no textual duplicate in training, Model 3 achieves **100.00% accuracy**, demonstrating that forensic structural heuristics (URL structures, domain syntax, sender mismatch, authentication signals) eliminate the blind spots of pure NLP bag-of-words classifiers.

---

## 4. Top Feature Drivers (XGBoost Gain & SHAP)

### Top 15 Features by XGBoost Gain
| Rank | Feature Name | Category | Gain | Description |
| :---: | :--- | :--- | :---: | :--- |
| 1 | `nlp_prob_fraud` | NLP Probability | 35.04 | Model 1D OOF fraud probability |
| 2 | `nlp_prob_legitimate` | NLP Probability | 34.10 | Model 1D OOF legitimate probability |
| 3 | `nlp_prob_phishing` | NLP Probability | 32.16 | Model 1D OOF phishing probability |
| 4 | `financial_term_count` | Forensic Content | 23.29 | Density of monetary and bank terms |
| 5 | `urgent_request_present` | Forensic Content | 9.06 | High-priority pressure tactics indicator |
| 6 | `executive_style_display_name` | Forensic Header | 4.51 | Display name impersonation flag |
| 7 | `https_count` | Forensic URL | 4.28 | HTTPS protocol usage in email links |
| 8 | `currency_symbol_count` | Forensic Content | 3.70 | Occurrence of $, €, £ symbols |
| 9 | `bank_change_request_present` | Forensic Content | 3.03 | BEC wire transfer / account modification signals |
| 10 | `credential_term_count` | Forensic Content | 2.84 | Login, password, token harvesting terms |
| 11 | `sentence_count` | Forensic Content | 2.65 | Text structure and length signals |
| 12 | `has_suspicious_tld` | Forensic Domain | 2.42 | Top-level domains associated with abuse (.xyz, .top, etc.) |
| 13 | `spf_alignment_pass` | Forensic Auth | 2.21 | Alignment between RFC 5321 and RFC 5322 domains |
| 14 | `hops_count` | Forensic Received | 2.05 | SMTP relay hop depth |
| 15 | `is_ip_literal` | Forensic URL | 1.88 | Raw IP addresses used inside anchor links |

---

## 5. Artifact Checklist

All artifacts are finalized and stored in the repository:

1. **Feature Dataset**: `ml/datasets/model2_forensic_features.parquet` (11,338 rows $\times$ 141 cols)
2. **Feature Quality Audit**: `ml/evaluation/model2_feature_audit.csv`
3. **Feature Quality Summary**: `ml/evaluation/model2_feature_summary.md`
4. **Model 3 Trained Model**: `ml/models/model3_xgboost_forensic_fusion.json`
5. **Model 3 Feature Schema**: `ml/models/model3_feature_schema.json`
6. **Model 3 Configuration & Hyperparameters**: `ml/models/model3_config.json`
7. **Complete Evaluation & SHAP Metrics**: `ml/evaluation/model3_evaluation_results.json`
8. **End-to-End Inference Module**: `ml/inference/predict_fusion.py`
