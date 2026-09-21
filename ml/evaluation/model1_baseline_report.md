# SIH26106 — Model 1 (NLP Baseline) Technical Report

## 1. Dataset Overview

- **Balanced Dataset:** `ml/data/processed/emails_balanced.csv`
- **Total Records:** 11,338
- **Train Records (70%):** 7,936
- **Validation Records (15%):** 1,701
- **Test Records (15%):** 1,701

## 2. Split Methodology

Splits were generated using stratified random sampling on the composite key `our_label + '_' + source_dataset` with `random_state=42`. This ensures that every individual dataset and class is proportionally represented in Train, Validation, and Test.

## 3. Leakage Checks

- **Exact `text_hash` Overlap:** 0 records across all splits.
- **Normalized Text Overlap:** 0 records across all splits.
- **Feature Separation:** TF-IDF was fitted strictly on `train.csv`.

## 4. TF-IDF Configuration

- `ngram_range`: `(1, 2)`
- `sublinear_tf`: `True`
- `min_df`: `3`
- `max_df`: `0.95`
- `strip_accents`: `unicode`
- `lowercase`: `True`
- **Vocabulary Size:** 131,017 n-grams

## 5. Logistic Regression Configuration

- `C`: `1.0`
- `penalty`: `l2`
- `solver`: `lbfgs`
- `max_iter`: `2000`
- `class_weight`: `balanced`
- `random_state`: `42`

## 6. Validation Results

- **Accuracy:** 99.00%
- **Macro Precision:** 98.67%
- **Macro Recall:** 98.72%
- **Macro F1:** 98.69%
- **Weighted F1:** 99.00%

| Class | Precision | Recall | F1-Score | Validation Support |
| :--- | :---: | :---: | :---: | :---: |
| **`legitimate`** | 98.98% | 99.49% | **99.23%** | 974 |
| **`phishing`** | 97.03% | 98.28% | **97.65%** | 233 |
| **`fraud_related`** | 100.00% | 98.38% | **99.18%** | 494 |

## 7. Test Results (Final Evaluation)

- **Accuracy:** 99.24%
- **Macro Precision:** 98.91%
- **Macro Recall:** 98.98%
- **Macro F1:** 98.94%
- **Weighted F1:** 99.24%

| Class | Precision | Recall | F1-Score | Test Support |
| :--- | :---: | :---: | :---: | :---: |
| **`legitimate`** | 99.28% | 99.49% | **99.39%** | 976 |
| **`phishing`** | 97.44% | 98.28% | **97.85%** | 232 |
| **`fraud_related`** | 100.00% | 99.19% | **99.59%** | 493 |

## 8. Confusion Matrix Interpretation

Confusion matrices have been saved to `ml/evaluation/model1_validation_confusion_matrix.png` and `ml/evaluation/model1_test_confusion_matrix.png`.

## 9. Error Analysis Summary

See [`ml/evaluation/model1_error_analysis.md`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/evaluation/model1_error_analysis.md) for full breakdown.

## 10. Top Model Features

See [`ml/evaluation/model1_top_features.md`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/evaluation/model1_top_features.md) for top positive n-grams per class.

## 11. Limitations

1. **Text-Only Scope:** Relies entirely on email subject and body vocabulary. Has zero visibility into sender authentication (SPF/DKIM/DMARC) or network spoofing.
2. **Lexical Mimicry Vulnerability:** Highly sophisticated targeted spear-phishing that mimics internal memos without classic credential-phishing keywords may be misclassified as legitimate.
3. **Zero Dynamic Intelligence:** No URL reputation, passive DNS, or graph intelligence features are utilized in this baseline.

## 12. Next Experiments

1. **Feature Enhancement:** Integrate domain reputation and structural lexical features (URL count, domain entropy, HTML tag ratio).
2. **Classifier Exploration:** Compare Logistic Regression against LightGBM and Transformer embeddings.
3. **Investigation Layer:** Integrate Module 1 forensic signals to implement multi-tier routing for `suspicious` and `impersonated`.
