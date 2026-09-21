# SIH26106 — Dataset Balancing & Rebalancing Report

## 1. Overview

This document records the rectification of the initial 49:1 class imbalance in the SIH26106 email corpus. Under the **ZERO LABEL MANUFACTURING** policy, no synthetic samples were generated and no labels were manufactured. Balance was achieved via **source-stratified downsampling** of the majority `legitimate` class and an optional non-contaminating **`spam` class extraction**.

## 2. Before vs. After Comparison

### 2.1 Three-Class Configuration (Model 1 v1 Default)

| Class | Original Count | Original % | Balanced Count | Balanced % | Ratio (vs Phishing) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **`legitimate`** | 75,946 | 94.0% | **6,500** | **57.3%** | **4.2 : 1** |
| **`fraud_related`** | 3,290 | 4.1% | **3,290** | **29.0%** | **2.1 : 1** |
| **`phishing`** | 1,548 | 1.9% | **1,548** | **13.7%** | **1.0 : 1** |
| **Total** | 80,784 | 100.0% | **11,338** | 100.0% | — |

### 2.2 Four-Class Configuration (With Explicit Verified Spam)

| Class | Balanced Count | Balanced % | Ratio (vs Phishing) | Source Pool |
| :--- | :---: | :---: | :---: | :--- |
| **`legitimate`** | **6,500** | **45.2%** | **4.2 : 1** | Enron, CEAS, TREC, SpamAssassin, Ling |
| **`spam`** | **3,036** | **21.1%** | **2.0 : 1** | Enron, CEAS, TREC, SpamAssassin, Ling |
| **`fraud_related`** | **3,290** | **22.9%** | **2.1 : 1** | Radev CLAIR 419 |
| **`phishing`** | **1,548** | **10.8%** | **1.0 : 1** | Jose Nazario Phishing |
| **Total** | **14,374** | 100.0% | — | All Accepted Pools |

## 3. Source-Stratified Legitimate Allocation

To prevent the classifier from overfitting to any single company's vocabulary, legitimate samples were downsampled in exact proportion to their available population across all 6 verified sources:

| Source Dataset | Cleaned Available | Downsampled Allocation | Stratified Proportion |
| :--- | :---: | :---: | :---: |
| `TREC_07` | 24,341 | **2,083** | 32.0% |
| `CEAS_08` | 17,282 | **1,479** | 22.8% |
| `Enron` | 15,472 | **1,324** | 20.4% |
| `TREC_06` | 12,361 | **1,058** | 16.3% |
| `SpamAssassin` | 4,090 | **350** | 5.4% |
| `Ling` | 2,400 | **206** | 3.2% |

## 4. How to Handle 'Suspicious' and 'Impersonated'

Under our policy, `suspicious` and `impersonated` are not static training labels, but dynamic inference classifications:
1. **Confidence Margin**: Predicted threat probability between 0.40 and 0.70 routes to `suspicious`.
2. **Forensic Fusion**: Header verification failure from Module 1 (SPF/DKIM/DMARC) combined with moderate model threat score escalates to `impersonated`.
