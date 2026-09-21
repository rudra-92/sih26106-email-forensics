"""
balance_dataset.py - Source-Stratified Dataset Balancing for SIH26106.

Policy & Rationale:
1. Retains 100% of high-value verified threat samples (phishing and fraud_related).
2. Performs source-stratified downsampling of the majority `legitimate` class
   to reduce the extreme 49:1 imbalance down to ~4:1 or ~2:1.
3. Preserves identical source proportions across all 6 legitimate sources
   (Enron, CEAS-08, TREC-06, TREC-07, SpamAssassin, Ling-Spam).
4. Uses fixed random seed (seed=42) for deterministic, auditable splits.
5. Supports both:
   - 3-Class Balanced Dataset (Default for Model 1 v1: legitimate, phishing, fraud_related)
   - 4-Class Balanced Dataset (Adding verified spam from quarantine pool without converting to phishing)
"""

import os
import sys
import argparse
from typing import Dict, Any, List
import pandas as pd
import numpy as np

# Ensure root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from ml.preprocessing.clean_text import clean_email_text, clean_subject, clean_body
from ml.preprocessing.quality_filter import check_record_quality
from ml.preprocessing.deduplicate import compute_text_hash

PROCESSED_BASE = os.path.join("ml", "data", "processed")
METADATA_BASE = os.path.join("ml", "data", "metadata")
RAW_BASE = os.path.join("ml", "data", "raw")


def balance_3class(
    df_cleaned: pd.DataFrame,
    target_legitimate_count: int = 6500,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Performs source-stratified downsampling of legitimate records while retaining
    100% of phishing and fraud_related records.
    """
    # 1. Retain 100% of minority threat classes
    df_phishing = df_cleaned[df_cleaned["our_label"] == "phishing"].copy()
    df_fraud = df_cleaned[df_cleaned["our_label"] == "fraud_related"].copy()
    df_legit = df_cleaned[df_cleaned["our_label"] == "legitimate"].copy()

    total_legit = len(df_legit)
    print(f"Total available legitimate: {total_legit:,}")
    print(f"Target downsampled legitimate: {target_legitimate_count:,}")

    # 2. Source-stratified sampling across the 6 legitimate sources
    source_counts = df_legit["source_dataset"].value_counts()
    sampled_legit_dfs = []

    allocated_so_far = 0
    sources_sorted = source_counts.index.tolist()

    for i, src in enumerate(sources_sorted):
        count_src = source_counts[src]
        proportion = count_src / total_legit
        
        # Allocate sample count proportionally
        if i == len(sources_sorted) - 1:
            target_src = target_legitimate_count - allocated_so_far
        else:
            target_src = int(round(proportion * target_legitimate_count))
            allocated_so_far += target_src

        src_subset = df_legit[df_legit["source_dataset"] == src]
        sampled_src = src_subset.sample(n=target_src, random_state=random_state)
        sampled_legit_dfs.append(sampled_src)
        print(f"  -> {src:15s}: {count_src:6d} available -> {target_src:5d} sampled ({target_src/target_legitimate_count*100:.1f}%)")

    df_legit_sampled = pd.concat(sampled_legit_dfs, ignore_index=True)

    # 3. Combine into balanced 3-class dataset
    df_balanced_3class = pd.concat([df_legit_sampled, df_fraud, df_phishing], ignore_index=True)
    # Shuffle
    df_balanced_3class = df_balanced_3class.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    return df_balanced_3class


def extract_verified_spam_sample(
    target_spam_count: int = 3200,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Ingests and cleans verified spam records from the quarantined raw pools
    (CEAS_08, TREC_06, TREC_07, SpamAssassin, Enron, Ling-Spam)
    under label 'spam' to prevent contaminating the 'phishing' boundary.
    """
    print(f"\nExtracting {target_spam_count:,} verified spam records from quarantine pool...")

    spam_sources = [
        {"name": "CEAS_08", "path": os.path.join(RAW_BASE, "phishing", "CEAS_08.csv"), "label": 1},
        {"name": "TREC_06", "path": os.path.join(RAW_BASE, "phishing", "TREC_06.csv"), "label": 1},
        {"name": "TREC_07", "path": os.path.join(RAW_BASE, "phishing", "TREC_07.csv"), "label": 1},
        {"name": "SpamAssassin", "path": os.path.join(RAW_BASE, "phishing", "SpamAssasin.csv"), "label": 1},
        {"name": "Enron", "path": os.path.join(RAW_BASE, "enron", "Enron.csv"), "label": 1},
        {"name": "Ling", "path": os.path.join(RAW_BASE, "phishing", "Ling.csv"), "label": 1},
    ]

    # Target allocation per source
    quota_per_source = target_spam_count // len(spam_sources)
    all_spam_records: List[Dict[str, Any]] = []

    for src_cfg in spam_sources:
        name = src_cfg["name"]
        path = src_cfg["path"]
        lbl_val = src_cfg["label"]

        if not os.path.exists(path):
            continue

        try:
            df = pd.read_csv(path)
        except Exception:
            df = pd.read_csv(path, on_bad_lines="skip", engine="python")

        lbl_numeric = pd.to_numeric(df["label"], errors="coerce")
        subset = df[lbl_numeric == lbl_val].copy()

        # Sample quota
        sample_n = min(len(subset), quota_per_source)
        sampled = subset.sample(n=sample_n, random_state=random_state)
        bcol = "body" if "body" in sampled.columns else "text"

        print(f"  -> {name:15s} spam: {len(subset):6d} available -> {len(sampled):5d} sampled")

        for idx, row in sampled.iterrows():
            raw_sub = str(row["subject"]) if "subject" in row and pd.notna(row["subject"]) else ""
            raw_body = str(row[bcol]) if pd.notna(row[bcol]) else ""
            
            c_sub = clean_subject(raw_sub, source=name)
            c_body = clean_body(raw_body, source=name)
            c_text = clean_email_text(raw_sub, raw_body, source=name)

            # Quality check
            decision = check_record_quality(
                subject=c_sub,
                body=c_body,
                clean_text=c_text,
                source=name,
                original_label=lbl_val,
                our_label="legitimate"  # dummy for quality check
            )

            if decision.is_valid:
                all_spam_records.append({
                    "record_id": f"{name}_spam_{idx}",
                    "source_dataset": name,
                    "source_record_id": idx,
                    "original_label": lbl_val,
                    "our_label": "spam",
                    "subject": raw_sub,
                    "body": raw_body,
                    "clean_text": c_text,
                    "clean_subject": c_sub,
                    "clean_body": c_body,
                    "text_hash": compute_text_hash(c_text)
                })

    df_spam = pd.DataFrame(all_spam_records)
    # Dedup
    df_spam = df_spam.drop_duplicates(subset=["text_hash"]).reset_index(drop=True)
    if len(df_spam) > target_spam_count:
        df_spam = df_spam.sample(n=target_spam_count, random_state=random_state).reset_index(drop=True)

    print(f"Extracted {len(df_spam)} unique quality-passed verified spam records.")
    return df_spam


def main():
    parser = argparse.ArgumentParser(description="Balance SIH26106 dataset")
    parser.add_argument("--target-legit", type=int, default=6500, help="Target count for downsampled legitimate class")
    parser.add_argument("--include-spam", action="store_true", default=True, help="Also generate 4-class balanced dataset with verified spam")
    args = parser.parse_args()

    cleaned_csv = os.path.join(PROCESSED_BASE, "emails_cleaned.csv")
    if not os.path.exists(cleaned_csv):
        print(f"Error: Processed dataset not found at {cleaned_csv}. Run build_dataset.py first.")
        sys.exit(1)

    print("=" * 80)
    print("SIH26106 DATASET BALANCING EXECUTION")
    print("=" * 80)

    print(f"Loading cleaned dataset from {cleaned_csv}...")
    df_cleaned = pd.read_csv(cleaned_csv)
    print(f"Total records in cleaned corpus: {len(df_cleaned):,}")

    # 1. Build 3-Class Balanced Dataset (Model 1 v1 default)
    print("\n--- Generating 3-Class Balanced Dataset (legitimate, phishing, fraud_related) ---")
    df_balanced_3class = balance_3class(df_cleaned, target_legitimate_count=args.target_legit)

    path_3class = os.path.join(PROCESSED_BASE, "emails_balanced_3class.csv")
    df_balanced_3class.to_csv(path_3class, index=False)
    print(f"\nSaved 3-Class Balanced Dataset: {path_3class} ({len(df_balanced_3class):,} rows)")

    # 2. Build 4-Class Balanced Dataset (Including verified spam)
    if args.include_spam:
        print("\n--- Generating 4-Class Balanced Dataset (Adding explicit 'spam' class) ---")
        df_spam = extract_verified_spam_sample(target_spam_count=3200)
        df_balanced_4class = pd.concat([df_balanced_3class, df_spam], ignore_index=True)
        df_balanced_4class = df_balanced_4class.sample(frac=1.0, random_state=42).reset_index(drop=True)

        path_4class = os.path.join(PROCESSED_BASE, "emails_balanced_4class.csv")
        df_balanced_4class.to_csv(path_4class, index=False)
        print(f"Saved 4-Class Balanced Dataset: {path_4class} ({len(df_balanced_4class):,} rows)")

    # Default canonical balanced file (points to 3-class for Model 1 v1 compatibility)
    path_default = os.path.join(PROCESSED_BASE, "emails_balanced.csv")
    df_balanced_3class.to_csv(path_default, index=False)
    print(f"Default balanced dataset linked to: {path_default}")

    # Generate Markdown Summary Report
    report_path = os.path.join(METADATA_BASE, "balanced_dataset_report.md")
    generate_report(df_cleaned, df_balanced_3class, df_balanced_4class if args.include_spam else None, report_path)
    print(f"Saved balancing report to: {report_path}")

    print("\n" + "=" * 80)
    print("BALANCING COMPLETE")
    print("=" * 80)


def generate_report(
    df_orig: pd.DataFrame,
    df_3c: pd.DataFrame,
    df_4c: pd.DataFrame,
    filepath: str
) -> None:
    """Writes an auditable report detailing the before-and-after distributions."""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# SIH26106 — Dataset Balancing & Rebalancing Report\n\n")
        f.write("## 1. Overview\n\n")
        f.write(
            "This document records the rectification of the initial 49:1 class imbalance in the SIH26106 "
            "email corpus. Under the **ZERO LABEL MANUFACTURING** policy, no synthetic samples were generated "
            "and no labels were manufactured. Balance was achieved via **source-stratified downsampling** of the "
            "majority `legitimate` class and an optional non-contaminating **`spam` class extraction**.\n\n"
        )

        f.write("## 2. Before vs. After Comparison\n\n")
        f.write("### 2.1 Three-Class Configuration (Model 1 v1 Default)\n\n")
        f.write("| Class | Original Count | Original % | Balanced Count | Balanced % | Ratio (vs Phishing) |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :---: |\n")

        total_orig = len(df_orig)
        total_3c = len(df_3c)
        phish_3c = len(df_3c[df_3c["our_label"] == "phishing"])

        for cls in ["legitimate", "fraud_related", "phishing"]:
            c_orig = len(df_orig[df_orig["our_label"] == cls])
            p_orig = c_orig / total_orig * 100.0
            c_3c = len(df_3c[df_3c["our_label"] == cls])
            p_3c = c_3c / total_3c * 100.0
            ratio = c_3c / phish_3c
            f.write(f"| **`{cls}`** | {c_orig:,} | {p_orig:.1f}% | **{c_3c:,}** | **{p_3c:.1f}%** | **{ratio:.1f} : 1** |\n")

        f.write(f"| **Total** | {total_orig:,} | 100.0% | **{total_3c:,}** | 100.0% | — |\n\n")

        if df_4c is not None:
            total_4c = len(df_4c)
            phish_4c = len(df_4c[df_4c["our_label"] == "phishing"])
            f.write("### 2.2 Four-Class Configuration (With Explicit Verified Spam)\n\n")
            f.write("| Class | Balanced Count | Balanced % | Ratio (vs Phishing) | Source Pool |\n")
            f.write("| :--- | :---: | :---: | :---: | :--- |\n")
            for cls in ["legitimate", "spam", "fraud_related", "phishing"]:
                c_4c = len(df_4c[df_4c["our_label"] == cls])
                p_4c = c_4c / total_4c * 100.0
                ratio = c_4c / phish_4c
                pool = (
                    "Enron, CEAS, TREC, SpamAssassin, Ling" if cls in ("legitimate", "spam") else
                    "Radev CLAIR 419" if cls == "fraud_related" else "Jose Nazario Phishing"
                )
                f.write(f"| **`{cls}`** | **{c_4c:,}** | **{p_4c:.1f}%** | **{ratio:.1f} : 1** | {pool} |\n")
            f.write(f"| **Total** | **{total_4c:,}** | 100.0% | — | All Accepted Pools |\n\n")

        f.write("## 3. Source-Stratified Legitimate Allocation\n\n")
        f.write(
            "To prevent the classifier from overfitting to any single company's vocabulary, legitimate samples "
            "were downsampled in exact proportion to their available population across all 6 verified sources:\n\n"
        )
        f.write("| Source Dataset | Cleaned Available | Downsampled Allocation | Stratified Proportion |\n")
        f.write("| :--- | :---: | :---: | :---: |\n")

        legit_orig = df_orig[df_orig["our_label"] == "legitimate"]["source_dataset"].value_counts()
        legit_3c = df_3c[df_3c["our_label"] == "legitimate"]["source_dataset"].value_counts()

        for src in legit_orig.index:
            c_o = legit_orig[src]
            c_s = legit_3c.get(src, 0)
            prop = c_s / len(df_3c[df_3c["our_label"] == "legitimate"]) * 100.0
            f.write(f"| `{src}` | {c_o:,} | **{c_s:,}** | {prop:.1f}% |\n")

        f.write("\n## 4. How to Handle 'Suspicious' and 'Impersonated'\n\n")
        f.write(
            "Under our policy, `suspicious` and `impersonated` are not static training labels, but dynamic "
            "inference classifications:\n"
            "1. **Confidence Margin**: Predicted threat probability between 0.40 and 0.70 routes to `suspicious`.\n"
            "2. **Forensic Fusion**: Header verification failure from Module 1 (SPF/DKIM/DMARC) combined with "
            "moderate model threat score escalates to `impersonated`.\n"
        )


if __name__ == "__main__":
    main()
