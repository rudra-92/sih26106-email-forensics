"""
split_dataset.py - Source-Aware Stratified Train / Validation / Test Splitting.

Splits `ml/data/processed/emails_balanced.csv` into:
- 70% Train (ml/data/processed/train.csv)
- 15% Validation (ml/data/processed/validation.csv)
- 15% Test (ml/data/processed/test.csv)

Stratification:
- Uses the composite stratum `our_label + "_" + source_dataset`.
- Ensures balanced class and source distributions across all splits.
- Rigorously audits against text hash leakage and normalized content overlap.
"""

import os
import sys
import re
import hashlib
from typing import Dict, Any, Tuple
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

PROCESSED_BASE = os.path.join("ml", "data", "processed")
INPUT_DATASET = os.path.join(PROCESSED_BASE, "emails_balanced.csv")


def normalize_for_near_dup(text: str) -> str:
    """Collapses whitespace and case-folds for leakage verification."""
    return re.sub(r'\s+', ' ', str(text)).strip().lower()


def perform_splits(
    random_state: int = 42,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Splits dataset with stratification on (our_label + source_dataset)."""
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, "Ratios must sum to 1.0"
    
    print(f"Loading input dataset: {INPUT_DATASET}...")
    df = pd.read_csv(INPUT_DATASET)
    total_len = len(df)
    print(f"Total records in dataset: {total_len:,}")

    # Create composite stratum
    df["stratum"] = df["our_label"].astype(str) + "_" + df["source_dataset"].astype(str)
    print("\nStratum distribution in full dataset:")
    print(df["stratum"].value_counts())

    # Step 1: Split into Train (70%) and Temp (30%)
    temp_ratio = val_ratio + test_ratio  # 0.30
    df_train, df_temp = train_test_split(
        df,
        test_size=temp_ratio,
        random_state=random_state,
        stratify=df["stratum"]
    )

    # Step 2: Split Temp into Validation (50% of 30% = 15%) and Test (50% of 30% = 15%)
    val_temp_ratio = val_ratio / temp_ratio  # 0.50
    df_val, df_test = train_test_split(
        df_temp,
        test_size=(1.0 - val_temp_ratio),
        random_state=random_state,
        stratify=df_temp["stratum"]
    )

    # Remove temporary stratum column from output dataframes
    df_train = df_train.drop(columns=["stratum"]).reset_index(drop=True)
    df_val = df_val.drop(columns=["stratum"]).reset_index(drop=True)
    df_test = df_test.drop(columns=["stratum"]).reset_index(drop=True)

    print(f"\nSplit complete:")
    print(f"  Train:      {len(df_train):,d} ({len(df_train)/total_len*100:.2f}%)")
    print(f"  Validation: {len(df_val):,d} ({len(df_val)/total_len*100:.2f}%)")
    print(f"  Test:       {len(df_test):,d} ({len(df_test)/total_len*100:.2f}%)")

    return df_train, df_val, df_test


def audit_leakage(
    df_train: pd.DataFrame,
    df_val: pd.DataFrame,
    df_test: pd.DataFrame
) -> Dict[str, Any]:
    """Runs comprehensive train/val/test data leakage checks."""
    print("\n" + "=" * 80)
    print("LEAKAGE AUDIT ACROSS SPLITS")
    print("=" * 80)

    results = {}

    # 1. Exact text_hash check
    train_hashes = set(df_train["text_hash"])
    val_hashes = set(df_val["text_hash"])
    test_hashes = set(df_test["text_hash"])

    train_val_hash_overlap = train_hashes.intersection(val_hashes)
    train_test_hash_overlap = train_hashes.intersection(test_hashes)
    val_test_hash_overlap = val_hashes.intersection(test_hashes)

    results["train_val_hash_overlap"] = len(train_val_hash_overlap)
    results["train_test_hash_overlap"] = len(train_test_hash_overlap)
    results["val_test_hash_overlap"] = len(val_test_hash_overlap)

    print(f"1. Exact text_hash overlaps:")
    print(f"   Train <-> Validation: {len(train_val_hash_overlap)}")
    print(f"   Train <-> Test:       {len(train_test_hash_overlap)}")
    print(f"   Val   <-> Test:       {len(val_test_hash_overlap)}")

    # 2. Normalized clean_text check (whitespace-collapsed, lowercase)
    train_norm = set(df_train["clean_text"].apply(normalize_for_near_dup))
    val_norm = set(df_val["clean_text"].apply(normalize_for_near_dup))
    test_norm = set(df_test["clean_text"].apply(normalize_for_near_dup))

    train_val_norm_overlap = train_norm.intersection(val_norm)
    train_test_norm_overlap = train_norm.intersection(test_norm)
    val_test_norm_overlap = val_norm.intersection(test_norm)

    results["train_val_norm_overlap"] = len(train_val_norm_overlap)
    results["train_test_norm_overlap"] = len(train_test_norm_overlap)
    results["val_test_norm_overlap"] = len(val_test_norm_overlap)

    print(f"\n2. Normalized text overlaps:")
    print(f"   Train <-> Validation: {len(train_val_norm_overlap)}")
    print(f"   Train <-> Test:       {len(train_test_norm_overlap)}")
    print(f"   Val   <-> Test:       {len(val_test_norm_overlap)}")

    # 3. Class presence check
    expected_classes = {"legitimate", "phishing", "fraud_related"}
    train_classes = set(df_train["our_label"])
    val_classes = set(df_val["our_label"])
    test_classes = set(df_test["our_label"])

    assert train_classes == expected_classes, f"Train missing classes: {expected_classes - train_classes}"
    assert val_classes == expected_classes, f"Val missing classes: {expected_classes - val_classes}"
    assert test_classes == expected_classes, f"Test missing classes: {expected_classes - test_classes}"
    print(f"\n3. Class presence verified: All 3 classes exist in Train, Validation, and Test.")

    # 4. Source distributions
    print(f"\n4. Class Distributions:")
    for name, s_df in [("Train", df_train), ("Validation", df_val), ("Test", df_test)]:
        print(f"\n   [{name} Class Dist]")
        for c, count in s_df["our_label"].value_counts().items():
            print(f"     {c:15s}: {count:5d} ({count/len(s_df)*100:.2f}%)")

    print(f"\n5. Source Distributions:")
    for name, s_df in [("Train", df_train), ("Validation", df_val), ("Test", df_test)]:
        print(f"\n   [{name} Source Dist]")
        for src, count in s_df["source_dataset"].value_counts().items():
            print(f"     {src:15s}: {count:5d} ({count/len(s_df)*100:.2f}%)")

    return results


def main():
    df_train, df_val, df_test = perform_splits()
    audit_results = audit_leakage(df_train, df_val, df_test)

    # Save split files
    train_path = os.path.join(PROCESSED_BASE, "train.csv")
    val_path = os.path.join(PROCESSED_BASE, "validation.csv")
    test_path = os.path.join(PROCESSED_BASE, "test.csv")

    df_train.to_csv(train_path, index=False)
    df_val.to_csv(val_path, index=False)
    df_test.to_csv(test_path, index=False)

    print("\n" + "=" * 80)
    print("SPLIT FILES PERSISTED")
    print(f"  Saved Train:      {train_path} ({len(df_train):,} rows)")
    print(f"  Saved Validation: {val_path} ({len(df_val):,} rows)")
    print(f"  Saved Test:       {test_path} ({len(df_test):,} rows)")
    print("=" * 80)


if __name__ == "__main__":
    main()
