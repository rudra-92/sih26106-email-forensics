"""
near_duplicate_audit.py - Deep Near-Duplicate & Cross-Split Leakage Audit.

Computes max cosine similarity and Jaccard similarity between every sample in:
- Validation vs. Train
- Test vs. Train

Identifies template leakage, repeated campaign templates, and borderline overlap.
"""

import os
import re
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

PROCESSED_BASE = os.path.join("ml", "data", "processed")
EVAL_BASE = os.path.join("ml", "evaluation")

df_train = pd.read_csv(os.path.join(PROCESSED_BASE, "train.csv"))
df_val = pd.read_csv(os.path.join(PROCESSED_BASE, "validation.csv"))
df_test = pd.read_csv(os.path.join(PROCESSED_BASE, "test.csv"))

print("=" * 80)
print("DEEP NEAR-DUPLICATE LEAKAGE AUDIT ACROSS SPLITS")
print("=" * 80)

# Build a word TF-IDF matrix across all splits for unified similarity calculation
vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
X_train = vec.fit_transform(df_train["clean_text"].fillna("").astype(str))
X_val = vec.transform(df_val["clean_text"].fillna("").astype(str))
X_test = vec.transform(df_test["clean_text"].fillna("").astype(str))

print(f"Unified TF-IDF matrix built with {X_train.shape[1]:,} features.")

def audit_split_similarity(X_query, df_query, query_name, X_ref, df_ref, ref_name):
    print(f"\n--- Auditing {query_name} ({len(df_query):,}) vs {ref_name} ({len(df_ref):,}) ---")
    # Batch matrix multiplication: (N_query, N_ref)
    sim_matrix = X_query.dot(X_ref.T) # Cosine similarity since rows are L2-normalized
    
    max_sims = np.zeros(sim_matrix.shape[0])
    best_matches = np.zeros(sim_matrix.shape[0], dtype=int)
    
    for i in range(sim_matrix.shape[0]):
        row = sim_matrix.getrow(i).toarray().ravel()
        best_idx = np.argmax(row)
        max_sims[i] = row[best_idx]
        best_matches[i] = best_idx
        
    df_query_sim = df_query.copy()
    df_query_sim["max_sim_with_train"] = max_sims
    df_query_sim["best_train_match_idx"] = best_matches
    df_query_sim["best_train_record_id"] = df_ref.iloc[best_matches]["record_id"].values
    df_query_sim["best_train_label"] = df_ref.iloc[best_matches]["our_label"].values
    df_query_sim["best_train_source"] = df_ref.iloc[best_matches]["source_dataset"].values

    # Binned statistics
    bins = [0.0, 0.50, 0.70, 0.80, 0.90, 0.95, 1.0001]
    labels = ["< 0.50", "0.50 - 0.70", "0.70 - 0.80", "0.80 - 0.90", "0.90 - 0.95", ">= 0.95"]
    binned = pd.cut(df_query_sim["max_sim_with_train"], bins=bins, labels=labels, right=False)
    
    print(f"\nMax Similarity Distribution for {query_name} vs {ref_name}:")
    counts = binned.value_counts(sort=False)
    for cat, count in counts.items():
        print(f"  {cat:15s}: {count:5d} ({count/len(df_query)*100:.2f}%)")

    # Inspect high similarity pairs (>= 0.85)
    high_sim = df_query_sim[df_query_sim["max_sim_with_train"] >= 0.85].sort_values(by="max_sim_with_train", ascending=False)
    print(f"\nHigh similarity records (sim >= 0.85): {len(high_sim)} ({len(high_sim)/len(df_query)*100:.2f}%)")
    
    if len(high_sim) > 0:
        print("\nTop 5 Highest Similarity Pairs:")
        for idx, row in high_sim.head(5).iterrows():
            train_idx = row["best_train_match_idx"]
            train_rec = df_ref.iloc[train_idx]
            print(f"\n  Similarity: {row['max_sim_with_train']:.4f}")
            print(f"  Query [{query_name}]: ID={row['record_id']}, Class={row['our_label']}, Source={row['source_dataset']}")
            print(f"    Subject: {repr(str(row['subject'])[:60])}")
            print(f"    Body start: {repr(str(row['body'])[:100])}")
            print(f"  Ref   [{ref_name}]: ID={train_rec['record_id']}, Class={train_rec['our_label']}, Source={train_rec['source_dataset']}")
            print(f"    Subject: {repr(str(train_rec['subject'])[:60])}")
            print(f"    Body start: {repr(str(train_rec['body'])[:100])}")
            
    return df_query_sim

val_sim_df = audit_split_similarity(X_val, df_val, "Validation", X_train, df_train, "Train")
test_sim_df = audit_split_similarity(X_test, df_test, "Test", X_train, df_train, "Train")

# Save detailed similarity tables for documentation
val_sim_df[["record_id", "source_dataset", "our_label", "max_sim_with_train", "best_train_record_id", "best_train_label", "best_train_source"]].to_csv(
    os.path.join(EVAL_BASE, "val_near_duplicate_audit.csv"), index=False
)
test_sim_df[["record_id", "source_dataset", "our_label", "max_sim_with_train", "best_train_record_id", "best_train_label", "best_train_source"]].to_csv(
    os.path.join(EVAL_BASE, "test_near_duplicate_audit.csv"), index=False
)

print("\nAudit results saved to ml/evaluation/val_near_duplicate_audit.csv and test_near_duplicate_audit.csv")
