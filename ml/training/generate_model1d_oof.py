"""
generate_model1d_oof.py - Generate 5-Fold Out-of-Fold (OOF) Model 1D Probabilities for Train Split.

Prevents in-sample stacking leakage for Model 3 (XGBoost Forensic Fusion).
Produces realistic cross-validated NLP probabilities on train.csv:
- nlp_prob_legitimate
- nlp_prob_spam
- nlp_prob_phishing
- nlp_prob_fraud
"""

import os
import time
import json
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score, f1_score

SOURCE_ARTIFACT_STOPWORDS = [
    "enron", "vince", "kaminski", "houston",
    "monkey", "jose", "monkey org", "jose monkey", "l monkey",
    "aclweb", "aclweb org",
    "linguist", "linguistics",
    "ceas", "ceas challenge"
]


def build_model1d_vectorizer():
    filtered_stopwords = list(ENGLISH_STOP_WORDS.union(set(SOURCE_ARTIFACT_STOPWORDS)))
    vec = FeatureUnion([
        ("word", TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=3,
            max_df=0.95,
            stop_words=filtered_stopwords
        )),
        ("char", TfidfVectorizer(
            ngram_range=(3, 5),
            analyzer="char_wb",
            sublinear_tf=True,
            min_df=5,
            max_df=0.95
        ))
    ])
    return vec


def main():
    print("=" * 80)
    print("GENERATING 5-FOLD OUT-OF-FOLD (OOF) MODEL 1D PROBABILITIES FOR TRAIN.CSV")
    print("=" * 80)

    train_path = os.path.join("ml", "data", "processed", "train.csv")
    df_train = pd.read_csv(train_path)
    print(f"[+] Loaded train.csv: {len(df_train):,} records.")

    texts = df_train["clean_text"].fillna("").astype(str).values
    labels = df_train["our_label"].astype(str).values
    record_ids = df_train["record_id"].astype(str).values

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    # Classes in standard order
    classes = np.array(["fraud_related", "legitimate", "phishing"])
    n_samples = len(df_train)
    oof_probs = np.zeros((n_samples, len(classes)), dtype=np.float64)

    t_start = time.time()
    for fold, (train_idx, val_idx) in enumerate(skf.split(texts, labels), 1):
        t_fold = time.time()
        print(f"\n--- Fold {fold}/5 ---")
        print(f"  Train: {len(train_idx):,} | OOF Val: {len(val_idx):,}")

        vec = build_model1d_vectorizer()
        X_tr = vec.fit_transform(texts[train_idx])
        y_tr = labels[train_idx]

        lr = LogisticRegression(class_weight="balanced", max_iter=2000, random_state=42, solver="lbfgs")
        lr.fit(X_tr, y_tr)

        # Check classes alignment
        assert list(lr.classes_) == list(classes), f"Mismatch in classes: {lr.classes_} vs {classes}"

        X_va = vec.transform(texts[val_idx])
        fold_probs = lr.predict_proba(X_va)
        oof_probs[val_idx] = fold_probs

        fold_preds = classes[np.argmax(fold_probs, axis=1)]
        fold_acc = accuracy_score(labels[val_idx], fold_preds)
        fold_f1 = f1_score(labels[val_idx], fold_preds, average="macro")
        print(f"  Fold {fold} finished in {time.time()-t_fold:.2f}s -> Acc: {fold_acc*100:.2f}%, Macro F1: {fold_f1*100:.2f}%")

    total_time = time.time() - t_start
    print(f"\n[+] 5-Fold OOF CV Complete in {total_time:.2f}s")

    # Overall OOF Metrics
    oof_preds = classes[np.argmax(oof_probs, axis=1)]
    overall_acc = accuracy_score(labels, oof_preds)
    overall_f1 = f1_score(labels, oof_preds, average="macro")
    print(f"  Overall OOF Accuracy: {overall_acc*100:.2f}%")
    print(f"  Overall OOF Macro F1: {overall_f1*100:.2f}%")
    print("\nOOF Classification Report:")
    print(classification_report(labels, oof_preds, target_names=classes, digits=4))

    # Construct DataFrame
    # Note: Model 2 columns are: nlp_prob_legitimate, nlp_prob_spam, nlp_prob_phishing, nlp_prob_fraud
    # Mapping from classes: fraud_related -> fraud, legitimate -> legitimate, phishing -> phishing
    class_to_idx = {c: i for i, c in enumerate(classes)}

    df_oof = pd.DataFrame({
        "record_id": record_ids,
        "nlp_prob_legitimate": np.round(oof_probs[:, class_to_idx["legitimate"]], 4),
        "nlp_prob_spam": 0.0,
        "nlp_prob_phishing": np.round(oof_probs[:, class_to_idx["phishing"]], 4),
        "nlp_prob_fraud": np.round(oof_probs[:, class_to_idx["fraud_related"]], 4),
    })

    out_path = os.path.join("ml", "data", "processed", "model1d_train_oof_probabilities.csv")
    df_oof.to_csv(out_path, index=False)
    print(f"[+] Saved OOF probabilities to: {out_path}")


if __name__ == "__main__":
    main()
