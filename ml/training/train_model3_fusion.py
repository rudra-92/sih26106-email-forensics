"""
train_model3_fusion.py - Model 3: XGBoost Forensic Fusion Classifier for SIH26106.

Combines:
- 4 Model 1D NLP probabilities (OOF 5-fold cross-validated for train, frozen for val/test)
- 136 Model 2 forensic features (86 numerical, 50 binary flags)
= 140 total features

Strict Leakage Elimination:
- Purges email_id, labels, corpus identifiers, source metadata, raw provenance
- Uses 5-fold OOF Model 1D probabilities for training to prevent stacking overconfidence
- Uses native NaN handling in XGBoost (preserves true missingness without fabrication)

Configuration:
- XGBClassifier(objective="multi:softprob", n_estimators=300, max_depth=6,
                learning_rate=0.05, subsample=0.8, colsample_bytree=0.8,
                eval_metric="mlogloss", random_state=42)
"""

import os
import sys
import json
import time
import argparse
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

PROCESSED_DATA_DIR = os.path.join("ml", "data", "processed")
DATASETS_DIR = os.path.join("ml", "datasets")
MODELS_DIR = os.path.join("ml", "models")
EVAL_DIR = os.path.join("ml", "evaluation")

CLASS_NAMES = ["fraud_related", "legitimate", "phishing"]
CLASS_TO_INT = {name: idx for idx, name in enumerate(CLASS_NAMES)}
INT_TO_CLASS = {idx: name for idx, name in enumerate(CLASS_NAMES)}

EXCLUDED_COLUMNS = {
    "email_id", "record_id", "source_dataset", "source_record_id",
    "original_label", "our_label", "label", "text_hash",
    "clean_text", "clean_subject", "clean_body", "subject", "body"
}


def load_fusion_data():
    """
    Loads Model 2 forensic features and joins them with train, validation, and test splits.
    Replaces training set NLP probabilities with 5-fold OOF probabilities.
    """
    m2_path = os.path.join(DATASETS_DIR, "model2_forensic_features.parquet")
    if not os.path.exists(m2_path):
        raise FileNotFoundError(f"Model 2 forensic features not found at: {m2_path}")

    print(f"[+] Ingesting Model 2 Forensic Features: {m2_path}")
    df_m2 = pd.read_parquet(m2_path)
    print(f"  -> Loaded {len(df_m2):,} rows, {df_m2.shape[1]} columns.")

    # Load splits
    train_split = pd.read_csv(os.path.join(PROCESSED_DATA_DIR, "train.csv"))
    val_split = pd.read_csv(os.path.join(PROCESSED_DATA_DIR, "validation.csv"))
    test_split = pd.read_csv(os.path.join(PROCESSED_DATA_DIR, "test.csv"))

    # Load 5-fold OOF probabilities for train
    oof_path = os.path.join(PROCESSED_DATA_DIR, "model1d_train_oof_probabilities.csv")
    if not os.path.exists(oof_path):
        raise FileNotFoundError(f"OOF probabilities not found at {oof_path}. Run generate_model1d_oof.py first!")
    df_oof = pd.read_csv(oof_path)
    print(f"[+] Loaded 5-Fold OOF Model 1D probabilities for training: {len(df_oof):,} rows.")

    # Index Model 2 by email_id
    df_m2 = df_m2.set_index("email_id")

    # Merge Train
    df_train_joined = train_split[["record_id", "our_label"]].join(df_m2, on="record_id", how="inner")
    print(f"  -> Train joined: {len(df_train_joined):,} rows.")

    # Replace in-sample Model 1D probabilities with OOF probabilities for Train
    df_oof_indexed = df_oof.set_index("record_id")
    for prob_col in ["nlp_prob_legitimate", "nlp_prob_spam", "nlp_prob_phishing", "nlp_prob_fraud"]:
        if prob_col in df_train_joined.columns and prob_col in df_oof_indexed.columns:
            df_train_joined[prob_col] = df_train_joined["record_id"].map(df_oof_indexed[prob_col])

    # Merge Val and Test (using frozen out-of-sample Model 1D probabilities already in df_m2)
    df_val_joined = val_split[["record_id", "our_label"]].join(df_m2, on="record_id", how="inner")
    df_test_joined = test_split[["record_id", "our_label"]].join(df_m2, on="record_id", how="inner")
    print(f"  -> Validation joined: {len(df_val_joined):,} rows.")
    print(f"  -> Test joined: {len(df_test_joined):,} rows.")

    # Determine Feature Columns
    feature_cols = [c for c in df_train_joined.columns if c not in EXCLUDED_COLUMNS]
    print(f"[+] Final Feature Set: {len(feature_cols)} features.")

    # Prepare X and y
    X_train = df_train_joined[feature_cols].copy()
    y_train = df_train_joined["our_label"].map(CLASS_TO_INT).values

    X_val = df_val_joined[feature_cols].copy()
    y_val = df_val_joined["our_label"].map(CLASS_TO_INT).values

    X_test = df_test_joined[feature_cols].copy()
    y_test = df_test_joined["our_label"].map(CLASS_TO_INT).values

    return (X_train, y_train, df_train_joined["record_id"]), \
           (X_val, y_val, df_val_joined["record_id"]), \
           (X_test, y_test, df_test_joined["record_id"]), \
           feature_cols


def train_xgboost(X_train, y_train, X_val, y_val, feature_cols):
    """
    Trains XGBClassifier with exact user parameters and native NaN handling.
    """
    print("\n" + "=" * 80)
    print("TRAINING MODEL 3: XGBOOST FORENSIC FUSION CLASSIFIER")
    print("=" * 80)

    params = {
        "objective": "multi:softprob",
        "num_class": 3,
        "n_estimators": 300,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "eval_metric": "mlogloss",
        "random_state": 42,
        "n_jobs": -1,
        "tree_method": "hist"
    }

    model = xgb.XGBClassifier(**params)

    t0 = time.time()
    model.fit(
        X_train, y_train,
        eval_set=[(X_train, y_train), (X_val, y_val)],
        verbose=50
    )
    elapsed = round(time.time() - t0, 2)
    print(f"[+] Model 3 trained in {elapsed}s.")

    return model, params


def compute_metrics(y_true, y_pred, y_probs, split_name="Test"):
    """
    Computes complete evaluation metrics.
    """
    acc = accuracy_score(y_true, y_pred)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro")
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted")
    per_p, per_r, per_f1, per_supp = precision_recall_fscore_support(y_true, y_pred, average=None)
    cm = confusion_matrix(y_true, y_pred)

    metrics = {
        "split": split_name,
        "accuracy": round(float(acc), 4),
        "macro_precision": round(float(macro_p), 4),
        "macro_recall": round(float(macro_r), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "per_class": {
            CLASS_NAMES[i]: {
                "precision": round(float(per_p[i]), 4),
                "recall": round(float(per_r[i]), 4),
                "f1": round(float(per_f1[i]), 4),
                "support": int(per_supp[i])
            } for i in range(len(CLASS_NAMES))
        },
        "confusion_matrix": cm.tolist()
    }
    return metrics


def save_artifacts(model, feature_cols, params, metrics_val, metrics_test):
    """
    Saves:
    1. ml/models/model3_xgboost_forensic_fusion.json
    2. ml/models/model3_feature_schema.json
    3. ml/models/model3_config.json
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    # 1. Model JSON
    model_path = os.path.join(MODELS_DIR, "model3_xgboost_forensic_fusion.json")
    model.save_model(model_path)
    print(f"[+] Saved Model 3 XGBoost to: {model_path}")

    # 2. Feature Schema JSON
    schema_path = os.path.join(MODELS_DIR, "model3_feature_schema.json")
    schema = {
        "total_features": len(feature_cols),
        "feature_names": feature_cols,
        "features": []
    }
    for idx, fname in enumerate(feature_cols):
        if fname.startswith("nlp_prob_"):
            cat = "nlp_probability"
            dtype = "float64"
        elif fname.startswith(("has_", "is_", "missing_", "multiple_")) or fname.endswith(("_present", "_fail", "_pass", "_neutral", "_softfail", "_none", "_issue", "_candidate", "_flag", "_mismatch", "_anomaly")):
            cat = "forensic_binary_flag"
            dtype = "int64"
        else:
            cat = "forensic_numerical"
            dtype = "float64" if "entropy" in fname or "ratio" in fname or "length" in fname else "int64"

        schema["features"].append({
            "index": idx,
            "feature_name": fname,
            "category": cat,
            "expected_dtype": dtype
        })

    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    print(f"[+] Saved Feature Schema to: {schema_path}")

    # 3. Model Config JSON
    config_path = os.path.join(MODELS_DIR, "model3_config.json")
    config = {
        "model_name": "Model 3 — XGBoost Forensic Fusion Classifier",
        "version": "1.0.0",
        "task": "email_threat_multiclass_classification",
        "objective": "multi:softprob",
        "classes": CLASS_NAMES,
        "class_to_int": CLASS_TO_INT,
        "int_to_class": INT_TO_CLASS,
        "hyperparameters": params,
        "total_features": len(feature_cols),
        "validation_metrics": metrics_val,
        "test_metrics": metrics_test,
        "leakage_prevention": {
            "oof_folds": 5,
            "oof_model": "Model 1D Word + Char_wb TF-IDF Artifact-Filtered LR",
            "excluded_columns": list(EXCLUDED_COLUMNS),
            "native_nan_handling": True
        }
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    print(f"[+] Saved Model Config to: {config_path}")


def main():
    (X_tr, y_tr, ids_tr), (X_va, y_va, ids_va), (X_te, y_te, ids_te), feature_cols = load_fusion_data()

    model, params = train_xgboost(X_tr, y_tr, X_va, y_va, feature_cols)

    # Validation Evaluation
    val_probs = model.predict_proba(X_va)
    val_preds = np.argmax(val_probs, axis=1)
    val_metrics = compute_metrics(y_va, val_preds, val_probs, split_name="Validation")

    # Test Evaluation
    test_probs = model.predict_proba(X_te)
    test_preds = np.argmax(test_probs, axis=1)
    test_metrics = compute_metrics(y_te, test_preds, test_probs, split_name="Test")

    print("\n" + "=" * 80)
    print("MODEL 3 EVALUATION RESULTS")
    print("=" * 80)
    print(f"Validation -> Accuracy: {val_metrics['accuracy']*100:.2f}% | Macro F1: {val_metrics['macro_f1']*100:.2f}% | Phish F1: {val_metrics['per_class']['phishing']['f1']*100:.2f}% | Fraud F1: {val_metrics['per_class']['fraud_related']['f1']*100:.2f}%")
    print(f"Test       -> Accuracy: {test_metrics['accuracy']*100:.2f}% | Macro F1: {test_metrics['macro_f1']*100:.2f}% | Phish F1: {test_metrics['per_class']['phishing']['f1']*100:.2f}% | Fraud F1: {test_metrics['per_class']['fraud_related']['f1']*100:.2f}%")

    print("\nTest Classification Report:")
    print(classification_report(y_te, test_preds, target_names=CLASS_NAMES, digits=4))

    save_artifacts(model, feature_cols, params, val_metrics, test_metrics)


if __name__ == "__main__":
    main()
