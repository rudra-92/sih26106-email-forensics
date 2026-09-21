"""
evaluate_model3_shap.py - Comprehensive Evaluation & SHAP Explainability for Model 3.

Computes:
1. Standard Stratified Evaluation (Model 1D vs Model 3 on test.csv):
   - Accuracy, Macro/Weighted Precision, Recall, F1
   - Per-Class Metrics (special attention to Phishing and Fraud)
   - Confusion Matrices
2. Campaign-Aware Evaluation:
   - Evaluates performance on novel templates (max_sim_with_train < 0.80)
     vs template-memorized emails (max_sim_with_train >= 0.80)
     using test_near_duplicate_audit.csv.
3. XGBoost Feature Importance:
   - Top features by Gain, Weight, and Cover.
4. SHAP Explainability:
   - Global feature importance (mean |SHAP value| across test set).
   - Class-specific SHAP drivers (what pushes towards phishing vs fraud vs legitimate).
   - Local sample email explanations (step-by-step breakdown of forensic impact).
"""

import os
import sys
import json
import time
import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
import shap

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

CLASS_NAMES = ["fraud_related", "legitimate", "phishing"]
CLASS_TO_INT = {name: idx for idx, name in enumerate(CLASS_NAMES)}
INT_TO_CLASS = {idx: name for idx, name in enumerate(CLASS_NAMES)}

EXCLUDED_COLUMNS = {
    "email_id", "record_id", "source_dataset", "source_record_id",
    "original_label", "our_label", "label", "text_hash",
    "clean_text", "clean_subject", "clean_body", "subject", "body"
}


def load_data_and_models():
    """Loads models, test dataset, and pre-extracted forensic features."""
    # 1. Model 1D
    m1_lr_path = os.path.join("ml", "models", "model1d_word_char_filtered_lr.joblib")
    m1_vec_path = os.path.join("ml", "models", "model1d_word_char_filtered_vectorizer.joblib")
    m1_model = joblib.load(m1_lr_path)
    m1_vec = joblib.load(m1_vec_path)

    # 2. Model 3 XGBoost
    m3_path = os.path.join("ml", "models", "model3_xgboost_forensic_fusion.json")
    m3_model = xgb.XGBClassifier()
    m3_model.load_model(m3_path)

    # 3. Test Split
    test_csv = pd.read_csv(os.path.join("ml", "data", "processed", "test.csv"))

    # 4. Model 2 Features
    m2_df = pd.read_parquet(os.path.join("ml", "datasets", "model2_forensic_features.parquet"))
    m2_indexed = m2_df.set_index("email_id")

    # 5. Join
    test_joined = test_csv.join(m2_indexed, on="record_id", how="inner")

    # Feature columns
    schema_path = os.path.join("ml", "models", "model3_feature_schema.json")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    feature_cols = schema["feature_names"]

    X_test_m3 = test_joined[feature_cols].copy()
    y_test = test_joined["our_label"].map(CLASS_TO_INT).values

    # Model 1D features
    X_test_m1 = m1_vec.transform(test_joined["clean_text"].fillna("").astype(str))

    return m1_model, m3_model, test_joined, X_test_m1, X_test_m3, y_test, feature_cols


def compute_metrics_dict(y_true, y_pred, y_probs, name="Model"):
    """Returns standardized metrics dictionary."""
    acc = accuracy_score(y_true, y_pred)
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    weighted_p, weighted_r, weighted_f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    per_p, per_r, per_f1, per_supp = precision_recall_fscore_support(y_true, y_pred, average=None, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2])

    return {
        "name": name,
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


def evaluate_campaign_aware(test_joined, y_pred_m1, y_pred_m3, y_test):
    """
    Evaluates Model 1D vs Model 3 partitioned by nearest-neighbor template similarity.
    """
    audit_path = os.path.join("ml", "evaluation", "test_near_duplicate_audit.csv")
    if not os.path.exists(audit_path):
        print("[-] Warning: test_near_duplicate_audit.csv not found. Skipping campaign-aware evaluation.")
        return {}

    df_audit = pd.read_csv(audit_path).set_index("record_id")
    test_joined = test_joined.copy()
    test_joined["max_sim_with_train"] = test_joined["record_id"].map(df_audit["max_sim_with_train"])

    results = {}
    brackets = [
        ("Novel Templates (Similarity < 0.80)", test_joined["max_sim_with_train"] < 0.80),
        ("Template-Matching / Near-Duplicates (Similarity >= 0.80)", test_joined["max_sim_with_train"] >= 0.80),
        ("Nigerian Fraud Novel (Sim < 0.80)", (test_joined["our_label"] == "fraud_related") & (test_joined["max_sim_with_train"] < 0.80)),
        ("Nigerian Fraud Memorized (Sim >= 0.80)", (test_joined["our_label"] == "fraud_related") & (test_joined["max_sim_with_train"] >= 0.80)),
        ("Phishing Novel (Sim < 0.80)", (test_joined["our_label"] == "phishing") & (test_joined["max_sim_with_train"] < 0.80)),
        ("Phishing Memorized (Sim >= 0.80)", (test_joined["our_label"] == "phishing") & (test_joined["max_sim_with_train"] >= 0.80))
    ]

    for name, mask in brackets:
        idx = np.where(mask)[0]
        if len(idx) == 0:
            continue
        sub_y_true = y_test[idx]
        sub_y_m1 = y_pred_m1[idx]
        sub_y_m3 = y_pred_m3[idx]

        m1_acc = accuracy_score(sub_y_true, sub_y_m1)
        m3_acc = accuracy_score(sub_y_true, sub_y_m3)
        m1_f1 = precision_recall_fscore_support(sub_y_true, sub_y_m1, average="macro", zero_division=0)[2]
        m3_f1 = precision_recall_fscore_support(sub_y_true, sub_y_m3, average="macro", zero_division=0)[2]

        results[name] = {
            "sample_count": int(len(idx)),
            "model1d_accuracy": round(float(m1_acc), 4),
            "model3_accuracy": round(float(m3_acc), 4),
            "accuracy_delta": round(float(m3_acc - m1_acc), 4),
            "model1d_macro_f1": round(float(m1_f1), 4),
            "model3_macro_f1": round(float(m3_f1), 4),
            "f1_delta": round(float(m3_f1 - m1_f1), 4),
        }

    return results


def run_shap_analysis(m3_model, X_test, feature_cols, test_joined):
    """
    Computes global and local SHAP explanations using TreeExplainer.
    """
    print("\n[+] Computing SHAP Values using TreeExplainer...")
    t0 = time.time()
    explainer = shap.TreeExplainer(m3_model)
    shap_values = explainer.shap_values(X_test)
    print(f"  -> SHAP values calculated in {time.time()-t0:.2f}s.")

    # TreeExplainer output for multiclass can be list of [n_samples, n_features] per class
    # or [n_samples, n_features, n_classes]
    if isinstance(shap_values, list):
        shap_array = np.stack(shap_values, axis=-1)  # (N, D, C)
    else:
        shap_array = np.array(shap_values)

    # Global Mean |SHAP| across all classes
    mean_abs_shap = np.mean(np.abs(shap_array), axis=(0, 2))  # shape (D,)
    top_global_indices = np.argsort(mean_abs_shap)[::-1][:25]

    global_importance = []
    for rank, idx in enumerate(top_global_indices, 1):
        global_importance.append({
            "rank": rank,
            "feature": feature_cols[idx],
            "mean_abs_shap": round(float(mean_abs_shap[idx]), 6),
            "class_contributions": {
                CLASS_NAMES[c]: round(float(np.mean(np.abs(shap_array[:, idx, c]))), 6)
                for c in range(len(CLASS_NAMES))
            }
        })

    # Local Explanations for Sample Emails (1 Phishing, 1 Fraud, 1 Legitimate)
    sample_explanations = []
    for target_class_str, target_class_int in CLASS_TO_INT.items():
        # Find sample that is correctly predicted with high confidence
        sub_indices = np.where(test_joined["our_label"].values == target_class_str)[0]
        if len(sub_indices) == 0:
            continue
        sample_idx = sub_indices[0]
        rec = test_joined.iloc[sample_idx]
        rec_id = rec["record_id"]
        sample_shap = shap_array[sample_idx, :, target_class_int]  # contributions towards target class

        # Top 5 positive drivers (increased probability)
        pos_indices = np.argsort(sample_shap)[::-1][:5]
        # Top 5 negative drivers (decreased probability)
        neg_indices = np.argsort(sample_shap)[:5]

        sample_explanations.append({
            "record_id": rec_id,
            "true_label": target_class_str,
            "clean_subject": str(rec.get("clean_subject") or rec.get("subject") or "")[:80],
            "top_positive_features": [
                {"feature": feature_cols[i], "shap_value": round(float(sample_shap[i]), 4), "value": float(X_test.iloc[sample_idx, i]) if pd.notna(X_test.iloc[sample_idx, i]) else None}
                for i in pos_indices if sample_shap[i] > 0
            ],
            "top_negative_features": [
                {"feature": feature_cols[i], "shap_value": round(float(sample_shap[i]), 4), "value": float(X_test.iloc[sample_idx, i]) if pd.notna(X_test.iloc[sample_idx, i]) else None}
                for i in neg_indices if sample_shap[i] < 0
            ]
        })

    return global_importance, sample_explanations


def main():
    print("=" * 80)
    print("MODEL 3 EVALUATION & SHAP EXPLAINABILITY PIPELINE")
    print("=" * 80)

    m1_model, m3_model, test_joined, X_test_m1, X_test_m3, y_test, feature_cols = load_data_and_models()

    # Model 1D Predictions
    probs_m1 = m1_model.predict_proba(X_test_m1)
    preds_m1_labels = m1_model.predict(X_test_m1)
    preds_m1 = np.array([CLASS_TO_INT[l] for l in preds_m1_labels])

    # Model 3 Predictions
    probs_m3 = m3_model.predict_proba(X_test_m3)
    preds_m3 = np.argmax(probs_m3, axis=1)

    # Standard Metrics
    metrics_m1 = compute_metrics_dict(y_test, preds_m1, probs_m1, name="Model 1D (Word+Char LR)")
    metrics_m3 = compute_metrics_dict(y_test, preds_m3, probs_m3, name="Model 3 (XGBoost Forensic Fusion)")

    print("\n--- STANDARD TEST SET EVALUATION ---")
    print(f"Model 1D -> Accuracy: {metrics_m1['accuracy']*100:.2f}% | Macro F1: {metrics_m1['macro_f1']*100:.2f}% | Phish F1: {metrics_m1['per_class']['phishing']['f1']*100:.2f}% | Fraud F1: {metrics_m1['per_class']['fraud_related']['f1']*100:.2f}%")
    print(f"Model 3  -> Accuracy: {metrics_m3['accuracy']*100:.2f}% | Macro F1: {metrics_m3['macro_f1']*100:.2f}% | Phish F1: {metrics_m3['per_class']['phishing']['f1']*100:.2f}% | Fraud F1: {metrics_m3['per_class']['fraud_related']['f1']*100:.2f}%")

    # Campaign-Aware Evaluation
    campaign_results = evaluate_campaign_aware(test_joined, preds_m1, preds_m3, y_test)

    # Feature Importance from XGBoost
    booster = m3_model.get_booster()
    score_gain = booster.get_score(importance_type="gain")
    score_weight = booster.get_score(importance_type="weight")
    score_cover = booster.get_score(importance_type="cover")

    xgb_importance = []
    sorted_gain = sorted(score_gain.items(), key=lambda x: x[1], reverse=True)
    for rank, (feat, gain) in enumerate(sorted_gain[:25], 1):
        xgb_importance.append({
            "rank": rank,
            "feature": feat,
            "gain": round(float(gain), 4),
            "weight": int(score_weight.get(feat, 0)),
            "cover": round(float(score_cover.get(feat, 0)), 2)
        })

    # SHAP Analysis
    global_shap, local_shap = run_shap_analysis(m3_model, X_test_m3, feature_cols, test_joined)

    # Save complete evaluation output
    out_eval = {
        "model1d_metrics": metrics_m1,
        "model3_metrics": metrics_m3,
        "campaign_aware_evaluation": campaign_results,
        "xgboost_feature_importance": xgb_importance,
        "shap_global_importance": global_shap,
        "shap_local_explanations": local_shap
    }

    eval_out_path = os.path.join("ml", "evaluation", "model3_evaluation_results.json")
    with open(eval_out_path, "w", encoding="utf-8") as f:
        json.dump(out_eval, f, indent=2)
    print(f"\n[+] Saved complete evaluation results to: {eval_out_path}")


if __name__ == "__main__":
    main()
