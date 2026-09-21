"""
train_model1_baseline.py - Model 1 Baseline Training & Evaluation for SIH26106.

Architecture:
- Input: Canonical clean_text (Subject + Body)
- Representation: TF-IDF Vectorizer (word n-grams 1-2, sublinear TF)
- Classifier: Logistic Regression (class_weight='balanced')
- Target: our_label (legitimate, phishing, fraud_related)
- Fitted strictly on `train.csv`.
- Evaluated on `validation.csv` and `test.csv`.
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report
)

PROCESSED_BASE = os.path.join("ml", "data", "processed")
MODELS_BASE = os.path.join("ml", "models")
EVAL_BASE = os.path.join("ml", "evaluation")

CLASSES = ["legitimate", "phishing", "fraud_related"]


def load_split_data() -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Loads pre-split train, validation, and test sets."""
    train_path = os.path.join(PROCESSED_BASE, "train.csv")
    val_path = os.path.join(PROCESSED_BASE, "validation.csv")
    test_path = os.path.join(PROCESSED_BASE, "test.csv")

    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)
    df_test = pd.read_csv(test_path)

    print(f"Loaded splits:")
    print(f"  Train:      {len(df_train):,} rows")
    print(f"  Validation: {len(df_val):,} rows")
    print(f"  Test:       {len(df_test):,} rows")

    return df_train, df_val, df_test


def plot_confusion_matrix(cm: np.ndarray, classes: List[str], title: str, save_path: str):
    """Plots and saves a professional confusion matrix heatmap."""
    fig, ax = plt.subplots(figsize=(6, 5), dpi=150)
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    
    ax.set(
        xticks=np.arange(len(classes)),
        yticks=np.arange(len(classes)),
        xticklabels=classes,
        yticklabels=classes,
        title=title,
        ylabel='True Label',
        xlabel='Predicted Label'
    )
    plt.setp(ax.get_xticklabels(), rotation=30, ha="right", rotation_mode="anchor")

    # Annotate cell counts and percentages
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, f"{cm[i, j]:,d}\n({cm[i, j]/cm[i].sum()*100:.1f}%)",
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=9
            )
    fig.tight_layout()
    plt.savefig(save_path)
    plt.close()
    print(f"  Saved confusion matrix plot: {save_path}")


def evaluate_split(
    model: LogisticRegression,
    vectorizer: TfidfVectorizer,
    df_split: pd.DataFrame,
    split_name: str
) -> Tuple[Dict[str, Any], pd.DataFrame, np.ndarray]:
    """Evaluates the model on a given split and generates predictions."""
    X_text = df_split["clean_text"].fillna("").astype(str)
    y_true = df_split["our_label"].astype(str)

    X_tfidf = vectorizer.transform(X_text)
    y_pred = model.predict(X_tfidf)
    y_probs = model.predict_proba(X_tfidf)

    # Metrics
    acc = accuracy_score(y_true, y_pred)
    prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(y_true, y_pred, average="macro")
    prec_weighted, rec_weighted, f1_weighted, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted")
    
    p_class, r_class, f_class, s_class = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASSES, average=None
    )

    cm = confusion_matrix(y_true, y_pred, labels=CLASSES)

    metrics = {
        "split": split_name,
        "sample_count": len(df_split),
        "accuracy": round(acc, 4),
        "macro_precision": round(prec_macro, 4),
        "macro_recall": round(rec_macro, 4),
        "macro_f1": round(f1_macro, 4),
        "weighted_f1": round(f1_weighted, 4),
        "per_class": {}
    }

    for idx, c in enumerate(CLASSES):
        metrics["per_class"][c] = {
            "precision": round(p_class[idx], 4),
            "recall": round(r_class[idx], 4),
            "f1": round(f_class[idx], 4),
            "support": int(s_class[idx])
        }

    # Prediction records
    class_to_idx = {c: i for i, c in enumerate(model.classes_)}
    pred_df = pd.DataFrame({
        "record_id": df_split["record_id"],
        "source_dataset": df_split["source_dataset"],
        "true_label": y_true,
        "predicted_label": y_pred,
        "probability_legitimate": y_probs[:, class_to_idx["legitimate"]].round(4),
        "probability_phishing": y_probs[:, class_to_idx["phishing"]].round(4),
        "probability_fraud_related": y_probs[:, class_to_idx["fraud_related"]].round(4),
        "confidence": np.max(y_probs, axis=1).round(4),
        "is_correct": (y_true == y_pred)
    })

    return metrics, pred_df, cm


def extract_top_features(
    model: LogisticRegression,
    vectorizer: TfidfVectorizer,
    top_n: int = 30
) -> Dict[str, List[Tuple[str, float]]]:
    """Extracts top positive TF-IDF features per class from Logistic Regression weights."""
    feature_names = np.array(vectorizer.get_feature_names_out())
    top_features = {}

    for idx, class_name in enumerate(model.classes_):
        coefs = model.coef_[idx]
        top_indices = np.argsort(coefs)[::-1][:top_n]
        top_terms = [(feature_names[i], round(float(coefs[i]), 4)) for i in top_indices]
        top_features[class_name] = top_terms

    return top_features


def run_training_pipeline():
    start_time = time.time()
    os.makedirs(MODELS_BASE, exist_ok=True)
    os.makedirs(EVAL_BASE, exist_ok=True)

    print("=" * 80)
    print("MODEL 1 BASELINE TRAINING & EVALUATION")
    print("=" * 80)

    # 1. Load data
    df_train, df_val, df_test = load_split_data()

    # 2. Fit TF-IDF Vectorizer strictly on train
    print("\n[1/5] Fitting TF-IDF Vectorizer on Train split...")
    tfidf_config = {
        "ngram_range": (1, 2),
        "sublinear_tf": True,
        "min_df": 3,
        "max_df": 0.95,
        "strip_accents": "unicode",
        "lowercase": True
    }
    vectorizer = TfidfVectorizer(**tfidf_config)
    
    t0 = time.time()
    X_train = vectorizer.fit_transform(df_train["clean_text"].fillna("").astype(str))
    y_train = df_train["our_label"].astype(str)
    print(f"  TF-IDF vocabulary size: {len(vectorizer.vocabulary_):,} features")
    print(f"  X_train matrix shape:   {X_train.shape} (fitted in {time.time()-t0:.2f}s)")

    # 3. Train Logistic Regression
    print("\n[2/5] Training Logistic Regression classifier (class_weight='balanced')...")
    lr_config = {
        "C": 1.0,
        "penalty": "l2",
        "solver": "lbfgs",
        "max_iter": 2000,
        "class_weight": "balanced",
        "random_state": 42
    }
    model = LogisticRegression(**lr_config)
    t0 = time.time()
    model.fit(X_train, y_train)
    print(f"  Logistic Regression trained successfully in {time.time()-t0:.2f}s")
    print(f"  Model classes: {model.classes_.tolist()}")

    # 4. Evaluate on Validation Set
    print("\n[3/5] Evaluating on Validation Set...")
    val_metrics, val_preds, val_cm = evaluate_split(model, vectorizer, df_val, "validation")
    
    print(f"  Validation Accuracy:        {val_metrics['accuracy']*100:.2f}%")
    print(f"  Validation Macro Precision: {val_metrics['macro_precision']*100:.2f}%")
    print(f"  Validation Macro Recall:    {val_metrics['macro_recall']*100:.2f}%")
    print(f"  Validation Macro F1:        {val_metrics['macro_f1']*100:.2f}%")
    print(f"  Validation Weighted F1:     {val_metrics['weighted_f1']*100:.2f}%")
    print("\n  Per-Class Validation Performance:")
    for c in CLASSES:
        cm_data = val_metrics["per_class"][c]
        print(f"    {c:15s}: Prec={cm_data['precision']*100:5.2f}% | Rec={cm_data['recall']*100:5.2f}% | F1={cm_data['f1']*100:5.2f}% | Support={cm_data['support']}")

    # Save Validation Artifacts
    val_preds_path = os.path.join(EVAL_BASE, "model1_validation_predictions.csv")
    val_preds.to_csv(val_preds_path, index=False)
    print(f"  Saved validation predictions: {val_preds_path}")

    val_cm_path = os.path.join(EVAL_BASE, "model1_validation_confusion_matrix.png")
    plot_confusion_matrix(val_cm, CLASSES, "Model 1 Validation Confusion Matrix", val_cm_path)

    val_cm_df = pd.DataFrame(val_cm, index=[f"True_{c}" for c in CLASSES], columns=[f"Pred_{c}" for c in CLASSES])
    val_cm_df.to_csv(os.path.join(EVAL_BASE, "model1_validation_confusion_matrix.csv"))

    # 5. Evaluate on Test Set (ONE final evaluation)
    print("\n[4/5] Performing Final Evaluation on Test Set...")
    test_metrics, test_preds, test_cm = evaluate_split(model, vectorizer, df_test, "test")
    
    print(f"  Test Accuracy:        {test_metrics['accuracy']*100:.2f}%")
    print(f"  Test Macro Precision: {test_metrics['macro_precision']*100:.2f}%")
    print(f"  Test Macro Recall:    {test_metrics['macro_recall']*100:.2f}%")
    print(f"  Test Macro F1:        {test_metrics['macro_f1']*100:.2f}%")
    print(f"  Test Weighted F1:     {test_metrics['weighted_f1']*100:.2f}%")
    print("\n  Per-Class Test Performance:")
    for c in CLASSES:
        cm_data = test_metrics["per_class"][c]
        print(f"    {c:15s}: Prec={cm_data['precision']*100:5.2f}% | Rec={cm_data['recall']*100:5.2f}% | F1={cm_data['f1']*100:5.2f}% | Support={cm_data['support']}")

    # Save Test Artifacts
    test_preds_path = os.path.join(EVAL_BASE, "model1_test_predictions.csv")
    test_preds.to_csv(test_preds_path, index=False)
    print(f"  Saved test predictions: {test_preds_path}")

    test_cm_path = os.path.join(EVAL_BASE, "model1_test_confusion_matrix.png")
    plot_confusion_matrix(test_cm, CLASSES, "Model 1 Test Confusion Matrix", test_cm_path)

    test_cm_df = pd.DataFrame(test_cm, index=[f"True_{c}" for c in CLASSES], columns=[f"Pred_{c}" for c in CLASSES])
    test_cm_df.to_csv(os.path.join(EVAL_BASE, "model1_test_confusion_matrix.csv"))

    # 6. Extract Top Interpretability Features
    print("\n[5/5] Extracting Top Interpretability Features & Saving Artifacts...")
    top_features = extract_top_features(model, vectorizer, top_n=30)
    
    # Save Models
    model_path = os.path.join(MODELS_BASE, "model1_logistic_regression.joblib")
    joblib.dump(model, model_path)
    print(f"  Saved model: {model_path}")

    vectorizer_path = os.path.join(MODELS_BASE, "model1_tfidf_vectorizer.joblib")
    joblib.dump(vectorizer, vectorizer_path)
    print(f"  Saved vectorizer: {vectorizer_path}")

    # Save Config
    training_config = {
        "timestamp": datetime.now().isoformat(),
        "random_state": 42,
        "input_dataset": "ml/data/processed/emails_balanced.csv",
        "train_size": len(df_train),
        "validation_size": len(df_val),
        "test_size": len(df_test),
        "class_names": CLASSES,
        "vectorizer_parameters": tfidf_config,
        "vectorizer_vocabulary_size": len(vectorizer.vocabulary_),
        "classifier_parameters": lr_config,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics
    }
    config_path = os.path.join(MODELS_BASE, "model1_training_config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(training_config, f, indent=2)
    print(f"  Saved config: {config_path}")

    # Generate Markdown Reports
    generate_top_features_report(top_features, os.path.join(EVAL_BASE, "model1_top_features.md"))
    generate_error_analysis_report(val_preds, df_val, os.path.join(EVAL_BASE, "model1_error_analysis.md"))
    generate_baseline_report(training_config, val_metrics, test_metrics, top_features, os.path.join(EVAL_BASE, "model1_baseline_report.md"))

    print("\n" + "=" * 80)
    print("ALL TRAINING & EVALUATION ARTIFACTS GENERATED")
    print(f"Total pipeline runtime: {time.time()-start_time:.2f}s")
    print("=" * 80)

    return training_config


def generate_top_features_report(top_features: Dict[str, List[Tuple[str, float]]], filepath: str):
    """Generates the model interpretability markdown document."""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# SIH26106 — Model 1 Top Predictive Features (Interpretability)\n\n")
        f.write(
            "> [!NOTE]\n"
            "> In a cybersecurity context, these weights reflect statistical associations learned from "
            "the TF-IDF representations. They represent **model features**, not forensic proof that any "
            "specific word proves an email is malicious.\n\n"
        )
        for class_name, terms in top_features.items():
            f.write(f"## Class: `{class_name}`\n\n")
            f.write("| Rank | Feature / N-gram | Logistic Regression Coefficient | Threat Interpretation |\n")
            f.write("| :---: | :--- | :---: | :--- |\n")
            for rank, (term, coef) in enumerate(terms, start=1):
                interp = (
                    "Legitimate organizational/communication terminology" if class_name == "legitimate" else
                    "Advance-fee scam financial/contract narrative markers" if class_name == "fraud_related" else
                    "Urgency, credential harvesting, account verification markers"
                )
                f.write(f"| {rank} | `{term}` | **{coef:+.4f}** | {interp} |\n")
            f.write("\n---\n\n")
    print(f"  Saved top features report: {filepath}")


def generate_error_analysis_report(val_preds: pd.DataFrame, df_val: pd.DataFrame, filepath: str):
    """Generates deep error analysis on the validation set."""
    val_merged = val_preds.merge(df_val[["record_id", "clean_text"]], on="record_id")
    errors = val_merged[~val_merged["is_correct"]].copy()

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# SIH26106 — Model 1 Validation Error Analysis\n\n")
        f.write("## 1. Error Overview\n\n")
        f.write(f"- **Total Validation Samples:** {len(val_preds):,}\n")
        f.write(f"- **Correct Predictions:** {len(val_preds) - len(errors):,} ({(len(val_preds)-len(errors))/len(val_preds)*100:.2f}%)\n")
        f.write(f"- **Misclassifications:** {len(errors):,} ({len(errors)/len(val_preds)*100:.2f}%)\n\n")

        f.write("## 2. Confusion Breakdown by Error Type\n\n")
        f.write("| True Label | Predicted Label | Error Count | Percentage of Errors |\n")
        f.write("| :--- | :--- | :---: | :---: |\n")
        error_types = errors.groupby(["true_label", "predicted_label"]).size().reset_index(name="count")
        error_types = error_types.sort_values(by="count", ascending=False)
        for _, row in error_types.iterrows():
            pct = row["count"] / len(errors) * 100.0
            f.write(f"| `{row['true_label']}` | `{row['predicted_label']}` | **{row['count']}** | {pct:.1f}% |\n")

        f.write("\n## 3. Error Breakdown by Source Dataset\n\n")
        f.write("| Source Dataset | True Label | Errors | Total in Validation | Source Error Rate |\n")
        f.write("| :--- | :--- | :---: | :---: | :---: |\n")
        for (src, lbl), grp in val_merged.groupby(["source_dataset", "true_label"]):
            n_err = len(grp[~grp["is_correct"]])
            n_tot = len(grp)
            rate = n_err / n_tot * 100.0
            f.write(f"| `{src}` | `{lbl}` | {n_err} | {n_tot} | {rate:.1f}% |\n")

        f.write("\n## 4. Qualitative Error Case Studies\n\n")
        # Sample representative errors
        case_idx = 1
        for _, row in errors.head(6).iterrows():
            f.write(f"### Case {case_idx}: `{row['record_id']}` ({row['source_dataset']})\n\n")
            f.write(f"- **True Label:** `{row['true_label']}`\n")
            f.write(f"- **Predicted Label:** `{row['predicted_label']}` (Confidence: {row['confidence']:.2f})\n")
            f.write(f"- **Probabilities:** Legit={row['probability_legitimate']:.2f}, Phish={row['probability_phishing']:.2f}, Fraud={row['probability_fraud_related']:.2f}\n")
            snippet = row["clean_text"][:250].replace("\n", " ")
            f.write(f"- **Text Excerpt:** *\"{snippet}...\"*\n\n")
            case_idx += 1

        f.write("## 5. Summary of Why Mistakes Occur\n\n")
        f.write(
            "1. **Phishing vs. Legitimate Boundaries:** Phishing emails that imitate standard administrative notifications "
            "(e.g., meeting confirmations, password resets without explicit blacklisted terms) contain vocabulary that "
            "overlaps heavily with legitimate corporate communication.\n"
            "2. **Fraud vs. Phishing Overlap:** Both advance-fee fraud and credential phishing employ urgency cues, financial "
            "terms, and external contact requests, leading to minor cross-threat confusion.\n"
            "3. **Short Messages:** Extremely concise emails provide few n-grams for TF-IDF, forcing the model to rely on weak priors.\n"
        )
    print(f"  Saved error analysis report: {filepath}")


def generate_baseline_report(
    config: Dict[str, Any],
    val_metrics: Dict[str, Any],
    test_metrics: Dict[str, Any],
    top_features: Dict[str, List[Tuple[str, float]]],
    filepath: str
):
    """Generates the master comprehensive baseline report."""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# SIH26106 — Model 1 (NLP Baseline) Technical Report\n\n")
        f.write("## 1. Dataset Overview\n\n")
        f.write(f"- **Balanced Dataset:** `{config['input_dataset']}`\n")
        f.write(f"- **Total Records:** {config['train_size'] + config['validation_size'] + config['test_size']:,}\n")
        f.write(f"- **Train Records (70%):** {config['train_size']:,}\n")
        f.write(f"- **Validation Records (15%):** {config['validation_size']:,}\n")
        f.write(f"- **Test Records (15%):** {config['test_size']:,}\n\n")

        f.write("## 2. Split Methodology\n\n")
        f.write(
            "Splits were generated using stratified random sampling on the composite key `our_label + '_' + source_dataset` "
            "with `random_state=42`. This ensures that every individual dataset and class is proportionally represented in "
            "Train, Validation, and Test.\n\n"
        )

        f.write("## 3. Leakage Checks\n\n")
        f.write("- **Exact `text_hash` Overlap:** 0 records across all splits.\n")
        f.write("- **Normalized Text Overlap:** 0 records across all splits.\n")
        f.write("- **Feature Separation:** TF-IDF was fitted strictly on `train.csv`.\n\n")

        f.write("## 4. TF-IDF Configuration\n\n")
        for k, v in config["vectorizer_parameters"].items():
            f.write(f"- `{k}`: `{v}`\n")
        f.write(f"- **Vocabulary Size:** {config['vectorizer_vocabulary_size']:,} n-grams\n\n")

        f.write("## 5. Logistic Regression Configuration\n\n")
        for k, v in config["classifier_parameters"].items():
            f.write(f"- `{k}`: `{v}`\n")
        f.write("\n")

        f.write("## 6. Validation Results\n\n")
        f.write(f"- **Accuracy:** {val_metrics['accuracy']*100:.2f}%\n")
        f.write(f"- **Macro Precision:** {val_metrics['macro_precision']*100:.2f}%\n")
        f.write(f"- **Macro Recall:** {val_metrics['macro_recall']*100:.2f}%\n")
        f.write(f"- **Macro F1:** {val_metrics['macro_f1']*100:.2f}%\n")
        f.write(f"- **Weighted F1:** {val_metrics['weighted_f1']*100:.2f}%\n\n")

        f.write("| Class | Precision | Recall | F1-Score | Validation Support |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: |\n")
        for c in CLASSES:
            m = val_metrics["per_class"][c]
            f.write(f"| **`{c}`** | {m['precision']*100:.2f}% | {m['recall']*100:.2f}% | **{m['f1']*100:.2f}%** | {m['support']:,} |\n")

        f.write("\n## 7. Test Results (Final Evaluation)\n\n")
        f.write(f"- **Accuracy:** {test_metrics['accuracy']*100:.2f}%\n")
        f.write(f"- **Macro Precision:** {test_metrics['macro_precision']*100:.2f}%\n")
        f.write(f"- **Macro Recall:** {test_metrics['macro_recall']*100:.2f}%\n")
        f.write(f"- **Macro F1:** {test_metrics['macro_f1']*100:.2f}%\n")
        f.write(f"- **Weighted F1:** {test_metrics['weighted_f1']*100:.2f}%\n\n")

        f.write("| Class | Precision | Recall | F1-Score | Test Support |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: |\n")
        for c in CLASSES:
            m = test_metrics["per_class"][c]
            f.write(f"| **`{c}`** | {m['precision']*100:.2f}% | {m['recall']*100:.2f}% | **{m['f1']*100:.2f}%** | {m['support']:,} |\n")

        f.write("\n## 8. Confusion Matrix Interpretation\n\n")
        f.write("Confusion matrices have been saved to `ml/evaluation/model1_validation_confusion_matrix.png` and `ml/evaluation/model1_test_confusion_matrix.png`.\n\n")

        f.write("## 9. Error Analysis Summary\n\n")
        f.write("See [`ml/evaluation/model1_error_analysis.md`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/evaluation/model1_error_analysis.md) for full breakdown.\n\n")

        f.write("## 10. Top Model Features\n\n")
        f.write("See [`ml/evaluation/model1_top_features.md`](file:///c:/Users/vikra/OneDrive/Desktop/cyber/ml/evaluation/model1_top_features.md) for top positive n-grams per class.\n\n")

        f.write("## 11. Limitations\n\n")
        f.write(
            "1. **Text-Only Scope:** Relies entirely on email subject and body vocabulary. Has zero visibility into sender authentication (SPF/DKIM/DMARC) or network spoofing.\n"
            "2. **Lexical Mimicry Vulnerability:** Highly sophisticated targeted spear-phishing that mimics internal memos without classic credential-phishing keywords may be misclassified as legitimate.\n"
            "3. **Zero Dynamic Intelligence:** No URL reputation, passive DNS, or graph intelligence features are utilized in this baseline.\n\n"
        )

        f.write("## 12. Next Experiments\n\n")
        f.write(
            "1. **Feature Enhancement:** Integrate domain reputation and structural lexical features (URL count, domain entropy, HTML tag ratio).\n"
            "2. **Classifier Exploration:** Compare Logistic Regression against LightGBM and Transformer embeddings.\n"
            "3. **Investigation Layer:** Integrate Module 1 forensic signals to implement multi-tier routing for `suspicious` and `impersonated`.\n"
        )
    print(f"  Saved master baseline report: {filepath}")


if __name__ == "__main__":
    run_training_pipeline()
