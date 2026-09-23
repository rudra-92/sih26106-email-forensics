"""
predict_fusion.py - End-to-End Inference Pipeline for SIH26106.

Executes the full forensic fusion detection pipeline:
Raw Email (.eml / dict / string)
   ↓
Model 1D (Word+Char TF-IDF LR)
   ↓
4 NLP Probabilities
   ↓
Model 2 (Forensic Intelligence Extractors)
   ↓
136 Forensic Features (Headers, Auth, IPs, Domains, URLs, Linguistic/BEC, Attachments, YARA)
   ↓
Model 3 XGBoost Fusion Classifier
   ↓
Class Probabilities + Prediction + SHAP Local Explainability
"""

import os
import sys

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

import json
import numpy as np
import pandas as pd
import joblib
import xgboost as xgb
import shap
from typing import Dict, Any, Union, Optional, List

from ml.forensic.email_parser import parse_email, ParsedEmail
from ml.forensic.feature_pipeline import ForensicFeaturePipeline


CLASS_NAMES = ["fraud_related", "legitimate", "phishing"]


def _resolve_path(path: str) -> str:
    """Resolves relative file path using cwd or WORKSPACE_ROOT."""
    if not path or os.path.isabs(path):
        return path
    if os.path.exists(path):
        return os.path.abspath(path)
    cand = os.path.join(WORKSPACE_ROOT, path)
    if os.path.exists(cand):
        return cand
    return path


class FusionThreatPredictor:
    """End-to-end Forensic Fusion inference pipeline."""

    def __init__(
        self,
        m1_lr_path: str = "ml/models/model1d_word_char_filtered_lr.joblib",
        m1_vec_path: str = "ml/models/model1d_word_char_filtered_vectorizer.joblib",
        m3_model_path: str = "ml/models/model3_xgboost_forensic_fusion.json",
        schema_path: str = "ml/models/model3_feature_schema.json",
        config_path: str = "ml/models/model3_config.json"
    ):
        r_m1_lr = _resolve_path(m1_lr_path)
        r_m1_vec = _resolve_path(m1_vec_path)
        r_m3 = _resolve_path(m3_model_path)
        r_schema = _resolve_path(schema_path)

        # 1. Load Model 1D artifacts
        if not os.path.exists(r_m1_lr) or not os.path.exists(r_m1_vec):
            raise FileNotFoundError("Model 1D artifacts missing.")
        self.m1_model = joblib.load(r_m1_lr)
        self.m1_vec = joblib.load(r_m1_vec)
        self.m1_classes = list(self.m1_model.classes_)

        # 2. Load Model 2 feature pipeline
        self.m2_pipeline = ForensicFeaturePipeline(
            model1_lr_path=r_m1_lr,
            model1_vec_path=r_m1_vec,
            model1_model=self.m1_model,
            model1_vectorizer=self.m1_vec,
        )

        # 3. Load Model 3 XGBoost
        if not os.path.exists(r_m3):
            raise FileNotFoundError(f"Model 3 model missing at {r_m3}")
        self.m3_model = xgb.XGBClassifier()
        self.m3_model.load_model(r_m3)

        # 4. Load Schema
        with open(r_schema, "r", encoding="utf-8") as f:
            self.schema = json.load(f)
        self.feature_names = self.schema["feature_names"]

        # 5. Initialize SHAP Explainer
        self.explainer = shap.TreeExplainer(self.m3_model)

    def predict_email(self, email_input: Union[str, bytes, Dict[str, Any]], email_id: str = "eval_0") -> Dict[str, Any]:
        """
        Analyzes a single email and returns threat classification with SHAP explanation.
        """
        # Step 1: Parse Email
        parsed = parse_email(email_input, email_id=email_id)

        # Step 2: Extract Model 2 Forensic Features & Evidence
        # Note: extract_features computes Model 1 probabilities internally as well
        features_dict, evidence_dict = self.m2_pipeline.extract_features(email_input, email_id=email_id)

        # Step 3: Align with exact Model 3 feature schema
        feature_row = {}
        for fname in self.feature_names:
            val = features_dict.get(fname, np.nan)
            # Ensure NLP probability features fed to Model 3 are strictly finite and non-NaN
            if fname in ("nlp_prob_legitimate", "nlp_prob_spam", "nlp_prob_phishing", "nlp_prob_fraud"):
                if val is None or not np.isfinite(val):
                    val = 0.0
            feature_row[fname] = val

        df_features = pd.DataFrame([feature_row])[self.feature_names]

        # Step 4: Model 3 Inference
        probs = self.m3_model.predict_proba(df_features)[0]
        pred_idx = int(np.argmax(probs))
        pred_label = CLASS_NAMES[pred_idx]
        confidence = float(probs[pred_idx])

        # Step 5: SHAP Local Explanation
        shap_vals = self.explainer.shap_values(df_features)
        if isinstance(shap_vals, list):
            target_shap = shap_vals[pred_idx][0]  # (n_features,)
        else:
            target_shap = shap_vals[0, :, pred_idx]

        pos_drivers = []
        neg_drivers = []
        for i, val in enumerate(target_shap):
            fname = self.feature_names[i]
            feat_val = feature_row[fname]
            if val > 0.05:
                pos_drivers.append({"feature": fname, "shap_impact": round(float(val), 4), "feature_value": feat_val})
            elif val < -0.05:
                neg_drivers.append({"feature": fname, "shap_impact": round(float(val), 4), "feature_value": feat_val})

        pos_drivers.sort(key=lambda x: x["shap_impact"], reverse=True)
        neg_drivers.sort(key=lambda x: x["shap_impact"])

        def sanitize(v):
            if v is None or (isinstance(v, float) and (np.isnan(v) or np.isinf(v))):
                return None
            if hasattr(v, "item"):
                return v.item()
            return v

        pos_drivers_clean = [
            {"feature": d["feature"], "shap_impact": d["shap_impact"], "feature_value": sanitize(d["feature_value"])}
            for d in pos_drivers[:8]
        ]
        neg_drivers_clean = [
            {"feature": d["feature"], "shap_impact": d["shap_impact"], "feature_value": sanitize(d["feature_value"])}
            for d in neg_drivers[:5]
        ]

        return {
            "email_id": email_id,
            "prediction": {
                "label": pred_label,
                "confidence": round(confidence, 4),
                "probabilities": {
                    CLASS_NAMES[i]: round(float(probs[i]), 4)
                    for i in range(len(CLASS_NAMES))
                }
            },
            "nlp_signals": {
                "model1d_probs": {
                    "legitimate": sanitize(features_dict.get("nlp_prob_legitimate", 0.0)) or 0.0,
                    "spam": sanitize(features_dict.get("nlp_prob_spam", 0.0)) or 0.0,
                    "phishing": sanitize(features_dict.get("nlp_prob_phishing", 0.0)) or 0.0,
                    "fraud_related": sanitize(features_dict.get("nlp_prob_fraud", 0.0)) or 0.0,
                }
            },
            "explainability": {
                "target_class": pred_label,
                "top_positive_forensic_drivers": pos_drivers_clean,
                "top_negative_counter_signals": neg_drivers_clean
            },
            "forensic_evidence_summary": {
                "spf_pass": int(sanitize(features_dict.get("spf_pass")) or 0),
                "spf_alignment_issue": sanitize(features_dict.get("spf_alignment_issue")),
                "dkim_pass": int(sanitize(features_dict.get("dkim_pass")) or 0),
                "dkim_alignment_issue": sanitize(features_dict.get("dkim_alignment_issue")),
                "dmarc_pass": int(sanitize(features_dict.get("dmarc_pass")) or 0),
                "dmarc_alignment_issue": sanitize(features_dict.get("dmarc_alignment_issue")),
                "sender_domain_mismatch": int(1 if sanitize(features_dict.get("sender_domain_replyto_domain_mismatch")) == 1 else 0),
                "url_count": int(sanitize(features_dict.get("url_count")) or 0),
                "ip_based_url_count": int(sanitize(features_dict.get("ip_based_url_count")) or 0),
                "urgency_term_count": int(sanitize(features_dict.get("urgency_term_count")) or 0),
                "financial_term_count": int(sanitize(features_dict.get("financial_term_count")) or 0),
                "attachment_count": int(sanitize(features_dict.get("attachment_count")) or 0),
                "executable_attachment": int(sanitize(features_dict.get("executable_attachment")) or 0),
                "yara_match_count": int(sanitize(features_dict.get("yara_match_count")) or 0)
            }
        }


def main():
    print("=" * 80)
    print("TESTING END-TO-END FUSION INFERENCE PIPELINE")
    print("=" * 80)

    # Check if models exist
    if not os.path.exists("ml/models/model3_xgboost_forensic_fusion.json"):
        print("[-] Model 3 not yet trained. Run train_model3_fusion.py first.")
        return

    predictor = FusionThreatPredictor()

    sample_email = {
        "subject": "Urgent: Verify your banking credentials immediately",
        "clean_text": "Dear customer, your bank account has been locked. Click here immediately to verify your identity and password.",
        "sender": "Security Desk <alert@security-update-bank.xyz>",
        "reply_to": "attacker@darkweb-drop.com"
    }

    result = predictor.predict_email(sample_email, email_id="demo_phish_001")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
