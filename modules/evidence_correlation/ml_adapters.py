"""External Machine Learning model adapters for Module 6.

Provides framework-agnostic ingestion adapters and contracts for:
1. Email Threat Classifier (EmailThreatModelAdapter)
   Expected concepts: legitimate, suspicious, impersonated, phishing, fraud
2. BEC / Intent Classifier (BECIntentModelAdapter)
   Expected concepts: payment_diversion, fake_invoice, credential_harvesting,
   executive_impersonation, and other relevant intent labels.
3. URL Risk Classifier (URLRiskModelAdapter)
   Consumes the 14 static URL features already produced by Module 3.

CRITICAL FORENSIC SEMANTICS & ATTRIBUTION GUARDRAILS:
- Zero ML framework imports (no torch, tensorflow, sklearn, transformers, onnxruntime).
- Every ML prediction receives trust_state = 'inferred'; NEVER treated as observed facts.
- Confidence scores are recorded with confidence_metric = 'heuristic_non_calibrated_consensus'.
- Adapters NEVER assert human attacker identity, physical location, guaranteed attacker IP,
  or malice as a factual certainty.
- Malformed, missing, or partial framework outputs degrade gracefully without crashing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple, Union

from .models import MlPrediction, NormalizedEvidence

# Explicit 14 static URL features contract produced by Module 3
EXPECTED_MODULE3_FEATURES: Tuple[str, ...] = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "special_character_count",
    "percent_encoded_count",
    "host_is_ip",
    "non_default_port",
    "userinfo_present",
    "login_token_present",
    "redirect_indicator",
    "visible_href_mismatch",
    "domain_similarity_score",
)

FORBIDDEN_ATTRIBUTION_KEYS = {
    "attacker_name",
    "attacker_identity",
    "attacker_location",
    "home_address",
    "physical_location",
    "suspect_name",
    "culprit",
}


class BaseModelAdapter:
    """Abstract base adapter enforcing forensic boundaries and framework independence."""

    MODEL_NAME: str = "base_model"
    DEFAULT_CONFIDENCE_METRIC: str = "heuristic_non_calibrated_consensus"

    @classmethod
    def sanitize_raw(cls, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Strip any disallowed speculative attribution keys from model payloads."""
        cleaned = dict(raw)
        for key in FORBIDDEN_ATTRIBUTION_KEYS:
            if key in cleaned:
                cleaned.pop(key, None)
        return cleaned

    @classmethod
    def parse_confidence(cls, val: Any) -> float:
        """Coerce raw confidence score safely into bounded float [0.0, 1.0]."""
        try:
            c = float(val) if val is not None else 0.0
            return max(0.0, min(1.0, c))
        except (ValueError, TypeError):
            return 0.0

    @classmethod
    def from_framework_output(
        cls,
        output: Any,
        class_labels: Optional[List[str]] = None,
        model_name: Optional[str] = None,
        model_version: Optional[str] = None,
        input_reference: Optional[str] = None,
        features_used: Optional[List[str]] = None,
        top_features: Optional[List[str]] = None,
        provenance: Optional[List[str]] = None,
    ) -> Optional[MlPrediction]:
        """Convert generic framework outputs (sklearn, PyTorch, TF, ONNX) into MlPrediction.

        Accepts:
        - Dict with label/confidence/probabilities
        - Tuple of (label, confidence) or (probabilities_list, class_labels)
        - List/iterable of float probabilities matching class_labels
        """
        if output is None:
            return None

        m_name = model_name or cls.MODEL_NAME
        resolved_prov = list(provenance or [m_name])
        resolved_feat = list(features_used or [])
        resolved_top = list(top_features or [])

        # 1. Output is already a dictionary
        if isinstance(output, dict):
            label = str(output.get("label", output.get("prediction", "unknown"))).lower()
            conf = cls.parse_confidence(output.get("confidence", output.get("score", 0.0)))
            raw = cls.sanitize_raw(output)
            m_ver = output.get("model_version", model_version)
            ref = output.get("input_reference", input_reference)
            feats = output.get("features_used", resolved_feat)
            top_f = output.get("top_features", resolved_top)

            return MlPrediction(
                model=m_name,
                model_version=str(m_ver) if m_ver else None,
                label=label,
                confidence=conf,
                confidence_metric=cls.DEFAULT_CONFIDENCE_METRIC,
                input_reference=str(ref) if ref else None,
                trust_state="inferred",
                features_used=list(feats),
                top_features=list(top_f),
                provenance=resolved_prov,
                raw_prediction=raw,
            )

        # 2. Output is a tuple (label, confidence)
        if isinstance(output, tuple) and len(output) >= 2:
            label = str(output[0]).lower()
            conf = cls.parse_confidence(output[1])
            return MlPrediction(
                model=m_name,
                model_version=str(model_version) if model_version else None,
                label=label,
                confidence=conf,
                confidence_metric=cls.DEFAULT_CONFIDENCE_METRIC,
                input_reference=str(input_reference) if input_reference else None,
                trust_state="inferred",
                features_used=resolved_feat,
                top_features=resolved_top,
                provenance=resolved_prov,
                raw_prediction={"label": label, "confidence": conf},
            )

        # 3. Output is an iterable of probabilities matching class_labels (sklearn/pytorch/onnx)
        if isinstance(output, (list, tuple)) and class_labels and len(output) == len(class_labels):
            try:
                probs = [float(p) for p in output]
                max_idx = probs.index(max(probs))
                best_label = str(class_labels[max_idx]).lower()
                best_conf = cls.parse_confidence(probs[max_idx])
                raw = {
                    "probabilities": dict(zip(class_labels, probs)),
                    "argmax_index": max_idx,
                }
                return MlPrediction(
                    model=m_name,
                    model_version=str(model_version) if model_version else None,
                    label=best_label,
                    confidence=best_conf,
                    confidence_metric=cls.DEFAULT_CONFIDENCE_METRIC,
                    input_reference=str(input_reference) if input_reference else None,
                    trust_state="inferred",
                    features_used=resolved_feat,
                    top_features=resolved_top,
                    provenance=resolved_prov,
                    raw_prediction=raw,
                )
            except (ValueError, TypeError):
                return None

        # 4. Object with attributes (e.g. custom container)
        if hasattr(output, "label") or hasattr(output, "prediction"):
            label = str(getattr(output, "label", getattr(output, "prediction", "unknown"))).lower()
            conf = cls.parse_confidence(getattr(output, "confidence", getattr(output, "score", 0.0)))
            m_ver = getattr(output, "model_version", model_version)
            ref = getattr(output, "input_reference", input_reference)
            raw = {"label": label, "confidence": conf}
            return MlPrediction(
                model=m_name,
                model_version=str(m_ver) if m_ver else None,
                label=label,
                confidence=conf,
                confidence_metric=cls.DEFAULT_CONFIDENCE_METRIC,
                input_reference=str(ref) if ref else None,
                trust_state="inferred",
                features_used=resolved_feat,
                top_features=resolved_top,
                provenance=resolved_prov,
                raw_prediction=raw,
            )

        return None


class EmailThreatModelAdapter(BaseModelAdapter):
    """Adapter for external Email Threat Classifier predictions.

    Expected concepts:
    - legitimate
    - suspicious
    - impersonated
    - phishing
    - fraud
    """

    MODEL_NAME = "email_threat_classifier"

    CONCEPT_CANONICALIZATION = {
        "benign": "legitimate",
        "clean": "legitimate",
        "ham": "legitimate",
        "safe": "legitimate",
        "anomaly": "suspicious",
        "spoofed": "impersonated",
        "lookalike": "impersonated",
        "phish": "phishing",
        "credential_phishing": "phishing",
        "bec": "fraud",
        "scam": "fraud",
        "extortion": "fraud",
    }

    @classmethod
    def canonicalize_label(cls, raw_label: str) -> str:
        """Map raw model label to standard threat concept while preserving semantics."""
        clean = raw_label.strip().lower()
        return cls.CONCEPT_CANONICALIZATION.get(clean, clean)

    @classmethod
    def parse(
        cls,
        prediction: Union[Dict[str, Any], Any],
        case_id: Optional[str] = None,
    ) -> Optional[MlPrediction]:
        """Ingest and normalize an email threat prediction."""
        if prediction is None:
            return None

        features_used: List[str] = []
        top_features: List[str] = []

        if isinstance(prediction, dict):
            raw_lbl = str(prediction.get("label", prediction.get("threat_type", "unknown"))).lower()
            label = cls.canonicalize_label(raw_lbl)
            conf_raw = prediction.get("confidence", prediction.get("score", 0.0))
            ref = str(prediction.get("input_reference", prediction.get("case_id", case_id or "")))
            model_ver = prediction.get("model_version")
            features_used = list(prediction.get("features_used", []))
            top_features = list(prediction.get("top_features", []))
            raw = cls.sanitize_raw(dict(prediction))
        elif hasattr(prediction, "label"):
            raw_lbl = str(getattr(prediction, "label")).lower()
            label = cls.canonicalize_label(raw_lbl)
            conf_raw = getattr(prediction, "confidence", 0.0)
            ref = str(getattr(prediction, "input_reference", case_id or ""))
            model_ver = getattr(prediction, "model_version", None)
            features_used = list(getattr(prediction, "features_used", []))
            top_features = list(getattr(prediction, "top_features", []))
            raw = {"label": label, "confidence": conf_raw}
        else:
            return cls.from_framework_output(prediction, model_name=cls.MODEL_NAME, input_reference=case_id)

        conf = cls.parse_confidence(conf_raw)

        return MlPrediction(
            model=cls.MODEL_NAME,
            model_version=str(model_ver) if model_ver else None,
            label=label,
            confidence=conf,
            confidence_metric=cls.DEFAULT_CONFIDENCE_METRIC,
            input_reference=ref if ref else None,
            trust_state="inferred",
            features_used=features_used,
            top_features=top_features,
            provenance=[cls.MODEL_NAME],
            raw_prediction=raw,
        )


# Backward-compatible alias
EmailThreatClassifierAdapter = EmailThreatModelAdapter


class BECIntentModelAdapter(BaseModelAdapter):
    """Adapter for external BEC / Intent Classifier predictions.

    Expected concepts:
    - payment_diversion
    - fake_invoice
    - credential_harvesting
    - executive_impersonation
    - other relevant intent labels (urgent_request, gift_card, payroll_diversion, vendor_fraud)
    """

    MODEL_NAME = "bec_intent_classifier"

    INTENT_CANONICALIZATION = {
        "bank_change": "payment_diversion",
        "payment_update": "payment_diversion",
        "invoice_fraud": "fake_invoice",
        "billing_fraud": "fake_invoice",
        "password_reset": "credential_harvesting",
        "login_theft": "credential_harvesting",
        "ceo_fraud": "executive_impersonation",
        "vip_impersonation": "executive_impersonation",
    }

    @classmethod
    def canonicalize_intent(cls, raw_label: str) -> str:
        """Map raw model intent label to standard concept while preserving semantics."""
        clean = raw_label.strip().lower()
        return cls.INTENT_CANONICALIZATION.get(clean, clean)

    @classmethod
    def parse(
        cls,
        prediction: Union[Dict[str, Any], Any],
        case_id: Optional[str] = None,
    ) -> Optional[MlPrediction]:
        """Ingest and normalize a BEC intent prediction."""
        if prediction is None:
            return None

        features_used: List[str] = []
        top_features: List[str] = []

        if isinstance(prediction, dict):
            raw_lbl = str(
                prediction.get(
                    "intent_label",
                    prediction.get("label", prediction.get("intent", "unknown")),
                )
            ).lower()
            label = cls.canonicalize_intent(raw_lbl)
            conf_raw = prediction.get("confidence", prediction.get("score", 0.0))
            ref = str(prediction.get("input_reference", prediction.get("case_id", case_id or "")))
            model_ver = prediction.get("model_version")
            features_used = list(prediction.get("features_used", []))
            top_features = list(prediction.get("top_features", []))
            raw = cls.sanitize_raw(dict(prediction))
        elif hasattr(prediction, "label") or hasattr(prediction, "intent_label"):
            raw_lbl = str(getattr(prediction, "intent_label", getattr(prediction, "label", "unknown"))).lower()
            label = cls.canonicalize_intent(raw_lbl)
            conf_raw = getattr(prediction, "confidence", 0.0)
            ref = str(getattr(prediction, "input_reference", case_id or ""))
            model_ver = getattr(prediction, "model_version", None)
            features_used = list(getattr(prediction, "features_used", []))
            top_features = list(getattr(prediction, "top_features", []))
            raw = {"label": label, "confidence": conf_raw}
        else:
            return cls.from_framework_output(prediction, model_name=cls.MODEL_NAME, input_reference=case_id)

        conf = cls.parse_confidence(conf_raw)

        return MlPrediction(
            model=cls.MODEL_NAME,
            model_version=str(model_ver) if model_ver else None,
            label=label,
            confidence=conf,
            confidence_metric=cls.DEFAULT_CONFIDENCE_METRIC,
            input_reference=ref if ref else None,
            trust_state="inferred",
            features_used=features_used,
            top_features=top_features,
            provenance=[cls.MODEL_NAME],
            raw_prediction=raw,
        )


# Backward-compatible alias
BecIntentClassifierAdapter = BECIntentModelAdapter


class URLRiskModelAdapter(BaseModelAdapter):
    """Adapter for external URL Risk Classifier predictions.

    Consumes static URL features produced by Module 3.
    """

    MODEL_NAME = "url_risk_classifier"
    EXPECTED_FEATURES: Tuple[str, ...] = EXPECTED_MODULE3_FEATURES

    @classmethod
    def extract_features_from_module3(
        cls,
        url_features_or_dict: Union[Dict[str, Any], Any],
    ) -> Dict[str, Any]:
        """Extract and validate the 14 Module 3 static URL features.

        Expected features:
        1. url_length (int)
        2. hostname_length (int)
        3. path_length (int)
        4. query_length (int)
        5. subdomain_count (int)
        6. special_character_count (int)
        7. percent_encoded_count (int)
        8. host_is_ip (bool)
        9. non_default_port (bool)
        10. userinfo_present (bool)
        11. login_token_present (bool)
        12. redirect_indicator (bool)
        13. visible_href_mismatch (bool)
        14. domain_similarity_score (float)
        """
        if hasattr(url_features_or_dict, "to_dict"):
            src = url_features_or_dict.to_dict()
        elif isinstance(url_features_or_dict, dict):
            src = url_features_or_dict
        else:
            src = {}

        extracted: Dict[str, Any] = {}
        for feat in cls.EXPECTED_FEATURES:
            if feat in src:
                extracted[feat] = src[feat]
            elif hasattr(url_features_or_dict, feat):
                extracted[feat] = getattr(url_features_or_dict, feat)
            else:
                # Default typing fallback
                if feat == "domain_similarity_score":
                    extracted[feat] = 0.0
                elif feat in (
                    "host_is_ip",
                    "non_default_port",
                    "userinfo_present",
                    "login_token_present",
                    "redirect_indicator",
                    "visible_href_mismatch",
                ):
                    extracted[feat] = False
                else:
                    extracted[feat] = 0
        return extracted

    @classmethod
    def parse(
        cls,
        prediction: Union[Dict[str, Any], Any],
        url_ref: Optional[str] = None,
    ) -> Optional[MlPrediction]:
        """Ingest and normalize a URL risk prediction."""
        if prediction is None:
            return None

        features_used: List[str] = []
        top_features: List[str] = []

        if isinstance(prediction, dict):
            label = str(
                prediction.get(
                    "risk_label",
                    prediction.get("label", prediction.get("prediction", "unknown")),
                )
            ).lower()
            conf_raw = prediction.get("confidence", prediction.get("risk_score", prediction.get("score", 0.0)))
            ref = str(prediction.get("url", prediction.get("input_reference", url_ref or "")))
            model_ver = prediction.get("model_version")
            features_used = list(prediction.get("features_used", []))
            top_features = list(prediction.get("top_features", []))
            raw = cls.sanitize_raw(dict(prediction))
        elif hasattr(prediction, "label") or hasattr(prediction, "risk_label"):
            label = str(getattr(prediction, "risk_label", getattr(prediction, "label", "unknown"))).lower()
            conf_raw = getattr(prediction, "confidence", 0.0)
            ref = str(getattr(prediction, "url", getattr(prediction, "input_reference", url_ref or "")))
            model_ver = getattr(prediction, "model_version", None)
            features_used = list(getattr(prediction, "features_used", []))
            top_features = list(getattr(prediction, "top_features", []))
            raw = {"label": label, "confidence": conf_raw}
        else:
            return cls.from_framework_output(prediction, model_name=cls.MODEL_NAME, input_reference=url_ref)

        conf = cls.parse_confidence(conf_raw)

        return MlPrediction(
            model=cls.MODEL_NAME,
            model_version=str(model_ver) if model_ver else None,
            label=label,
            confidence=conf,
            confidence_metric=cls.DEFAULT_CONFIDENCE_METRIC,
            input_reference=ref if ref else None,
            trust_state="inferred",
            features_used=features_used,
            top_features=top_features,
            provenance=[cls.MODEL_NAME],
            raw_prediction=raw,
        )


# Backward-compatible alias
UrlRiskClassifierAdapter = URLRiskModelAdapter


class ForensicFusionModelAdapter(BaseModelAdapter):
    """Adapter for the real trained Forensic Fusion Model (Model 3 XGBoost + Model 1D NLP + Model 2 features).

    Consumes the exact output payload produced by FusionThreatPredictor.predict_email():
    - prediction: label, confidence, probabilities (fraud_related, legitimate, phishing)
    - nlp_signals: model1d_probs (legitimate, spam, phishing, fraud_related)
    - explainability: target_class, top_positive_forensic_drivers, top_negative_counter_signals
    - forensic_evidence_summary: dictionary of extracted forensic features

    CRITICAL FORENSIC SEMANTICS & ATTRIBUTION GUARDRAILS:
    - trust_state is ALWAYS 'inferred'; ML predictions are NEVER treated as observed facts.
    - confidence_metric is strictly 'heuristic_non_calibrated_consensus'.
    - NEVER asserts attacker identity, physical location, or guaranteed malice.
    - Positive SHAP drivers and negative counter-signals are preserved as explanatory evidence.
    - Model 1D NLP distribution is preserved separately from Model 3 fusion probabilities.
    """

    MODEL_NAME = "ml_forensic_fusion"
    DEFAULT_CONFIDENCE_METRIC = "heuristic_non_calibrated_consensus"

    @classmethod
    def parse(
        cls,
        payload: Union[Dict[str, Any], Any],
        case_id: Optional[str] = None,
    ) -> Optional[MlPrediction]:
        """Ingest and normalize a real FusionThreatPredictor output payload into an MlPrediction."""
        if payload is None:
            return None

        if hasattr(payload, "to_dict"):
            raw_data = payload.to_dict()
        elif isinstance(payload, dict):
            raw_data = payload
        else:
            return cls.from_framework_output(payload, model_name=cls.MODEL_NAME, input_reference=case_id)

        # 1. Prediction details
        pred_dict = raw_data.get("prediction", {})
        if not isinstance(pred_dict, dict):
            pred_dict = raw_data

        raw_label = str(pred_dict.get("label", "unknown")).lower()
        conf_raw = pred_dict.get("confidence", 0.0)
        conf = cls.parse_confidence(conf_raw)

        ref = str(raw_data.get("email_id", raw_data.get("input_reference", case_id or "")))

        # 2. Extract SHAP positive drivers and format into top_features
        explainability = raw_data.get("explainability", {})
        pos_drivers = explainability.get("top_positive_forensic_drivers", []) if isinstance(explainability, dict) else []
        top_features: List[str] = []
        features_used: List[str] = []

        if isinstance(pos_drivers, list):
            for d in pos_drivers:
                if isinstance(d, dict):
                    fname = str(d.get("feature", ""))
                    impact = d.get("shap_impact", 0.0)
                    try:
                        impact_val = float(impact)
                    except (ValueError, TypeError):
                        impact_val = 0.0
                    if fname:
                        features_used.append(fname)
                        top_features.append(f"{fname} (+{impact_val:.4f})" if impact_val >= 0 else f"{fname} ({impact_val:.4f})")

        # Negative counter-signals
        neg_drivers = explainability.get("top_negative_counter_signals", []) if isinstance(explainability, dict) else []
        if isinstance(neg_drivers, list):
            for d in neg_drivers:
                if isinstance(d, dict):
                    fname = str(d.get("feature", ""))
                    if fname and fname not in features_used:
                        features_used.append(fname)

        # 3. Sanitize raw data to guarantee zero forbidden attribution speculation
        cleaned_raw = cls.sanitize_raw(raw_data)

        return MlPrediction(
            model=cls.MODEL_NAME,
            model_version=str(raw_data.get("model_version", "1.0.0-fusion")),
            label=raw_label,
            confidence=conf,
            confidence_metric=cls.DEFAULT_CONFIDENCE_METRIC,
            input_reference=ref if ref else None,
            trust_state="inferred",
            features_used=features_used,
            top_features=top_features,
            provenance=[cls.MODEL_NAME, "predict_fusion.FusionThreatPredictor"],
            raw_prediction=cleaned_raw,
        )

    @classmethod
    def to_normalized_evidence(
        cls,
        payload_or_prediction: Union[Dict[str, Any], MlPrediction, Any],
        case_id: Optional[str] = None,
        start_index: int = 1,
    ) -> List[NormalizedEvidence]:
        """Convert real fusion output into structured, granular NormalizedEvidence objects."""
        ev_list: List[NormalizedEvidence] = []
        idx = start_index

        pred: Optional[MlPrediction] = None
        raw: Dict[str, Any] = {}

        if isinstance(payload_or_prediction, MlPrediction):
            pred = payload_or_prediction
            raw = pred.raw_prediction or {}
        elif isinstance(payload_or_prediction, dict):
            pred = cls.parse(payload_or_prediction, case_id=case_id)
            if pred is None:
                return []
            raw = pred.raw_prediction
        else:
            return []

        if pred is None:
            return []

        ref = pred.input_reference or case_id or ""
        entities = [ref] if ref else []
        prov = list(pred.provenance or [cls.MODEL_NAME])

        # --- 1. Primary Fusion Threat Prediction Evidence ---
        pred_dict = raw.get("prediction", {}) if isinstance(raw, dict) else {}
        probs = pred_dict.get("probabilities", {}) if isinstance(pred_dict, dict) else {}

        sev = "informational"
        if pred.label in ("phishing", "fraud_related", "fraud", "malware"):
            sev = "high"
        elif pred.label in ("suspicious", "spam"):
            sev = "medium"
        elif pred.label in ("legitimate", "benign", "safe"):
            sev = "low"

        desc = (
            f"Forensic fusion model '{pred.model}' predicted '{pred.label}' "
            f"(confidence: {pred.confidence:.4f}, consensus metric: {pred.confidence_metric})"
        )
        ev_list.append(
            NormalizedEvidence(
                evidence_id=f"EV-FUSION-{idx:04d}",
                source_module=cls.MODEL_NAME,
                evidence_type="ml_prediction",
                rule_id=f"RULE-ML-FUSION-{pred.label.upper()}",
                severity=sev,
                trust_state="inferred",
                description=desc,
                entity_ids=entities,
                timestamp=None,
                provenance=prov,
                supporting_fields={
                    "model": pred.model,
                    "model_version": pred.model_version,
                    "label": pred.label,
                    "confidence": pred.confidence,
                    "confidence_metric": pred.confidence_metric,
                    "model3_probabilities": dict(probs) if isinstance(probs, dict) else {},
                    "top_features": list(pred.top_features),
                },
            )
        )
        idx += 1

        # --- 2. Model 1D NLP Linguistics Signal Evidence ---
        nlp_signals = raw.get("nlp_signals", {}) if isinstance(raw, dict) else {}
        m1d_probs = nlp_signals.get("model1d_probs", {}) if isinstance(nlp_signals, dict) else {}
        if isinstance(m1d_probs, dict) and m1d_probs:
            phish_p = float(m1d_probs.get("phishing", 0.0) or 0.0)
            fraud_p = float(m1d_probs.get("fraud_related", 0.0) or 0.0)
            spam_p = float(m1d_probs.get("spam", 0.0) or 0.0)
            legit_p = float(m1d_probs.get("legitimate", 0.0) or 0.0)

            nlp_sev = "high" if (phish_p >= 0.70 or fraud_p >= 0.70) else ("medium" if (phish_p >= 0.30 or fraud_p >= 0.30 or spam_p >= 0.50) else "low")
            dominant_sig = max(m1d_probs.items(), key=lambda x: float(x[1] or 0.0))[0] if m1d_probs else "unknown"
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=f"EV-M1D-{idx:04d}",
                    source_module=cls.MODEL_NAME,
                    evidence_type="ml_prediction",
                    rule_id="RULE-ML-MODEL1D-NLP-SIGNALS",
                    severity=nlp_sev,
                    trust_state="inferred",
                    description=(
                        f"Model 1D NLP linguistic analysis: phishing={phish_p:.4f}, "
                        f"fraud_related={fraud_p:.4f}, spam={spam_p:.4f}, legitimate={legit_p:.4f}"
                    ),
                    entity_ids=entities,
                    timestamp=None,
                    provenance=[cls.MODEL_NAME, "model1d_word_char_filtered_lr"],
                    supporting_fields={
                        "model1d_probabilities": {
                            "phishing": phish_p,
                            "fraud_related": fraud_p,
                            "spam": spam_p,
                            "legitimate": legit_p,
                        },
                        "dominant_nlp_signal": dominant_sig,
                    },
                )
            )
            idx += 1

        # --- 3. SHAP Positive Supporting Drivers ---
        explainability = raw.get("explainability", {}) if isinstance(raw, dict) else {}
        pos_drivers = explainability.get("top_positive_forensic_drivers", []) if isinstance(explainability, dict) else []
        if isinstance(pos_drivers, list):
            for d in pos_drivers[:8]:
                if isinstance(d, dict):
                    feat = str(d.get("feature", ""))
                    impact = float(d.get("shap_impact", 0.0))
                    val = d.get("feature_value")
                    target = str(explainability.get("target_class", pred.label))

                    ev_list.append(
                        NormalizedEvidence(
                            evidence_id=f"EV-SHAP-POS-{idx:04d}",
                            source_module=cls.MODEL_NAME,
                            evidence_type="ml_prediction",
                            rule_id="RULE-ML-SHAP-SUPPORTING-DRIVER",
                            severity="medium" if impact >= 0.20 else "low",
                            trust_state="inferred",
                            description=(
                                f"SHAP local attribution: feature '{feat}' (+{impact:.4f}) "
                                f"supports threat classification '{target}' (observed value: {val})"
                            ),
                            entity_ids=entities,
                            timestamp=None,
                            provenance=[cls.MODEL_NAME, "shap.TreeExplainer"],
                            supporting_fields={
                                "feature": feat,
                                "shap_impact": impact,
                                "feature_value": val,
                                "direction": "supporting",
                                "target_class": target,
                            },
                        )
                    )
                    idx += 1

        # --- 4. SHAP Negative Counter-Signals (Preserved!) ---
        neg_drivers = explainability.get("top_negative_counter_signals", []) if isinstance(explainability, dict) else []
        if isinstance(neg_drivers, list):
            for d in neg_drivers[:5]:
                if isinstance(d, dict):
                    feat = str(d.get("feature", ""))
                    impact = float(d.get("shap_impact", 0.0))
                    val = d.get("feature_value")
                    target = str(explainability.get("target_class", pred.label))

                    ev_list.append(
                        NormalizedEvidence(
                            evidence_id=f"EV-SHAP-NEG-{idx:04d}",
                            source_module=cls.MODEL_NAME,
                            evidence_type="ml_prediction",
                            rule_id="RULE-ML-SHAP-COUNTER-SIGNAL",
                            severity="informational",
                            trust_state="inferred",
                            description=(
                                f"SHAP local attribution counter-signal: feature '{feat}' ({impact:.4f}) "
                                f"contests classification '{target}' (observed value: {val})"
                            ),
                            entity_ids=entities,
                            timestamp=None,
                            provenance=[cls.MODEL_NAME, "shap.TreeExplainer"],
                            supporting_fields={
                                "feature": feat,
                                "shap_impact": impact,
                                "feature_value": val,
                                "direction": "counter-signal",
                                "target_class": target,
                            },
                        )
                    )
                    idx += 1

        # --- 5. Forensic Evidence Summary (Observed ML inputs) ---
        feat_sum = raw.get("forensic_evidence_summary", {}) if isinstance(raw, dict) else {}
        if isinstance(feat_sum, dict) and feat_sum:
            ev_list.append(
                NormalizedEvidence(
                    evidence_id=f"EV-FEATSUM-{idx:04d}",
                    source_module=cls.MODEL_NAME,
                    evidence_type="ml_prediction",
                    rule_id="RULE-ML-FEATURE-SUMMARY",
                    severity="informational",
                    trust_state="inferred",
                    description="Observed forensic feature summary consumed during ML fusion inference",
                    entity_ids=entities,
                    timestamp=None,
                    provenance=[cls.MODEL_NAME, "ForensicFeaturePipeline"],
                    supporting_fields=dict(feat_sum),
                )
            )
            idx += 1

        return ev_list


class UnifiedMlAdapter:
    """Consolidated adapter managing ingestion across all external ML models."""

    @classmethod
    def parse_all(
        cls,
        threat_prediction: Optional[Union[Dict[str, Any], Any]] = None,
        bec_prediction: Optional[Union[Dict[str, Any], Any]] = None,
        url_predictions: Optional[List[Union[Dict[str, Any], Any]]] = None,
        fusion_prediction: Optional[Union[Dict[str, Any], Any]] = None,
        case_id: Optional[str] = None,
    ) -> List[MlPrediction]:
        """Parse predictions from all available models into a validated list of MlPrediction."""
        results: List[MlPrediction] = []

        # 1. Real Forensic Fusion Predictor (Priority)
        if fusion_prediction is not None:
            p_fusion = ForensicFusionModelAdapter.parse(fusion_prediction, case_id=case_id)
            if p_fusion:
                results.append(p_fusion)

        # 2. Email Threat Classifier
        if threat_prediction is not None:
            p_threat = EmailThreatModelAdapter.parse(threat_prediction, case_id=case_id)
            if p_threat:
                results.append(p_threat)

        # 3. BEC Intent Classifier
        if bec_prediction is not None:
            p_bec = BECIntentModelAdapter.parse(bec_prediction, case_id=case_id)
            if p_bec:
                results.append(p_bec)

        # 4. URL Risk Classifier
        if url_predictions:
            for u_pred in url_predictions:
                p_url = URLRiskModelAdapter.parse(u_pred)
                if p_url:
                    results.append(p_url)

        return results

    @classmethod
    def to_normalized_evidence(
        cls,
        predictions: List[MlPrediction],
        start_index: int = 1,
    ) -> List[NormalizedEvidence]:
        """Convert ML predictions to NormalizedEvidence with trust_state = 'inferred'."""
        ev_list: List[NormalizedEvidence] = []
        cur_idx = start_index
        for pred in predictions:
            if pred.model == ForensicFusionModelAdapter.MODEL_NAME:
                fusion_ev = ForensicFusionModelAdapter.to_normalized_evidence(
                    pred,
                    case_id=pred.input_reference,
                    start_index=cur_idx,
                )
                ev_list.extend(fusion_ev)
                cur_idx += len(fusion_ev)
                continue

            severity = "informational"
            if pred.label in (
                "phishing",
                "malware",
                "high_risk",
                "credential_harvesting",
                "wire_fraud",
                "payment_diversion",
                "fraud",
            ):
                severity = "high"
            elif pred.label in (
                "suspicious",
                "impersonated",
                "spam",
                "medium_risk",
                "urgent_request",
                "fake_invoice",
                "executive_impersonation",
            ):
                severity = "medium"
            elif pred.label in ("low_risk", "promotional", "legitimate"):
                severity = "low"

            desc = f"ML model '{pred.model}' predicted '{pred.label}' (confidence: {pred.confidence:.2f})"
            entities = [pred.input_reference] if pred.input_reference else []

            ev_list.append(
                NormalizedEvidence(
                    evidence_id=f"EV-ML-{cur_idx:03d}",
                    source_module=pred.model,
                    evidence_type="ml_prediction",
                    rule_id=f"RULE-ML-{pred.model.upper()}",
                    severity=severity,
                    trust_state="inferred",  # GUARANTEE: Never treated as observed facts
                    description=desc,
                    entity_ids=entities,
                    timestamp=None,
                    provenance=list(pred.provenance or [pred.model]),
                    supporting_fields={
                        "label": pred.label,
                        "confidence": pred.confidence,
                        "confidence_metric": pred.confidence_metric,
                        "model_version": pred.model_version,
                        "features_used": pred.features_used,
                        "top_features": pred.top_features,
                        "raw_prediction": pred.raw_prediction,
                    },
                )
            )
            cur_idx += 1
        return ev_list
