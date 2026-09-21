"""
feature_pipeline.py - Master Forensic Feature Extraction Pipeline for SIH26106.

Orchestrates all 12 forensic analyzer components:
1. email_parser: Standardizes RFC 822 or tabular records
2. header_analyzer: Header anomaly indicators
3. auth_analyzer: SPF, DKIM, DMARC parsing and alignment
4. received_analyzer: SMTP hop chains, anomalies, and infrastructure provenance
5. ip_analyzer: Public/private IP classification and enrichment stub
6. domain_analyzer: Domain syntax, typosquatting / homoglyph detection
7. url_analyzer: URL extraction, syntax heuristics, reputation stub
8. content_analyzer: Text metrics, linguistic ratios, lexical and BEC signals
9. attachment_analyzer: File extensions, MIME mismatches, entropy, byte strings
10. pe_analyzer: Static PE sections and categorized API import counts
11. document_analyzer: Office VBA macro inspection and OLE object detection
12. pdf_analyzer: Active PDF structural tokens (/JavaScript, /OpenAction)
13. yara_scanner: External YARA signature match count
14. model1_integration: Injects Model 1D NLP probabilities (legitimate, spam, phishing, fraud)

Outputs:
- Programmatic feature schema (Numerical, Binary, Categorical, Evidence)
- Parquet feature dataset (ml/datasets/model2_forensic_features.parquet)
- Feature quality audit (ml/evaluation/model2_feature_audit.csv)
- Feature summary markdown (ml/evaluation/model2_feature_summary.md)
"""

import os
import sys
import logging
import argparse
import time
from typing import Dict, List, Any, Optional, Tuple, Union
import numpy as np
import pandas as pd
import joblib

from .email_parser import ParsedEmail, parse_email
from .header_analyzer import HeaderAnalyzer
from .auth_analyzer import AuthAnalyzer
from .received_analyzer import ReceivedAnalyzer
from .ip_analyzer import IPAnalyzer
from .url_analyzer import URLAnalyzer
from .domain_analyzer import DomainAnalyzer
from .content_analyzer import ContentAnalyzer
from .attachment_analyzer import AttachmentAnalyzer
from .pe_analyzer import PEAnalyzer
from .document_analyzer import DocumentAnalyzer
from .pdf_analyzer import PDFAnalyzer
from .yara_scanner import YaraScanner

logger = logging.getLogger("ForensicFeaturePipeline")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


class ForensicFeaturePipeline:
    """Master orchestrator for Model 2 forensic feature extraction."""

    def __init__(
        self,
        config_path: str = "ml/configs/forensic_config.yaml",
        rules_dir: str = "rules",
        model1_lr_path: str = "ml/models/model1d_word_char_filtered_lr.joblib",
        model1_vec_path: str = "ml/models/model1d_word_char_filtered_vectorizer.joblib"
    ):
        self.config_path = config_path
        self.rules_dir = rules_dir

        # Initialize modular analyzers
        self.header_analyzer = HeaderAnalyzer()
        self.auth_analyzer = AuthAnalyzer()
        self.received_analyzer = ReceivedAnalyzer()
        self.ip_analyzer = IPAnalyzer()
        self.domain_analyzer = DomainAnalyzer(config_path=config_path)
        self.url_analyzer = URLAnalyzer()
        self.content_analyzer = ContentAnalyzer(config_path=config_path)
        self.attachment_analyzer = AttachmentAnalyzer()
        self.pe_analyzer = PEAnalyzer()
        self.document_analyzer = DocumentAnalyzer()
        self.pdf_analyzer = PDFAnalyzer()
        self.yara_scanner = YaraScanner(rules_dir=rules_dir)

        # Model 1 Integration
        self.model1_model = None
        self.model1_vectorizer = None
        self.model1_classes = []

        if os.path.exists(model1_lr_path) and os.path.exists(model1_vec_path):
            try:
                self.model1_model = joblib.load(model1_lr_path)
                self.model1_vectorizer = joblib.load(model1_vec_path)
                self.model1_classes = list(self.model1_model.classes_)
                logger.info(f"Loaded Model 1D: classes={self.model1_classes}")
            except Exception as e:
                logger.warning(f"Could not load Model 1D artifacts: {e}")
        else:
            logger.warning(f"Model 1D artifacts not found at {model1_lr_path}")

    def predict_model1_probabilities(self, text: str) -> Dict[str, float]:
        """
        Computes 4-class NLP probabilities from Model 1D.
        Classes: legitimate, spam, phishing, fraud_related
        """
        default_probs = {
            "nlp_prob_legitimate": np.nan,
            "nlp_prob_spam": 0.0,
            "nlp_prob_phishing": np.nan,
            "nlp_prob_fraud": np.nan,
        }

        if self.model1_model is None or self.model1_vectorizer is None:
            return default_probs

        clean_input = str(text or "").strip()
        if not clean_input:
            clean_input = " "

        try:
            feats = self.model1_vectorizer.transform([clean_input])
            probs = self.model1_model.predict_proba(feats)[0]
            prob_map = dict(zip(self.model1_classes, probs))

            return {
                "nlp_prob_legitimate": round(float(prob_map.get("legitimate", 0.0)), 4),
                "nlp_prob_spam": round(float(prob_map.get("spam", 0.0)), 4),
                "nlp_prob_phishing": round(float(prob_map.get("phishing", 0.0)), 4),
                "nlp_prob_fraud": round(float(prob_map.get("fraud_related", 0.0)), 4),
            }
        except Exception as e:
            logger.error(f"Error evaluating Model 1 probability: {e}")
            return default_probs

    def extract_features(self, input_data: Any, email_id: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Extracts complete forensic feature set and evidence for one email.
        Returns:
            features: flat dictionary of ML features (numerical, binary, categorical)
            evidence: dictionary of raw preserved provenance records
        """
        parsed = parse_email(input_data, email_id=email_id)

        # 1. Header Analysis
        header_feats, header_ev = self.header_analyzer.analyze(parsed)
        sender_dom = header_ev.get("sender_domain") or ""
        reply_dom = header_ev.get("reply_to_domain") or ""
        from_display = header_ev.get("from_display_name") or ""

        # 2. Authentication Analysis
        auth_feats, auth_ev = self.auth_analyzer.analyze(parsed, sender_domain=sender_dom)

        # 3. Received Header Hop Analysis
        rec_feats, rec_ev = self.received_analyzer.analyze(parsed)

        # 4. IP Analysis
        ip_feats, ip_ev = self.ip_analyzer.analyze(parsed, received_evidence=rec_ev)

        # 5. Domain Analysis
        dom_feats, dom_ev = self.domain_analyzer.analyze(sender_dom, reply_to_domain=reply_dom)

        # 6. URL Analysis
        url_feats, url_ev = self.url_analyzer.analyze(
            text_plain=parsed.body_plain,
            text_html=parsed.body_html
        )

        # 7. Content & Linguistic & BEC Analysis
        content_feats, content_ev = self.content_analyzer.analyze(
            text_plain=parsed.body_plain,
            text_html=parsed.body_html,
            display_name=from_display
        )

        # 8. Attachment & Static Byte Analysis
        att_feats, att_ev = self.attachment_analyzer.analyze(parsed.attachments)

        # 9, 10, 11, 12: PE, Document, PDF, YARA Analyzers across attachments
        pe_feats = {
            "is_pe": 0, "pe_entropy": np.nan, "section_count": 0,
            "suspicious_section_count": 0, "import_count": 0, "dll_count": 0,
            "export_count": 0, "pe_process_creation_apis": 0,
            "pe_command_execution_apis": 0, "pe_network_communication_apis": 0,
            "pe_memory_manipulation_apis": 0, "pe_persistence_apis": 0,
            "pe_credential_access_apis": 0
        }
        pe_ev = []

        doc_feats = {
            "has_macro": 0, "macro_count": 0,
            "embedded_object_count": 0, "suspicious_macro_indicator": 0
        }
        doc_ev = []

        pdf_feats = {
            "pdf_has_javascript": 0, "pdf_has_openaction": 0,
            "pdf_has_launch": 0, "pdf_has_embedded_file": 0,
            "pdf_has_acroform": 0
        }
        pdf_ev = []

        yara_match_count = 0
        yara_matched_rules = []

        for att in parsed.attachments:
            c_bytes = att.get("content_bytes") or b""
            f_name = att.get("filename") or ""

            # PE inspection
            if c_bytes.startswith(b"MZ"):
                p_f, p_e = self.pe_analyzer.analyze_bytes(c_bytes)
                if p_f["is_pe"]:
                    for k in pe_feats:
                        if k == "pe_entropy":
                            pe_feats[k] = p_f[k]
                        else:
                            pe_feats[k] = max(pe_feats[k], p_f[k])
                    pe_ev.append(p_e)

            # Office doc inspection
            if any(f_name.lower().endswith(ext) for ext in (".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm")):
                d_f, d_e = self.document_analyzer.analyze_bytes(f_name, c_bytes)
                for k in doc_feats:
                    doc_feats[k] = max(doc_feats[k], d_f[k])
                doc_ev.append(d_e)

            # PDF inspection
            if f_name.lower().endswith(".pdf") or c_bytes.startswith(b"%PDF-"):
                pdf_f, pdf_e = self.pdf_analyzer.analyze_bytes(c_bytes)
                for k in pdf_feats:
                    pdf_feats[k] = max(pdf_feats[k], pdf_f[k])
                pdf_ev.append(pdf_e)

            # YARA scan
            if c_bytes:
                y_f, y_e = self.yara_scanner.scan_bytes(c_bytes)
                yara_match_count += y_f["yara_match_count"]
                yara_matched_rules.extend(y_e.get("yara_rule_names", []))

        # 13. Model 1 Integration
        # Prefer clean_text if present, else plain body, else subject + body
        nlp_text = parsed.clean_text if parsed.clean_text else f"{parsed.subject}\n{parsed.body_plain}"
        nlp_probs = self.predict_model1_probabilities(nlp_text)

        # Merge all features into flat dictionary
        features = {
            "email_id": parsed.email_id,
            # NLP Probabilities
            **nlp_probs,
            # Header Features
            **header_feats,
            # Authentication Features
            **auth_feats,
            # Received Hop Features
            **rec_feats,
            # IP Features
            **ip_feats,
            # Domain Features
            **dom_feats,
            # URL Features
            **url_feats,
            # Content & BEC Features
            **content_feats,
            # Attachment Features
            **att_feats,
            # Executable / PE Features
            **pe_feats,
            # Document Features
            **doc_feats,
            # PDF Features
            **pdf_feats,
            # YARA Match Count
            "yara_match_count": yara_match_count,
        }

        # Evidence dictionary (never fed directly to XGBoost)
        evidence = {
            "email_id": parsed.email_id,
            "headers": header_ev,
            "authentication": auth_ev,
            "received_hops": rec_ev,
            "ip_forensics": ip_ev,
            "domain_forensics": dom_ev,
            "url_forensics": url_ev,
            "content_evidence": content_ev,
            "attachment_forensics": att_ev,
            "pe_forensics": pe_ev,
            "document_forensics": doc_ev,
            "pdf_forensics": pdf_ev,
            "yara_rule_names": list(set(yara_matched_rules)),
        }

        return features, evidence

    @classmethod
    def get_feature_schema(cls) -> Dict[str, Dict[str, str]]:
        """
        Programmatically classifies every feature into Numerical, Binary, Categorical, or Metadata.
        """
        sample_pipeline = cls()
        dummy_feats, _ = sample_pipeline.extract_features({"subject": "test", "body": "test"}, email_id="test_0")
        
        schema = {}
        for feat_name, val in dummy_feats.items():
            if feat_name == "email_id":
                f_type = "metadata"
            elif isinstance(val, (int, np.integer)):
                # Check if binary (values 0 or 1)
                if feat_name.startswith(("has_", "is_", "missing_", "multiple_")) or feat_name.endswith(("_present", "_fail", "_pass", "_neutral", "_softfail", "_none", "_issue", "_candidate", "_flag", "_mismatch", "_anomaly")):
                    f_type = "binary"
                else:
                    f_type = "numerical"
            elif isinstance(val, (float, np.floating)):
                # Float probabilities, ratios, entropy
                f_type = "numerical"
            elif isinstance(val, str):
                f_type = "categorical"
            else:
                f_type = "numerical"

            schema[feat_name] = {
                "feature_name": feat_name,
                "feature_type": f_type,
                "example_value": str(val)
            }
        return schema

    def process_batch(self, records: List[Dict[str, Any]]) -> pd.DataFrame:
        """Processes a list of records into a feature DataFrame."""
        rows = []
        total = len(records)
        t_start = time.time()
        for i, rec in enumerate(records):
            rec_id = str(rec.get("record_id") or rec.get("id") or f"row_{i}")
            if (i + 1) % 1000 == 0 or (i + 1) == total:
                elapsed = time.time() - t_start
                rate = (i + 1) / max(elapsed, 0.001)
                print(f"  [Progress] {i + 1}/{total} records ({((i+1)/total)*100:.1f}%) processed in {elapsed:.1f}s ({rate:.1f} recs/s)", flush=True)
            try:
                feats, _ = self.extract_features(rec, email_id=rec_id)
                rows.append(feats)
            except Exception as e:
                logger.error(f"Failed to extract features for {rec_id}: {e}")
                # Append row with NaNs rather than crashing batch
                empty_row = {"email_id": rec_id}
                rows.append(empty_row)

        df = pd.DataFrame(rows)
        return df


def audit_feature_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Performs feature quality audit on extracted features:
    - feature_name, dtype, missing_percentage, unique_values, min, max, mean, std
    - Detects constant, near-constant, duplicate, and highly correlated features.
    """
    audit_rows = []
    num_rows = len(df)

    constant_features = []
    near_constant_features = []
    duplicate_features = []
    high_correlations = []

    # Exclude metadata for stats
    cols = [c for c in df.columns if c != "email_id"]

    for col in cols:
        s = df[col]
        missing_count = int(s.isna().sum())
        missing_pct = round(missing_count / num_rows * 100, 2) if num_rows > 0 else 0.0
        unique_cnt = int(s.nunique(dropna=True))

        min_val = round(float(s.min()), 4) if pd.api.types.is_numeric_dtype(s) and unique_cnt > 0 else np.nan
        max_val = round(float(s.max()), 4) if pd.api.types.is_numeric_dtype(s) and unique_cnt > 0 else np.nan
        mean_val = round(float(s.mean()), 4) if pd.api.types.is_numeric_dtype(s) and unique_cnt > 0 else np.nan
        std_val = round(float(s.std()), 4) if pd.api.types.is_numeric_dtype(s) and unique_cnt > 0 else np.nan

        if unique_cnt <= 1:
            constant_features.append(col)
        elif unique_cnt > 1 and num_rows > 0:
            top_val_freq = s.value_counts(dropna=True, normalize=True).iloc[0]
            if top_val_freq >= 0.999:
                near_constant_features.append(col)

        audit_rows.append({
            "feature_name": col,
            "dtype": str(s.dtype),
            "missing_percentage": missing_pct,
            "unique_values": unique_cnt,
            "min": min_val,
            "max": max_val,
            "mean": mean_val,
            "std": std_val,
        })

    audit_df = pd.DataFrame(audit_rows)

    # Check high correlations among numerical features
    num_df = df.select_dtypes(include=[np.number]).dropna(axis=1, how="all")
    if len(num_df.columns) > 1 and len(num_df) > 10:
        corr = num_df.corr().abs()
        for i in range(len(corr.columns)):
            for j in range(i + 1, len(corr.columns)):
                c1 = corr.columns[i]
                c2 = corr.columns[j]
                val = corr.iloc[i, j]
                if val >= 0.98:
                    high_correlations.append((c1, c2, round(val, 4)))

    summary_stats = {
        "total_features": len(cols),
        "total_records": num_rows,
        "constant_features": constant_features,
        "near_constant_features": near_constant_features,
        "high_correlations": high_correlations,
    }

    return audit_df, summary_stats


def main():
    parser = argparse.ArgumentParser(description="Model 2 Forensic Feature Extraction Pipeline")
    parser.add_argument("--input", type=str, default="ml/data/processed/emails_balanced.csv", help="Input CSV dataset")
    parser.add_argument("--sample", type=int, default=None, help="Sample N records (default: all)")
    parser.add_argument("--output", type=str, default="ml/datasets/model2_forensic_features.parquet", help="Output Parquet path")
    parser.add_argument("--audit", type=str, default="ml/evaluation/model2_feature_audit.csv", help="Audit CSV path")
    parser.add_argument("--summary", type=str, default="ml/evaluation/model2_feature_summary.md", help="Summary markdown path")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    os.makedirs(os.path.dirname(args.audit), exist_ok=True)

    print("=" * 80)
    print("MODEL 2 — FORENSIC FEATURE EXTRACTION PIPELINE")
    print("=" * 80)

    pipeline = ForensicFeaturePipeline()

    print(f"\n[+] Ingesting input: {args.input}")
    df_in = pd.read_csv(args.input, low_memory=False)
    if args.sample and args.sample < len(df_in):
        print(f"  -> Sampling {args.sample} records from {len(df_in)} total.")
        df_in = df_in.sample(n=args.sample, random_state=42).reset_index(drop=True)
    else:
        print(f"  -> Processing all {len(df_in)} records.")

    records = df_in.to_dict(orient="records")

    t0 = time.time()
    df_features = pipeline.process_batch(records)
    elapsed = round(time.time() - t0, 2)
    print(f"\n[+] Extracted features for {len(df_features)} emails in {elapsed}s ({round(len(df_features)/max(elapsed, 0.001), 1)} emails/sec)")

    # Save to Parquet
    df_features.to_parquet(args.output, index=False)
    print(f"[+] Saved feature dataset to {args.output}")

    # Feature Quality Audit
    audit_df, summary = audit_feature_dataframe(df_features)
    audit_df.to_csv(args.audit, index=False)
    print(f"[+] Saved feature audit to {args.audit}")

    # Save Summary Markdown
    with open(args.summary, "w", encoding="utf-8") as f:
        f.write("# Model 2 — Forensic Feature Quality Audit Summary\n\n")
        f.write(f"- **Total Records Processed**: {summary['total_records']:,}\n")
        f.write(f"- **Total Forensic Features**: {summary['total_features']}\n")
        f.write(f"- **Processing Time**: {elapsed} seconds\n\n")

        f.write("## Constant & Near-Constant Feature Checks\n\n")
        f.write(f"- **Constant Features ({len(summary['constant_features'])})**: {', '.join(summary['constant_features']) if summary['constant_features'] else 'None'}\n")
        f.write(f"- **Near-Constant Features (>99.9% same value) ({len(summary['near_constant_features'])})**: {', '.join(summary['near_constant_features']) if summary['near_constant_features'] else 'None'}\n\n")

        f.write("## High Pairwise Correlations (> 0.98)\n\n")
        if summary["high_correlations"]:
            f.write("| Feature 1 | Feature 2 | Correlation |\n")
            f.write("| :--- | :--- | :---: |\n")
            for c1, c2, val in summary["high_correlations"]:
                f.write(f"| `{c1}` | `{c2}` | {val} |\n")
        else:
            f.write("None detected.\n")

        try:
            f.write(audit_df.head(40).to_markdown(index=False))
        except Exception:
            f.write("| " + " | ".join(audit_df.columns) + " |\n")
            f.write("| " + " | ".join(["---"] * len(audit_df.columns)) + " |\n")
            for _, r in audit_df.head(40).iterrows():
                f.write("| " + " | ".join([str(val) for val in r.values]) + " |\n")
        f.write("\n")

    print(f"[+] Saved feature summary to {args.summary}")


if __name__ == "__main__":
    main()
