# Module 6: Evidence Correlation & Attribution Support

> **Forensic Semantic Notice:**
> Module 6 correlates evidence and model predictions to support forensic investigation. It does not independently establish attacker identity or physical location.

---

## 1. Architecture & Objective

Module 6 serves as the central investigative synthesis engine for the SIH26106 platform. It aggregates deterministic forensic findings from Modules 1–5 alongside predictions from external machine learning models (Email Threat Classifier, BEC / Intent Classifier, URL Risk Classifier) into a normalized, evidence-bearing graph and unified forensic case investigation output.

### Core Guarantees & Non-Attribution Boundaries
1. **Observable Infrastructure vs. Attacker Identity**: The module identifies and groups observable network infrastructure (IPs, ASNs, domains, hosting providers, Tor exit nodes, relays). It **never** outputs an attacker name, physical home address, guaranteed attacker location, or guaranteed attacker IP.
2. **Machine Learning as Inferred Evidence**: ML predictions are classified strictly under `trust_state = "inferred"` and are **never** treated as observed facts or allowed to override deterministic forensic findings blindly.
3. **Heuristic, Non-Calibrated Consensus Metric**: All numerical confidence values represent an investigative **heuristic, non-calibrated consensus metric** (`confidence_metric = "heuristic_non_calibrated_consensus"`), **NOT** statistical probabilities and are **NOT** statistically calibrated. Independent evidence sources are never naively summed or multiplied.
4. **Contradiction Preservation**: Forensic conflicts (e.g. SPF pass on a lookalike domain, user vs. server country divergence, ML benign prediction despite high-severity deterministic indicators) are recorded under `RULE-CORR-EVIDENCE-CONFLICT` and **never** suppressed.
5. **Offline-First & Local Operation**: Module 6 operates deterministically on already extracted evidence without requiring external cloud services, graph databases, or live network calls.

---

## 2. Nine-Stage Pipeline

```text
Module 1 Output (Sender Identity & Auth)
Module 2 Output (Lookalike Domain Detection)
Module 3 Output (URL Static Analysis)
Module 4 Output (Attachment Forensics)
Module 5 Output (Origin & Infrastructure)
External ML Predictions (Threat, BEC, URL)
                  ↓
       1. ML Prediction Ingestion
                  ↓
       2. Evidence Normalization
                  ↓
       3. Entity Resolution
                  ↓
       4. Relationship Engine
                  ↓
       5. Cross-Module Corroboration
                  ↓
       6. Contradiction Detection
                  ↓
       7. Temporal / Cross-Case Correlation
                  ↓
       8. Case Hypothesis Evaluation
                  ↓
       9. Attribution Support & Case Synthesis
```

---

## 3. Input Formats

The engine cleanly accepts either typed report dataclasses or dictionary outputs from:
* **Module 1**: `SenderIdentityReport`
* **Module 2**: `ContextualAssessmentReport`
* **Module 3**: `UrlAnalysisReport`
* **Module 4**: `AttachmentReport`
* **Module 5**: `OriginInfrastructureReport`
* **ML Predictions**:
  * `ml_threat_prediction`: Dict or object containing `model`, `label`, `confidence`, `input_reference`
  * `ml_bec_prediction`: Dict or object containing `model`, `intent_label`, `confidence`, `input_reference`
  * `ml_url_predictions`: List of dicts or objects containing URL risk predictions

---

## 4. Normalized Evidence Model (`NormalizedEvidence`)

Every finding across Modules 1–5 and ML predictions is normalized into a standard schema:
* `evidence_id`: Canonical identifier (e.g. `EV-M1-OBS-0001`, `EV-ML-0002`)
* `source_module`: Originating module or model name
* `evidence_type`: `observation`, `authentication`, `lookalike_signal`, `url_observation`, `attachment_anomaly`, `routing_anomaly`, `ml_prediction`
* `rule_id`: Standardized forensic rule identifier
* `severity`: `informational`, `low`, `medium`, `high`
* `trust_state`: `observed`, `verified`, `enriched`, `inferred`, `unknown`
* `description`: Human-readable summary
* `entity_ids`: Associated canonical entity IDs
* `timestamp`: ISO timestamp if available
* `provenance`: Traceable source headers, modules, or datasets
* `supporting_fields`: Raw supporting key-value attributes

---

## 5. Unified Graph Model

### Entities (`CorrelatedEntity`)
De-duplicates and unifies equivalent entities across all modules:
- `email`: e.g. `email:E001`
- `email_address`: e.g. `email_address:billing@paypa1.com`
- `domain`: e.g. `domain:paypa1.com`
- `url`: e.g. `url:https://paypa1.com/login`
- `ip`: e.g. `ip:198.51.100.77`
- `asn`: e.g. `asn:AS15169`
- `attachment`: e.g. `attachment:invoice.pdf.exe`
- `hash`: e.g. `hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `message_id`: e.g. `message_id:<msg-12345@evil.com>`
- `hostname`: e.g. `hostname:mail.evil.com`
- `country`: e.g. `country:Germany`
- `infrastructure`: e.g. `infrastructure:cloud_hosting`
- `case`: e.g. `case:CASE-E001`

### Relationships (`CorrelatedRelationship`)
Evidence-bearing directed edges between entities:
- `case` → `contains` → `email`
- `email` → `sent_by` → `email_address`
- `email_address` → `belongs_to` → `domain`
- `domain` → `resembles` → `domain` (lookalike target)
- `email` → `contains_url` → `url`
- `url` → `hosted_on` → `domain` or `ip`
- `email` → `contains_attachment` → `attachment`
- `attachment` → `has_hash` → `hash`
- `email` → `observed_from` → `ip`
- `ip` → `belongs_to` → `asn`
- `ip` → `located_in` → `country`
- `ip` → `infrastructure_type` → `infrastructure`

---

## 6. External Machine Learning Adapters

Three resilient adapters ingest predictions from external models:
1. **`EmailThreatClassifierAdapter`**: Ingests email-level threat classifications (`phishing`, `malware`, `spam`, `benign`).
2. **`BecIntentClassifierAdapter`**: Ingests intent predictions (`credential_harvesting`, `wire_fraud`, `gift_card`, `urgent_request`).
3. **`UrlRiskClassifierAdapter`**: Ingests URL-level risk predictions and feature vectors.

All ML predictions are mapped to `trust_state = "inferred"` with `confidence_metric = "heuristic_non_calibrated_consensus"`.

---

## 7. Multi-Module Corroboration Engine

Detects multi-signal convergence across independent modules:
* **`correlated_identity_deception`**: Module 2 lookalike candidate + Module 1 Reply-To/Return-Path divergence + Module 3 deceptive URL domain.
* **`correlated_credential_phishing`**: Module 3 visible/href mismatch or login cues + Module 1/2 domain deception + BEC/Threat ML phishing prediction.
* **`correlated_malware_delivery`**: Module 4 executable/macro attachment + Module 5 cloud/anonymized origin infrastructure + ML malware threat.
* **`correlated_infrastructure_abuse`**: Module 5 hosting/Tor origin + Module 1 unverified external peer.
* **`correlated_bec_impersonation`**: BEC ML intent + Module 1 display name spoofing or unaligned routing.

---

## 8. Contradiction Detection Engine

Explicitly records and preserves conflicting forensic signals:
* **`RULE-CORR-AUTH-LOOKALIKE-CONFLICT`**: SPF/DKIM `pass` on an identified lookalike domain (attacker provisioned auth on their own domain).
* **`RULE-CORR-GEOGRAPHIC-CONFLICT`**: Disagreement between endpoint user country and server relay country (`country_agreement = False`).
* **`RULE-CORR-ML-FORENSIC-CONFLICT`**: ML model predicts benign/legitimate while deterministic rules flag high-severity structural anomalies.
* **`RULE-CORR-EVIDENCE-CONFLICT`**: Header identity divergence (e.g. From vs. Return-Path).

---

## 9. Cross-Case & Temporal Correlation

Maintains an in-memory historical case store:
* Correlates repeated IPs, ASNs, domains, URLs, and attachment hashes across multiple email cases.
* Emits `CampaignCluster` records:
  - `reused_attachment`: Identical attachment SHA-256 across distinct emails.
  - `recurring_infrastructure`: Repeated IP or ASN across different cases.
  - `reused_domain_infrastructure`: Repeated lookalike or routing domain.
  - `possible_campaign_cluster`: Multi-entity overlap indicating campaign correlation.
* Computes `first_seen`, `last_seen`, `occurrence_count`, and `inter_case_time_delta_seconds`.

---

## 10. Competing Case Hypotheses

Produces ranked case explanations:
* `possible_domain_impersonation`
* `possible_phishing`
* `possible_credential_harvesting`
* `possible_bec_attempt`
* `possible_campaign_reuse`
* `possible_compromised_account`
* `possible_provider_masking`
* `possible_anonymized_infrastructure`
* `insufficient_evidence`

Each hypothesis lists all supporting evidence IDs, contradicting evidence summaries, and a bounded heuristic score (≤ 0.94).

---

## 11. Example Unified Investigation Output

```json
{
  "case_id": "CASE-E001",
  "email_id": "E001",
  "file_hash_sha256": "4a7d...31",
  "evidence": [
    {
      "evidence_id": "EV-M1-OBS-0001",
      "source_module": "sender_identity",
      "evidence_type": "observation",
      "rule_id": "RULE-ID-REPLY-TO-MISMATCH",
      "severity": "medium",
      "trust_state": "observed",
      "description": "Reply-To domain 'paypa1.com' does not match From domain 'paypal.com'."
    }
  ],
  "entities": [
    {
      "entity_id": "domain:paypa1.com",
      "type": "domain",
      "value": "paypa1.com",
      "source_modules": ["sender_identity", "lookalike_domain", "url_analysis"]
    }
  ],
  "relationships": [
    {
      "relationship_id": "REL-0001",
      "from_entity": "email:E001",
      "relationship_type": "contains_url",
      "to_entity": "url:https://paypa1.com/login",
      "evidence_ids": ["EV-M3-URL-0001"]
    }
  ],
  "correlated_findings": [
    {
      "finding_id": "CORR-FIND-0001",
      "finding_type": "correlated_identity_deception",
      "heuristic_support_strength": "critical",
      "confidence_metric": "heuristic_non_calibrated_consensus"
    }
  ],
  "contradictions": [
    {
      "contradiction_id": "CONTRADICT-0001",
      "rule_id": "RULE-CORR-AUTH-LOOKALIKE-CONFLICT",
      "conflict_type": "auth_vs_lookalike"
    }
  ],
  "hypotheses": [
    {
      "hypothesis_type": "possible_domain_impersonation",
      "heuristic_confidence": 0.88,
      "confidence_metric": "heuristic_non_calibrated_consensus"
    }
  ],
  "attribution_support": {
    "observable_infrastructure": [
      { "entity_id": "ip:198.51.100.77", "type": "ip", "value": "198.51.100.77" }
    ],
    "probable_origin": {
      "earliest_reliable_peer_ip": "198.51.100.77",
      "asn": "AS24940",
      "observed_infrastructure_location": "Frankfurt am Main"
    },
    "limitations": [
      "Observed infrastructure geolocation represents network routing Point-of-Presence (PoP), NOT human attacker physical location."
    ]
  }
}
```
