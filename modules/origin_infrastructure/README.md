# Module 5: Origin & Infrastructure Reconstruction Engine

> **Forensic Semantic Notice:**
> The module reconstructs observable email infrastructure and generates origin hypotheses. It does not guarantee identification of the human attacker or their physical location.

---

## 1. Architecture & Objective

Module 5 reconstructs the observable email transmission path from RFC 5321/5322 `Received` headers, identifies the **earliest reliable external peer / observable origin infrastructure**, analyzes temporal hop consistency, correlates SPF/DKIM/DMARC and Authenticated Received Chain (ARC) evidence, enriches network infrastructure via offline-first local adapters (GeoIP, ASN, Cloud/VPN/Tor), correlates historical cases, and produces multi-hypothesis origin assessments with bounded heuristic confidence (≤ 0.94).

### Key Architectural Distinctions
* **Observed Infrastructure vs. Attacker IP**: The engine identifies the earliest observable peer in the transmission route; it explicitly avoids claiming an observed IP is a "guaranteed attacker IP".
* **Network Geolocation vs. Physical Attacker Location**: Geolocation attributes reflect the physical location of the observed server/datacenter, not the human actor behind the email.
* **Authentication as Transport Evidence**: `PASS` results (SPF/DKIM/DMARC/ARC) validate transport authorization, not general message legitimacy.

---

## 2. Processing Pipeline

```text
RAW .EML / Parsed Message
        ↓
Received Header Parser
  (Extracts from/by host, IP, protocol, TLS cipher, id, for, raw timestamp)
        ↓
Hop Reconstruction
  (Inverts stack to transmission sequence: 1 = earliest origin, N = recipient boundary)
        ↓
Trust-Boundary Analysis
  (Assigns trust states: observed, verified, enriched, inferred, unknown)
        ↓
Temporal Analysis
  (UTC normalization, transit delays, negative intervals, Date-vs-Received gaps)
        ↓
SPF / DKIM / DMARC / ARC Correlation
  (Evaluates authentication reports and validates ARC instance continuity)
        ↓
Earliest Reliable Peer Detection
  (Walks hops backwards, evaluates provider masking and private IP hops)
        ↓
Local Infrastructure Enrichment
  (Offline GeoIP, ASN, Cloud CIDRs, VPN, and Tor exit indicators)
        ↓
Cross-Case Correlation
  (Detects recurring infrastructure across historical cases)
        ↓
Origin Hypothesis Engine
  (Produces competing heuristic hypotheses with bounded confidence <= 0.94)
        ↓
Evidence Graph & Forensic Output
  (Graph nodes & relationships with strict provenance tracking)
```

---

## 3. Input Formats

The module cleanly consumes any of the following through [OriginInfrastructureAnalyzer.analyze](file:///c:/sih26106/modules/origin_infrastructure/analyzer.py#L80) or [analyze_origin_infrastructure](file:///c:/sih26106/modules/origin_infrastructure/analyzer.py#L380):
* Raw `.eml` bytes (`bytes`)
* Email content string (`str`)
* Path to an `.eml` file (`pathlib.Path`)
* Standard library `email.message.EmailMessage` or `Message`
* Module 1 `ParsedEmailEvidence` object

---

## 4. Evidence & Trust Model

Every finding, hop, and graph edge preserves strict forensic provenance:
* `source_header`: Originating header (`Received[0]`, `Date`, etc.)
* `source_module`: `"origin_infrastructure"`
* `observation_id`: Sequential identifier (e.g. `OBS-TIME-001`, `OBS-AUTH-001`)
* `rule_id`: Standardized forensic rule identifier
* `trust_state`:
  * `observed`: Extracted directly from email headers. Default trust state for all parsed hops.
  * `trusted_configured`: Matches an explicitly configured trusted gateway (`trusted_gateways`). Never assigned merely for being the receiving hop.
  * `verified`: Corroborated by cryptographic proof or authoritative independent verification.
  * `enriched`: Augmented by local GeoIP / ASN / infrastructure reference datasets.
  * `inferred`: Derived through heuristic analysis, candidate evaluation, or temporal correlation.
  * `unknown`: Cannot be corroborated.

---

## 5. Temporal Analysis

Timestamps are parsed with `email.utils.parsedate_to_datetime` and converted to UTC:
* **Hop Delays**: Delay between consecutive hops in transit direction (`later_hop - earlier_hop`).
* **Negative Intervals** (`RULE-TIME-NEGATIVE-HOP`): Later hop timestamp occurs before earlier hop timestamp (chronology contradiction).
* **Excessive Delays** (`RULE-TIME-EXCESSIVE-DELAY`): Hops with delays exceeding configurable threshold (default: 3600s).
* **Future Timestamps** (`RULE-TIME-FUTURE`): Timestamps ahead of analysis reference time.
* **Date vs Received Gap** (`RULE-TIME-DATE-RECEIVED-GAP`): Discrepancies between `Date:` header and earliest Received timestamp.

---

## 6. Authentication & ARC Validation Reality

The engine ingests reported SPF, DKIM, and DMARC results and parses Authenticated Received Chain (ARC - RFC 8617) headers:
* **Structural Validation Only** (`RULE-ARC-STRUCTURE-VALID`): Evaluates instance sequence continuity (`i=1, 2, ...`), presence of required headers (`ARC-Seal`, `ARC-Message-Signature`, `ARC-Authentication-Results`), and parsed chain validation parameters (`cv=none`, `cv=pass`).
* **Cryptographic Verification Notice**: Cryptographic ARC signature verification (message canonicalization, RSA/Ed25519 signature computation, and live DNS public key resolution) is **NOT implemented**. ARC findings are classified under `reported` fact type.

---

## 7. Origin Candidate Logic

Candidate selection is **NOT** simply equivalent to "first IP", "first public IP", or "oldest Received header".
The algorithm considers:
* Received hop sequence from destination boundary to origin
* Public, private (RFC 1918), and documentation (RFC 5737) address status
* Trust state (`observed` vs `trusted_configured`)
* Timestamp consistency and negative transit intervals
* Authentication context (SPF/DKIM/ARC)
* Mail provider / cloud gateway context
* Incomplete or corrupted hops
* Contradictory evidence across headers

**Definition**: `earliest_reliable_external_peer` represents the **earliest externally observable infrastructure supported by available evidence**, and is **never** designated as a "guaranteed attacker IP".

---

## 8. Real Local Infrastructure Enrichment & Data Sources

Enrichment is entirely offline, provider-agnostic, and adapter-based:
* **GeoIP**: [LocalGeoIPProvider](file:///c:/sih26106/modules/origin_infrastructure/enrichment/geoip.py)
* **ASN**: [LocalASNProvider](file:///c:/sih26106/modules/origin_infrastructure/enrichment/asn.py)
* **Infrastructure & Tor**: [LocalInfrastructureProvider](file:///c:/sih26106/modules/origin_infrastructure/enrichment/infrastructure.py)

### Primary Real Dataset: DB-IP Lite
Module 5 natively supports **DB-IP Lite** in MMDB format:
- **IP to City Lite MMDB** (`dbip-city-lite.mmdb`)
- **IP to Country Lite MMDB** (`dbip-country-lite.mmdb`)
- **IP to ASN Lite MMDB** (`dbip-asn-lite.mmdb`)

### Mandatory Dataset Attribution:
> **Attribution Notice:**
> *"IP geolocation and ASN data provided by DB-IP Lite, licensed under CC BY 4.0."*
> 
> * **License**: Creative Commons Attribution 4.0 International (CC BY 4.0)
> * **Dataset Nature**: DB-IP Lite is a free dataset, **not** "open-source software".
> * **Redistribution**: Database files should **NOT** be committed directly to a public Git repository unless redistribution terms are explicitly satisfied. Downloaded `.mmdb` files are ignored via `.gitignore`.

### Optional Tor Exit Node Feed:
Module 5 supports an optional local feed from the Tor Project's free bulk exit list:
- Source: `https://check.torproject.org/torbulkexitlist`
- Architecture: `Tor exit list` → `local IP set` → `candidate IP lookup` → `tor_exit_indicator = true/false/unknown`
- **Offline Guardrail**: Normal email analysis **never** makes live network calls to Tor or external services.
- **Contextual Semantics**: `tor_exit_indicator = true` is transport context only; it is **never** used alone to infer maliciousness.

### Secondary Real Datasets: PDDL Multi-Source Geographic & Routing Evidence
Module 5 supports optional, secondary offline datasets from `sapics/ip-location-db` under the Public Domain Dedication and License (**PDDL-1.0**):
- **`user-country.mmdb`**: Prioritizes likely end-user network endpoint country.
- **`server-country.mmdb`**: Prioritizes physical server/relay infrastructure country.
- **`origin-asn.mmdb`**: Autonomous System Number and BGP origin routing authority.

#### Mandatory Semantic Invariants (Audit Enforced):
1. **NEVER infer `user_country == server_country` → `direct_origin_infrastructure`**:
   Agreement between user and server country indicates country-level consistency (`country_agreement = true`, `interpretation = "country-level evidence is consistent"`). It does **NEVER** imply direct origin on its own.
2. **NEVER infer `user_country == server_country` → no relay/proxy**:
   Email relays, enterprise gateways, and proxies frequently operate within the exact same country (domestic relays).
3. **When `user_country != server_country`**:
   Record `country_agreement = false` and `interpretation = "country-level geographic evidence is inconsistent"`.
4. **Neither agreement nor disagreement alone may determine**:
   `direct_origin_infrastructure`, `relay_infrastructure`, `provider_infrastructure`, or `anonymized_infrastructure`. Without broader hop context, location type defaults to `"unknown"`.
5. **Origin location type determination requires broader Module 5 evidence**:
   Location type is synthesized strictly by combining:
   - Hop position (`hop_sequence_num`: hop 1 earliest peer vs intermediate upstream relays)
   - Trust state (`verified`, `observed`, `trusted_configured`)
   - Temporal consistency (chronology and delay anomalies)
   - Infrastructure classification (hosting, cloud, gateway, tor, vpn)
   - ASN (carrier, transit, cloud BGP origin)
   - Authentication context (SPF, DKIM, DMARC, ARC alignment)
   - Country evidence (agreement/disagreement corroboration)
   - Cross-case evidence (recurring campaign infrastructure across historical cases)
6. **Confidence values are heuristic consensus metrics, NOT probabilities**:
   Numeric confidence values such as `0.95` (multi-source database consensus) and `0.45` (divergent country evidence) are explicitly non-calibrated heuristic metrics (`confidence_metric = "heuristic_non_calibrated_consensus"`), never statistical probabilities.
7. **No physical attacker location claim**:
   Country and city evidence reflect observed infrastructure routing locations only, never the human attacker's physical location.
8. **DB-IP city remains infrastructure geolocation**:
   Secondary PDDL datasets provide only country-level resolution. City and coordinates are anchored strictly in DB-IP City Lite and are never inferred or fabricated.

### Directory Layout & Configuration
Place local data files in `data/geoip/` (or any custom directory):
```text
data/geoip/
├── dbip-city-lite.mmdb       # City geolocation (DB-IP Lite)
├── dbip-asn-lite.mmdb        # Autonomous System Numbers (DB-IP Lite)
├── dbip-country-lite.mmdb    # (Optional) Country-only database
├── tor_exit_nodes.txt        # (Optional) Tor Project bulk exit list
├── user-country.mmdb         # (Optional) PDDL user-country
├── server-country.mmdb       # (Optional) PDDL server-country
└── origin-asn.mmdb           # (Optional) PDDL origin-asn
```

Configure paths via environment variables or constructor arguments:
```bash
# Environment variable configuration (Windows & POSIX safe)
export GEOIP_CITY_DB="data/geoip/dbip-city-lite.mmdb"
export GEOIP_COUNTRY_DB="data/geoip/dbip-country-lite.mmdb"
export GEOIP_ASN_DB="data/geoip/dbip-asn-lite.mmdb"
export TOR_EXIT_LIST_PATH="data/geoip/tor_exit_nodes.txt"
export USER_COUNTRY_DB="data/geoip/user-country.mmdb"
export SERVER_COUNTRY_DB="data/geoip/server-country.mmdb"
export ORIGIN_ASN_DB="data/geoip/origin-asn.mmdb"
```

If local database files are missing:
- `status = "unavailable"` is reported without crashing.
- In-memory synthetic reference tables are utilized for deterministic unit tests.
- Unknown IPs in active databases return `status = "not_found"`.
- Malformed IP inputs return `status = "invalid_input"`.

---

## 9. Verification & Validation Scripts

Module 5 includes dedicated scripts for verification and performance benchmarking:
* **Real Single/Batch IP Lookup**:
  ```bash
  python scripts/test_real_enrichment.py 8.8.8.8
  python scripts/test_real_enrichment.py 1.1.1.1
  python scripts/test_real_enrichment.py 171.25.193.25
  ```
  Reports geolocation, ASN, network CIDR, dataset metadata, and measures 100-run lookup latency.
* **End-to-End Email Forensic Reconstruction**:
  ```bash
  python scripts/test_e2e_real_pipeline.py
  ```
  Runs a raw multi-hop `.eml` through the entire forensic pipeline and produces the structured origin and infrastructure JSON report.

---

## 10. Limitations & Non-Attribution Boundaries

1. **Header Forgery**: Upstream `Received` headers added before an email reaches authenticated providers can be forged. The trust model marks upstream headers as `observed` rather than `verified`.
2. **Webmail Masking**: When an email is sent via webmail interfaces (e.g. Gmail/Outlook web client), client origin IP is masked by the provider, leaving only provider infrastructure observable.
3. **No Attacker Physical Location**: Geographic enrichment strictly produces `observed_infrastructure_geolocation` and never `attacker_physical_location`.
4. **Contextual Infrastructure**: Cloud hosting, VPN endpoints, proxies, or Tor exit nodes are network transit attributes and do not constitute proof of malicious intent.

---

## 9. Example Output

```json
{
  "origin_assessment": {
    "earliest_reliable_peer": "198.51.100.77",
    "peer_hostname": "mail.external-sender.com",
    "source_visibility": "visible",
    "confidence": 0.85,
    "assessment_reason": "Hop 1 represents the earliest reliable external peer (198.51.100.77) observable in the reconstructed transmission path."
  },
  "temporal_analysis": {
    "chronology_consistent": true,
    "negative_intervals": 0,
    "abnormal_delays": 0,
    "total_transit_seconds": 90.0
  },
  "enriched_peers": [
    {
      "ip": "198.51.100.77",
      "geolocation": {
        "status": "available",
        "country": "Germany",
        "city": "Frankfurt am Main",
        "semantic_note": "Observed infrastructure geolocation, NOT human attacker physical location."
      },
      "asn": {
        "status": "available",
        "asn": "AS24940",
        "organization": "Hetzner Online GmbH"
      },
      "infrastructure": {
        "is_hosting": true,
        "classification": "cloud_hosting",
        "provider_name": "Hetzner"
      }
    }
  ],
  "hypotheses": [
    {
      "hypothesis_type": "possible_cloud_infrastructure",
      "confidence": 0.82,
      "supporting_evidence": [
        "Peer IP '198.51.100.77' belongs to recognized cloud or hosting provider (Hetzner).",
        "Network classified as 'cloud_hosting'."
      ]
    },
    {
      "hypothesis_type": "possible_direct_origin",
      "confidence": 0.70,
      "supporting_evidence": [
        "Hop 1 is the earliest reliable external peer (198.51.100.77).",
        "Observable transmission path connects directly from this peer to recipient infrastructure."
      ]
    }
  ]
}
```

---

## 10. Running Tests

Run the Module 5 test suite:
```bash
python -m unittest modules/origin_infrastructure/test_origin_infrastructure.py -v
```

Run the entire platform test suite (Modules 1–5):
```bash
python -m unittest discover -s modules -p "test_*.py" -v
```

Or via pytest:
```bash
pytest -q
```
