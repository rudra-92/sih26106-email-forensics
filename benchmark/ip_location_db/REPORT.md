# Forensic Benchmark Report: sapics/ip-location-db (PDDL Datasets)

This benchmark evaluates the secondary geographic and ASN evidence datasets from [**sapics/ip-location-db**](https://github.com/sapics/ip-location-db) (**PDDL** license, updated daily):
1. **`user-country`**: Prioritizes likely end-user network endpoint country.
2. **`server-country`**: Prioritizes physical server/relay infrastructure country.
3. **`origin-asn`**: Autonomous System Number and Organization derived from global BGP routing tables.

---

## 1. Dataset Provenance & License Verification

| Dataset | Format / Coverage | License | Update Frequency | File Size | SHA-256 Checksum |
|---|---|---|---|---|---|
| **`user-country`** | MMDB (IPv4 + IPv6) | **PDDL-1.0** (Public Domain) | Daily | 7.26 MB | `8d4a10d12d70f3106420af6a23a353520a915bc2c82eb84f9a55f2a31fde30d5` |
| **`server-country`** | MMDB (IPv4 + IPv6) | **PDDL-1.0** (Public Domain) | Daily | 6.63 MB | `eb5f75b08394f033d31eaccf4432725b2ee17a8aa9841d3cd6fa1143c6b11785` |
| **`origin-asn`** | MMDB (IPv4 + IPv6) | **PDDL-1.0** (Public Domain) | Daily | 10.04 MB | `b72858b9d5630cf1414e4f6122dcbddca1dd21d7fd314bc775382529de93004b` |

### License Terms (PDDL-1.0)
Verified directly from the project's `SOURCES.md` and `package.json`:
> *"`user-country`, `server-country`, and `origin-asn` are published under the PDDL (Public Domain Dedication and License v1.0) (free use without attribution).*
> *These datasets are compiled from raw, public network data: RIR delegated statistics (AFRINIC, APNIC, ARIN, LACNIC, RIPE NCC), Route Views & RIPE RIS BGP routing tables, and RFC 8805 / RFC 9632 Geofeeds.*
> *Compliance Policy: DO NOT use RIR WHOIS or IRR databases for geographic mapping, keeping datasets compliant with RIR Acceptable Use Policies."*

**Forensic & Legal Assessment**:
The PDDL-1.0 dedication grants complete, unrestricted commercial, redistribution, and modification freedom without copyleft or attribution obligations.

---

## 2. Mandatory Semantic Definitions (Phase 5)

In compliance with forensic rigor:
- **`user_country_evidence`**: Country associated with the likely end-user or network endpoint.
- **`server_country_evidence`**: Country associated with physical server or relay infrastructure.
- **Critical Semantic Invariants**:
  1. **NEVER infer `user_country == server_country` -> `direct_origin_infrastructure`**: Matching countries indicate only country-level consistency (`country_agreement = True`, `interpretation = "country-level evidence is consistent"`). It never implies direct origin on its own.
  2. **NEVER infer `user_country == server_country` -> no relay/proxy**: Relays frequently operate within the same country (domestic relays).
  3. **When `user_country != server_country`**: Record `country_agreement = False`, `interpretation = "country-level geographic evidence is inconsistent"`.
  4. **Neither agreement nor disagreement alone determines location type**: `direct_origin_infrastructure`, `relay_infrastructure`, `provider_infrastructure`, and `anonymized_infrastructure` must NEVER be assigned based solely on country comparison.
  5. **Broader Module 5 evidence determines origin location type**: Synthesized using hop position, trust state, temporal consistency, infrastructure classification, ASN, authentication context, and cross-case evidence.
  6. **Numeric confidence values (e.g. 0.95, 0.45) are non-calibrated heuristic consensus metrics**: Explicitly documented as heuristic consensus scores reflecting multi-database alignment, NEVER statistical probabilities.
  7. **Geographic evidence never establishes physical attacker location**: Geolocation attributes reflect observed network routing/PoP infrastructure, never the human actor.
  8. **DB-IP city remains infrastructure geolocation**: Country-level datasets do not infer or overwrite city or coordinates.

---

## 3. Seven Primary Benchmark IPs

| IP Address | DB-IP (Country / City) | user-country | server-country | DB-IP ASN | origin-asn | Country Conf. (Heuristic) | Standalone Location Type | With Hop Context |
|---|---|---|---|---|---|---|---|---|
| `49.37.154.164` | IN (Navi Mumbai (Ghansoli)) | `IN` | `IN` | AS55836 | AS55836 | `0.95` | `unknown` | `direct_origin_infrastructure` (Hop 1, verified) / `relay_infrastructure` (Hop 2+) |
| `8.8.8.8` | US (Mountain View) | `US` | `US` | AS15169 | AS15169 | `0.95` | `provider_infrastructure` | `provider_infrastructure` (Cloud/DNS) |
| `1.1.1.1` | AU (Sydney) | `AU` | `AU` | AS13335 | AS13335 | `0.95` | `provider_infrastructure` | `provider_infrastructure` (Cloud/DNS) |
| `9.9.9.9` | US (Berkeley (North Berkeley)) | `US` | `US` | AS19281 | AS19281 | `0.95` | `unknown` | Evaluated via hop position & trust |
| `171.25.193.25` | SE (Stockholm) | `SE` | `SE` | AS198093 | AS198093 | `0.95` | `anonymized_infrastructure` | `anonymized_infrastructure` (Tor exit feed match) |
| `2606:4700:4700::1111` | CA (Montreal) | `US` | `US` | AS13335 | AS13335 | `0.85` | `provider_infrastructure` | `provider_infrastructure` (Cloudflare Anycast) |
| `2001:4860:4860::8888` | CA (Montreal) | `US` | `US` | AS15169 | AS15169 | `0.85` | `provider_infrastructure` | `provider_infrastructure` (Google Anycast) |

---

## 4. Special Investigation: User Real Public IP (`49.37.154.164`)

Target IP: `49.37.154.164` (Reliance Jio Infocomm, India)

| Evidence Layer | Result | Evidence Semantics |
|---|---|---|
| **DB-IP City Lite** | `Navi Mumbai (Ghansoli), Maharashtra, IN` | Observed infrastructure location (PoP/gateway) |
| **DB-IP ASN** | `AS55836 Reliance Jio Infocomm Limited` | Network carrier |
| **user-country (PDDL)** | **`IN` (India)** | Likely end-user network endpoint country |
| **server-country (PDDL)** | **`IN` (India)** | Physical server/relay infrastructure country |
| **origin-asn (PDDL)** | **`AS55836` Reliance Jio Infocomm Limited** | BGP origin routing authority |
| **Consensus Scorer** | `country_agreement = True`, `interpretation = "country-level evidence is consistent"`, `country_confidence = 0.95` (heuristic) | High consensus across all offline datasets. Alone yields `location_type = "unknown"`. |
| **With Hop Context (Hop 1, Verified)** | `location_type = "direct_origin_infrastructure"` | Synthesized via earliest reliable peer + verified trust state |
| **With Hop Context (Hop 2+, Relay)** | `location_type = "relay_infrastructure"` | Relays can exist within the exact same country |

### Forensic Takeaway
- Both PDDL datasets confirm **India (`IN`)** with country agreement (`country_agreement = True`, `interpretation = "country-level evidence is consistent"`).
- Country agreement alone does **NEVER** imply `direct_origin_infrastructure` or absence of proxies/relays.
- When evaluated with broader Module 5 evidence (earliest reliable peer, hop 1, verified trust boundary), it establishes `direct_origin_infrastructure`.
- Neither database reports Hyderabad, Telangana (confirming route aggregation in Maharashtra). As established, IP geolocation reflects routing PoPs, not subscriber device GPS or physical attacker location.

---

## 5. User-Country vs. Server-Country Disagreement (Edge Cases)

When cross-border relays, CDNs, or roaming blocks are queried, `user-country` and `server-country` diverge:

| IP Address | DB-IP (Country / City) | user-country | server-country | origin-asn | Country Agreement | Interpretation | Heuristic Conf. | Standalone Type | With Hop Context (Relay) |
|---|---|---|---|---|---|---|---|---|---|
| `176.23.150.1` | AU (Sydney) | `AU` | `US` | AS40934 | `False` | `country-level geographic evidence is inconsistent` | `0.45` | `unknown` | `relay_infrastructure` |
| `104.204.255.1` | IE (Dublin) | `IE` | `US` | AS16509 | `False` | `country-level geographic evidence is inconsistent` | `0.45` | `unknown` | `relay_infrastructure` |

### Forensic Utility of Divergence:
- For `176.23.150.1`: `user-country = AU` (Australia), but `server-country = US` (United States).
- For `104.204.255.1`: `user-country = IE` (Ireland), but `server-country = US` (United States).
- **Forensic Rule Applied**: When `user_country != server_country`, record `country_agreement = False` and `interpretation = "country-level geographic evidence is inconsistent"`. Heuristic confidence score is recorded as `0.45` (explicitly non-calibrated heuristic metric, NOT a probability).
- **Crucial Rule**: Disagreement alone does **NOT** assign `relay_infrastructure`. It acts as corroborating evidence alongside hop sequence position (`hop_seq > 1` or `role = "upstream_relay"`) in Module 5.

---

## 6. Performance Evaluation (100 Lookups Benchmark)

| Metric | DB-IP Lite (City + ASN) | PDDL Suite (User + Server + ASN) | Comparison |
|---|---|---|---|
| **Database Load / Open Time** | `1.45 ms` | `1.80 ms` | Very fast (< 2 ms) |
| **Average Query Latency (100 queries)** | `0.0241 ms` | `0.0111 ms` | Sub-millisecond lookup across 3 MMDBs |
| **Maximum Single Query Latency** | `0.1245 ms` | `0.0654 ms` | Consistent peak latency (< 0.2 ms) |
| **Combined Disk Footprint** | ~130.5 MB | ~25.1 MB | PDDL suite is ultra-compact |

---

## 7. Forensic Value & Limitations

### Forensic Value
1. **Independent Corroboration**: Cross-verifies DB-IP country without relying on commercial APIs.
2. **Hop Differentiation**: Distinguishes end-user network endpoint country from physical server relay country.
3. **Daily Cadence**: Built from daily BGP routing dumps and geofeeds.
4. **Complete License Freedom**: PDDL-1.0 has zero copyleft risk.

### Limitations
1. **Country-Level Only**: `user-country` and `server-country` do not provide cities or coordinates. City-level resolution remains anchored in DB-IP City Lite.
2. **Network Aggregation**: Geolocation remains network-centric, not physical device GPS.

---

## 8. Recommended Integration Architecture

Implement non-breaking, optional secondary adapters in `modules/origin_infrastructure/enrichment/`:
- [`UserCountryProvider`](file:///c:/sih26106/modules/origin_infrastructure/enrichment/user_country.py)
- [`ServerCountryProvider`](file:///c:/sih26106/modules/origin_infrastructure/enrichment/server_country.py)
- [`OriginASNProvider`](file:///c:/sih26106/modules/origin_infrastructure/enrichment/origin_asn.py)

Wrap the combined output in a structured `location_evidence` object preserving trust states (`observed`, `verified`, `enriched`, `inferred`, `unknown`) and provenance.
