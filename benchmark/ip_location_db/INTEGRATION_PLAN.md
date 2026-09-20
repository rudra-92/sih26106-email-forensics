# Production Integration Plan: Secondary PDDL Evidence Providers

## 1. Overview & Objective

Integrate secondary geographic and ASN evidence providers from **sapics/ip-location-db** into Module 5 without altering existing DB-IP Lite enrichment or modifying Modules 1–4.

### Guiding Architectural Principles:
1. **Additive & Non-Breaking**: DB-IP Lite remains the default primary offline provider.
2. **Offline-First & PDDL-Licensed**: Zero network dependencies during analysis, zero commercial API keys, 100% public domain (`PDDL-1.0`).
3. **Graceful Degradation**: If secondary MMDB files are absent, provider status is `"unavailable"`, and analysis proceeds smoothly with zero errors.
4. **Strict Forensic Semantics**:
   - `user_country` = country associated with likely end-user network endpoint.
   - `server_country` = country associated with physical server/relay infrastructure.
   - **Never** equate either to "attacker physical location".
5. **No City Inference from Country Datasets**: Country datasets provide only ISO 3166-1 alpha-2 country codes. City-level resolution remains anchored in DB-IP City Lite.

---

## 2. Proposed Component Architecture

```
modules/origin_infrastructure/
├── enrichment/
│   ├── base.py                   # Shared ProviderStatus, ProviderResult, etc.
│   ├── geoip.py                  # Primary DB-IP City provider (UNTOUCHED)
│   ├── asn.py                    # Primary DB-IP ASN provider (UNTOUCHED)
│   ├── infrastructure.py         # Primary Tor Exit List provider (UNTOUCHED)
│   ├── user_country.py           # [NEW] Secondary UserCountryProvider (PDDL)
│   ├── server_country.py         # [NEW] Secondary ServerCountryProvider (PDDL)
│   └── origin_asn.py             # [NEW] Secondary OriginASNProvider (PDDL)
└── models.py                     # [EXTEND] LocationEvidence data model
```

---

## 3. Provider Interfaces

### A. `UserCountryProvider` (`modules/origin_infrastructure/enrichment/user_country.py`)
- Purpose: Looks up the likely end-user network endpoint country.
- Default path: `data/geoip/user-country.mmdb` (or custom path via constructor / env var `USER_COUNTRY_DB`).
- Method: `lookup(ip: str) -> UserCountryResult`:
  - `status`: `"available"`, `"not_found"`, or `"unavailable"`
  - `country_code`: e.g. `"IN"`
  - `trust_state`: `"enriched"` when available, `"unknown"` when missing
  - `source_dataset`: `"sapics/ip-location-db (user-country)"`
  - `license`: `"PDDL-1.0"`

### B. `ServerCountryProvider` (`modules/origin_infrastructure/enrichment/server_country.py`)
- Purpose: Looks up the physical server / relay infrastructure country.
- Default path: `data/geoip/server-country.mmdb` (or custom path via constructor / env var `SERVER_COUNTRY_DB`).
- Method: `lookup(ip: str) -> ServerCountryResult`:
  - `status`: `"available"`, `"not_found"`, or `"unavailable"`
  - `country_code`: e.g. `"US"`
  - `trust_state`: `"enriched"` when available, `"unknown"` when missing
  - `source_dataset`: `"sapics/ip-location-db (server-country)"`
  - `license`: `"PDDL-1.0"`

### C. `OriginASNProvider` (`modules/origin_infrastructure/enrichment/origin_asn.py`)
- Purpose: Secondary BGP origin routing lookup.
- Default path: `data/geoip/origin-asn.mmdb` (or custom path via constructor / env var `ORIGIN_ASN_DB`).
- Method: `lookup(ip: str) -> OriginASNResult`:
  - `status`: `"available"`, `"not_found"`, or `"unavailable"`
  - `asn`: e.g. `"AS55836"`
  - `organization`: e.g. `"Reliance Jio Infocomm Limited"`
  - `trust_state`: `"enriched"` when available, `"unknown"` when missing
  - `source_dataset`: `"sapics/ip-location-db (origin-asn)"`
  - `license`: `"PDDL-1.0"`

---

## 4. Aggregated Location Evidence Model

In `modules/origin_infrastructure/models.py`, add `LocationEvidence`:

```python
@dataclass(frozen=True)
class LocationEvidence:
    ip: str
    dbip_infrastructure_location: Optional[GeoIPResult] = None
    user_country: Optional[UserCountryResult] = None
    server_country: Optional[ServerCountryResult] = None
    origin_asn: Optional[OriginASNResult] = None
    country_agreement: Optional[bool] = None
    user_server_disagreement: bool = False
    country_confidence: float = 0.0
    location_type: str = "unknown"
    provenance: List[str] = field(default_factory=list)
```

Where `location_type` is one of:
- `direct_origin_infrastructure`
- `relay_infrastructure`
- `provider_infrastructure`
- `anonymized_infrastructure`
- `campaign_infrastructure`
- `unknown`

---

## 5. Fallback & Safe Degradation Strategy

1. If `user-country.mmdb`, `server-country.mmdb`, or `origin-asn.mmdb` are not found on disk, the providers initialize safely with `status = "unavailable"`.
2. Existing email analysis, hop reconstruction, authentication validation, and DB-IP enrichment continue working with 100% fidelity.
3. Tests will cover both presence and absence of secondary datasets.
