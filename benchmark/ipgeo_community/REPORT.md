# Forensic Benchmark Report: DB-IP Lite vs. ipgeo Community Edition

This benchmark compares the current production enrichment provider (**DB-IP Lite**, CC BY 4.0) with candidate open dataset (**ipgeo Community Edition**, CC BY-SA 4.0 by WhoisXML API / Whois API LLC).

This evaluation is **strictly read/test-only**. No production modules, providers, or configurations were modified.

---

## 1. Dataset Information & Provenance

| Metric / Metadata | DB-IP Lite (Current Production) | ipgeo Community Edition (Candidate) |
|---|---|---|
| **Publisher** | DB-IP.com | WhoisXML API / Whois API LLC |
| **Release Version** | September 2026 (`2026-09`) | September 14, 2026 (`2026-09-14`) |
| **Database Type in MMDB** | `DBIP-City-Lite`, `DBIP-ASN-Lite` | `ipgeo` (flat schema, `.get()` access) |
| **Record Count** | ~3.8M City blocks, ~1.2M ASN blocks | `16,482,321` network-block records |
| **VPN Feed Rows** | N/A (Tor Project bulk feed: 1,364 exit IPs) | `11,564` rows (`community-vpn-list.csv.gz`) |
| **Binary Size on Disk** | City: 121.4 MB, ASN: 9.1 MB (Total: 130.5 MB) | `174.7 MB` (`ipgeo-community.mmdb`) |
| **Checksum (SHA-256)** | Verified during setup | `70e61c90865de7bcd39896e1a32f0406e3cc3dc33871247432ddb911e556d2b7` (Verified MATCH) |
| **Update Cadence** | Monthly (1st of each month) | Weekly (Mondays) |
| **Single Address Handling** | Includes /32 and /128 | Network-blocks only (254,942 single-address rows dropped) |
| **Excluded Sources** | N/A | CAIDA ITDK, IP2Location Lite |

---

## 2. Licensing & Attribution

- **DB-IP Lite**:
  - License: **Creative Commons Attribution 4.0 International (CC BY 4.0)**.
  - Requirement: Attribution notice (*"IP geolocation and ASN data provided by DB-IP Lite, licensed under CC BY 4.0"*). Permissive for integration and derivative software without copyleft restrictions.
- **ipgeo Community Edition**:
  - License: **Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)**.
  - License text:
    > `ipgeo Community Edition — License

This database is licensed under Creative Commons Attribution-ShareAlike 4.0
International (CC BY-SA 4.0): https://creativecommons.org/licenses/by-sa/4.0/

You must give appropriate credit and distribute any derivative under the same
license. Required attribution and per-source notices are in ATTRIBUTION.txt.`
  - Attribution notice (`ATTRIBUTION.txt`):
    > *"IP geolocation data provided by ipgeo Community Edition by WhoisXML API, licensed under CC BY-SA 4.0."*
  - **Forensic & Legal Consideration**:
    - CC BY-SA 4.0 includes a **ShareAlike (copyleft)** provision on adaptations of the dataset. Distributing modified or merged database files would require licensing under CC BY-SA 4.0. Consuming the database via query adapter in an application generally does not trigger ShareAlike on the software code itself, but caution is warranted when bundling or combining database artifacts.

---

## 3. Candidate Field Extraction on Test IPs

All target IPv4 and IPv6 addresses were parsed using the standard `maxminddb` reader with `.get(ip)`:

| IP Address | Country | Region | City | Postal Code | Timezone | ASN | Organization | `is_vpn` | `is_datacenter` | `ip_type` |
|---|---|---|---|---|---|---|---|---|---|---|
| `49.37.154.164` | India (IN) | Maharashtra | Navi Mumbai (Ghansoli) | — | Asia/Kolkata | AS55836 | RELIANCEJIO-IN Reliance Jio Infocomm Limited | `None` | `None` | `mobile_carrier` |
| `8.8.8.8` | United States (US) | California | Mountain View | — | America/Los_Angeles | AS15169 | GOOGLE | `None` | `True` | `datacenter` |
| `1.1.1.1` | Australia (AU) | New South Wales | Sydney | — | Australia/Sydney | AS13335 | CLOUDFLARENET | `None` | `True` | `cdn` |
| `9.9.9.9` | United States (US) | California | Berkeley (North Berkeley) | — | America/Los_Angeles | AS19281 | QUAD9-AS-1 | `None` | `None` | `None` |
| `171.25.193.25` | Sweden (SE) | — | — | — | Europe/Stockholm | AS198093 | DFRI-AS Foreningen for digitala fri- och rattigheter | `None` | `None` | `None` |
| `2606:4700:4700::1111` | Canada (CA) | Quebec | Montreal | — | America/Toronto | AS13335 | CLOUDFLARENET - Cloudflare, Inc. | `None` | `True` | `cdn` |
| `2001:4860:4860::8888` | Canada (CA) | Quebec | Montreal | — | America/Toronto | — | — | `None` | `None` | `None` |

*Note: As specified in SCHEMA.md, missing fields represent unknown values and must not be interpreted as negative evidence.*

---

## 4. Side-by-Side Comparison: DB-IP Lite vs. ipgeo Community

| IP Address | DB-IP CC | ipgeo CC | DB-IP Region | ipgeo Region | DB-IP City | ipgeo City | DB-IP Lat/Lon | ipgeo Lat/Lon | DB-IP ASN | ipgeo ASN | DB-IP Organization | ipgeo Organization |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `49.37.154.164` | IN | IN | Maharashtra | Maharashtra | Navi Mumbai (Ghansoli) | Navi Mumbai (Ghansoli) | 19.1258, 73.0004 | 19.1258, 73.0004 | AS55836 | AS55836 | Reliance Jio Infocomm Limited | RELIANCEJIO-IN Reliance Jio Infocomm Limited |
| `8.8.8.8` | US | US | California | California | Mountain View | Mountain View | 37.4220, -122.0850 | 37.4220, -122.0850 | AS15169 | AS15169 | Google LLC | GOOGLE |
| `1.1.1.1` | AU | AU | New South Wales | New South Wales | Sydney | Sydney | -33.8688, 151.2090 | -33.8688, 151.2090 | AS13335 | AS13335 | Cloudflare, Inc. | CLOUDFLARENET |
| `9.9.9.9` | US | US | California | California | Berkeley (North Berkeley) | Berkeley (North Berkeley) | 37.8806, -122.2680 | 37.8806, -122.2680 | AS19281 | AS19281 | Quad9 | QUAD9-AS-1 |
| `171.25.193.25` | SE | SE | Stockholm | — | Stockholm | — | 59.3327, 18.0656 | None | AS198093 | AS198093 | Foreningen for digitala fri- och rattigheter | DFRI-AS Foreningen for digitala fri- och rattigheter |
| `2606:4700:4700::1111` | CA | CA | Quebec | Quebec | Montreal | Montreal | 45.5019, -73.5674 | 45.5019, -73.5674 | AS13335 | AS13335 | Cloudflare, Inc. | CLOUDFLARENET - Cloudflare, Inc. |
| `2001:4860:4860::8888` | CA | CA | Quebec | Quebec | Montreal | Montreal | 45.5019, -73.5674 | 45.5019, -73.5674 | AS15169 | — | Google LLC | — |

### Agreement Metrics Across Test Dataset (N=7)

- **Country Agreement**: **7/7 (100.0%)**
- **Region Agreement**: **6/7 (85.7%)**
- **City Agreement**: **6/7 (85.7%)**
- **ASN Agreement**: **6/7 (85.7%)**
- **Organization Agreement**: **5/7 (71.4%)**

---

## 5. Special Investigation: User Public IP (`49.37.154.164`)

Target IP: `49.37.154.164` (Reliance Jio Infocomm, India)

| Metric | DB-IP Lite Result | ipgeo Community Result | Forensic Comparison |
|---|---|---|---|
| **Country** | India (`IN`) | India (`IN`) | **100% Agreement** |
| **Region** | Maharashtra | Maharashtra | **100% Agreement** (neither returned Telangana) |
| **City** | `Navi Mumbai (Ghansoli)` | `Navi Mumbai (Ghansoli)` | **100% Agreement** (identical neighborhood resolution) |
| **Coordinates** | `19.1258, 73.0004` | `19.1258, 73.0004` | **Identical coordinates** |
| **Timezone** | *(Not returned in City Lite)* | `Asia/Kolkata` | **ipgeo advantage** (timezone populated) |
| **ASN** | `AS55836` | `AS55836` | **100% Agreement** |
| **Organization** | Reliance Jio Infocomm Limited | RELIANCEJIO-IN Reliance Jio Infocomm Limited | **100% Agreement** (same entity) |
| **Infrastructure Type** | Residential/Mobile | `is_vpn=None`, `is_datacenter=None`, `ip_type=mobile_carrier` | **ipgeo advantage** (`mobile_carrier` identified) |

### Forensic Takeaway
- Both **DB-IP Lite** and **ipgeo Community** exhibited complete consensus for `49.37.154.164`, resolving to **Navi Mumbai (Ghansoli), Maharashtra, India** under **AS55836 (Reliance Jio)**.
- Neither database reported **Hyderabad, Telangana**. The previous external service report of Hyderabad likely originated from a stale BGP aggregation or Anycast / dynamic cellular IP reallocation.
- ipgeo Community provided valuable added metadata: timezone (`Asia/Kolkata`) and carrier infrastructure classification (`ip_type: mobile_carrier`).
- Forensic ground truth principle: IP geolocation reflects network route aggregation and regional gateway points-of-presence (PoP), not physical subscriber device GPS coordinates.

---

## 6. VPN and Threat Infrastructure Benchmark

### Tor Exit Node Test: `171.25.193.25`
- **DB-IP + SIH26106 Engine**:
  - Identified as **Tor Exit Node** via Tor Project Bulk Exit List feed (`tor_exit_nodes.txt`).
  - Flagged rule: `RULE-INFRA-TOR-EXIT` (Confidence: 0.95).
  - Geolocation: Stockholm, Sweden (AS198093 - Foreningen for digitala fri- och rattigheter).
- **ipgeo Community MMDB**:
  - `is_vpn`: `None` (not flagged as commercial VPN)
  - `is_datacenter`: `None`
  - `ip_type`: `None`
  - ASN: `AS198093` (DFRI-AS Foreningen for digitala fri- och rattigheter)
  - Geolocation: Sweden (`country_code="SE"`, city/region unpopulated)
- **community-vpn-list.csv Feed**:
  - `171.25.193.25` was **not found** in the community VPN feed (0 subnet matches). The community VPN list focuses on commercial VPN operators (Mullvad, NordVPN, Private Internet Access, etc.) rather than volunteer-run Tor relays.

**Critical Forensic Finding**:
Commercial VPN feeds and native ASN flags (`is_vpn`) do **not** reliably substitute for a dedicated dynamic Tor exit node feed. SIH26106's existing Tor Project feed integration correctly flags Tor exit relays that open/commercial VPN databases miss.

### Infrastructure Typing (`ip_type`):
- `8.8.8.8`: `is_datacenter=True`, `ip_type=datacenter`
- `1.1.1.1`: `is_datacenter=True`, `ip_type=cdn`
- `2606:4700:4700::1111`: `is_datacenter=True`, `ip_type=cdn`
- `49.37.154.164`: `is_datacenter=None`, `ip_type=mobile_carrier`
- `9.9.9.9`: `is_datacenter=None`, `ip_type=None`

**Forensic Evaluation**:
The `ip_type` classification (`datacenter`, `cdn`, `mobile_carrier`, `satellite`, `education`, `government`) adds actionable intelligence for email hop classification, distinguishing consumer residential/mobile hops from datacenter relays and CDNs.

---

## 7. Performance Evaluation

Performance benchmarks measured across 100 consecutive queries using `maxminddb`:

| Metric | DB-IP Lite (City + ASN) | ipgeo Community Edition | Performance Comparison |
|---|---|---|---|
| **Database Load / Open Time** | `1.21 ms` (2 MMDB files) | `0.61 ms` (1 unified MMDB) | ipgeo opens faster (single file) |
| **Average Query Latency (100 runs)** | `0.0197 ms` / query | `0.0069 ms` / query | Both ultra-fast sub-millisecond |
| **Maximum Single Query Latency** | `0.0844 ms` | `0.0432 ms` | Both under 0.2 ms peak latency |
| **Memory / File Descriptors** | 2 open file descriptors | 1 open file descriptor | Unified reader reduces descriptor overhead |

---

## 8. Comprehensive Reliability & Capability Matrix

| Capability / Attribute | DB-IP Lite | ipgeo Community Edition | Comparison / Forensic Analysis |
|---|---|---|---|
| **Country Coverage** | Near-universal | Near-universal | Equal |
| **Region / State Coverage** | High | High | Equal |
| **City Coverage** | High | High | Equal for test targets |
| **Coordinates (Lat/Lon)** | Included | Included | High consensus |
| **Timezone** | Not in City Lite | Included (IANA & UTC offsets) | **Advantage: ipgeo** |
| **Postal Code** | Included in City Lite | Sparse minority | **Advantage: DB-IP** |
| **ASN & AS Organization** | Separate MMDB (`dbip-asn-lite`) | Unified in single record | **Advantage: ipgeo** (unified lookup) |
| **VPN Indicator** | None (requires external feed) | Built-in `is_vpn` flag + VPN CSV | **Advantage: ipgeo** (for commercial VPNs) |
| **Tor Detection** | None (relies on Tor feed) | None (`is_vpn=None` on Tor test IP) | **Equal** (both need dedicated Tor feed) |
| **Datacenter Indicator** | None | Built-in `is_datacenter` flag | **Advantage: ipgeo** |
| **Infrastructure Type** | None | Built-in `ip_type` classification | **Advantage: ipgeo** |
| **IPv4 Support** | Full | Full | Equal |
| **IPv6 Support** | Full (City + ASN) | City full, ASN omitted for some IPv6 | **Advantage: DB-IP** (DB-IP had IPv6 ASN for 2001:4860:4860::8888) |
| **Subnet Granularity** | Up to /32 and /128 | Network-blocks only (no /32 or /128) | **Advantage: DB-IP** |
| **Update Frequency** | Monthly (1st of month) | Weekly (Mondays) | **Advantage: ipgeo** |
| **License** | **CC BY 4.0** (Permissive) | **CC BY-SA 4.0** (ShareAlike copyleft) | **Advantage: DB-IP** (more permissive) |
| **Local / Offline Operation** | 100% Offline MMDB | 100% Offline MMDB | Equal |
| **API Dependency** | None | None | Equal |
| **Rate / Request Limits** | None (Local file) | None (Local file) | Equal |
| **Total Disk Size** | ~130.5 MB (2 MMDBs) | ~174.7 MB (1 MMDB) | DB-IP slightly smaller |

---

## 9. Key Disagreements & Observations

1. **IPv6 ASN Coverage**:
   - `2001:4860:4860::8888` (Google Public DNS IPv6): DB-IP ASN resolved to `AS15169 Google LLC`. ipgeo Community returned `None` for ASN and Organization, though it resolved City and Country.
2. **Tor Node Resolution**:
   - `171.25.193.25` (DFRI Tor exit relay): DB-IP provided City-level resolution (`Stockholm, Sweden`), whereas ipgeo Community only resolved country-level (`Sweden`) with empty region and city. Furthermore, ipgeo did not flag it as VPN/proxy.
3. **Organization Strings**:
   - `1.1.1.1`: DB-IP = `Cloudflare, Inc.`, ipgeo = `CLOUDFLARENET`.
   - `8.8.8.8`: DB-IP = `Google LLC`, ipgeo = `GOOGLE`.
   - `9.9.9.9`: DB-IP = `Quad9`, ipgeo = `QUAD9-AS-1`.
   ipgeo uses uppercase network handle formats directly from RIR WHOIS, whereas DB-IP uses legal corporate names.
4. **License Constraints**:
   - DB-IP Lite's **CC BY 4.0** allows broad incorporation without copyleft obligations.
   - ipgeo Community's **CC BY-SA 4.0** requires any adaptation/derivative dataset to be shared under the same license.

---

## 10. Architectural Recommendation

### Recommendation: **Support Both as Independent Evidence Sources (Multi-Provider Architecture)**

1. **Do NOT drop or replace DB-IP Lite**:
   - DB-IP Lite provides clean **CC BY 4.0** licensing, complete IPv6 ASN resolution (as demonstrated on Google IPv6), and specific /32 and /128 subnet mappings.
2. **Add `IpgeoCommunityProvider` as an Optional / Supplementary Provider**:
   - ipgeo Community offers valuable weekly updates, a unified schema (reducing disk I/O and open descriptors), and infrastructure annotations (`ip_type: mobile_carrier`, `ip_type: cdn`, `ip_type: datacenter`, `is_datacenter`).
3. **Preserve Dedicated Tor Exit Feed**:
   - Neither DB-IP nor ipgeo Community natively detects volunteer Tor relays like `171.25.193.25`. The SIH26106 Tor Project bulk feed remains essential.
4. **Multi-Source Forensic Corroboration**:
   - In forensic origin attribution, querying multiple independent offline datasets strengthens evidence credibility when providers agree, and flags anomalies (e.g. Anycast or regional routing variances) when they disagree.
