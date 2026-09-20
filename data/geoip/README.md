# Local GeoIP, ASN & Threat Infrastructure Data Directory

This directory stores local offline database files used by **Module 5: Origin & Infrastructure Reconstruction Engine**.

## Supported Datasets (Offline-First)

### 1. DB-IP Lite (Primary Dataset)
* **IP to City Lite (MMDB)**: `data/geoip/dbip-city-lite.mmdb`
* **IP to ASN Lite (MMDB)**: `data/geoip/dbip-asn-lite.mmdb`
* **IP to Country Lite (MMDB)**: `data/geoip/dbip-country-lite.mmdb` (optional fallback)

**Download Links (Free, updated monthly):**
* [IP to City Lite (MMDB format)](https://db-ip.com/db/download/ip-to-city-lite)
* [IP to ASN Lite (MMDB format)](https://db-ip.com/db/download/ip-to-asn-lite)

**License & Attribution:**
IP geolocation and ASN data provided by [DB-IP Lite](https://db-ip.com), licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
Database files are not committed to Git per licensing guidelines.

### 2. Tor Bulk Exit List (Optional Contextual Feed)
* **File**: `data/geoip/tor_exit_nodes.txt`
* Free feed provided by The Tor Project: `https://check.torproject.org/torbulkexitlist`

## Automated Setup Procedure

To automatically download, decompress, and validate all required datasets on a fresh clone, run:
```bash
python scripts/setup_geoip.py
```

### Setup Options:
* **Validate existing files**: `python scripts/setup_geoip.py --check`
* **Force re-download**: `python scripts/setup_geoip.py --force`
* **Custom data directory**: `python scripts/setup_geoip.py --data-dir /path/to/custom/dir`
* **Specify release month**: `python scripts/setup_geoip.py --release 2026-09`
* **Skip Tor exit list**: `python scripts/setup_geoip.py --skip-tor`

## Configuration via Environment Variables

The engine automatically discovers database files in `data/geoip/`. Alternatively, you can configure custom paths via environment variables:
* `GEOIP_CITY_DB` (or `SIH_GEOIP_DB_PATH`): Path to City or Country MMDB
* `GEOIP_COUNTRY_DB`: Path to Country MMDB
* `GEOIP_ASN_DB` (or `SIH_ASN_DB_PATH`): Path to ASN MMDB
* `TOR_EXIT_LIST_PATH`: Path to Tor exit list text file

