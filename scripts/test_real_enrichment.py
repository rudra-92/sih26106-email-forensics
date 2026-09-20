#!/usr/bin/env python
"""Real local database enrichment validation script for Module 5.

Queries local DB-IP Lite databases (City & ASN MMDB) and optional Tor bulk exit list.
Accepts an IP address as a CLI argument (default: 8.8.8.8).

Semantic Requirement:
Output reflects observed infrastructure geolocation only, NEVER physical human attacker attribution.
"""

import os
import sys
import time
from pathlib import Path

# Safe Windows stdout encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.origin_infrastructure.enrichment import (
    CompositeEnrichmentProvider,
    LocalASNProvider,
    LocalGeoIPProvider,
    LocalInfrastructureProvider,
)


def run_validation(target_ip: str) -> None:
    city_db = Path("data/geoip/dbip-city-lite.mmdb")
    asn_db = Path("data/geoip/dbip-asn-lite.mmdb")
    tor_file = Path("data/geoip/tor_exit_nodes.txt")

    print("=" * 65)
    print("MODULE 5: REAL LOCAL ENRICHMENT VERIFICATION")
    print("=" * 65)
    print(f"Target IP Address: {target_ip}")
    print(f"City Database    : {city_db} ({'FOUND' if city_db.is_file() else 'MISSING'})")
    print(f"ASN Database     : {asn_db} ({'FOUND' if asn_db.is_file() else 'MISSING'})")
    print(f"Tor Exit List    : {tor_file} ({'FOUND' if tor_file.is_file() else 'MISSING'})")
    print("-" * 65)

    # 1. Measure DB initialization time
    t0 = time.perf_counter()
    geoip = LocalGeoIPProvider(db_path=str(city_db) if city_db.is_file() else None)
    asn = LocalASNProvider(db_path=str(asn_db) if asn_db.is_file() else None)
    infra = LocalInfrastructureProvider(tor_exit_list_path=str(tor_file) if tor_file.is_file() else None)
    composite = CompositeEnrichmentProvider(
        geoip_provider=geoip,
        asn_provider=asn,
        infrastructure_provider=infra,
    )
    init_duration_ms = (time.perf_counter() - t0) * 1000.0

    # 2. Perform Single Lookup
    enriched = composite.enrich(target_ip)
    geo = enriched.geolocation
    asn_data = enriched.asn
    infra_data = enriched.infrastructure

    print("\n--- ENRICHMENT RESULT ---")
    print(f"IP                  : {enriched.ip}")
    print(f"Country             : {geo.country or 'N/A'} ({geo.country_code or 'N/A'})")
    print(f"Region              : {geo.region or 'N/A'}")
    print(f"City                : {geo.city or 'N/A'}")
    print(f"Latitude            : {geo.latitude if geo.latitude is not None else 'N/A'}")
    print(f"Longitude           : {geo.longitude if geo.longitude is not None else 'N/A'}")
    print(f"Timezone            : {geo.timezone or 'N/A'}")
    print(f"Accuracy (km)       : {geo.accuracy_radius_km if geo.accuracy_radius_km is not None else 'N/A'}")
    print(f"ASN                 : {asn_data.asn or 'N/A'}")
    print(f"Organization        : {asn_data.organization or 'N/A'}")
    print(f"Network CIDR        : {asn_data.network_cidr or 'N/A'}")
    print(f"Classification      : {infra_data.classification}")
    print(f"Tor Exit Indicator  : {infra_data.tor_exit_indicator}")
    print(f"Data Source (GeoIP) : {geo.source_dataset} ({geo.dataset_name or 'N/A'})")
    print(f"Data Source (ASN)   : {asn_data.source_dataset} ({asn_data.dataset_name or 'N/A'})")
    print(f"Dataset Date        : GeoIP={geo.dataset_date or 'N/A'}, ASN={asn_data.dataset_date or 'N/A'}")
    print(f"Lookup Timestamp    : {geo.lookup_timestamp or 'N/A'}")
    print(f"Observed Geolocation: {geo.observed_infrastructure_geolocation}")
    print(f"Semantic Guardrail  : {geo.semantic_note}")

    # 3. Performance Benchmark: 100 Lookups
    print("\n--- PERFORMANCE BENCHMARK (100 REPEATED LOOKUPS) ---")
    print(f"Database Init Time  : {init_duration_ms:.2f} ms")

    latencies_us = []
    # Warm up 5 runs
    for _ in range(5):
        composite.enrich(target_ip)

    for _ in range(100):
        start = time.perf_counter()
        composite.enrich(target_ip)
        elapsed = (time.perf_counter() - start) * 1_000_000.0  # microseconds
        latencies_us.append(elapsed)

    avg_us = sum(latencies_us) / len(latencies_us)
    max_us = max(latencies_us)
    min_us = min(latencies_us)

    print(f"Average Latency     : {avg_us:.1f} \u03bcs ({avg_us / 1000.0:.3f} ms)")
    print(f"Maximum Latency     : {max_us:.1f} \u03bcs ({max_us / 1000.0:.3f} ms)")
    print(f"Minimum Latency     : {min_us:.1f} \u03bcs ({min_us / 1000.0:.3f} ms)")
    print("=" * 65)

    geoip.close()
    asn.close()


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    run_validation(ip)
