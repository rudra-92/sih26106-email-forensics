#!/usr/bin/env python
"""End-to-End Email Forensic Analysis with Real Local Database Enrichment.

Runs a multi-hop synthetic .eml through Module 5:
RAW .EML -> Module 5 -> earliest reliable peer -> local GeoIP -> local ASN
-> infrastructure classification -> origin hypothesis -> evidence graph.
"""

import json
import sys
from pathlib import Path

# Safe Windows stdout encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.origin_infrastructure.analyzer import OriginInfrastructureAnalyzer
from modules.origin_infrastructure.enrichment import (
    LocalASNProvider,
    LocalGeoIPProvider,
    LocalInfrastructureProvider,
)


def run_e2e_email_test() -> None:
    # 1. Multi-hop synthetic .eml
    raw_eml = (
        b"From: billing@legitimate-service.com\r\n"
        b"To: finance@victim-corp.com\r\n"
        b"Subject: Invoice Notification #8821\r\n"
        b"Date: Sun, 20 Sep 2026 12:00:00 +0000\r\n"
        b"Message-ID: <inv-8821-alert@legitimate-service.com>\r\n"
        # Hop 3 (Top / Most recent): Internal gateway delivery to mailstore
        b"Received: from mx1.victim-corp.com ([192.168.1.5]) by mailstore.victim-corp.com "
        b"with LMTP id MS1002; Sun, 20 Sep 2026 12:04:00 +0000\r\n"
        # Hop 2: External perimeter ingestion from public peer 8.8.8.8
        b"Received: from mail.external-service.com (dns.google [8.8.8.8]) "
        b"by mx1.victim-corp.com (Postfix) with ESMTPS id V1001 "
        b"for <finance@victim-corp.com>; Sun, 20 Sep 2026 12:02:00 +0000\r\n"
        # Hop 1 (Earliest / Upstream): Internal private workstation hop
        b"Received: from workstation-fin.lan ([10.0.1.25]) "
        b"by mail.external-service.com with ESMTP id EXT901; Sun, 20 Sep 2026 12:00:30 +0000\r\n"
        b"\r\n"
        b"Please review your attached quarterly billing summary."
    )

    city_db = Path("data/geoip/dbip-city-lite.mmdb")
    asn_db = Path("data/geoip/dbip-asn-lite.mmdb")
    tor_file = Path("data/geoip/tor_exit_nodes.txt")

    geoip = LocalGeoIPProvider(db_path=str(city_db) if city_db.is_file() else None)
    asn = LocalASNProvider(db_path=str(asn_db) if asn_db.is_file() else None)
    infra = LocalInfrastructureProvider(tor_exit_list_path=str(tor_file) if tor_file.is_file() else None)

    analyzer = OriginInfrastructureAnalyzer(
        geoip_provider=geoip,
        asn_provider=asn,
        infrastructure_provider=infra,
    )

    report = analyzer.analyze(raw_eml, email_id="EML-E2E-REAL-001")

    # Extract peer enrichment
    peer_ip = report.origin_assessment.earliest_reliable_peer
    peer_enrichment = next((p for p in report.enriched_peers if p.ip == peer_ip), None)

    structured_result = {
        "email_id": report.email_id,
        "origin_assessment": {
            "earliest_reliable_peer": report.origin_assessment.earliest_reliable_peer,
            "source_visibility": report.origin_assessment.source_visibility,
            "confidence": report.origin_assessment.confidence,
            "assessment_reason": report.origin_assessment.assessment_reason,
        },
        "infrastructure": {
            "ip": peer_ip,
            "country": peer_enrichment.geolocation.country if peer_enrichment else None,
            "country_code": peer_enrichment.geolocation.country_code if peer_enrichment else None,
            "region": peer_enrichment.geolocation.region if peer_enrichment else None,
            "city": peer_enrichment.geolocation.city if peer_enrichment else None,
            "latitude": peer_enrichment.geolocation.latitude if peer_enrichment else None,
            "longitude": peer_enrichment.geolocation.longitude if peer_enrichment else None,
            "asn": peer_enrichment.asn.asn if peer_enrichment else None,
            "organization": peer_enrichment.asn.organization if peer_enrichment else None,
            "network_cidr": peer_enrichment.asn.network_cidr if peer_enrichment else None,
            "classification": peer_enrichment.infrastructure.classification if peer_enrichment else None,
            "tor_exit_indicator": peer_enrichment.infrastructure.tor_exit_indicator if peer_enrichment else None,
            "observed_infrastructure_geolocation": True,
            "semantic_note": "Observed infrastructure geolocation, NOT human attacker physical location.",
        },
        "provenance": {
            "geoip_source": peer_enrichment.geolocation.source_dataset if peer_enrichment else None,
            "geoip_dataset": peer_enrichment.geolocation.dataset_name if peer_enrichment else None,
            "geoip_date": peer_enrichment.geolocation.dataset_date if peer_enrichment else None,
            "asn_source": peer_enrichment.asn.source_dataset if peer_enrichment else None,
            "asn_dataset": peer_enrichment.asn.dataset_name if peer_enrichment else None,
            "asn_date": peer_enrichment.asn.dataset_date if peer_enrichment else None,
            "lookup_timestamp": peer_enrichment.geolocation.lookup_timestamp if peer_enrichment else None,
        },
        "forensic_hypotheses": [
            {
                "type": h.hypothesis_type,
                "confidence": h.confidence,
                "supporting_evidence": h.supporting_evidence,
                "contradicting_evidence": h.contradicting_evidence,
            }
            for h in report.hypotheses
        ],
        "evidence_graph": {
            "entities_count": len(report.entities),
            "relationships_count": len(report.relationships),
        },
    }

    print(json.dumps(structured_result, indent=2))

    geoip.close()
    asn.close()


if __name__ == "__main__":
    run_e2e_email_test()
