"""Passive DNS and MX resolution using pure standard-library network facilities.

Does NOT execute crawling, port scanning, or active interaction with infrastructure.
Strictly passive query resolution with 2.0s timeouts and graceful fallback.
"""

from __future__ import annotations

from datetime import datetime, timezone
import random
import socket
import struct
from typing import Any, List, Optional, Tuple

from .models import MxRecordData, PassiveDnsData

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28


def _encode_domain_name(name: str) -> bytes:
    parts = name.strip().strip(".").split(".")
    encoded = b""
    for part in parts:
        try:
            b_part = part.encode("idna")
        except Exception:
            b_part = part.encode("utf-8", errors="replace")
        encoded += bytes([len(b_part)]) + b_part
    return encoded + b"\x00"


def _decode_domain_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    original_offset = offset
    max_jumps = 10
    jumps = 0

    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            jumps += 1
            if jumps > max_jumps:
                break
            continue
        offset += 1
        if offset + length > len(data):
            break
        raw_label = data[offset:offset + length]
        try:
            label = raw_label.decode("idna")
        except Exception:
            label = raw_label.decode("utf-8", errors="replace")
        labels.append(label)
        offset += length

    domain = ".".join(labels)
    final_offset = original_offset if jumped else offset
    return domain, final_offset


def _query_dns_udp(
    query_name: str,
    qtype: int,
    nameserver: str = "8.8.8.8",
    timeout: float = 2.0,
) -> Tuple[str, List[Any]]:
    """Query DNS via standard RFC 1035 UDP. Returns (status, records)."""
    if not query_name or not query_name.strip():
        return "not_found", []

    tx_id = random.randint(0, 65535)
    flags = 0x0100  # Standard query with recursion desired
    encoded_name = _encode_domain_name(query_name)
    packet = struct.pack(">HHHHHH", tx_id, flags, 1, 0, 0, 0) + encoded_name + struct.pack(">HH", qtype, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return "unavailable", []
    except Exception:
        return "unavailable", []
    finally:
        sock.close()

    try:
        if len(data) < 12:
            return "unavailable", []

        r_id, r_flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
        if r_id != tx_id:
            return "unavailable", []

        rcode = r_flags & 0x0F
        if rcode == 3:
            return "not_found", []
        if rcode != 0:
            return "unavailable", []

        offset = 12
        # Skip questions
        for _ in range(qdcount):
            _, offset = _decode_domain_name(data, offset)
            offset += 4  # qtype + qclass

        results: List[Any] = []
        for _ in range(ancount):
            if offset >= len(data):
                break
            _, offset = _decode_domain_name(data, offset)
            if offset + 10 > len(data):
                break
            ans_type, ans_class, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            rdata_end = offset + rdlength

            if ans_type == QTYPE_A and rdlength == 4:
                ip = socket.inet_ntoa(data[offset:offset + 4])
                results.append(ip)
            elif ans_type == QTYPE_AAAA and rdlength == 16:
                ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
                results.append(ip)
            elif ans_type in (QTYPE_CNAME, QTYPE_NS):
                target_name, _ = _decode_domain_name(data, offset)
                results.append(target_name)
            elif ans_type == QTYPE_MX and rdlength >= 3:
                preference = struct.unpack(">H", data[offset:offset + 2])[0]
                mx_host, _ = _decode_domain_name(data, offset + 2)
                results.append({"host": mx_host, "preference": preference})
            elif ans_type == QTYPE_TXT:
                txt_parts: List[str] = []
                txt_offset = offset
                while txt_offset < rdata_end:
                    txt_len = data[txt_offset]
                    txt_offset += 1
                    txt_str = data[txt_offset:txt_offset + txt_len].decode("utf-8", errors="replace")
                    txt_parts.append(txt_str)
                    txt_offset += txt_len
                results.append("".join(txt_parts))

            offset = rdata_end

        return "available", results
    except Exception:
        return "unavailable", []


def resolve_passive_dns(
    domain: str,
    nameserver: str = "8.8.8.8",
    timeout: float = 2.0,
) -> PassiveDnsData:
    """Resolve A, AAAA, CNAME, NS, TXT (SPF & DMARC) for a domain name."""
    now_ts = datetime.now(timezone.utc).isoformat()
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return PassiveDnsData(status="unavailable", query_name=domain, lookup_timestamp=now_ts)

    # 1. Query A records
    st_a, a_recs = _query_dns_udp(clean_domain, QTYPE_A, nameserver, timeout)
    # 2. Query AAAA records
    st_aaaa, aaaa_recs = _query_dns_udp(clean_domain, QTYPE_AAAA, nameserver, timeout)
    # 3. Query CNAME records
    st_cname, cname_recs = _query_dns_udp(clean_domain, QTYPE_CNAME, nameserver, timeout)
    # 4. Query NS records
    st_ns, ns_recs = _query_dns_udp(clean_domain, QTYPE_NS, nameserver, timeout)
    # 5. Query TXT records
    st_txt, txt_recs = _query_dns_udp(clean_domain, QTYPE_TXT, nameserver, timeout)

    # Extract SPF
    spf_record: Optional[str] = None
    for txt in txt_recs:
        if isinstance(txt, str) and txt.strip().startswith("v=spf1"):
            spf_record = txt.strip()
            break

    # Extract DMARC
    dmarc_record: Optional[str] = None
    st_dmarc, dmarc_txt_recs = _query_dns_udp(f"_dmarc.{clean_domain}", QTYPE_TXT, nameserver, timeout)
    if st_dmarc == "available":
        for txt in dmarc_txt_recs:
            if isinstance(txt, str) and "v=DMARC1" in txt:
                dmarc_record = txt.strip()
                break

    statuses = [st_a, st_aaaa, st_cname, st_ns, st_txt]
    if any(s == "available" for s in statuses):
        overall_status = "available"
    elif any(s == "not_found" for s in statuses):
        overall_status = "not_found"
    else:
        overall_status = "unavailable"

    return PassiveDnsData(
        status=overall_status,
        query_name=clean_domain,
        a_records=[str(r) for r in a_recs],
        aaaa_records=[str(r) for r in aaaa_recs],
        cname_records=[str(r) for r in cname_recs],
        ns_records=[str(r) for r in ns_recs],
        txt_records=[str(r) for r in txt_recs],
        spf_record=spf_record,
        dmarc_record=dmarc_record,
        lookup_timestamp=now_ts,
    )


def resolve_mx_records(
    domain: str,
    nameserver: str = "8.8.8.8",
    timeout: float = 2.0,
) -> MxRecordData:
    """Resolve MX records for a domain name and neutrally classify provider."""
    now_ts = datetime.now(timezone.utc).isoformat()
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return MxRecordData(status="unavailable", query_domain=domain, lookup_timestamp=now_ts)

    st_mx, mx_results = _query_dns_udp(clean_domain, QTYPE_MX, nameserver, timeout)
    if st_mx != "available":
        mx_st = "no_mx" if st_mx == "not_found" else "unavailable"
        return MxRecordData(
            status=st_mx,
            query_domain=clean_domain,
            records=[],
            primary_provider="none" if mx_st == "no_mx" else "unknown",
            is_null_mx=False,
            mx_status=mx_st,
            lookup_timestamp=now_ts,
        )

    # Sort records by preference ascending
    records = sorted([r for r in mx_results if isinstance(r, dict)], key=lambda x: x.get("preference", 100))

    # Check for RFC 7505 Null MX (single MX record with preference 0 and target "." or "")
    if len(records) == 1 and records[0].get("preference") == 0 and str(records[0].get("host", "")).strip() in ("", "."):
        return MxRecordData(
            status="available",
            query_domain=clean_domain,
            records=records,
            primary_provider="null_mx",
            is_null_mx=True,
            mx_status="null_mx",
            lookup_timestamp=now_ts,
        )

    if not records:
        return MxRecordData(
            status="available",
            query_domain=clean_domain,
            records=[],
            primary_provider="none",
            is_null_mx=False,
            mx_status="no_mx",
            lookup_timestamp=now_ts,
        )

    # Neutral provider classification based on explicit hostname evidence
    provider = "unknown"
    all_hosts = " ".join(str(r.get("host", "")).lower() for r in records)
    if "google.com" in all_hosts or "googlemail.com" in all_hosts:
        provider = "google_workspace"
    elif "outlook.com" in all_hosts or "protection.outlook.com" in all_hosts:
        provider = "microsoft_365"
    elif "pphosted.com" in all_hosts or "proofpoint.com" in all_hosts:
        provider = "proofpoint"
    elif "mimecast.com" in all_hosts:
        provider = "mimecast"
    elif "protonmail.ch" in all_hosts or "proton.me" in all_hosts:
        provider = "protonmail"
    else:
        provider = "self_hosted_or_custom"

    return MxRecordData(
        status="available",
        query_domain=clean_domain,
        records=records,
        primary_provider=provider,
        is_null_mx=False,
        mx_status="normal",
        lookup_timestamp=now_ts,
    )
