"""RDAP / Registration Intelligence client based on RFC 9082, RFC 9083, and RFC 9224.

Performs passive HTTPS queries to authoritative Regional Internet Registries (RIRs)
and domain registries. Enforces strict 2.0s timeouts and graceful offline fallback.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request

from .models import RdapRegistrationData


class RdapClient:
    """Registration Intelligence client for IP addresses and domain names."""

    # Authoritative base services for all 5 Regional Internet Registries (RIRs)
    RIR_SERVICES = {
        "ARIN": "https://rdap.arin.net/registry/ip/{query}",
        "RIPE": "https://rdap.db.ripe.net/ip/{query}",
        "APNIC": "https://rdap.apnic.net/ip/{query}",
        "LACNIC": "https://rdap.lacnic.net/rdap/ip/{query}",
        "AFRINIC": "https://rdap.afrinic.net/rdap/ip/{query}",
    }

    # IANA IPv4 /8 Bootstrap Delegation Registry per RFC 9224
    IANA_IPV4_BOOTSTRAP = {
        "AFRINIC": {41, 102, 105, 154, 196, 197},
        "LACNIC": {177, 179, 181, 186, 187, 189, 190, 191, 200, 201},
        "APNIC": {
            1, 14, 27, 36, 39, 42, 43, 49, 101, 103, 106, 133, 175, 180, 182, 183,
            202, 203, 210, 211, *range(58, 62), *range(110, 127), *range(218, 224),
        },
        "RIPE": {
            2, 5, 25, 31, 37, 46, 62, 109, 176, 178, 185, 188, 212, 213, 217,
            *range(77, 96), *range(193, 196),
        },
        "ARIN": {
            3, 8, 23, 24, 44, 47, 48, 50, 52, 54, 55, 104, 107, 108, 184, 198, 199,
            216, *range(63, 77), *range(96, 101), *range(128, 133), *range(134, 175),
            *range(204, 210), *range(214, 217),
        },
    }

    def __init__(self, timeout: float = 2.0) -> None:
        self.timeout = timeout

    def _fetch_rdap_json(self, url: str) -> Tuple[str, Dict[str, Any], Optional[str]]:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SIH26106-Forensics/1.0 (Passive Infrastructure Intelligence; RFC 9082/9083)",
                "Accept": "application/rdap+json, application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                content = response.read().decode("utf-8", errors="replace")
                data = json.loads(content)
                return "available", data, None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return "not_found", {}, f"HTTP 404: Not Found ({url})"
            return "unavailable", {}, f"HTTP {e.code}: {e.reason} ({url})"
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            return "unavailable", {}, f"Lookup error: {e}"

    def discover_endpoints_for_ip(self, ip_str: str) -> List[Tuple[str, str]]:
        """Discover authoritative RDAP endpoints using IANA bootstrap allocations (RFC 9224)."""
        ordered: List[Tuple[str, str]] = []
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            if addr.version == 4:
                first_octet = int(str(addr).split(".")[0])
                for rir, octets in self.IANA_IPV4_BOOTSTRAP.items():
                    if first_octet in octets:
                        ordered.append((rir, self.RIR_SERVICES[rir]))
                        break
            elif addr.version == 6:
                hex_prefix = addr.exploded[:4].lower()
                if hex_prefix in ("2001", "2400"):
                    ordered.append(("APNIC", self.RIR_SERVICES["APNIC"]))
                elif hex_prefix in ("2600", "2610", "2620"):
                    ordered.append(("ARIN", self.RIR_SERVICES["ARIN"]))
                elif hex_prefix in ("2a00", "2a01", "2a02"):
                    ordered.append(("RIPE", self.RIR_SERVICES["RIPE"]))
                elif hex_prefix in ("2800", "2801"):
                    ordered.append(("LACNIC", self.RIR_SERVICES["LACNIC"]))
                elif hex_prefix in ("2c00", "2c01"):
                    ordered.append(("AFRINIC", self.RIR_SERVICES["AFRINIC"]))
        except Exception:
            pass

        # Add open RFC 9224 redirector and any remaining RIRs as fallback
        ordered.append(("RDAP.ORG", "https://rdap.org/ip/{query}"))
        for rir, url_tpl in self.RIR_SERVICES.items():
            if not any(r == rir for r, _ in ordered):
                ordered.append((rir, url_tpl))
        return ordered

    def discover_endpoints_for_domain(self, domain: str) -> List[Tuple[str, str]]:
        """Discover authoritative RDAP endpoints using IANA DNS bootstrap registry (RFC 9224)."""
        tld = domain.strip().lower().split(".")[-1]
        ordered: List[Tuple[str, str]] = []
        if tld in ("com", "net"):
            ordered.append(("VeriSign", "https://rdap.verisign.com/com/v1/domain/{query}"))
        elif tld == "org":
            ordered.append(("PIR", "https://rdap.publicinterestregistry.org/rdap/domain/{query}"))
        elif tld in ("info", "biz", "mobi"):
            ordered.append(("IdentityDigital", "https://rdap.identitydigital.services/rdap/domain/{query}"))

        # Open IANA discovery service (RFC 9224 authoritative redirects) and ICANN discovery
        ordered.append(("RDAP.ORG", "https://rdap.org/domain/{query}"))
        ordered.append(("ICANN", "https://lookup.icann.org/api/rdap/domain/{query}"))
        return ordered

    def lookup_ip(self, ip_str: str) -> RdapRegistrationData:
        """Lookup IP registration / allocation intelligence (RFC 9082/9083)."""
        now_ts = datetime.now(timezone.utc).isoformat()
        clean_ip = ip_str.strip()
        if not clean_ip:
            return RdapRegistrationData(status="unavailable", query=ip_str, query_type="ip", lookup_timestamp=now_ts)

        endpoints = self.discover_endpoints_for_ip(clean_ip)
        last_error = None
        for rir_name, url_template in endpoints:
            url = url_template.format(query=clean_ip)
            status, raw, err = self._fetch_rdap_json(url)
            if status == "available" and isinstance(raw, dict):
                return self._parse_ip_rdap(clean_ip, rir_name, raw, now_ts)
            elif status == "not_found":
                last_error = err
                continue
            else:
                last_error = err

        return RdapRegistrationData(
            status="unavailable",
            query=clean_ip,
            query_type="ip",
            error_message=last_error,
            lookup_timestamp=now_ts,
        )

    def _parse_ip_rdap(self, ip_str: str, rir_name: str, data: Dict[str, Any], timestamp: str) -> RdapRegistrationData:
        network_name = data.get("name")
        handle = data.get("handle")
        cidr = None

        # Extract CIDR from IP version or cidr0_cidrs
        cidrs = data.get("cidr0_cidrs", [])
        if cidrs and isinstance(cidrs, list) and isinstance(cidrs[0], dict):
            prefix = cidrs[0].get("v4prefix") or cidrs[0].get("v6prefix")
            length = cidrs[0].get("length")
            if prefix and length is not None:
                cidr = f"{prefix}/{length}"

        if not cidr and data.get("startAddress") and data.get("endAddress"):
            cidr = f"{data.get('startAddress')} - {data.get('endAddress')}"

        # Extract events (creation/registration)
        creation_date = None
        for ev in data.get("events", []):
            if isinstance(ev, dict) and ev.get("eventAction") in ("registration", "allocated"):
                creation_date = ev.get("eventDate")
                break

        # Extract abuse contact
        abuse_email = None
        for ent in data.get("entities", []):
            if isinstance(ent, dict) and "abuse" in str(ent.get("roles", [])):
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if isinstance(prop, list) and prop and prop[0] == "email" and len(prop) >= 4:
                            abuse_email = str(prop[3])
                            break

        return RdapRegistrationData(
            status="available",
            query=ip_str,
            query_type="ip",
            rir=rir_name,
            network_name=network_name,
            cidr=cidr,
            handle=handle,
            creation_date=creation_date,
            abuse_contact_email=abuse_email,
            lookup_source="rdap_rir",
            lookup_timestamp=timestamp,
        )

    def lookup_domain(self, domain: str) -> RdapRegistrationData:
        """Lookup domain registration intelligence (RFC 9082/9083)."""
        now_ts = datetime.now(timezone.utc).isoformat()
        clean_domain = domain.strip().lower().rstrip(".")
        if not clean_domain:
            return RdapRegistrationData(status="unavailable", query=domain, query_type="domain", lookup_timestamp=now_ts)

        endpoints = self.discover_endpoints_for_domain(clean_domain)
        last_error = None
        for registry_name, url_template in endpoints:
            url = url_template.format(query=clean_domain)
            status, raw, err = self._fetch_rdap_json(url)
            if status == "available" and isinstance(raw, dict):
                return self._parse_domain_rdap(clean_domain, raw, now_ts)
            elif status == "not_found":
                return RdapRegistrationData(
                    status="not_found",
                    query=clean_domain,
                    query_type="domain",
                    error_message=err,
                    lookup_timestamp=now_ts,
                )
            else:
                last_error = err

        return RdapRegistrationData(
            status="unavailable",
            query=clean_domain,
            query_type="domain",
            error_message=last_error,
            lookup_timestamp=now_ts,
        )

    def _parse_domain_rdap(self, domain: str, data: Dict[str, Any], timestamp: str) -> RdapRegistrationData:
        registrar = None
        registrar_id = None
        creation_date = None
        expiration_date = None
        domain_age_days = None
        nameservers: List[str] = []
        abuse_email = None

        # 1. Registrar entity
        for ent in data.get("entities", []):
            if isinstance(ent, dict) and "registrar" in str(ent.get("roles", [])):
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if isinstance(prop, list) and prop and prop[0] == "fn" and len(prop) >= 4:
                            registrar = str(prop[3])
                for pub in ent.get("publicIds", []):
                    if isinstance(pub, dict) and pub.get("type") == "IANA Registrar ID":
                        registrar_id = str(pub.get("identifier"))
            # Abuse contact
            if isinstance(ent, dict) and "abuse" in str(ent.get("roles", [])):
                vcard = ent.get("vcardArray", [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if isinstance(prop, list) and prop and prop[0] == "email" and len(prop) >= 4:
                            abuse_email = str(prop[3])

        # 2. Events: registration & expiration
        for ev in data.get("events", []):
            if isinstance(ev, dict):
                action = ev.get("eventAction")
                dt_str = ev.get("eventDate")
                if action == "registration" and dt_str:
                    creation_date = dt_str
                    try:
                        clean_dt = dt_str.replace("Z", "+00:00")
                        c_dt = datetime.fromisoformat(clean_dt)
                        domain_age_days = max(0, (datetime.now(timezone.utc) - c_dt).days)
                    except (ValueError, TypeError):
                        pass
                elif action == "expiration" and dt_str:
                    expiration_date = dt_str

        # 3. Nameservers
        for ns in data.get("nameservers", []):
            if isinstance(ns, dict) and ns.get("ldhName"):
                nameservers.append(str(ns.get("ldhName")).lower())

        return RdapRegistrationData(
            status="available",
            query=domain,
            query_type="domain",
            registrar=registrar,
            registrar_id=registrar_id,
            creation_date=creation_date,
            expiration_date=expiration_date,
            domain_age_days=domain_age_days,
            nameservers=nameservers,
            abuse_contact_email=abuse_email,
            lookup_source="rdap_registry",
            lookup_timestamp=timestamp,
        )
