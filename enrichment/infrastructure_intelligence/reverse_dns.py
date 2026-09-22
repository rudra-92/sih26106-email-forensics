"""Reverse DNS (PTR) resolution and Forward-Confirmed Reverse DNS (FCrDNS) verification.

FCrDNS checks whether the PTR hostname for an IP address resolves back to the same IP.
Mismatches are treated as contextual routing observations, NOT definitive proof of spoofing.
"""

from __future__ import annotations

from datetime import datetime, timezone
import socket
from typing import Any, Dict, List, Optional, Tuple

from .models import ReverseDnsData


def resolve_reverse_dns(
    ip_str: str,
    helo_name: Optional[str] = None,
    timeout: float = 2.0,
) -> Tuple[ReverseDnsData, List[Dict[str, Any]]]:
    """Perform PTR lookup, forward-confirmed resolution (FCrDNS), and HELO comparison."""
    now_ts = datetime.now(timezone.utc).isoformat()
    clean_ip = ip_str.strip()
    observations: List[Dict[str, Any]] = []

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, aliases, _ = socket.gethostbyaddr(clean_ip)
        ptr_hosts = [host] + list(aliases)
    except socket.herror:
        # Host name not found
        socket.setdefaulttimeout(old_timeout)
        return (
            ReverseDnsData(
                status="not_found",
                query_ip=clean_ip,
                ptr_hostnames=[],
                fcrdns_valid=None,
                helo_ptr_match=None,
                lookup_timestamp=now_ts,
            ),
            observations,
        )
    except (socket.timeout, OSError) as e:
        socket.setdefaulttimeout(old_timeout)
        return (
            ReverseDnsData(
                status="unavailable",
                query_ip=clean_ip,
                error_message=str(e),
                lookup_timestamp=now_ts,
            ),
            observations,
        )
    finally:
        socket.setdefaulttimeout(old_timeout)

    # 2. Forward-confirm the primary PTR hostname
    primary_ptr = ptr_hosts[0]
    forward_ips: List[str] = []
    fcrdns_valid: Optional[bool] = None

    socket.setdefaulttimeout(timeout)
    try:
        addr_info = socket.getaddrinfo(primary_ptr, None)
        forward_ips = list({str(info[4][0]) for info in addr_info if info and len(info) >= 5 and info[4]})
        fcrdns_valid = clean_ip in forward_ips
    except (socket.gaierror, socket.timeout, OSError):
        fcrdns_valid = None
    finally:
        socket.setdefaulttimeout(old_timeout)

    # 3. HELO comparison if provided
    helo_ptr_match: Optional[bool] = None
    if helo_name:
        clean_helo = helo_name.strip().lower().rstrip(".")
        clean_ptr = primary_ptr.strip().lower().rstrip(".")
        helo_ptr_match = (clean_helo == clean_ptr) or clean_ptr.endswith(f".{clean_helo}")

    # 4. Contextual observation if FCrDNS is invalid (mismatched)
    if fcrdns_valid is False:
        observations.append(
            {
                "rule_id": "RULE-ORIGIN-FCRDNS-MISMATCH",
                "severity": "medium",
                "trust_state": "observed",
                "description": (
                    f"Forward-Confirmed Reverse DNS (FCrDNS) mismatch for peer IP '{clean_ip}': "
                    f"PTR hostname '{primary_ptr}' resolves forward to {forward_ips}, which does not include the IP. "
                    f"(Contextual routing observation, not proof of spoofing)."
                ),
                "evidence": {
                    "ip": clean_ip,
                    "ptr_hostname": primary_ptr,
                    "forward_ips": forward_ips,
                    "fcrdns_valid": False,
                },
            }
        )

    res_data = ReverseDnsData(
        status="available",
        query_ip=clean_ip,
        ptr_hostnames=ptr_hosts,
        fcrdns_valid=fcrdns_valid,
        helo_ptr_match=helo_ptr_match,
        forward_ips=forward_ips,
        lookup_timestamp=now_ts,
    )

    return res_data, observations
