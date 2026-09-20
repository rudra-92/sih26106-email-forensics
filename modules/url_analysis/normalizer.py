"""URL normalization and component decomposition.

Parses URLs into standardized components:
- scheme
- hostname
- port (default vs non-default)
- path
- query & query parameters
- fragment
- username & password (userinfo)
- IP address detection (IPv4 / IPv6)
- Integration with Module 2 Domain Normalizer
"""

import ipaddress
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

from modules.lookalike_domain.normalizer import (
    DomainNormalizationError,
    NormalizedDomain,
    normalize_domain,
)

from .models import NormalizedUrl

# Default standard ports for web protocols
DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
}


def is_ip_address(host: str) -> bool:
    """Check whether a host string is a valid IPv4 or IPv6 address."""
    if not host:
        return False
    clean = host.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def normalize_url(raw_url: str) -> NormalizedUrl:
    """Decompose and canonicalize a raw URL into structured components.

    Performs:
    1. Scheme lowercasing.
    2. Hostname lowercasing & IPv4/IPv6 detection.
    3. Port extraction (identifying explicit vs default).
    4. Path standardization (defaulting empty paths to '/').
    5. Query parsing into parameters.
    6. Extraction of userinfo (username/password) to detect obfuscation.
    7. Integration with Module 2's Domain Normalizer for canonical domain representation.

    Args:
        raw_url: Raw URL string.

    Returns:
        NormalizedUrl containing all parsed components.
    """
    cleaned = raw_url.strip()

    # Prepend scheme if missing (e.g. "example.com/login")
    if not cleaned.startswith(("http://", "https://", "ftp://")) and "://" not in cleaned:
        cleaned_with_scheme = "http://" + cleaned
    else:
        cleaned_with_scheme = cleaned

    try:
        split = urlsplit(cleaned_with_scheme)
    except Exception:
        # Fallback for malformed URLs
        split = urlsplit("http://malformed.invalid/")

    scheme = (split.scheme or "http").lower()
    raw_host = split.hostname or ""
    hostname = raw_host.lower()

    # Port extraction
    port = split.port
    is_ip = is_ip_address(hostname)

    # Path normalization
    path = split.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    query = split.query or ""
    query_params = parse_qs(query, keep_blank_values=True)
    fragment = split.fragment or ""
    username = split.username
    password = split.password

    # Module 2 Domain Normalization integration
    normalized_dom: Optional[NormalizedDomain] = None
    if hostname and not is_ip:
        try:
            normalized_dom = normalize_domain(hostname)
            # Use canonical normalized ASCII domain for consistency
            hostname = normalized_dom.normalized
        except DomainNormalizationError:
            normalized_dom = None

    # Reconstruct canonical normalized URL string
    netloc_parts = []
    if username or password:
        userinfo = username or ""
        if password:
            userinfo += f":{password}"
        netloc_parts.append(f"{userinfo}@")

    netloc_parts.append(hostname)
    if port and port != DEFAULT_PORTS.get(scheme):
        netloc_parts.append(f":{port}")

    norm_netloc = "".join(netloc_parts)
    normalized_url_str = urlunsplit((scheme, norm_netloc, path, query, fragment))

    return NormalizedUrl(
        raw_url=raw_url,
        normalized_url=normalized_url_str,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=query,
        query_params=query_params,
        fragment=fragment,
        username=username,
        password=password,
        netloc=norm_netloc,
        is_ip=is_ip,
        normalized_domain=normalized_dom,
    )
