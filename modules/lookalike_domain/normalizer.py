"""Domain normalization and reference domain management for lookalike detection.

Module 2 (Layer 1): Deterministic domain canonicalization, IDN/Unicode handling,
subdomain preservation, and configurable reference domain loading.

Design Constraints:
- Pure deterministic logic using Python standard library.
- No network calls, DNS queries, WHOIS lookups, or ML dependencies.
- Extensible boundary for future similarity analysis and graph integration.
"""

from dataclasses import asdict, dataclass
import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import unicodedata

logger = logging.getLogger(__name__)

# RFC 1035 / RFC 1123 label constraints:
# Labels can contain lowercase alphanumeric characters and hyphens,
# but cannot start or end with a hyphen.
_LABEL_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")

# Default reference domains config location
_DEFAULT_REFERENCE_PATH = Path(__file__).resolve().parent / "reference_domains.json"


class DomainNormalizationError(ValueError):
    """Raised when a domain string or entity is invalid or cannot be normalized."""
    pass


@dataclass(frozen=True)
class NormalizedDomain:
    """Canonical representation of a domain.

    Preserves both raw input provenance and standardized forms (ASCII Punycode
    and Unicode) for downstream inspection by the similarity engine.
    """
    original: str
    normalized: str
    ascii_form: str
    unicode_form: str
    labels: Tuple[str, ...]
    is_idn: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert to standard dictionary representation."""
        return {
            "original": self.original,
            "normalized": self.normalized,
            "ascii_form": self.ascii_form,
            "unicode_form": self.unicode_form,
            "labels": list(self.labels),
            "is_idn": self.is_idn,
        }

    def __str__(self) -> str:
        return self.normalized


# =============================================================================
# Registrable Domain Handling & Public Suffix List (PSL) Architectural Boundary
# =============================================================================
# ARCHITECTURAL NOTE & DOCUMENTED LIMITATION:
# Accurately determining registrable domains (e.g. distinguishing
# 'login.paypal.com' -> 'paypal.com' vs 'example.co.uk' -> 'example.co.uk')
# strictly requires the ICANN Public Suffix List (PSL). Multi-part public suffixes
# like '.co.uk', '.com.au', or '.gov.uk' cannot be safely inferred via simple
# dot-count heuristics without producing false positives or incorrect parent splits.
#
# PER SPECIFICATION:
# A full external PSL dependency is intentionally NOT included in this layer.
# The normalizer preserves the full domain structure ('login.paypal.com') without
# lossy reduction. The helper below documents this boundary and provides an
# extensible entry point for future PSL-based resolvers.
# =============================================================================


@dataclass(frozen=True)
class RegistrableDomainInfo:
    """Structure for registrable domain decomposition.

    NOTE: Multi-part suffixes (e.g. .co.uk) require a PSL resolver to populate
    accurately. In this layer, the distinction between subdomains and root labels
    is preserved via the full labels tuple in NormalizedDomain.
    """
    full_domain: str
    registered_domain: Optional[str] = None
    subdomain: Optional[str] = None
    public_suffix: Optional[str] = None
    psl_verified: bool = False


def normalize_domain(domain_input: Union[str, Any]) -> NormalizedDomain:
    """Normalize a domain string or forensic entity to a canonical representation.

    Accepts:
        domain_input: Raw domain string or an object/Entity with a .value or
                      ['value'] attribute (such as Module 1's Entity(type='domain')).

    Performs:
        1. Entity unwrapping if an Entity or dict is passed.
        2. Whitespace stripping and lowercase canonicalization.
        3. Removal of a single trailing root dot ('.').
        4. Rejection of invalid inputs (empty, whitespace, URIs, emails, malformed dots).
        5. RFC 1035 label validation.
        6. IDN / Punycode conversion using standard library `idna` and `unicodedata`.
        7. Subdomain preservation (does NOT collapse subdomains into parent domains).

    Returns:
        NormalizedDomain dataclass with canonical ascii, unicode, and label representations.

    Raises:
        DomainNormalizationError: If input is None, empty, malformed, or unparseable.
    """
    # 1. Extract raw string from string or entity
    if domain_input is None:
        raise DomainNormalizationError("Domain input cannot be None.")

    # Handle Module 1 Entity object or dict with 'value'
    if hasattr(domain_input, "value") and hasattr(domain_input, "type"):
        if domain_input.type != "domain":
            raise DomainNormalizationError(
                f"Expected Entity of type 'domain', got '{domain_input.type}'"
            )
        raw_str = str(domain_input.value)
    elif isinstance(domain_input, dict) and "value" in domain_input:
        if domain_input.get("type", "domain") != "domain":
            raise DomainNormalizationError(
                f"Expected dict entity of type 'domain', got '{domain_input.get('type')}'"
            )
        raw_str = str(domain_input["value"])
    elif isinstance(domain_input, str):
        raw_str = domain_input
    else:
        raise DomainNormalizationError(
            f"Unsupported domain input type: {type(domain_input).__name__}. "
            "Expected str or Entity with type='domain'."
        )

    # 2. Strip surrounding whitespace
    cleaned = raw_str.strip()
    if not cleaned:
        raise DomainNormalizationError("Domain cannot be empty or whitespace-only.")

    # Check for obvious non-domain inputs (URL schemes, paths, email addresses, ports)
    if "://" in cleaned or "/" in cleaned or "\\" in cleaned:
        raise DomainNormalizationError(
            f"Invalid domain input '{raw_str}': contains URL scheme or path separator."
        )
    if "@" in cleaned:
        raise DomainNormalizationError(
            f"Invalid domain input '{raw_str}': contains '@' (email address format)."
        )
    if ":" in cleaned:
        raise DomainNormalizationError(
            f"Invalid domain input '{raw_str}': contains ':' (port or invalid character)."
        )
    if any(c in cleaned for c in (" ", "\t", "\n", "\r", "?", "#")):
        raise DomainNormalizationError(
            f"Invalid domain input '{raw_str}': contains whitespace or invalid characters."
        )

    # 3. Lowercase domain
    lowered = cleaned.lower()

    # 4. Remove one trailing root-domain dot if present
    if lowered.endswith("."):
        lowered = lowered[:-1]

    if not lowered:
        raise DomainNormalizationError("Domain is empty after stripping root dot.")

    # Reject leading dot or consecutive dots
    if lowered.startswith("."):
        raise DomainNormalizationError(
            f"Invalid domain '{raw_str}': cannot start with a dot."
        )
    if ".." in lowered:
        raise DomainNormalizationError(
            f"Invalid domain '{raw_str}': contains consecutive dots (empty label)."
        )

    # 5. Unicode normalization (NFC) and IDNA / Punycode conversion
    u_norm = unicodedata.normalize("NFC", lowered)

    try:
        # Standard library IDNA encoding produces ASCII punycode (A-label)
        ascii_form = u_norm.encode("idna").decode("ascii")
    except Exception as exc:
        raise DomainNormalizationError(
            f"Invalid domain '{raw_str}': IDNA encoding failed: {exc}"
        ) from exc

    try:
        # Decode back to Unicode (U-label)
        unicode_form = ascii_form.encode("ascii").decode("idna")
    except Exception:
        unicode_form = u_norm

    # 6. Validate labels (in ASCII form)
    labels = tuple(ascii_form.split("."))

    # An internet domain must consist of at least two labels (e.g. name + TLD)
    if len(labels) < 2:
        raise DomainNormalizationError(
            f"Invalid domain '{raw_str}': must have at least two labels (name and TLD)."
        )

    # Total domain length cannot exceed 253 characters (RFC 1035)
    if len(ascii_form) > 253:
        raise DomainNormalizationError(
            f"Invalid domain '{raw_str}': length exceeds 253 characters."
        )

    for label in labels:
        if not label:
            raise DomainNormalizationError(
                f"Invalid domain '{raw_str}': contains empty label."
            )
        if len(label) > 63:
            raise DomainNormalizationError(
                f"Invalid domain '{raw_str}': label '{label}' exceeds 63 characters."
            )
        if not _LABEL_REGEX.match(label):
            raise DomainNormalizationError(
                f"Invalid domain '{raw_str}': label '{label}' violates RFC 1035 naming rules."
            )

    # TLD cannot be purely numeric (RFC 1123 / ICANN rules)
    tld = labels[-1]
    if tld.isdigit():
        raise DomainNormalizationError(
            f"Invalid domain '{raw_str}': top-level domain cannot be all-numeric."
        )

    is_idn = (ascii_form != unicode_form) or any(lbl.startswith("xn--") for lbl in labels)

    # The canonical normalized form is the ASCII (A-label) lowercase representation,
    # ensuring consistent, RFC-compliant network format across all engines.
    normalized = ascii_form

    return NormalizedDomain(
        original=raw_str,
        normalized=normalized,
        ascii_form=ascii_form,
        unicode_form=unicode_form,
        labels=labels,
        is_idn=is_idn,
    )


def load_reference_domains(
    config_path: Optional[Union[str, Path]] = None,
    on_error: str = "raise",
) -> List[NormalizedDomain]:
    """Load, validate, normalize, and deduplicate reference domains from JSON.

    Args:
        config_path: Path to reference domains JSON file. Defaults to
                     bundled `reference_domains.json`.
        on_error: Behavior when encountering invalid domain entries:
                  'raise' raises DomainNormalizationError.
                  'skip' logs a warning and skips the entry.

    Returns:
        Deterministically sorted list of NormalizedDomain objects
        (ordered alphabetically by their canonical .normalized string).

    Raises:
        FileNotFoundError: If the specified configuration file does not exist.
        ValueError: If JSON schema is invalid or on_error mode is unknown.
        DomainNormalizationError: If an entry is invalid and on_error == 'raise'.
    """
    if on_error not in ("raise", "skip"):
        raise ValueError(f"Unknown on_error mode '{on_error}'. Must be 'raise' or 'skip'.")

    path = Path(config_path) if config_path is not None else _DEFAULT_REFERENCE_PATH

    if not path.is_file():
        raise FileNotFoundError(f"Reference domains configuration file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON in reference domains file '{path}': {exc}") from exc

    if not isinstance(data, dict) or "trusted_domains" not in data:
        raise ValueError(
            f"Invalid reference domains schema in '{path}': expected object with 'trusted_domains' array."
        )

    raw_list = data["trusted_domains"]
    if not isinstance(raw_list, list):
        raise ValueError(
            f"Invalid reference domains schema in '{path}': 'trusted_domains' must be a list."
        )

    normalized_map: Dict[str, NormalizedDomain] = {}

    for entry in raw_list:
        try:
            norm = normalize_domain(entry)
            # Deduplicate by canonical normalized representation
            if norm.normalized not in normalized_map:
                normalized_map[norm.normalized] = norm
        except DomainNormalizationError as err:
            if on_error == "raise":
                raise DomainNormalizationError(
                    f"Invalid reference domain entry '{entry}' in '{path}': {err}"
                ) from err
            logger.warning(
                "Skipping invalid reference domain entry '%s' in '%s': %s",
                entry,
                path,
                err,
            )

    # Return deterministically sorted list by canonical normalized domain string
    return sorted(normalized_map.values(), key=lambda d: d.normalized)


def create_domain_comparison_edge(
    observed: Union[NormalizedDomain, str],
    reference: Union[NormalizedDomain, str],
) -> Dict[str, Any]:
    """Create a graph-ready directed comparison edge between an observed domain and reference domain.

    Constructs a relationship compatible with Module 1's Relationship model:
        observed_domain --compared_with--> reference_domain

    Note: This does NOT emit a 'resembles' relationship, as similarity scoring
    is not performed in this layer.
    """
    obs_norm = observed.normalized if isinstance(observed, NormalizedDomain) else normalize_domain(observed).normalized
    ref_norm = reference.normalized if isinstance(reference, NormalizedDomain) else normalize_domain(reference).normalized

    return {
        "source": obs_norm,
        "relation": "compared_with",
        "target": ref_norm,
    }
