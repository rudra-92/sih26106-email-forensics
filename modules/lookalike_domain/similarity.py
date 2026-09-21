"""Similarity and candidate generation engine for lookalike domain detection.

Module 2 (Layer 2): Multi-signal similarity analysis, candidate generation,
and explainable forensic scoring.

Signals computed:
1. Damerau-Levenshtein edit distance & normalized edit similarity
2. Jaro-Winkler character-level similarity
3. Leetspeak / digit substitution detection (e.g. paypa1 -> paypal)
4. Character insertion and deletion detection (e.g. paypall, paypa -> paypal)
5. Character transposition detection (e.g. payapl -> paypal)
6. Token and label similarity (shared vs added tokens)
7. TLD variation detection (e.g. paypal.net vs paypal.com)
8. Prefix and suffix brand additions (e.g. paypal-login, secure-paypal)

Constraints:
- Pure deterministic logic using Python standard library.
- No network calls, DNS queries, WHOIS, or ML dependencies.
- Produces candidate investigation scores (0.0 to 1.0), NOT malicious verdicts.
"""

from dataclasses import asdict, dataclass
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from .normalizer import (
    NormalizedDomain,
    load_reference_domains,
    normalize_domain,
)

logger = logging.getLogger(__name__)

# Common leetspeak / homoglyphic digit substitutions
DIGIT_SUBSTITUTIONS = {
    "0": ["o"],
    "1": ["l", "i"],
    "3": ["e"],
    "4": ["a"],
    "5": ["s"],
    "8": ["b"],
}

# Reverse mapping: reference character to possible digit spoof
CHAR_TO_DIGIT_MAP = {
    "o": ["0"],
    "l": ["1"],
    "i": ["1"],
    "e": ["3"],
    "a": ["4"],
    "s": ["5"],
    "b": ["8"],
}


# =============================================================================
# Data Models
# =============================================================================


@dataclass(frozen=True)
class SimilaritySignals:
    """Structured forensic evidence signals computed between two domains."""
    raw_edit_distance: int
    edit_similarity: float
    character_similarity: float
    digit_substitution: Dict[str, Any]
    visual_substitution: Dict[str, Any]
    insertion_deletion: Dict[str, Any]
    transposition: Dict[str, Any]
    token_similarity: float
    shared_tokens: List[str]
    added_tokens: List[str]
    same_base_label: bool
    tld_changed: bool
    observed_tld: str
    reference_tld: str
    prefix_added: bool
    suffix_added: bool
    added_prefix: Optional[str]
    added_suffix: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CandidateResult:
    """Candidate similarity assessment result between an observed domain and reference domain.

    NOTE: The candidate_score (0.0 - 1.0) represents lexical and structural resemblance strength.
    It does NOT represent phishing probability, maliciousness, or attacker attribution.
    """
    observed_domain: str
    reference_domain: str
    candidate_score: float
    candidate: bool
    signals: SimilaritySignals
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observed_domain": self.observed_domain,
            "reference_domain": self.reference_domain,
            "candidate_score": self.candidate_score,
            "candidate": self.candidate,
            "signals": self.signals.to_dict(),
            "reason": self.reason,
        }


# =============================================================================
# Core Signal Extraction Algorithms (Pure Standard Library)
# =============================================================================


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Damerau-Levenshtein distance between two strings.

    Accounts for insertions, deletions, substitutions, and adjacent transpositions.
    """
    len1, len2 = len(s1), len(s2)
    if not s1:
        return len2
    if not s2:
        return len1

    # DP table: (len1 + 2) x (len2 + 2)
    max_dist = len1 + len2
    da: Dict[str, int] = {}

    # Initialize distance matrix
    h: List[List[int]] = [[0] * (len2 + 2) for _ in range(len1 + 2)]
    h[0][0] = max_dist

    for i in range(len1 + 1):
        h[i + 1][0] = max_dist
        h[i + 1][1] = i
    for j in range(len2 + 1):
        h[0][j + 1] = max_dist
        h[1][j + 1] = j

    for i in range(1, len1 + 1):
        db = 0
        for j in range(1, len2 + 1):
            k = da.get(s2[j - 1], 0)
            l = db
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            if cost == 0:
                db = j

            h[i + 1][j + 1] = min(
                h[i][j] + cost,        # substitution
                h[i + 1][j] + 1,       # insertion
                h[i][j + 1] + 1,       # deletion
                h[k][l] + (i - k - 1) + 1 + (j - l - 1),  # transposition
            )
        da[s1[i - 1]] = i

    return h[len1 + 1][len2 + 1]


def jaro_winkler_similarity(s1: str, s2: str, prefix_scaling: float = 0.1) -> float:
    """Compute the Jaro-Winkler character-level similarity (0.0 to 1.0).

    Jaro measures matching characters within a half-length window and transpositions.
    Winkler gives an additive bonus for common initial prefixes (up to 4 chars).
    """
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    if match_distance < 0:
        match_distance = 0

    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j]:
                continue
            if s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    # Count transpositions
    k = 0
    transpositions = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (
        (matches / len1) +
        (matches / len2) +
        ((matches - transpositions / 2) / matches)
    ) / 3.0

    # Common prefix length up to 4 characters
    prefix = 0
    for i in range(min(len1, len2, 4)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break

    return min(1.0, round(jaro + prefix * prefix_scaling * (1.0 - jaro), 4))


def detect_digit_substitution(obs: str, ref: str) -> Dict[str, Any]:
    """Detect digit-for-letter substitutions (e.g. 1 -> l/i, 0 -> o)."""
    changes: List[Dict[str, Any]] = []

    # Check same-length alignment
    if len(obs) == len(ref):
        for idx, (c_obs, c_ref) in enumerate(zip(obs, ref)):
            if c_obs != c_ref and c_obs.isdigit():
                valid_replacements = DIGIT_SUBSTITUTIONS.get(c_obs, [])
                if c_ref in valid_replacements:
                    changes.append({
                        "position": idx,
                        "observed": c_obs,
                        "reference": c_ref,
                    })

    return {
        "detected": len(changes) > 0,
        "changes": changes,
    }


def detect_insertion_deletion(obs: str, ref: str) -> Dict[str, Any]:
    """Detect single character insertions or deletions."""
    len_obs, len_ref = len(obs), len(ref)

    # 1. Single insertion: obs has one extra character
    if len_obs == len_ref + 1:
        # Find position where characters differ
        i = 0
        while i < len_ref and obs[i] == ref[i]:
            i += 1
        # Remainder should match
        if obs[i + 1:] == ref[i:]:
            return {
                "detected": True,
                "operation": "insertion",
                "character": obs[i],
                "position": i,
            }

    # 2. Single deletion: obs has one character missing
    elif len_obs == len_ref - 1:
        i = 0
        while i < len_obs and obs[i] == ref[i]:
            i += 1
        # Remainder should match
        if obs[i:] == ref[i + 1:]:
            return {
                "detected": True,
                "operation": "deletion",
                "character": ref[i],
                "position": i,
            }

    return {
        "detected": False,
        "operation": None,
        "character": None,
        "position": None,
    }


def detect_transposition(obs: str, ref: str) -> Dict[str, Any]:
    """Detect single adjacent character swaps (e.g. payapl vs paypal)."""
    if len(obs) != len(ref):
        return {
            "detected": False,
            "positions": None,
            "characters": None,
        }

    diffs = [i for i, (c1, c2) in enumerate(zip(obs, ref)) if c1 != c2]
    if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
        i, j = diffs[0], diffs[1]
        if obs[i] == ref[j] and obs[j] == ref[i]:
            return {
                "detected": True,
                "positions": [i, j],
                "characters": [obs[i], obs[j]],
            }

    return {
        "detected": False,
        "positions": None,
        "characters": None,
    }


def analyze_tokens_and_affixes(obs_base: str, ref_base: str) -> Dict[str, Any]:
    """Analyze token overlap and prefix/suffix brand additions."""
    obs_tokens = [t for t in obs_base.replace("-", " ").replace(".", " ").split() if t]
    ref_tokens = [t for t in ref_base.replace("-", " ").replace(".", " ").split() if t]

    obs_set = set(obs_tokens)
    ref_set = set(ref_tokens)

    shared = sorted(list(obs_set & ref_set))
    added = sorted(list(obs_set - ref_set))

    # Token Jaccard similarity
    union = obs_set | ref_set
    token_sim = len(shared) / max(len(union), 1) if union else 0.0

    # Prefix / suffix detection
    prefix_added = False
    suffix_added = False
    added_prefix = None
    added_suffix = None

    # Check hyphenated and unhyphenated prefix/suffix (e.g. secure-paypal, paypal-login, hdfc-bank vs hdfcbank)
    obs_unhyphen = obs_base.replace("-", "")
    ref_unhyphen = ref_base.replace("-", "")

    if ref_base in obs_base and ref_base != obs_base:
        if obs_base.startswith(ref_base + "-") or obs_base.startswith(ref_base):
            suffix_added = True
            added_suffix = obs_base[len(ref_base):].lstrip("-")
        elif obs_base.endswith("-" + ref_base) or obs_base.endswith(ref_base):
            prefix_added = True
            added_prefix = obs_base[:-len(ref_base)].rstrip("-")
    elif ref_unhyphen in obs_unhyphen and ref_unhyphen != obs_unhyphen:
        if obs_unhyphen.startswith(ref_unhyphen):
            suffix_added = True
            added_suffix = obs_unhyphen[len(ref_unhyphen):]
        elif obs_unhyphen.endswith(ref_unhyphen):
            prefix_added = True
            added_prefix = obs_unhyphen[:-len(ref_unhyphen)]

    return {
        "token_similarity": round(token_sim, 4),
        "shared_tokens": shared,
        "added_tokens": added,
        "prefix_added": prefix_added,
        "suffix_added": suffix_added,
        "added_prefix": added_prefix,
        "added_suffix": added_suffix,
    }


# =============================================================================
# Signal Aggregator & Explainable Scoring
# =============================================================================


VISUAL_DIGRAPH_MAP = {
    "rn": "m",
    "vv": "w",
    "cl": "d",
    "nn": "m",
}


def detect_visual_substitution(obs: str, ref: str) -> Dict[str, Any]:
    """Detect visual digraph confusables (e.g. 'rn' for 'm' as in arnazon -> amazon)."""
    for dg, single in VISUAL_DIGRAPH_MAP.items():
        if dg in obs and obs.replace(dg, single) == ref:
            idx = obs.find(dg)
            return {
                "detected": True,
                "observed": dg,
                "reference": single,
                "position": idx,
            }
    return {
        "detected": False,
        "observed": None,
        "reference": None,
        "position": None,
    }


def extract_signals(
    obs_norm: NormalizedDomain,
    ref_norm: NormalizedDomain,
) -> SimilaritySignals:
    """Extract all individual forensic similarity signals between observed and reference domains."""
    obs_labels = obs_norm.labels
    ref_labels = ref_norm.labels

    # Base brand label (second-level domain or primary label)
    obs_base = obs_labels[-2] if len(obs_labels) >= 2 else obs_labels[0]
    ref_base = ref_labels[-2] if len(ref_labels) >= 2 else ref_labels[0]

    obs_tld = obs_labels[-1] if len(obs_labels) >= 2 else ""
    ref_tld = ref_labels[-1] if len(ref_labels) >= 2 else ""

    same_base = (obs_base == ref_base)
    tld_changed = (obs_tld != ref_tld)

    # 1. Edit distance on base label
    raw_edit = damerau_levenshtein_distance(obs_base, ref_base)
    max_len = max(len(obs_base), len(ref_base), 1)
    edit_sim = round(max(0.0, 1.0 - (raw_edit / max_len)), 4)

    # 2. Character similarity (Jaro-Winkler)
    char_sim = jaro_winkler_similarity(obs_base, ref_base)

    # 3. Digit substitution
    digit_sub = detect_digit_substitution(obs_base, ref_base)

    # 4. Visual digraph substitution
    visual_sub = detect_visual_substitution(obs_base, ref_base)

    # 5. Insertion / deletion
    ins_del = detect_insertion_deletion(obs_base, ref_base)

    # 6. Transposition
    trans = detect_transposition(obs_base, ref_base)

    # 7. Tokens & Affixes
    token_analysis = analyze_tokens_and_affixes(obs_base, ref_base)

    return SimilaritySignals(
        raw_edit_distance=raw_edit,
        edit_similarity=edit_sim,
        character_similarity=char_sim,
        digit_substitution=digit_sub,
        visual_substitution=visual_sub,
        insertion_deletion=ins_del,
        transposition=trans,
        token_similarity=token_analysis["token_similarity"],
        shared_tokens=token_analysis["shared_tokens"],
        added_tokens=token_analysis["added_tokens"],
        same_base_label=same_base,
        tld_changed=tld_changed,
        observed_tld=obs_tld,
        reference_tld=ref_tld,
        prefix_added=token_analysis["prefix_added"],
        suffix_added=token_analysis["suffix_added"],
        added_prefix=token_analysis["added_prefix"],
        added_suffix=token_analysis["added_suffix"],
    )


def compute_candidate_score(
    signals: SimilaritySignals,
    obs_norm: NormalizedDomain,
    ref_norm: NormalizedDomain,
) -> Tuple[float, str]:
    """Calculate the explainable candidate similarity score (0.0 to 1.0) and forensic explanation.

    Scoring Logic & Weighting Architecture:
    ---------------------------------------
    The score quantifies morphological resemblance strength without claiming attack probability:
    1. Exact Match: score = 1.0
    2. Base Lexical Similarity (60% combined):
       - 30% Edit Similarity: Measures minimal edit operations on base brand label.
       - 30% Jaro-Winkler Character Similarity: Measures character match density and prefix alignment.
    3. Mutation Pattern Adjustments (additive, up to +35%):
       - +25% Digit Substitution: e.g. '0' for 'o', '1' for 'l'/'i' (leetspeak).
       - +20% Character Transposition: e.g. 'payapl' vs 'paypal' (typosquatting).
       - +20% Single Insertion/Deletion: e.g. 'paypall' or 'paypa' vs 'paypal'.
       - +35% TLD Variation on identical base: e.g. 'paypal.net' vs 'paypal.com' -> fixed high base score (0.85).
       - +30% Compound brand affix: e.g. 'paypal-login.com' where reference is intact as prefix/suffix.
    4. Anti-Inflation Constraint:
       A single metric (e.g. edit distance on short 2-character strings) cannot inflate the score
       without corroborating character or structural alignment.
    """
    if obs_norm.normalized == ref_norm.normalized:
        return 1.0, "Identical domain match."

    # Case A: Same base brand label, different TLD
    if signals.same_base_label and signals.tld_changed:
        score = 0.85
        reason = (
            f"Identical base brand name '{obs_norm.labels[-2]}' with TLD variation "
            f"('.{signals.observed_tld}' vs '.{signals.reference_tld}')."
        )
        return round(score, 4), reason

    # Base weighted lexical component
    base_lexical = 0.50 * signals.edit_similarity + 0.50 * signals.character_similarity
    bonus = 0.0
    reasons: List[str] = []

    # Case B: Digit substitution
    if signals.digit_substitution["detected"]:
        num_changes = len(signals.digit_substitution["changes"])
        bonus += min(0.40, 0.25 + 0.10 * (num_changes - 1))
        change_desc = ", ".join(
            f"'{c['observed']}' for '{c['reference']}' at pos {c['position']}"
            for c in signals.digit_substitution["changes"]
        )
        reasons.append(f"digit substitution detected ({change_desc})")

    # Case C: Visual digraph substitution (e.g. 'rn' for 'm')
    if signals.visual_substitution["detected"]:
        bonus += 0.25
        obs_dg = signals.visual_substitution["observed"]
        ref_dg = signals.visual_substitution["reference"]
        reasons.append(f"visual confusable digraph '{obs_dg}' for '{ref_dg}'")

    # Case C: Adjacent transposition
    if signals.transposition["detected"]:
        bonus += 0.20
        chars = signals.transposition["characters"]
        reasons.append(f"transposed adjacent characters '{chars[0]}' and '{chars[1]}'")

    # Case D: Single insertion or deletion
    if signals.insertion_deletion["detected"]:
        bonus += 0.20
        op = signals.insertion_deletion["operation"]
        char = signals.insertion_deletion["character"]
        pos = signals.insertion_deletion["position"]
        reasons.append(f"single character {op} of '{char}' at position {pos}")

    # Case E: Affix addition (prefix/suffix on brand)
    if signals.prefix_added or signals.suffix_added:
        ref_b = ref_norm.labels[-2]
        obs_b = obs_norm.labels[-2]
        if (ref_b in signals.shared_tokens or
            ref_b in obs_b or
            ref_b.replace("-", "") in obs_b.replace("-", "")):
            affix_desc = f"prefix '{signals.added_prefix}'" if signals.prefix_added else f"suffix '{signals.added_suffix}'"
            bonus += 0.35
            base_lexical = max(base_lexical, 0.70)
            reasons.append(f"brand container with added {affix_desc}")

    # Combine base lexical + structural bonus, bounded to [0.0, 1.0]
    raw_score = (base_lexical * 0.70) + bonus
    score = min(1.0, max(0.0, raw_score))

    # Formulate human-readable forensic explanation
    if reasons:
        reason_summary = "; ".join(reasons)
        reason = (
            f"Resemblance driven by {reason_summary} (edit distance: {signals.raw_edit_distance}, "
            f"character similarity: {signals.character_similarity:.2f})."
        )
    elif score >= 0.70:
        reason = (
            f"High lexical similarity (edit distance: {signals.raw_edit_distance}, "
            f"character similarity: {signals.character_similarity:.2f})."
        )
    else:
        reason = (
            f"Low lexical resemblance (edit distance: {signals.raw_edit_distance}, "
            f"character similarity: {signals.character_similarity:.2f})."
        )

    return round(score, 4), reason


# =============================================================================
# Pre-filtering & Multi-Reference Comparison Engine
# =============================================================================


def _quick_prefilter(obs_norm: NormalizedDomain, ref_norm: NormalizedDomain) -> bool:
    """Lightweight deterministic filter to bypass expensive signal extraction for unrelated pairs.

    Returns True if the pair should be evaluated, False if it can be safely skipped.
    """
    obs_base = obs_norm.labels[-2] if len(obs_norm.labels) >= 2 else obs_norm.labels[0]
    ref_base = ref_norm.labels[-2] if len(ref_norm.labels) >= 2 else ref_norm.labels[0]

    # Always compare if lengths are close (within 4 characters)
    len_diff = abs(len(obs_base) - len(ref_base))
    if len_diff <= 4:
        return True

    # If reference base is contained in observed base (e.g. prefix/suffix brand attachment)
    if ref_base in obs_base or obs_base in ref_base:
        return True

    # If they share common 2-grams
    if len(obs_base) >= 2 and len(ref_base) >= 2:
        obs_bigrams = {obs_base[i:i+2] for i in range(len(obs_base) - 1)}
        ref_bigrams = {ref_base[i:i+2] for i in range(len(ref_base) - 1)}
        if len(obs_bigrams & ref_bigrams) >= 2:
            return True

    return False


def compute_domain_similarity(
    observed: Union[str, NormalizedDomain, Any],
    reference: Union[str, NormalizedDomain, Any],
    threshold: float = 0.80,
) -> CandidateResult:
    """Compute forensic similarity signals and candidate status between two domains.

    Args:
        observed: Raw string, NormalizedDomain, or Module 1 Entity.
        reference: Raw string, NormalizedDomain, or Module 1 Entity.
        threshold: Candidate investigation threshold (default: 0.80).

    Returns:
        CandidateResult containing individual signals, score, candidate flag, and explanation.
    """
    obs_norm = observed if isinstance(observed, NormalizedDomain) else normalize_domain(observed)
    ref_norm = reference if isinstance(reference, NormalizedDomain) else normalize_domain(reference)

    signals = extract_signals(obs_norm, ref_norm)
    score, reason = compute_candidate_score(signals, obs_norm, ref_norm)

    is_candidate = (score >= threshold)

    return CandidateResult(
        observed_domain=obs_norm.normalized,
        reference_domain=ref_norm.normalized,
        candidate_score=score,
        candidate=is_candidate,
        signals=signals,
        reason=reason,
    )


def find_similarity_candidates(
    observed: Union[str, NormalizedDomain, Any],
    reference_domains: Optional[Iterable[Union[str, NormalizedDomain]]] = None,
    threshold: float = 0.80,
    limit: Optional[int] = None,
    prefilter: bool = True,
    return_all: bool = False,
) -> List[CandidateResult]:
    """Compare an observed domain against a collection of reference domains and return ranked candidates.

    Args:
        observed: Observed domain string, NormalizedDomain, or Module 1 forensic Entity.
        reference_domains: Collection of reference domains. Defaults to bundled reference_domains.json.
        threshold: Candidate investigation threshold (default: 0.80).
        limit: Optional maximum number of candidates to return.
        prefilter: If True, uses lightweight deterministic pre-filtering to skip distant pairs.
        return_all: If True, returns all scored pairs regardless of threshold (useful for evaluation).

    Returns:
        List of CandidateResult objects ranked in descending order of candidate_score.
    """
    obs_norm = observed if isinstance(observed, NormalizedDomain) else normalize_domain(observed)

    if reference_domains is None:
        refs = load_reference_domains()
    else:
        refs = [
            r if isinstance(r, NormalizedDomain) else normalize_domain(r)
            for r in reference_domains
        ]

    results: List[CandidateResult] = []

    for ref in refs:
        # Pre-filtering optimization for multi-reference comparison
        if prefilter and not _quick_prefilter(obs_norm, ref):
            continue

        cand = compute_domain_similarity(obs_norm, ref, threshold=threshold)

        if return_all or cand.candidate:
            results.append(cand)

    # Rank by candidate_score descending; break ties deterministically by reference_domain name
    ranked = sorted(results, key=lambda c: (-c.candidate_score, c.reference_domain))

    if limit is not None and limit > 0:
        return ranked[:limit]
    return ranked
