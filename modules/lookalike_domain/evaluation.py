"""Synthetic evaluation fixture generator for lookalike domain detection.

Generates controlled variants (substitutions, digit substitutions, insertions,
deletions, transpositions, prefixes, suffixes, TLD swaps) and hard negatives
from reference domains for rigorous evaluation of similarity signals.

NOTE: This is an evaluation tool, NOT a training dataset. No statistical accuracy
claims or ML models are implied.
"""

from dataclasses import dataclass
from typing import List, Optional

from .normalizer import normalize_domain


@dataclass(frozen=True)
class SyntheticVariant:
    """A synthetic domain variant generated for evaluation."""
    reference_domain: str
    variant_domain: str
    mutation_type: str
    expected_signal: str
    description: str


def generate_synthetic_variants(
    target_domains: Optional[List[str]] = None,
) -> List[SyntheticVariant]:
    """Generate a diverse, controlled set of synthetic lookalike variants and hard negatives.

    Covers:
    - Single character substitution
    - Digit substitution (leetspeak)
    - Insertion (typosquatting)
    - Deletion (omission)
    - Transposition (adjacent swap)
    - Prefix addition (brand attachment)
    - Suffix addition (brand attachment)
    - TLD variation
    - Hard negatives (legitimate-looking compound names or unrelated controls)
    """
    if target_domains is None:
        targets = ["paypal.com", "microsoft.com", "google.com", "amazon.com"]
    else:
        targets = target_domains

    variants: List[SyntheticVariant] = []

    for ref in targets:
        norm = normalize_domain(ref)
        base = norm.labels[-2]
        tld = norm.labels[-1]

        # 1. Digit substitution
        digit_swaps = {
            "paypal": ("paypa1", "digit_substitution", "1 for l at position 5"),
            "microsoft": ("micros0ft", "digit_substitution", "0 for o at position 6"),
            "google": ("g00gle", "digit_substitution", "0 for o at positions 1 and 2"),
            "amazon": ("amaz0n", "digit_substitution", "0 for o at position 4"),
        }
        if base in digit_swaps:
            var_base, m_type, desc = digit_swaps[base]
            variants.append(SyntheticVariant(
                reference_domain=ref,
                variant_domain=f"{var_base}.{tld}",
                mutation_type=m_type,
                expected_signal="digit_substitution",
                description=desc,
            ))

        # 2. Single-character substitution (letter-for-letter)
        if len(base) >= 4:
            # Replace character at index 1 with 'q'
            sub_base = base[0] + ("q" if base[1] != "q" else "z") + base[2:]
            variants.append(SyntheticVariant(
                reference_domain=ref,
                variant_domain=f"{sub_base}.{tld}",
                mutation_type="substitution",
                expected_signal="edit_distance",
                description=f"substituted character at position 1 in '{base}'",
            ))

        # 3. Insertion (e.g. repeated character)
        ins_base = base + base[-1]
        variants.append(SyntheticVariant(
            reference_domain=ref,
            variant_domain=f"{ins_base}.{tld}",
            mutation_type="insertion",
            expected_signal="insertion_deletion",
            description=f"inserted duplicate character at end of '{base}'",
        ))

        # 4. Deletion (e.g. missing character)
        if len(base) >= 4:
            del_base = base[:-1]
            variants.append(SyntheticVariant(
                reference_domain=ref,
                variant_domain=f"{del_base}.{tld}",
                mutation_type="deletion",
                expected_signal="insertion_deletion",
                description=f"deleted final character of '{base}'",
            ))

        # 5. Transposition (swap adjacent characters at index 2 and 3)
        if len(base) >= 4 and base[2] != base[3]:
            trans_base = base[:2] + base[3] + base[2] + base[4:]
            variants.append(SyntheticVariant(
                reference_domain=ref,
                variant_domain=f"{trans_base}.{tld}",
                mutation_type="transposition",
                expected_signal="transposition",
                description=f"transposed characters at index 2 and 3 in '{base}'",
            ))

        # 6. Prefix addition
        variants.append(SyntheticVariant(
            reference_domain=ref,
            variant_domain=f"secure-{base}.{tld}",
            mutation_type="prefix_addition",
            expected_signal="prefix_added",
            description=f"added prefix 'secure-' to '{base}'",
        ))

        # 7. Suffix addition
        variants.append(SyntheticVariant(
            reference_domain=ref,
            variant_domain=f"{base}-login.{tld}",
            mutation_type="suffix_addition",
            expected_signal="suffix_added",
            description=f"added suffix '-login' to '{base}'",
        ))

        # 8. TLD variation
        alt_tld = "net" if tld == "com" else "com"
        variants.append(SyntheticVariant(
            reference_domain=ref,
            variant_domain=f"{base}.{alt_tld}",
            mutation_type="tld_variation",
            expected_signal="tld_changed",
            description=f"swapped TLD from '.{tld}' to '.{alt_tld}'",
        ))

    # 9. Hard Negatives (legitimate multi-token or non-brand domains)
    hard_negatives = [
        SyntheticVariant(
            reference_domain="example.com",
            variant_domain="example-corporate-security.com",
            mutation_type="hard_negative",
            expected_signal="token_similarity",
            description="compound domain with shared common word",
        ),
        SyntheticVariant(
            reference_domain="microsoft.com",
            variant_domain="linux-foundation.org",
            mutation_type="unrelated_negative",
            expected_signal="none",
            description="completely unrelated domain control",
        ),
        SyntheticVariant(
            reference_domain="paypal.com",
            variant_domain="google.com",
            mutation_type="unrelated_negative",
            expected_signal="none",
            description="cross-brand negative control",
        ),
    ]
    variants.extend(hard_negatives)

    return variants
