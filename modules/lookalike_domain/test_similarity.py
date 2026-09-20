"""Unit tests for Module 2 Layer 2: Similarity and Candidate Generation.

Tests:
- Obvious lookalike detection (paypa1.com, micros0ft.com, g00gle.com, arnazon.com)
- Distinct mutation types (substitution, digit substitution, insertion, deletion, transposition, prefix, suffix, TLD variation)
- Negative controls and unrelated domains (example.com vs microsoft.com, google.com vs paypal.com)
- Hard negatives (company-security.com vs company.com)
- Multi-reference ranking and candidate thresholding
- Determinism across repeated executions
- Module 1 forensic Entity compatibility
- Synthetic evaluation fixture coverage
"""

import unittest

from modules.lookalike_domain import (
    CandidateResult,
    SimilaritySignals,
    compute_domain_similarity,
    damerau_levenshtein_distance,
    find_similarity_candidates,
    generate_synthetic_variants,
    jaro_winkler_similarity,
    load_reference_domains,
    normalize_domain,
)
from modules.sender_identity.models import Entity


class TestAlgorithmPrimitives(unittest.TestCase):
    """Test algorithmic primitives (Damerau-Levenshtein, Jaro-Winkler)."""

    def test_damerau_levenshtein(self):
        self.assertEqual(damerau_levenshtein_distance("", "test"), 4)
        self.assertEqual(damerau_levenshtein_distance("paypal", "paypal"), 0)
        self.assertEqual(damerau_levenshtein_distance("paypal", "paypa1"), 1)  # substitution
        self.assertEqual(damerau_levenshtein_distance("paypal", "payapl"), 1)  # transposition
        self.assertEqual(damerau_levenshtein_distance("paypal", "paypa"), 1)   # deletion
        self.assertEqual(damerau_levenshtein_distance("paypal", "paypall"), 1) # insertion

    def test_jaro_winkler(self):
        self.assertEqual(jaro_winkler_similarity("paypal", "paypal"), 1.0)
        self.assertEqual(jaro_winkler_similarity("", "test"), 0.0)
        sim = jaro_winkler_similarity("paypal", "paypa1")
        self.assertGreater(sim, 0.85)


class TestObviousLookalikes(unittest.TestCase):
    """Test detection of classic, obvious brand spoofing mutations."""

    def test_paypa1_lookalike(self):
        res = compute_domain_similarity("paypa1.com", "paypal.com", threshold=0.80)
        self.assertTrue(res.candidate)
        self.assertGreaterEqual(res.candidate_score, 0.80)
        self.assertTrue(res.signals.digit_substitution["detected"])
        self.assertEqual(res.signals.digit_substitution["changes"][0]["observed"], "1")
        self.assertEqual(res.signals.digit_substitution["changes"][0]["reference"], "l")
        self.assertIn("digit substitution", res.reason)

    def test_micros0ft_lookalike(self):
        res = compute_domain_similarity("micros0ft.com", "microsoft.com", threshold=0.80)
        self.assertTrue(res.candidate)
        self.assertGreaterEqual(res.candidate_score, 0.80)
        self.assertTrue(res.signals.digit_substitution["detected"])
        self.assertEqual(res.signals.digit_substitution["changes"][0]["observed"], "0")
        self.assertEqual(res.signals.digit_substitution["changes"][0]["reference"], "o")

    def test_g00gle_lookalike(self):
        res = compute_domain_similarity("g00gle.com", "google.com", threshold=0.80)
        self.assertTrue(res.candidate)
        self.assertGreaterEqual(res.candidate_score, 0.80)
        self.assertTrue(res.signals.digit_substitution["detected"])
        self.assertEqual(len(res.signals.digit_substitution["changes"]), 2)

    def test_arnazon_lookalike(self):
        # 'rn' -> 'm' visual confusable
        res = compute_domain_similarity("arnazon.com", "amazon.com", threshold=0.80)
        self.assertTrue(res.candidate)
        self.assertGreaterEqual(res.candidate_score, 0.80)
        self.assertEqual(res.signals.raw_edit_distance, 2)
        self.assertTrue(res.signals.visual_substitution["detected"])


class TestMutationTypes(unittest.TestCase):
    """Test isolated forensic signals across distinct mutation types."""

    def test_character_substitution(self):
        res = compute_domain_similarity("paypel.com", "paypal.com")
        self.assertEqual(res.signals.raw_edit_distance, 1)
        self.assertGreater(res.signals.edit_similarity, 0.80)

    def test_digit_substitution(self):
        res = compute_domain_similarity("paypa1.com", "paypal.com")
        self.assertTrue(res.signals.digit_substitution["detected"])
        self.assertEqual(res.signals.digit_substitution["changes"][0]["position"], 5)

    def test_single_insertion(self):
        res = compute_domain_similarity("paypall.com", "paypal.com")
        self.assertTrue(res.signals.insertion_deletion["detected"])
        self.assertEqual(res.signals.insertion_deletion["operation"], "insertion")
        self.assertEqual(res.signals.insertion_deletion["character"], "l")
        self.assertEqual(res.signals.insertion_deletion["position"], 6)

    def test_single_deletion(self):
        res = compute_domain_similarity("paypa.com", "paypal.com")
        self.assertTrue(res.signals.insertion_deletion["detected"])
        self.assertEqual(res.signals.insertion_deletion["operation"], "deletion")
        self.assertEqual(res.signals.insertion_deletion["character"], "l")
        self.assertEqual(res.signals.insertion_deletion["position"], 5)

    def test_transposition(self):
        res = compute_domain_similarity("payapl.com", "paypal.com")
        self.assertTrue(res.signals.transposition["detected"])
        self.assertEqual(res.signals.transposition["characters"], ["a", "p"])
        self.assertIn("transposed", res.reason)

    def test_prefix_addition(self):
        res = compute_domain_similarity("secure-paypal.com", "paypal.com")
        self.assertTrue(res.signals.prefix_added)
        self.assertEqual(res.signals.added_prefix, "secure")
        self.assertIn("paypal", res.signals.shared_tokens)

    def test_suffix_addition(self):
        res = compute_domain_similarity("paypal-login.com", "paypal.com")
        self.assertTrue(res.signals.suffix_added)
        self.assertEqual(res.signals.added_suffix, "login")
        self.assertIn("paypal", res.signals.shared_tokens)

    def test_tld_variation(self):
        res = compute_domain_similarity("paypal.net", "paypal.com")
        self.assertTrue(res.signals.same_base_label)
        self.assertTrue(res.signals.tld_changed)
        self.assertEqual(res.signals.observed_tld, "net")
        self.assertEqual(res.signals.reference_tld, "com")
        self.assertEqual(res.candidate_score, 0.85)
        self.assertIn("TLD variation", res.reason)


class TestUnrelatedAndNegativeControls(unittest.TestCase):
    """Verify that unrelated domains produce low candidate scores and are excluded."""

    def test_unrelated_domains(self):
        res = compute_domain_similarity("example.com", "microsoft.com", threshold=0.80)
        self.assertFalse(res.candidate)
        self.assertLess(res.candidate_score, 0.50)

    def test_cross_brand_negative(self):
        res = compute_domain_similarity("google.com", "paypal.com", threshold=0.80)
        self.assertFalse(res.candidate)
        self.assertLess(res.candidate_score, 0.50)

    def test_hard_negative_evidence_not_malicious_verdict(self):
        # company-security.com shares token 'security' or structure with company.com
        res = compute_domain_similarity("company-security.com", "company.com", threshold=0.80)
        # Verify result is structured evidence, not a claim of attack
        self.assertIsInstance(res.candidate_score, float)
        self.assertNotIn("phishing", res.reason.lower())
        self.assertNotIn("malicious", res.reason.lower())


class TestMultiReferenceRanking(unittest.TestCase):
    """Verify candidate ranking across a collection of reference domains."""

    def test_ranking_closest_domain(self):
        observed = "paypa1.com"
        refs = ["paypal.com", "microsoft.com", "google.com"]

        candidates = find_similarity_candidates(
            observed=observed,
            reference_domains=refs,
            threshold=0.80,
            prefilter=False,
        )

        # Only paypal.com should exceed 0.80
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].reference_domain, "paypal.com")
        self.assertGreater(candidates[0].candidate_score, 0.80)

    def test_return_all_mode_ranks_descending(self):
        observed = "paypa1.com"
        refs = ["google.com", "paypal.com", "microsoft.com"]

        all_results = find_similarity_candidates(
            observed=observed,
            reference_domains=refs,
            threshold=0.80,
            return_all=True,
            prefilter=False,
        )

        self.assertEqual(len(all_results), 3)
        self.assertEqual(all_results[0].reference_domain, "paypal.com")
        self.assertGreater(all_results[0].candidate_score, all_results[1].candidate_score)
        self.assertGreaterEqual(all_results[1].candidate_score, all_results[2].candidate_score)

    def test_full_dataset_candidate_search(self):
        # Search against all ~160 loaded reference domains
        candidates = find_similarity_candidates(
            observed="micros0ft.com",
            threshold=0.80,
        )
        self.assertGreaterEqual(len(candidates), 1)
        self.assertEqual(candidates[0].reference_domain, "microsoft.com")
        self.assertGreaterEqual(candidates[0].candidate_score, 0.85)


class TestCandidateThreshold(unittest.TestCase):
    """Test configurable threshold sensitivity."""

    def test_strict_threshold_excludes_weaker_matches(self):
        # A weaker mutation with threshold 0.95 vs 0.70
        res_low = find_similarity_candidates("paypa1.com", ["paypal.com"], threshold=0.70)
        self.assertEqual(len(res_low), 1)

        res_ultra_strict = find_similarity_candidates("paypa1.com", ["paypal.com"], threshold=0.99)
        self.assertEqual(len(res_ultra_strict), 0)


class TestDeterminism(unittest.TestCase):
    """Verify that repeated comparisons produce identical outputs."""

    def test_repeated_scoring_identity(self):
        run1 = compute_domain_similarity("micros0ft.com", "microsoft.com")
        run2 = compute_domain_similarity("micros0ft.com", "microsoft.com")

        self.assertEqual(run1.candidate_score, run2.candidate_score)
        self.assertEqual(run1.candidate, run2.candidate)
        self.assertEqual(run1.reason, run2.reason)
        self.assertEqual(run1.signals.to_dict(), run2.signals.to_dict())


class TestModule1EntityIntegration(unittest.TestCase):
    """Test consuming Module 1 forensic Entity object."""

    def test_consume_entity_input(self):
        entity = Entity(
            type="domain",
            value="Billing.Paypa1.Com.",
            source="From",
        )
        candidates = find_similarity_candidates(
            observed=entity,
            reference_domains=["paypal.com", "microsoft.com"],
            threshold=0.80,
        )
        self.assertGreaterEqual(len(candidates), 1)
        self.assertEqual(candidates[0].reference_domain, "paypal.com")


class TestSyntheticEvaluationFixture(unittest.TestCase):
    """Test synthetic evaluation variants generation."""

    def test_generate_variants(self):
        variants = generate_synthetic_variants(["paypal.com"])
        self.assertGreater(len(variants), 5)
        types = {v.mutation_type for v in variants}
        self.assertIn("digit_substitution", types)
        self.assertIn("substitution", types)
        self.assertIn("insertion", types)
        self.assertIn("deletion", types)
        self.assertIn("transposition", types)
        self.assertIn("prefix_addition", types)
        self.assertIn("suffix_addition", types)
        self.assertIn("tld_variation", types)


if __name__ == "__main__":
    unittest.main()
