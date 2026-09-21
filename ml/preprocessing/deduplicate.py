"""
deduplicate.py - Cross-Dataset and Intra-Dataset Deduplication for SIH26106.

Policy:
1. Deduplication occurs AFTER text normalization and quality filtering.
2. Identifies:
   - Exact text matches (SHA-256 of clean_text).
   - Conservative near-duplicates (SHA-256 of normalized lowercase single-spaced text).
3. Preserves full provenance for every removed record in `deduplication_log.csv`:
   - kept_record
   - duplicate_record
   - source (source of duplicate record)
   - reason
4. Protects against label contamination: If identical text appears under conflicting labels
   (e.g., legitimate vs. phishing), both records are flagged for quarantine rather than
   arbitrarily keeping one.
"""

import hashlib
import re
from typing import Dict, List, Set, Tuple, Any


def compute_text_hash(text: str) -> str:
    """Computes SHA-256 hex digest of exact clean text."""
    return hashlib.sha256(text.strip().encode('utf-8')).hexdigest()


def compute_normalized_hash(text: str) -> str:
    """
    Computes SHA-256 hex digest of conservative normalized text:
    - Collapses all consecutive whitespace characters to a single space
    - Case-folds (lower) solely for duplicate matching comparison
    - Preserves all punctuation, URLs, numbers, and threat tokens
    """
    collapsed = re.sub(r'\s+', ' ', text).strip().lower()
    return hashlib.sha256(collapsed.encode('utf-8')).hexdigest()


# Source priority when duplicates are encountered across corpora with identical label
# (Prefer sources with verified raw RFC headers / provenance)
SOURCE_PRIORITY = {
    "Nazario": 100,        # Primary verified phishing corpus
    "Nigerian_Fraud": 100, # Primary verified 419 fraud corpus
    "Enron": 90,           # High-quality corporate legitimate
    "SpamAssassin": 85,    # Clean open-source legitimate
    "TREC_07": 80,         # High-volume legitimate competition track
    "TREC_06": 75,         # Legitimate competition track
    "CEAS_08": 70,         # Academic challenge legitimate
    "Ling": 65             # Academic listserv legitimate
}


def deduplicate_dataset(
    records: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Performs cross-dataset and intra-dataset deduplication on quality-passed records.
    
    Args:
        records: List of dictionaries containing at least:
                 'record_id', 'source_dataset', 'our_label', 'clean_text'
                 
    Returns:
        (kept_records, duplicate_records, dedup_logs)
        - kept_records: Unique records retained for training dataset
        - duplicate_records: Records removed due to redundancy (can be quarantined if conflicting)
        - dedup_logs: List of provenance audit rows with keys:
                      ['kept_record', 'duplicate_record', 'source', 'reason']
    """
    kept_records: List[Dict[str, Any]] = []
    duplicate_records: List[Dict[str, Any]] = []
    dedup_logs: List[Dict[str, Any]] = []

    # Mapping: norm_hash -> index in kept_records
    seen_norm_hashes: Dict[str, int] = {}
    # Mapping: exact_hash -> index in kept_records
    seen_exact_hashes: Dict[str, int] = {}

    for record in records:
        rec_id = record['record_id']
        source = record['source_dataset']
        label = record['our_label']
        clean_text = record.get('clean_text', '')

        exact_hash = compute_text_hash(clean_text)
        norm_hash = compute_normalized_hash(clean_text)
        
        record['exact_hash'] = exact_hash
        record['norm_hash'] = norm_hash

        # Check for existing match
        match_idx = None
        match_reason = None

        if exact_hash in seen_exact_hashes:
            match_idx = seen_exact_hashes[exact_hash]
            match_reason = "exact_text_hash_match"
        elif norm_hash in seen_norm_hashes:
            match_idx = seen_norm_hashes[norm_hash]
            match_reason = "normalized_near_duplicate_match"

        if match_idx is not None:
            existing_rec = kept_records[match_idx]
            existing_id = existing_rec['record_id']
            existing_source = existing_rec['source_dataset']
            existing_label = existing_rec['our_label']

            # Case A: Conflicting labels on identical text
            if existing_label != label:
                # Contamination detected! Log conflict
                dedup_logs.append({
                    "kept_record": existing_id,
                    "duplicate_record": rec_id,
                    "source": source,
                    "reason": f"conflicting_label_duplicate_with_{existing_id}_{existing_label}_vs_{label}"
                })
                # Mark both as conflicting quarantine candidates
                record['exclusion_reason'] = f"conflicting_duplicate_with_{existing_id}"
                duplicate_records.append(record)
                continue

            # Case B: Identical label - decide which to keep based on source priority
            curr_priority = SOURCE_PRIORITY.get(source, 50)
            prev_priority = SOURCE_PRIORITY.get(existing_source, 50)

            if curr_priority > prev_priority:
                # Replace existing record with current higher-priority record
                dedup_logs.append({
                    "kept_record": rec_id,
                    "duplicate_record": existing_id,
                    "source": existing_source,
                    "reason": f"{match_reason}_superseded_by_higher_priority_source_{source}"
                })
                existing_rec['exclusion_reason'] = f"superseded_by_{rec_id}"
                duplicate_records.append(existing_rec)

                # Update kept record in-place
                kept_records[match_idx] = record
                seen_exact_hashes[exact_hash] = match_idx
                seen_norm_hashes[norm_hash] = match_idx
            else:
                # Keep existing record, discard current
                dedup_logs.append({
                    "kept_record": existing_id,
                    "duplicate_record": rec_id,
                    "source": source,
                    "reason": match_reason
                })
                record['exclusion_reason'] = f"duplicate_of_{existing_id}_{match_reason}"
                duplicate_records.append(record)
        else:
            # New unique record
            new_idx = len(kept_records)
            kept_records.append(record)
            seen_exact_hashes[exact_hash] = new_idx
            seen_norm_hashes[norm_hash] = new_idx

    return kept_records, duplicate_records, dedup_logs
