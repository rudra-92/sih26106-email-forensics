"""Cross-case and temporal correlation engine for Module 6.

Correlates forensic entities across historical cases to detect recurring infrastructure,
reused attachments, shared domains, and temporal clustering.

STRICT ATTRIBUTION GUARDRAILS:
- Never claims common attacker ownership solely from infrastructure or hash reuse.
- Employs bounded forensic phrasing: 'recurring infrastructure observed' or 'possible campaign relationship'.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .models import CampaignCluster, CorrelatedEntity


def parse_iso_or_utc(ts_str: Optional[str]) -> Optional[datetime]:
    """Safely parse an ISO or common email UTC timestamp."""
    if not ts_str:
        return None
    try:
        # Handle ISO format
        clean = ts_str.strip().replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


class CrossCaseCorrelator:
    """Manages historical forensic cases and correlates multi-case entity recurrences."""

    INDEXABLE_TYPES = ("ip", "asn", "domain", "url", "hash", "email_address", "infrastructure")

    def __init__(self) -> None:
        # In-memory historical case records: list of case dicts
        self._historical_cases: List[Dict[str, Any]] = []
        self._counter = 1

    def _next_id(self) -> str:
        cid = f"CLUSTER-{self._counter:04d}"
        self._counter += 1
        return cid

    def add_case(self, case_record: Dict[str, Any]) -> None:
        """Register a completed case record in the cross-case correlation store."""
        # Ensure we don't add duplicate cases
        cid = case_record.get("case_id")
        if cid:
            self._historical_cases = [c for c in self._historical_cases if c.get("case_id") != cid]
        self._historical_cases.append(case_record)

    def correlate_case(
        self,
        current_case_id: str,
        current_entities: List[CorrelatedEntity],
        current_timestamp: Optional[str] = None,
    ) -> List[CampaignCluster]:
        """Correlate entities in the current case against historical cases."""
        if not self._historical_cases:
            return []

        clusters: List[CampaignCluster] = []

        # Index current entities by type
        curr_by_type: Dict[str, Set[str]] = {}
        for ent in current_entities:
            if ent.type in self.INDEXABLE_TYPES and ent.value:
                curr_by_type.setdefault(ent.type, set()).add(ent.value)

        curr_dt = parse_iso_or_utc(current_timestamp)

        # Iterate over historical cases
        for hist in self._historical_cases:
            h_id = hist.get("case_id", "unknown_case")
            if h_id == current_case_id:
                continue

            h_dt = parse_iso_or_utc(hist.get("timestamp", hist.get("first_seen")))
            time_delta: Optional[float] = None
            if curr_dt and h_dt:
                time_delta = abs((curr_dt - h_dt).total_seconds())

            # Check for shared entities
            hist_entities = hist.get("entities", [])
            shared: List[Dict[str, str]] = []

            for h_ent in hist_entities:
                h_type = h_ent.get("type") if isinstance(h_ent, dict) else getattr(h_ent, "type", None)
                h_val = h_ent.get("value") if isinstance(h_ent, dict) else getattr(h_ent, "value", None)

                if h_type in curr_by_type and h_val in curr_by_type[h_type]:
                    entry = {"type": h_type, "value": h_val}
                    if entry not in shared:
                        shared.append(entry)

            if not shared:
                continue

            # Determine cluster type and description
            shared_types = {s["type"] for s in shared}
            shared_vals = [s["value"] for s in shared]

            cluster_type = "possible_campaign_cluster"
            if shared_types == {"hash"}:
                cluster_type = "reused_attachment"
                desc = f"Identical attachment hash '{shared_vals[0][:12]}...' observed across cases {current_case_id} and {h_id}."
            elif shared_types == {"domain"}:
                cluster_type = "reused_domain_infrastructure"
                desc = f"Shared domain infrastructure '{shared_vals[0]}' observed across cases {current_case_id} and {h_id}."
            elif "ip" in shared_types or "asn" in shared_types:
                cluster_type = "recurring_infrastructure"
                desc = f"Recurring network infrastructure observed across cases {current_case_id} and {h_id} (shared: {', '.join(shared_vals[:3])})."
            else:
                desc = f"Multiple shared entities ({', '.join(shared_vals[:3])}) indicate a possible campaign relationship."

            # Calculate first and last seen
            timestamps = [t for t in [current_timestamp, hist.get("timestamp")] if t]
            f_seen = min(timestamps) if timestamps else None
            l_seen = max(timestamps) if timestamps else None

            clusters.append(
                CampaignCluster(
                    cluster_id=self._next_id(),
                    cluster_type=cluster_type,
                    shared_entities=shared,
                    case_ids=[h_id, current_case_id],
                    occurrence_count=len(shared) + 1,
                    first_seen=f_seen,
                    last_seen=l_seen,
                    inter_case_time_delta_seconds=time_delta,
                    description=desc,
                )
            )

        return clusters
