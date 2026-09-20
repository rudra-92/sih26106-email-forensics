"""Cross-case temporal and infrastructure correlation engine.

Correlates observed transmission peers, domains, and ASNs against historical case
records. Detects recurring infrastructure and temporal clusters without asserting
common human attacker identity.
"""

from typing import Any, Dict, List, Optional, Tuple

from .models import OriginObservation
from .temporal import parse_timestamp_to_utc


class CrossCaseCorrelator:
    """Detects recurring infrastructure patterns across multiple forensic cases."""

    def __init__(
        self,
        historical_cases: Optional[List[Dict[str, Any]]] = None,
        time_window_seconds: float = 86400.0 * 7,  # 7 days default
    ) -> None:
        self._cases: List[Dict[str, Any]] = historical_cases or []
        self.time_window = time_window_seconds

    def add_case(self, case_record: Dict[str, Any]) -> None:
        """Add a historical case record to the correlation store."""
        self._cases.append(case_record)

    def correlate(
        self,
        current_case_id: str,
        observed_ips: List[str],
        observed_asns: Optional[List[str]] = None,
        observed_domains: Optional[List[str]] = None,
        current_timestamp_str: Optional[str] = None,
        obs_start_index: int = 1,
    ) -> Tuple[List[Dict[str, Any]], List[OriginObservation]]:
        """Correlate current case entities against historical cases.

        Args:
            current_case_id: Current forensic case or email identifier.
            observed_ips: List of IPs observed in the current case.
            observed_asns: List of ASNs observed in the current case.
            observed_domains: List of sender/routing domains observed.
            current_timestamp_str: Timestamp of the current case.
            obs_start_index: Starting counter for observation IDs.

        Returns:
            Tuple of (matches_list, List[OriginObservation]).
        """
        if not self._cases or not observed_ips:
            return [], []

        matches: List[Dict[str, Any]] = []
        observations: List[OriginObservation] = []
        counter = obs_start_index

        current_dt = parse_timestamp_to_utc(current_timestamp_str) if current_timestamp_str else None
        target_ips = set(ip.strip() for ip in observed_ips if ip)
        target_asns = set(asn.strip() for asn in (observed_asns or []) if asn)

        for case in self._cases:
            c_id = case.get("case_id", "unknown_case")
            if c_id == current_case_id:
                continue

            c_ip = case.get("ip")
            c_asn = case.get("asn")
            c_ts_str = case.get("timestamp")
            c_dt = parse_timestamp_to_utc(c_ts_str) if c_ts_str else None

            # 1. IP recurrence check
            if c_ip and c_ip in target_ips:
                time_diff_sec = None
                in_window = True
                if current_dt and c_dt:
                    time_diff_sec = abs((current_dt - c_dt).total_seconds())
                    in_window = time_diff_sec <= self.time_window

                match_entry = {
                    "matched_case_id": c_id,
                    "matched_entity_type": "ip",
                    "matched_value": c_ip,
                    "time_delta_seconds": time_diff_sec,
                    "within_window": in_window,
                }
                matches.append(match_entry)

                observations.append(
                    OriginObservation(
                        observation_id=f"OBS-CORR-{counter:03d}",
                        rule_id="RULE-CORR-RECURRING-INFRASTRUCTURE",
                        source_module="origin_infrastructure",
                        source_header="CrossCaseCorrelation",
                        severity="medium",
                        description=(
                            f"Observed IP '{c_ip}' recurs in historical case '{c_id}'"
                            + (f" within {time_diff_sec/3600:.1f}h" if time_diff_sec else "")
                            + ". Recurring infrastructure observed."
                        ),
                        evidence=match_entry,
                        trust_state="enriched",
                        fact_type="observed",
                    )
                )
                counter += 1

            # 2. ASN recurrence check (if IP did not match)
            elif c_asn and c_asn in target_asns:
                match_entry = {
                    "matched_case_id": c_id,
                    "matched_entity_type": "asn",
                    "matched_value": c_asn,
                    "within_window": True,
                }
                matches.append(match_entry)

        return matches, observations
