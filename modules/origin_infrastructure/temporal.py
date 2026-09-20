"""Temporal analysis engine for Origin & Infrastructure Reconstruction.

Normalizes transport timestamps to UTC, evaluates chronological consistency
across sequential transmission hops, measures transit delays, calculates Date-to-Received
discrepancies, and emits structured forensic observations for negative intervals,
excessive delays, future timestamps, and clock skews.
"""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Optional, Tuple

from .models import (
    OriginObservation,
    ReconstructedHop,
    TemporalAnalysisResult,
)


def parse_timestamp_to_utc(ts_str: Optional[str]) -> Optional[datetime]:
    """Parse an RFC 2822 / 5322 date-time string and convert to UTC datetime."""
    if not ts_str:
        return None
    try:
        dt = parsedate_to_datetime(ts_str.strip())
        if dt.tzinfo is None:
            # Assume UTC if tzinfo is absent
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


class TemporalAnalyzer:
    """Forensic temporal analyzer for email relay chains."""

    def __init__(
        self,
        excessive_delay_threshold_seconds: float = 3600.0,  # 1 hour
        date_received_gap_threshold_seconds: float = 86400.0,  # 24 hours
        reference_time: Optional[datetime] = None,
    ) -> None:
        self.excessive_delay_threshold = excessive_delay_threshold_seconds
        self.date_received_gap_threshold = date_received_gap_threshold_seconds
        self._reference_time = reference_time

    def analyze(
        self,
        hops: List[ReconstructedHop],
        date_header_str: Optional[str] = None,
        obs_start_index: int = 1,
        reference_time: Optional[datetime] = None,
    ) -> Tuple[List[ReconstructedHop], TemporalAnalysisResult, List[OriginObservation]]:
        """Perform complete temporal analysis across reconstructed hops.

        Args:
            hops: List of ReconstructedHop objects ordered from earliest (1) to latest (N).
            date_header_str: Raw Date header string from the email message.
            obs_start_index: Starting counter index for generated observation IDs.
            reference_time: Optional override for analysis reference time.

        Returns:
            Tuple of (updated_hops_with_utc, TemporalAnalysisResult, List[OriginObservation]).
        """
        now_utc = reference_time or self._reference_time or datetime.now(timezone.utc).replace(microsecond=0)
        updated_hops: List[ReconstructedHop] = []
        parsed_datetimes: List[Optional[datetime]] = []
        observations: List[OriginObservation] = []
        counter = obs_start_index

        # 1. Parse each hop timestamp to UTC
        malformed_count = 0
        future_count = 0

        for hop in hops:
            utc_dt = parse_timestamp_to_utc(hop.timestamp_raw)
            parsed_datetimes.append(utc_dt)
            iso_utc = utc_dt.isoformat() if utc_dt else None

            if hop.timestamp_raw and utc_dt is None:
                malformed_count += 1
                observations.append(
                    OriginObservation(
                        observation_id=f"OBS-TIME-{counter:03d}",
                        rule_id="RULE-TIME-MALFORMED",
                        source_module="origin_infrastructure",
                        source_header=f"Received (Hop {hop.hop_sequence_num})",
                        severity="low",
                        description=(
                            f"Hop {hop.hop_sequence_num} contains unparseable timestamp "
                            f"'{hop.timestamp_raw}'."
                        ),
                        evidence={
                            "hop_sequence": hop.hop_sequence_num,
                            "raw_timestamp": hop.timestamp_raw,
                        },
                        trust_state="observed",
                        fact_type="observed",
                    )
                )
                counter += 1
            elif utc_dt and utc_dt > now_utc:
                future_count += 1
                observations.append(
                    OriginObservation(
                        observation_id=f"OBS-TIME-{counter:03d}",
                        rule_id="RULE-TIME-FUTURE",
                        source_module="origin_infrastructure",
                        source_header=f"Received (Hop {hop.hop_sequence_num})",
                        severity="medium",
                        description=(
                            f"Hop {hop.hop_sequence_num} timestamp ({iso_utc}) appears "
                            f"in the future relative to reference time ({now_utc.isoformat()})."
                        ),
                        evidence={
                            "hop_sequence": hop.hop_sequence_num,
                            "timestamp_utc": iso_utc,
                            "reference_time": now_utc.isoformat(),
                        },
                        trust_state="observed",
                        fact_type="observed",
                    )
                )
                counter += 1

            # Create updated hop with timestamp_utc populated
            updated_hops.append(
                ReconstructedHop(
                    hop_sequence_num=hop.hop_sequence_num,
                    original_header_index=hop.original_header_index,
                    source_host=hop.source_host,
                    source_ip=hop.source_ip,
                    receiver_host=hop.receiver_host,
                    receiver_ip=hop.receiver_ip,
                    timestamp_raw=hop.timestamp_raw,
                    timestamp_utc=iso_utc,
                    protocol=hop.protocol,
                    is_source_private=hop.is_source_private,
                    is_receiver_private=hop.is_receiver_private,
                    trust_state=hop.trust_state,
                    direction=hop.direction,
                )
            )

        # 2. Calculate consecutive hop delays
        hop_delays: List[Optional[float]] = []
        negative_intervals = 0
        abnormal_delays = 0
        possible_clock_skew = False

        for i in range(len(parsed_datetimes) - 1):
            t_curr = parsed_datetimes[i]
            t_next = parsed_datetimes[i + 1]

            if t_curr is not None and t_next is not None:
                delay = (t_next - t_curr).total_seconds()
                hop_delays.append(delay)

                if delay < 0:
                    negative_intervals += 1
                    # If the negative interval is within -120 seconds, flag as possible clock skew
                    if -120.0 <= delay < 0:
                        possible_clock_skew = True

                    observations.append(
                        OriginObservation(
                            observation_id=f"OBS-TIME-{counter:03d}",
                            rule_id="RULE-TIME-NEGATIVE-HOP",
                            source_module="origin_infrastructure",
                            source_header=f"Received (Hop {i + 1} -> {i + 2})",
                            severity="medium",
                            description=(
                                f"Negative transport interval ({delay:.1f}s) between hop {i + 1} "
                                f"({t_curr.isoformat()}) and hop {i + 2} ({t_next.isoformat()}). "
                                "Later hop occurred before earlier hop."
                            ),
                            evidence={
                                "earlier_hop": i + 1,
                                "later_hop": i + 2,
                                "interval_seconds": delay,
                                "earlier_time": t_curr.isoformat(),
                                "later_time": t_next.isoformat(),
                            },
                            trust_state="inferred",
                            fact_type="inferred",
                        )
                    )
                    counter += 1
                elif delay > self.excessive_delay_threshold:
                    abnormal_delays += 1
                    observations.append(
                        OriginObservation(
                            observation_id=f"OBS-TIME-{counter:03d}",
                            rule_id="RULE-TIME-EXCESSIVE-DELAY",
                            source_module="origin_infrastructure",
                            source_header=f"Received (Hop {i + 1} -> {i + 2})",
                            severity="low",
                            description=(
                                f"Excessive relay transit delay ({delay:.1f}s) between hop {i + 1} "
                                f"and hop {i + 2} (threshold: {self.excessive_delay_threshold:.0f}s). "
                                "Recorded as contextual anomaly indicator."
                            ),
                            evidence={
                                "earlier_hop": i + 1,
                                "later_hop": i + 2,
                                "delay_seconds": delay,
                                "threshold": self.excessive_delay_threshold,
                            },
                            trust_state="inferred",
                            fact_type="inferred",
                        )
                    )
                    counter += 1
            else:
                hop_delays.append(None)

        # 3. Overall chronology consistency check
        chronology_consistent = (negative_intervals == 0) and (malformed_count == 0)
        if negative_intervals >= 2:
            observations.append(
                OriginObservation(
                    observation_id=f"OBS-TIME-{counter:03d}",
                    rule_id="RULE-TIME-CHRONOLOGY-INCONSISTENCY",
                    source_module="origin_infrastructure",
                    source_header="Received",
                    severity="medium",
                    description=(
                        f"Multiple negative intervals ({negative_intervals}) indicate an "
                        "internally inconsistent transport route."
                    ),
                    evidence={"negative_intervals": negative_intervals},
                    trust_state="inferred",
                    fact_type="inferred",
                )
            )
            counter += 1

        # 4. Total transit time calculation
        valid_dts = [dt for dt in parsed_datetimes if dt is not None]
        total_transit_seconds = None
        if len(valid_dts) >= 2:
            total_transit_seconds = (valid_dts[-1] - valid_dts[0]).total_seconds()

        # 5. Date header vs first reliable Received timestamp
        date_dt = parse_timestamp_to_utc(date_header_str)
        date_to_first_gap = None
        if date_dt is not None and valid_dts:
            first_received_dt = valid_dts[0]
            date_to_first_gap = (first_received_dt - date_dt).total_seconds()

            if abs(date_to_first_gap) > self.date_received_gap_threshold:
                observations.append(
                    OriginObservation(
                        observation_id=f"OBS-TIME-{counter:03d}",
                        rule_id="RULE-TIME-DATE-RECEIVED-GAP",
                        source_module="origin_infrastructure",
                        source_header="Date / Received",
                        severity="low",
                        description=(
                            f"Significant time difference ({abs(date_to_first_gap):.1f}s) between declared "
                            f"Date header ({date_dt.isoformat()}) and earliest Received hop ({first_received_dt.isoformat()})."
                        ),
                        evidence={
                            "date_header": date_header_str,
                            "date_utc": date_dt.isoformat(),
                            "first_received_utc": first_received_dt.isoformat(),
                            "gap_seconds": date_to_first_gap,
                            "threshold": self.date_received_gap_threshold,
                        },
                        trust_state="observed",
                        fact_type="observed",
                    )
                )
                counter += 1

        result = TemporalAnalysisResult(
            chronology_consistent=chronology_consistent,
            negative_intervals=negative_intervals,
            abnormal_delays=abnormal_delays,
            hop_delays_seconds=hop_delays,
            total_transit_seconds=total_transit_seconds,
            date_to_first_received_seconds=date_to_first_gap,
            future_timestamps=future_count,
            malformed_timestamps=malformed_count,
            possible_clock_skew=possible_clock_skew,
            details={
                "excessive_delay_threshold": self.excessive_delay_threshold,
                "date_received_gap_threshold": self.date_received_gap_threshold,
            },
        )

        return updated_hops, result, observations
