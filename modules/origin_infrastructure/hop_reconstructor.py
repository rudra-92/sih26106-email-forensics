"""Hop reconstruction engine for Origin & Infrastructure Reconstruction Engine.

Reconstructs the normalized, sequential transmission path of an email from
the inverted stack of Received headers. Assigns canonical sequence numbers
(1 = earliest sender-side hop, N = final receiving hop) while preserving original
header positions, IP roles, and trust states.
"""

from typing import List, Optional, Set, Union

from .models import ParsedReceivedHop, ReconstructedHop


class HopReconstructor:
    """Reconstructs transmission path sequence and trust boundaries from parsed hops."""

    def __init__(
        self,
        trusted_gateways: Optional[Union[List[str], Set[str]]] = None,
    ) -> None:
        self.trusted_gateways: Set[str] = (
            {g.strip().lower() for g in trusted_gateways if g}
            if trusted_gateways
            else set()
        )

    def reconstruct(
        self,
        parsed_hops: List[ParsedReceivedHop],
        trusted_gateways: Optional[Union[List[str], Set[str]]] = None,
    ) -> List[ReconstructedHop]:
        """Reconstruct the transmission path in chronological transport order (earliest to latest).

        In SMTP, each receiving MTA prepends its Received header at the top.
        Therefore:
        - parsed_hops[0] is the final receiver hop (closest to recipient).
        - parsed_hops[-1] is the earliest recorded hop (closest to origin).

        Reconstructed sequence numbers start at 1 for the earliest hop and increase
        to N for the final receiver hop.

        Trust Semantics:
        - Parsed hops from an email are 'observed' by default.
        - A hop is marked 'trusted_configured' only if its receiving host or IP
          explicitly matches a configured trusted gateway.
        - Receiving hops are never marked 'verified' merely for being the topmost header.

        Args:
            parsed_hops: List of ParsedReceivedHop objects in original header order.
            trusted_gateways: Optional set/list of hostnames or IPs of trusted gateways.

        Returns:
            List of ReconstructedHop objects ordered from earliest (1) to latest (N).
        """
        if not parsed_hops:
            return []

        effective_trusted: Set[str] = set(self.trusted_gateways)
        if trusted_gateways:
            effective_trusted.update(g.strip().lower() for g in trusted_gateways if g)

        reconstructed: List[ReconstructedHop] = []

        # Iterate in reverse header order (from bottom of header stack to top)
        for seq_num, hop in enumerate(reversed(parsed_hops), start=1):
            pf = hop.parsed_fields

            # Trust state resolution:
            is_configured_trust = False
            if effective_trusted:
                by_h = (pf.by_host or "").lower()
                by_ip = (pf.by_ip or "").lower()
                if (by_h and by_h in effective_trusted) or (by_ip and by_ip in effective_trusted):
                    is_configured_trust = True

            trust_state = "trusted_configured" if is_configured_trust else "observed"

            reconstructed.append(
                ReconstructedHop(
                    hop_sequence_num=seq_num,
                    original_header_index=hop.hop_index,
                    source_host=pf.from_host,
                    source_ip=pf.from_ip,
                    receiver_host=pf.by_host,
                    receiver_ip=pf.by_ip,
                    timestamp_raw=pf.timestamp_raw,
                    timestamp_utc=None,  # Populated during temporal analysis
                    protocol=pf.with_protocol,
                    is_source_private=pf.is_source_private,
                    is_receiver_private=pf.is_receiver_private,
                    trust_state=trust_state,
                    direction="upstream_to_downstream",
                )
            )

        return reconstructed
