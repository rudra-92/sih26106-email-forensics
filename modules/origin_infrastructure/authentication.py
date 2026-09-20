"""Authentication and ARC correlator for Origin & Infrastructure Reconstruction.

Evaluates reported SPF, DKIM, and DMARC results alongside Authenticated Received Chain
(ARC - RFC 8617) headers. Validates ARC sequence continuity, header completeness,
and reported seal results.

IMPORTANT: ARC processing performs structural validation only (instance ordering,
header presence, completeness, and reported cv= parameters). Cryptographic ARC signature
verification (canonicalization, RSA/Ed25519 signature verification against DNS public keys)
is NOT implemented.

Emits structured forensic observations treating authentication as transport evidence
rather than conclusive legitimacy.
"""

from email.message import EmailMessage, Message
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from modules.sender_identity.models import AuthResults
from .models import (
    ArcAnalysisResult,
    ArcInstance,
    OriginObservation,
)


class AuthenticationCorrelator:
    """Correlates SPF, DKIM, DMARC, and ARC authentication evidence."""

    def __init__(self) -> None:
        pass

    def correlate(
        self,
        email_msg: Optional[Union[EmailMessage, Message]] = None,
        auth_results: Optional[AuthResults] = None,
        obs_start_index: int = 1,
    ) -> Tuple[ArcAnalysisResult, List[OriginObservation]]:
        """Evaluate transport authentication and ARC headers.

        Args:
            email_msg: EmailMessage to inspect ARC and raw auth headers from.
            auth_results: Pre-extracted AuthResults from Module 1 (optional).
            obs_start_index: Starting counter index for generated observation IDs.

        Returns:
            Tuple of (ArcAnalysisResult, List[OriginObservation]).
        """
        observations: List[OriginObservation] = []
        counter = obs_start_index

        # 1. Correlate SPF / DKIM / DMARC findings if provided
        if auth_results:
            if auth_results.spf:
                spf_sev = "informational" if auth_results.spf == "pass" else (
                    "medium" if auth_results.spf == "fail" else "low"
                )
                observations.append(
                    OriginObservation(
                        observation_id=f"OBS-AUTH-{counter:03d}",
                        rule_id="RULE-AUTH-SPF",
                        source_module="origin_infrastructure",
                        source_header="Authentication-Results / Received-SPF",
                        severity=spf_sev,
                        description=(
                            f"Reported SPF validation result is '{auth_results.spf}' "
                            f"for domain '{auth_results.spf_domain or 'unknown'}'. "
                            "Recorded as supporting transport evidence."
                        ),
                        evidence={
                            "result": auth_results.spf,
                            "domain": auth_results.spf_domain,
                        },
                        trust_state="reported",
                        fact_type="reported",
                    )
                )
                counter += 1

            if auth_results.dkim:
                dkim_sev = "informational" if auth_results.dkim == "pass" else (
                    "medium" if auth_results.dkim == "fail" else "low"
                )
                observations.append(
                    OriginObservation(
                        observation_id=f"OBS-AUTH-{counter:03d}",
                        rule_id="RULE-AUTH-DKIM",
                        source_module="origin_infrastructure",
                        source_header="Authentication-Results",
                        severity=dkim_sev,
                        description=(
                            f"Reported DKIM validation result is '{auth_results.dkim}' "
                            f"for domain '{auth_results.dkim_domain or 'unknown'}'. "
                            "Recorded as supporting transport evidence."
                        ),
                        evidence={
                            "result": auth_results.dkim,
                            "domain": auth_results.dkim_domain,
                        },
                        trust_state="reported",
                        fact_type="reported",
                    )
                )
                counter += 1

            if auth_results.dmarc:
                dmarc_sev = "informational" if auth_results.dmarc == "pass" else (
                    "high" if auth_results.dmarc == "fail" else "low"
                )
                observations.append(
                    OriginObservation(
                        observation_id=f"OBS-AUTH-{counter:03d}",
                        rule_id="RULE-AUTH-DMARC",
                        source_module="origin_infrastructure",
                        source_header="Authentication-Results",
                        severity=dmarc_sev,
                        description=(
                            f"Reported DMARC policy alignment result is '{auth_results.dmarc}' "
                            f"for domain '{auth_results.dmarc_domain or 'unknown'}'. "
                            "Recorded as supporting transport evidence."
                        ),
                        evidence={
                            "result": auth_results.dmarc,
                            "domain": auth_results.dmarc_domain,
                        },
                        trust_state="reported",
                        fact_type="reported",
                    )
                )
                counter += 1

        # 2. Parse and evaluate ARC (Authenticated Received Chain - RFC 8617)
        arc_result, arc_obs = self._evaluate_arc(email_msg, counter)
        observations.extend(arc_obs)

        return arc_result, observations

    def _evaluate_arc(
        self,
        msg: Optional[Union[EmailMessage, Message]],
        start_counter: int,
    ) -> Tuple[ArcAnalysisResult, List[OriginObservation]]:
        """Parse ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results headers."""
        if not msg:
            return ArcAnalysisResult(has_arc=False), []

        arc_seals = msg.get_all("ARC-Seal", [])
        arc_ams = msg.get_all("ARC-Message-Signature", [])
        arc_aar = msg.get_all("ARC-Authentication-Results", [])

        if not arc_seals and not arc_ams and not arc_aar:
            return ArcAnalysisResult(has_arc=False), []

        # Index ARC components by instance number i=1, 2, ...
        instances_dict: Dict[int, Dict[str, Any]] = {}

        def get_instance_num(header_str: str) -> Optional[int]:
            m = re.search(r"\bi\s*=\s*(\d+)\b", header_str)
            return int(m.group(1)) if m else None

        for s in arc_seals:
            s_str = str(s)
            i_num = get_instance_num(s_str)
            if i_num is not None:
                instances_dict.setdefault(i_num, {})["seal"] = s_str
                # Extract cv= (chain validation) parameter: cv=none, cv=pass, cv=fail
                cv_match = re.search(r"\bcv\s*=\s*([a-zA-Z]+)\b", s_str)
                if cv_match:
                    instances_dict[i_num]["cv"] = cv_match.group(1).lower()
                d_match = re.search(r"\bd\s*=\s*([^\s;]+)", s_str)
                if d_match:
                    instances_dict[i_num]["domain"] = d_match.group(1).strip()

        for a in arc_ams:
            a_str = str(a)
            i_num = get_instance_num(a_str)
            if i_num is not None:
                instances_dict.setdefault(i_num, {})["ams"] = a_str

        for r in arc_aar:
            r_str = str(r)
            i_num = get_instance_num(r_str)
            if i_num is not None:
                instances_dict.setdefault(i_num, {})["aar"] = r_str

        sorted_indices = sorted(instances_dict.keys())
        instances: List[ArcInstance] = []
        is_chain_complete = True
        is_chain_consistent = True
        is_chain_valid = True
        counter = start_counter
        obs: List[OriginObservation] = []

        # Check sequence continuity: must start at 1 and be contiguous
        if not sorted_indices or sorted_indices[0] != 1:
            is_chain_consistent = False
        else:
            for idx, expected in enumerate(range(1, sorted_indices[-1] + 1)):
                if idx >= len(sorted_indices) or sorted_indices[idx] != expected:
                    is_chain_consistent = False
                    break

        for i_num in sorted_indices:
            data = instances_dict[i_num]
            has_seal = "seal" in data
            has_ams = "ams" in data
            has_aar = "aar" in data
            is_complete = has_seal and has_ams and has_aar
            cv_val = data.get("cv")

            if not is_complete:
                is_chain_complete = False

            # Valid seal requires cv=none for i=1, or cv=pass for i>1
            if i_num == 1:
                if cv_val not in ("none", "pass"):
                    is_chain_valid = False
            else:
                if cv_val != "pass":
                    is_chain_valid = False

            instances.append(
                ArcInstance(
                    instance_index=i_num,
                    seal_result=cv_val,
                    has_seal=has_seal,
                    has_signature=has_ams,
                    has_auth_results=has_aar,
                    is_complete=is_complete,
                    domain=data.get("domain"),
                )
            )

        if not is_chain_consistent or not is_chain_complete:
            obs.append(
                OriginObservation(
                    observation_id=f"OBS-AUTH-{counter:03d}",
                    rule_id="RULE-ARC-INCONSISTENT",
                    source_module="origin_infrastructure",
                    source_header="ARC-Seal / ARC-Message-Signature",
                    severity="medium",
                    description=(
                        f"Authenticated Received Chain (ARC) is broken or incomplete across "
                        f"{len(instances)} instance(s). Chain continuity or headers missing."
                    ),
                    evidence={
                        "instance_indices": sorted_indices,
                        "is_complete": is_chain_complete,
                        "is_consistent": is_chain_consistent,
                    },
                    trust_state="observed",
                    fact_type="observed",
                )
            )
            counter += 1
        elif is_chain_valid:
            obs.append(
                OriginObservation(
                    observation_id=f"OBS-AUTH-{counter:03d}",
                    rule_id="RULE-ARC-STRUCTURE-VALID",
                    source_module="origin_infrastructure",
                    source_header="ARC-Seal",
                    severity="informational",
                    description=(
                        f"Authenticated Received Chain (ARC) sequence continuity and header structure "
                        f"are valid across {len(instances)} instance(s). "
                        "Cryptographic ARC signature verification is not implemented."
                    ),
                    evidence={
                        "total_instances": len(instances),
                        "latest_instance": sorted_indices[-1],
                        "latest_seal": instances[-1].seal_result,
                        "cryptographic_verification": False,
                    },
                    trust_state="reported",
                    fact_type="reported",
                )
            )
            counter += 1

        result = ArcAnalysisResult(
            has_arc=True,
            instances=instances,
            is_chain_complete=is_chain_complete,
            is_chain_consistent=is_chain_consistent,
            is_chain_valid=is_chain_valid,
            details={"instance_count": len(instances)},
        )

        return result, obs
