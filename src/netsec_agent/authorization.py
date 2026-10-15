"""Deterministic authorization policy for network assessments."""

from dataclasses import dataclass
from ipaddress import ip_address

from netsec_agent.scope import validate_target

ALLOWED_SCAN_TYPES = frozenset({"host_discovery", "port_scan"})


@dataclass(frozen=True)
class AssessmentScope:
    """Explicit authorization and limits for one assessment."""

    authorized: bool = False
    approved_targets: tuple[str, ...] = ()
    max_targets: int = 1
    allowed_scan_types: frozenset[str] = frozenset()


def validate_assessment(
    target: str,
    scan_type: str,
    scope: AssessmentScope,
) -> str:
    """Return the normalized target only if policy permits the assessment."""
    if not scope.authorized:
        raise PermissionError("Assessment is not authorized.")

    if scan_type not in ALLOWED_SCAN_TYPES:
        raise PermissionError("This scan type is not permitted.")

    if not 1 <= scope.max_targets <= 10:
        raise ValueError("max_targets must be between 1 and 10.")

    if scan_type not in scope.allowed_scan_types:
        raise PermissionError("This scan type is not approved in the assessment scope.")

    if len(scope.approved_targets) > scope.max_targets:
        raise ValueError("Approved target count exceeds the configured limit.")

    target_ip = validate_target(target)
    approved = {str(ip_address(item)) for item in scope.approved_targets}

    if target_ip not in approved:
        raise PermissionError("Target is not explicitly approved.")

    return target_ip