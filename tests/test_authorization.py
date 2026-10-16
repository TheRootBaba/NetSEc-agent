import pytest

from netsec_agent.authorization import AssessmentScope, validate_assessment


def approved_scope() -> AssessmentScope:
    return AssessmentScope(
        authorized=True,
        approved_targets=("192.168.1.10",),
        max_targets=1,
        allowed_scan_types=frozenset({"port_scan"}),
    )


def test_allows_explicitly_approved_target() -> None:
    assert validate_assessment("192.168.1.10", "port_scan", approved_scope()) == "192.168.1.10"


def test_denies_when_not_authorized() -> None:
    scope = AssessmentScope(approved_targets=("192.168.1.10",))

    with pytest.raises(PermissionError, match="not authorized"):
        validate_assessment("192.168.1.10", "port_scan", scope)


def test_denies_target_outside_scope() -> None:
    with pytest.raises(PermissionError, match="not explicitly approved"):
        validate_assessment("192.168.1.11", "port_scan", approved_scope())


def test_denies_unapproved_scan_type() -> None:
    with pytest.raises(PermissionError, match="not approved"):
        validate_assessment("192.168.1.10", "host_discovery", approved_scope())


def test_denies_unknown_scan_type() -> None:
    with pytest.raises(PermissionError, match="not permitted"):
        validate_assessment("192.168.1.10", "packet_capture", approved_scope())


def test_rejects_excessive_target_limit() -> None:
    scope = AssessmentScope(
        authorized=True,
        approved_targets=("192.168.1.10",),
        max_targets=11,
        allowed_scan_types=frozenset({"port_scan"}),
    )

    with pytest.raises(ValueError, match="between 1 and 10"):
        validate_assessment("192.168.1.10", "port_scan", scope)


def test_rejects_approved_targets_exceeding_limit() -> None:
    scope = AssessmentScope(
        authorized=True,
        approved_targets=("192.168.1.10", "192.168.1.11"),
        max_targets=1,
        allowed_scan_types=frozenset({"port_scan"}),
    )

    with pytest.raises(ValueError, match="exceeds"):
        validate_assessment("192.168.1.10", "port_scan", scope)
