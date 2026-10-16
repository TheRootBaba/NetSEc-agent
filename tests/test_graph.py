import pytest

from netsec_agent.authorization import AssessmentScope
from netsec_agent.scope import validate_target


def test_default_scope_does_not_authorize_scans():
    scope = AssessmentScope()
    assert scope.authorized is False
    assert scope.approved_targets == ()
    assert scope.allowed_scan_types == frozenset()


def test_scope_rejects_scan_type_not_explicitly_allowed():
    from netsec_agent.authorization import validate_assessment

    scope = AssessmentScope(
        authorized=True,
        approved_targets=("127.0.0.1",),
        max_targets=1,
        allowed_scan_types=frozenset({"host_discovery"}),
    )

    with pytest.raises(PermissionError):
        validate_assessment("127.0.0.1", "port_scan", scope)


def test_scope_normalizes_approved_ip():
    assert validate_target(" 127.0.0.1 ") == "127.0.0.1"
