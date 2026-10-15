
import pytest

from netsec_agent.scope import validate_target


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.1.10", "192.168.1.10"),
        (" 192.168.1.10 ", "192.168.1.10"),
        ("127.0.0.1", "127.0.0.1"),
        ("2001:db8::1", "2001:db8::1"),
    ],
)
def test_valid_single_ip(target: str, expected: str) -> None:
    assert validate_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "localhost",
        "example.com",
        "192.168.1.0/24",
        "not-an-ip",
        "999.1.1.1",
    ],
)
def test_rejects_invalid_targets(target: str) -> None:
    with pytest.raises(ValueError):
        validate_target(target)


def test_rejects_non_string_target() -> None:
    with pytest.raises(TypeError):
        validate_target(None)  # type: ignore[arg-type]
