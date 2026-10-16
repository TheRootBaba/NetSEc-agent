"""Validate individual IP targets before any network assessment."""

from ipaddress import ip_address


def validate_target(target: str) -> str:
    """Return a normalized IP address or raise ValueError."""
    if not isinstance(target, str):
        raise TypeError("Target must be a string containing one IP address.")

    candidate = target.strip()
    if not candidate:
        raise ValueError("Target cannot be empty.")

    if "/" in candidate:
        raise ValueError("Network ranges are not allowed; provide one IP address.")

    try:
        address = ip_address(candidate)
    except ValueError as exc:
        raise ValueError(
            "Invalid target. Provide one IPv4 or IPv6 address, not a hostname."
        ) from exc

    return str(address)
