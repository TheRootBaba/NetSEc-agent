
"""Validation for explicitly approved private IPv4 subnet discovery."""

from ipaddress import IPv4Network, ip_network

MAX_HOSTS = 256

_PRIVATE_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)


def validate_subnet(
    subnet: str,
    approved_subnets: tuple[str, ...],
    authorized: bool,
) -> str:
    """Return a normalized subnet only when it passes every scope check."""
    if not authorized:
        raise PermissionError("Subnet discovery is not authorized.")

    try:
        network = ip_network(subnet.strip(), strict=True)
    except ValueError as exc:
        raise ValueError(
            "Enter a network address, such as 192.168.100.0/24. "
            "Do not enter a host address with a subnet mask."
        ) from exc

    if not isinstance(network, IPv4Network):
        raise TypeError("Only IPv4 subnets are supported.")

    if not any(network.subnet_of(private) for private in _PRIVATE_NETWORKS):
        raise ValueError("Only RFC1918 private IPv4 subnets are allowed.")

    if network.prefixlen == 32:
        raise ValueError(
            "A /32 is a single IP address. Enter a subnet range, "
            "such as 192.168.100.0/24."
        )

    if network.num_addresses > MAX_HOSTS:
        raise ValueError(
            f"Subnet discovery is limited to {MAX_HOSTS} addresses."
        )

    approved_networks = set()

    for item in approved_subnets:
        try:
            candidate = ip_network(item.strip(), strict=True)
        except ValueError:
            continue

        if isinstance(candidate, IPv4Network):
            approved_networks.add(candidate)

    if network not in approved_networks:
        raise PermissionError(
            "Subnet is not explicitly approved for this assessment."
        )

    return str(network)
