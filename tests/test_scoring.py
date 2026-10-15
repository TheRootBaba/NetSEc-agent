"""Deterministic scoring for observed network exposure."""

import re
from dataclasses import dataclass

# Heuristic exposure weights, not CVSS vulnerability scores.
PORT_WEIGHTS = {
    21: 12,    # FTP
    22: 5,     # SSH
    23: 20,    # Telnet
    80: 4,     # HTTP
    443: 1,    # HTTPS
    445: 18,   # SMB
    3306: 15,  # MySQL
    3389: 18,  # RDP
    5432: 15,  # PostgreSQL
    5900: 15,  # VNC
    6379: 15,  # Redis
    27017: 15, # MongoDB
}


@dataclass(frozen=True)
class ExposureScore:
    """A reproducible score based on observed open TCP ports."""

    score: int
    open_ports: tuple[int, ...]
    findings: tuple[str, ...]
    limitations: tuple[str, ...]


def parse_nmap_open_tcp_ports(output: str) -> list[int]:
    """Extract unique TCP ports explicitly reported as open in Nmap output."""
    if not isinstance(output, str):
        raise TypeError("Nmap output must be a string.")

    ports = {
        int(match.group(1))
        for match in re.finditer(
            r"^\s*(\d+)/tcp\s+open(?:\s|$)",
            output,
            flags=re.MULTILINE,
        )
    }
    return sorted(ports)


def score_open_ports(ports: list[int] | tuple[int, ...]) -> ExposureScore:
    """Return a 0–100 exposure score; higher means less observed exposure."""
    normalized = tuple(sorted(set(ports)))

    if any(
        not isinstance(port, int)
        or isinstance(port, bool)
        or not 1 <= port <= 65535
        for port in normalized
    ):
        raise ValueError("Ports must be integers between 1 and 65535.")

    penalty = sum(PORT_WEIGHTS.get(port, 2) for port in normalized)
    score = max(0, 100 - min(penalty, 100))

    findings = []
    for port in normalized:
        if port == 21:
            findings.append(
                "FTP is exposed; check whether encrypted alternatives are available."
            )
        elif port == 23:
            findings.append(
                "Telnet is exposed; it does not protect credentials in transit."
            )
        elif port == 445:
            findings.append(
                "SMB is exposed; restrict access to trusted networks."
            )
        elif port == 3389:
            findings.append(
                "RDP is exposed; restrict remote access and enforce strong authentication."
            )
        elif port in (3306, 5432, 6379, 27017):
            findings.append(
                f"Database or data-service port {port} is exposed; "
                "verify network access controls."
            )
        elif port == 5900:
            findings.append("VNC is exposed; restrict remote desktop access.")
        elif port == 22:
            findings.append(
                "SSH is exposed; review authentication and source restrictions."
            )
        elif port in (80, 443):
            findings.append(
                f"Web port {port} is open; review the service configuration."
            )
        else:
            findings.append(
                f"TCP port {port} is open; identify the service and confirm it is required."
            )

    return ExposureScore(
        score=score,
        open_ports=normalized,
        findings=tuple(findings),
        limitations=(
            "This is a heuristic exposure score, not a vulnerability scan.",
            "A closed or unobserved port does not prove that a host is secure.",
            ("Service versions, configuration, authentication, and patch status are not evaluated."),
        ),
    )


