"""Deterministic scoring for observed network exposure."""

import re
from dataclasses import dataclass

PORT_WEIGHTS = {
    21: 12,
    22: 5,
    23: 20,
    80: 4,
    443: 1,
    445: 18,
    3306: 15,
    3389: 18,
    5432: 15,
    5900: 15,
    6379: 15,
    27017: 15,
}


@dataclass(frozen=True)
class ExposureScore:
    """A reproducible score based on observed open TCP ports."""

    score: int
    open_ports: tuple[int, ...]
    findings: tuple[str, ...]
    limitations: tuple[str, ...]


def parse_nmap_open_tcp_ports(output: str) -> list[int]:
    """Extract unique TCP ports explicitly reported as open."""
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
    """Return a 0–100 heuristic exposure score."""
    normalized = tuple(sorted(set(ports)))

    if any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
        for port in normalized
    ):
        raise ValueError("Ports must be integers between 1 and 65535.")

    penalty = sum(PORT_WEIGHTS.get(port, 2) for port in normalized)
    score = max(0, 100 - min(penalty, 100))

    findings = []
    for port in normalized:
        if port == 21:
            findings.append("FTP is exposed; consider an encrypted alternative.")
        elif port == 22:
            findings.append("SSH is exposed; review authentication and source restrictions.")
        elif port == 23:
            findings.append("Telnet is exposed; credentials may be transmitted unencrypted.")
        elif port == 80:
            findings.append("HTTP is open; review the web service configuration.")
        elif port == 443:
            findings.append("HTTPS is open; review TLS and web service configuration.")
        elif port == 445:
            findings.append("SMB is exposed; restrict access to trusted networks.")
        elif port == 3389:
            findings.append(
                "RDP is exposed; restrict remote access and enforce strong authentication."
            )
        elif port in (3306, 5432, 6379, 27017):
            findings.append(f"Data-service port {port} is exposed; verify network access controls.")
        elif port == 5900:
            findings.append("VNC is exposed; restrict remote desktop access.")
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
            (
                "Service versions, configuration, authentication, and patch status "
                "are not evaluated."
            ),
        ),
    )
