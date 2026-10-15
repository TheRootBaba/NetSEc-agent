"""Restricted MCP server for authorized Nmap assessments."""

import os
import subprocess
from ipaddress import ip_address
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.mcpserver import MCPServer

from netsec_agent.scoring import parse_nmap_open_tcp_ports, score_open_ports

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

mcp = MCPServer(
    name="netsec-nmap",
    instructions="Runs fixed Nmap profiles against explicitly approved IPs.",
)

SCAN_PROFILES = {
    "host_discovery": ["-sn", "-T3"],
    "port_scan": ["-sT", "-T3", "--top-ports", "100"],
}
SCAN_TIMEOUT_SECONDS = 45
MAX_OUTPUT_CHARS = 12_000


def _validate_target(target: str) -> str:
    """Require one IP explicitly listed in the assessment scope."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Provide one IP address.")

    if "/" in target:
        raise ValueError("Network ranges are not allowed.")

    try:
        normalized = str(ip_address(target.strip()))
    except ValueError as exc:
        raise ValueError("Target must be an IPv4 or IPv6 address.") from exc

    if os.getenv("NETSEC_AUTHORIZED", "").lower() != "true":
        raise PermissionError("Assessment authorization has not been enabled.")

    approved = set()
    for item in os.getenv("NETSEC_AUTHORIZED_TARGETS", "").split(","):
        try:
            approved.add(str(ip_address(item.strip())))
        except ValueError:
            continue

    if normalized not in approved:
        raise PermissionError("Target is not in the approved target list.")

    return normalized


@mcp.tool()
def run_nmap_assessment(target: str, scan_type: str) -> str:
    """Run a fixed Nmap profile against one approved IP.

    scan_type must be 'host_discovery' or 'port_scan'.
    """
    if scan_type not in SCAN_PROFILES:
        raise ValueError("Unsupported scan type.")

    normalized_target = _validate_target(target)
    command = [
        os.getenv("NMAP_PATH", "nmap"),
        *SCAN_PROFILES[scan_type],
        "-oN",
        "-",
        normalized_target,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Nmap exceeded the 45-second time limit.") from exc
    except OSError as exc:
        raise RuntimeError("Could not start Nmap; check NMAP_PATH.") from exc

    output = (result.stdout + "\n" + result.stderr).strip()

    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap failed (exit code {result.returncode}): {output[:2000]}"
        )

    report = (
        f"Target: {normalized_target}\n"
        f"Profile: {scan_type}\n"
        f"Exit code: {result.returncode}\n\n"
        f"{output[:MAX_OUTPUT_CHARS]}"
    )

    if scan_type == "port_scan":
        ports = parse_nmap_open_tcp_ports(result.stdout)
        assessment = score_open_ports(ports)

        findings = (
            "\n".join(f"- {finding}" for finding in assessment.findings)
            if assessment.findings
            else "- No open TCP ports were identified in the parsed output."
        )
        limitations = "\n".join(
            f"- {item}" for item in assessment.limitations
        )

        report += (
            "\n\n=== Deterministic Exposure Assessment ===\n"
            f"Observed open TCP ports: {list(assessment.open_ports)}\n"
            f"Exposure score: {assessment.score}/100 "
            "(higher means less observed exposure)\n\n"
            f"Findings:\n{findings}\n\n"
            f"Limitations:\n{limitations}"
        )

    return report


if __name__ == "__main__":
    mcp.run(transport="stdio")
