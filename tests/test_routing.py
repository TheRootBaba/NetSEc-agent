import pytest

from netsec_agent.routing import is_scan_request


@pytest.mark.parametrize(
    "message",
    [
        "scan my network",
        "Can you scan my network for vulnerabilities?",
        "check my network",
        "Find open ports on this host",
        "Run an Nmap assessment",
        "check for vurnebilities",
    ],
)
def test_scan_requests_are_routed_to_assessment(message):
    assert is_scan_request(message) is True


@pytest.mark.parametrize(
    "message",
    [
        "hi",
        "What is a firewall?",
        "Explain the difference between TCP and UDP",
        "How do I secure SSH?",
    ],
)
def test_ordinary_security_questions_remain_in_chat(message):
    assert is_scan_request(message) is False
