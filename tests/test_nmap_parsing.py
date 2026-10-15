import pytest

from netsec_agent.scoring import parse_nmap_open_tcp_ports


def test_parses_open_tcp_ports():
    output = (
        "PORT     STATE SERVICE\n"
        "22/tcp   open  ssh\n"
        "80/tcp   open  http\n"
        "443/tcp  closed https\n"
        "445/tcp  filtered microsoft-ds\n"
    )
    assert parse_nmap_open_tcp_ports(output) == [22, 80]


def test_ignores_udp_and_non_open_ports():
    output = "53/udp open domain\n23/tcp closed telnet\n"
    assert parse_nmap_open_tcp_ports(output) == []


def test_removes_duplicate_ports():
    output = "80/tcp open http\n80/tcp open http\n"
    assert parse_nmap_open_tcp_ports(output) == [80]


@pytest.mark.parametrize("output", ["", "Nmap scan report", "No ports shown"])
def test_empty_or_unrelated_output_has_no_open_ports(output):
    assert parse_nmap_open_tcp_ports(output) == []
