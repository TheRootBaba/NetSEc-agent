"""Route network assessment requests away from ordinary chat."""

SCAN_TERMS = (
    "scan",
    "nmap",
    "vulnerabilit",
    "vurnebilit",
    "security assessment",
    "check my network",
    "check this host",
    "test my network",
    "test this host",
    "open ports",
    "discover hosts",
    "find open ports",
    "audit my network",
    "my ip is",
    "it's my ip",
    "its my ip",
    "i own this",
    "i have permission",
    "i am authorized",
    "discover devices",
    "find devices",
    "host discovery",
    "check if host is online",
    "is this host online",
    "analyze pcap",
    "analyse pcap",
    "packet capture",
)


def is_scan_request(message: str) -> bool:
    """Return True when a message relates to a scan or its authorization."""
    text = message.lower().strip()
    return any(term in text for term in SCAN_TERMS)
