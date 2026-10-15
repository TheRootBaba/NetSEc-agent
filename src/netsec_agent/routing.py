
"""Route explicit network assessment requests away from ordinary chat."""

import re

SCAN_PATTERNS = (
    (
        r"\b(?:run|start|perform|launch|execute)\s+(?:an?\s+)?"
        r"(?:host discovery|port scan|service scan|network scan|security assessment)\b"
    ),
    (
        r"\bscan(?:ning)?\s+(?:my\s+)?"
        r"(?:network|host|ip|subnet|device|target)\b"
    ),
    r"\b(?:discover hosts|discover devices|find devices|host discovery)\b",
    (
        r"\b(?:find open ports|open ports|service/version detection|"
        r"service version detection|service detection|version detection)\b"
    ),
    r"\bwhat services are running\b",
    (
        r"\b(?:check|test|audit)\s+(?:my\s+)?"
        r"(?:network|host|ip|subnet|device)\b"
    ),
    r"\bscan\b.*\b(?:\d{1,3}\.){3}\d{1,3}\b",
    r"\bnmap\b",
    r"\bcheck\s+for\s+(?:vulnerabilit\w*|vurnebilit\w*)\b",
)


def is_scan_request(message: str) -> bool:
    """Return True when a message requests an assessment action."""
    text = message.lower().strip()
    return any(re.search(pattern, text) for pattern in SCAN_PATTERNS)
