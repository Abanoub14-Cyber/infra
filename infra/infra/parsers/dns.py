"""DNS / LLMNR / NetBIOS name parser.

Used to extract:
- Domains queried via DNS (port 53)
- Hostnames advertised via LLMNR (port 5355) or NetBIOS-NS (port 137)
"""

import logging

log = logging.getLogger(__name__)


def parse_dns_name(data: bytes, offset: int = 12) -> str:
    """Extract the first QNAME from a DNS-style packet.

    Args:
        data: Full packet payload starting with DNS header.
        offset: Where the question section starts (12 for standard DNS).

    Returns:
        Domain string like 'example.com', or '' on error.
    """
    try:
        pos = offset
        labels: list[str] = []
        # Limit iterations to avoid pathological inputs
        for _ in range(64):
            if pos >= len(data):
                break
            length = data[pos]
            if length == 0:
                break
            # Pointer (compression) — we don't follow, just stop
            if length & 0xC0:
                break
            pos += 1
            if pos + length > len(data):
                break
            labels.append(
                data[pos:pos + length].decode("ascii", errors="ignore")
            )
            pos += length
        name = ".".join(labels).strip("\x00").strip()
        return name
    except (IndexError, UnicodeDecodeError) as e:
        log.debug(f"[DNS] parse error: {e}")
        return ""
