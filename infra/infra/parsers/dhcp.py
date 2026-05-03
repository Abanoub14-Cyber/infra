"""DHCP option parser for passive device fingerprinting.

Reads:
- Option 12 (hostname)
- Option 55 (parameter request list — the fingerprint)
- Option 60 (vendor class identifier)

The Option 55 list order is highly characteristic of OS/device. Combined with
Option 60 it gives a reliable passive OS fingerprint without active probing.
"""

import logging

log = logging.getLogger(__name__)

# Vendor class identifier (Option 60) prefixes -> human-readable label
DHCP_VENDORS = {
    "MSFT 5.0": "Windows",
    "MSFT 98": "Windows98",
    "android-dhcp": "Android",
    "dhcpcd": "Linux",
    "udhcp": "EmbeddedLinux",
    "Hewlett-Packard": "HP",
    "Lexmark": "Lexmark Printer",
    "Brother": "Brother Printer",
    "EPSON": "Epson Printer",
    "Canon": "Canon Printer",
    "Apple": "Apple",
    "iPhone": "iPhone",
    "iPad": "iPad",
    "Roku": "Roku",
    "VMware": "VMware",
    "PXEClient": "PXE Boot",
}

DHCP_MAGIC = b"\x63\x82\x53\x63"


def extract_dhcp(data: bytes) -> tuple[str, str]:
    """Parse a DHCP packet payload.

    Args:
        data: UDP payload of a DHCP packet (BOOTP header + options).

    Returns:
        (hostname, fingerprint) where fingerprint is "vendor|param_request_list".
    """
    try:
        # BOOTP header is 236 bytes, then 4-byte magic cookie, then options
        if len(data) < 244 or data[236:240] != DHCP_MAGIC:
            return "", ""

        hostname = ""
        vendor = ""
        prl = ""
        pos = 240

        while pos < len(data) - 1:
            opt = data[pos]
            if opt == 255:  # End option
                break
            if opt == 0:  # Pad option
                pos += 1
                continue
            if pos + 1 >= len(data):
                break
            opt_len = data[pos + 1]
            if pos + 2 + opt_len > len(data):
                break
            opt_data = data[pos + 2:pos + 2 + opt_len]

            if opt == 12:  # Hostname
                hostname = opt_data.decode("ascii", errors="ignore").strip("\x00")
            elif opt == 60:  # Vendor class identifier
                raw = opt_data.decode("ascii", errors="ignore")
                for prefix, name in DHCP_VENDORS.items():
                    if prefix in raw:
                        vendor = name
                        break
                if not vendor:
                    vendor = raw[:30]
            elif opt == 55:  # Parameter request list
                prl = ",".join(str(b) for b in opt_data)

            pos += 2 + opt_len

        fp = f"{vendor}|{prl}" if (vendor or prl) else ""
        if hostname or fp:
            log.debug(f"[DHCP] hostname={hostname!r} vendor={vendor!r}")
        return hostname, fp
    except (IndexError, UnicodeDecodeError) as e:
        log.debug(f"[DHCP] parse error: {e}")
        return "", ""
