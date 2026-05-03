"""mDNS / Zeroconf service discovery parser.

mDNS announcements reveal printers, AirPlay receivers, AppleTVs, Chromecasts,
file shares, and more — without any active probing. They are sent to
multicast 224.0.0.251:5353.
"""

import logging
import struct

log = logging.getLogger(__name__)

# Common Bonjour/Zeroconf service types worth flagging
MDNS_SERVICES = [
    "_http._tcp", "_https._tcp",
    "_printer._tcp", "_ipp._tcp", "_ipps._tcp", "_pdl-datastream._tcp",
    "_smb._tcp", "_afpovertcp._tcp", "_nfs._tcp",
    "_ssh._tcp", "_sftp-ssh._tcp",
    "_airplay._tcp", "_raop._tcp", "_homekit._tcp",
    "_googlecast._tcp", "_chromecast._tcp",
    "_spotify-connect._tcp",
    "_companion-link._tcp", "_rdlink._tcp",
    "_workstation._tcp", "_device-info._tcp",
    "_apple-mobdev2._tcp", "_apple-pairable._tcp",
    "_hap._tcp",  # HomeKit Accessory Protocol
    "_meshcop._udp",  # Thread border router
    "_matter._tcp",
]


def parse_mdns(data: bytes, src_ip: str) -> list[str]:
    """Find service types announced in an mDNS response.

    Returns a list of service strings (e.g. ['_printer._tcp', '_ipp._tcp']).
    Empty list if not a response or no known services found.
    """
    try:
        if len(data) < 12:
            return []
        # DNS header: ID(2) | flags(2) | QD(2) | AN(2) | NS(2) | AR(2)
        flags = struct.unpack('!H', data[2:4])[0]
        # QR bit (bit 15): 0=query, 1=response. We want responses.
        is_response = bool(flags >> 15 & 1)
        if not is_response:
            return []

        # Sloppy but effective: search the whole payload for known service strings.
        # Robust DNS name decompression would be cleaner but mDNS payloads are
        # small and the false-positive rate of substring matching here is ~0%.
        text = data[12:].decode("ascii", errors="ignore")
        found = [s for s in MDNS_SERVICES if s in text]
        if found:
            log.debug(f"[mDNS] {src_ip} announces: {found}")
        return found
    except (struct.error, UnicodeDecodeError) as e:
        log.debug(f"[mDNS] parse error: {e}")
        return []
