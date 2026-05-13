"""IPv6 header parser.

In 2026, ignoring IPv6 means missing 30-50% of modern network traffic
(especially Apple devices, which prefer IPv6 when available). This module
parses the fixed IPv6 header and resolves to an upper-layer protocol.

Extension headers (Hop-by-Hop, Routing, Fragment, AH, ESP, Destination
Options) are *partially* skipped — we follow the next-header chain until
we hit TCP/UDP/ICMPv6 or give up. This covers the common case but not
exotic header chains.
"""

import logging
import socket
import struct

log = logging.getLogger(__name__)

# Next Header values that are extension headers (skip and continue)
IPV6_EXTENSION_HEADERS = {0, 43, 44, 50, 51, 60, 135, 139, 140}

# Final-protocol next-header values
NH_TCP = 6
NH_UDP = 17
NH_ICMPV6 = 58


def parse_ipv6(raw: bytes, offset: int) -> dict | None:
    """Parse an IPv6 packet starting at `offset`.

    Returns dict with keys: src, dst, proto_num, payload_offset, payload_len, hop_limit
    Returns None if not parseable as IPv6.
    """
    if len(raw) < offset + 40:
        return None
    try:
        # Version + Traffic Class + Flow Label (4 bytes)
        ver_tc_fl = struct.unpack('!I', raw[offset:offset + 4])[0]
        version = ver_tc_fl >> 28
        if version != 6:
            return None

        payload_len = struct.unpack('!H', raw[offset + 4:offset + 6])[0]
        next_hdr = raw[offset + 6]
        hop_limit = raw[offset + 7]
        src = socket.inet_ntop(socket.AF_INET6, raw[offset + 8:offset + 24])
        dst = socket.inet_ntop(socket.AF_INET6, raw[offset + 24:offset + 40])

        # Walk extension headers (max 8 hops to avoid loops)
        cursor = offset + 40
        proto = next_hdr
        for _ in range(8):
            if proto not in IPV6_EXTENSION_HEADERS:
                break
            if cursor + 2 > len(raw):
                return None
            proto = raw[cursor]
            ext_len = (raw[cursor + 1] + 1) * 8  # length is in 8-octet units, +1
            # Fragment header is fixed 8 bytes
            if proto == 44:
                ext_len = 8
            cursor += ext_len

        return {
            "src": src,
            "dst": dst,
            "proto_num": proto,
            "payload_offset": cursor,
            "payload_len": payload_len,
            "hop_limit": hop_limit,
            "family": 6,
        }
    except (struct.error, ValueError, OSError) as e:
        log.debug(f"[IPv6] parse error: {e}")
        return None
