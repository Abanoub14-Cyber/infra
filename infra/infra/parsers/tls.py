"""TLS ClientHello parser: SNI + JA4 fingerprint.

JA4 is preferred over JA3 (introduced 2023 by FoxIO) because:
- It separates TLS version, ciphers, extensions into structured parts
- It is stable across browser updates (sorts ciphers/extensions)
- Format: q/t<version>d<sni_present>_<ciphers_hash>_<extensions_hash>

Spec: https://github.com/FoxIO-LLC/ja4
This is a *simplified* JA4_t (TCP TLS) implementation suitable for fingerprinting.
"""

import hashlib
import logging
import struct

log = logging.getLogger(__name__)

# GREASE values (RFC 8701) — must be filtered out from JA3/JA4
GREASE = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})

TLS_VERSION_MAP = {
    0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13",
}

# Known JA4 fingerprints — far more stable than JA3.
# These are placeholders; populate from observed traffic in production.
JA4_KNOWN: dict[str, str] = {
    # Format: "t13d1516h2_8daaf6152771_b186095e22b6": "Chrome 120 macOS"
    # Build your own DB by capturing labeled traffic.
}


def _is_clienthello(data: bytes) -> bool:
    """TLS record: type=0x16 (handshake), then handshake type 0x01 (ClientHello)."""
    return len(data) >= 6 and data[0] == 0x16 and data[5] == 0x01


def extract_sni(data: bytes) -> str:
    """Extract SNI from TLS ClientHello. Returns '' if not present or parse fails."""
    try:
        if not _is_clienthello(data) or len(data) < 44:
            return ""
        pos = 43  # past record header + handshake header + version + random
        if pos >= len(data):
            return ""

        # Session ID
        session_len = data[pos]
        pos += 1 + session_len
        if pos + 2 > len(data):
            return ""

        # Cipher suites
        cipher_len = struct.unpack('!H', data[pos:pos + 2])[0]
        pos += 2 + cipher_len
        if pos >= len(data):
            return ""

        # Compression methods
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos + 2 > len(data):
            return ""

        # Extensions
        ext_total = struct.unpack('!H', data[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(data))

        while pos + 4 <= end:
            ext_type, ext_size = struct.unpack('!HH', data[pos:pos + 4])
            pos += 4
            if ext_type == 0x0000 and ext_size > 5:  # server_name extension
                # Skip list length (2) + name type (1) + name length (2)
                if pos + 5 > len(data):
                    break
                name_len = struct.unpack('!H', data[pos + 3:pos + 5])[0]
                if pos + 5 + name_len <= len(data):
                    return data[pos + 5:pos + 5 + name_len].decode(
                        "ascii", errors="ignore"
                    )
            pos += ext_size
        return ""
    except (struct.error, IndexError, UnicodeDecodeError) as e:
        log.debug(f"[SNI] parse error: {e}")
        return ""


def extract_ja4(data: bytes, transport: str = "t") -> str:
    """Compute simplified JA4 fingerprint from a TLS ClientHello.

    Args:
        data: Raw TLS record bytes (starting with 0x16)
        transport: 't' for TCP, 'q' for QUIC. Default 't'.

    Returns:
        JA4 string like "t13d1516h2_8daaf6152771_b186095e22b6", or '' on error.
    """
    try:
        if not _is_clienthello(data) or len(data) < 44:
            return ""

        client_version = struct.unpack('!H', data[9:11])[0]
        pos = 43
        if pos >= len(data):
            return ""

        # Session ID
        pos += 1 + data[pos]
        if pos + 2 > len(data):
            return ""

        # Ciphers
        cipher_len = struct.unpack('!H', data[pos:pos + 2])[0]
        ciphers = []
        for i in range(pos + 2, min(pos + 2 + cipher_len, len(data)) - 1, 2):
            v = struct.unpack('!H', data[i:i + 2])[0]
            if v not in GREASE:
                ciphers.append(v)
        pos += 2 + cipher_len
        if pos >= len(data):
            return ""

        # Compression
        pos += 1 + data[pos]

        # Extensions
        extensions = []
        sni_present = False
        alpn_first = ""
        supported_versions_max = client_version

        if pos + 2 <= len(data):
            ext_total = struct.unpack('!H', data[pos:pos + 2])[0]
            pos += 2
            end = min(pos + ext_total, len(data))
            while pos + 4 <= end:
                et, es = struct.unpack('!HH', data[pos:pos + 4])
                pos += 4
                ed = data[pos:pos + es]
                if et not in GREASE:
                    extensions.append(et)
                    if et == 0x0000:  # SNI
                        sni_present = True
                    elif et == 0x0010 and len(ed) >= 2:  # ALPN
                        try:
                            alpn_list_len = struct.unpack('!H', ed[:2])[0]
                            if alpn_list_len > 0 and len(ed) >= 4:
                                proto_len = ed[2]
                                if 3 + proto_len <= len(ed):
                                    alpn_first = ed[3:3 + proto_len].decode(
                                        "ascii", errors="ignore"
                                    )
                        except (struct.error, IndexError):
                            pass
                    elif et == 0x002b and len(ed) >= 1:  # supported_versions
                        # Take the highest non-GREASE version offered
                        list_len = ed[0]
                        for i in range(1, min(1 + list_len, len(ed)) - 1, 2):
                            v = struct.unpack('!H', ed[i:i + 2])[0]
                            if v not in GREASE and v > supported_versions_max:
                                supported_versions_max = v
                pos += es

        # Build JA4 components
        ver_str = TLS_VERSION_MAP.get(supported_versions_max, "00")
        sni_flag = "d" if sni_present else "i"
        cipher_count = f"{min(len(ciphers), 99):02d}"
        ext_count = f"{min(len(extensions), 99):02d}"
        alpn_code = (alpn_first[:1] + alpn_first[-1:])[:2] if alpn_first else "00"

        # JA4_a (the prefix)
        prefix = f"{transport}{ver_str}{sni_flag}{cipher_count}{ext_count}{alpn_code}"

        # JA4_b: hash of sorted ciphers (truncated to 12 hex chars)
        cipher_str = ",".join(f"{c:04x}" for c in sorted(ciphers))
        ja4_b = hashlib.sha256(cipher_str.encode()).hexdigest()[:12]

        # JA4_c: hash of sorted extensions excluding SNI(0) and ALPN(0x10)
        ext_filtered = sorted(e for e in extensions if e not in (0x0000, 0x0010))
        ext_str = ",".join(f"{e:04x}" for e in ext_filtered)
        ja4_c = hashlib.sha256(ext_str.encode()).hexdigest()[:12]

        ja4 = f"{prefix}_{ja4_b}_{ja4_c}"
        log.debug(f"[JA4] {ja4}")
        return ja4
    except (struct.error, IndexError) as e:
        log.debug(f"[JA4] parse error: {e}")
        return ""
