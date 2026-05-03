"""LLDP parser — switches and infrastructure equipment announce themselves.

LLDP frames have ethertype 0x88CC and are sent every 30s by default. They
contain TLVs (Type-Length-Value) describing the device:
- Type 1: Chassis ID
- Type 2: Port ID
- Type 5: System Name
- Type 6: System Description
- Type 7: System Capabilities
- Type 0: End of LLDPDU

This is gold for network mapping — you learn switch make, model, port your
laptop is plugged into, neighbor topology, all passively.
"""

import json
import logging
import struct

log = logging.getLogger(__name__)


def parse_lldp(data: bytes) -> str:
    """Parse LLDP TLVs into a JSON-encoded dict.

    Returns JSON string with available fields, or '' if parse fails.
    """
    try:
        pos = 0
        info: dict[str, str] = {}
        while pos + 2 <= len(data):
            hdr = struct.unpack('!H', data[pos:pos + 2])[0]
            tlv_type = (hdr >> 9) & 0x7F
            tlv_len = hdr & 0x01FF
            pos += 2
            if tlv_type == 0:  # End of LLDPDU
                break
            if pos + tlv_len > len(data):
                break
            tlv_data = data[pos:pos + tlv_len]

            try:
                if tlv_type == 1 and tlv_len > 1:  # Chassis ID
                    subtype = tlv_data[0]
                    if subtype == 4:  # MAC address
                        info["chassis"] = tlv_data[1:].hex(":")
                    else:
                        info["chassis"] = tlv_data[1:].decode(
                            "ascii", errors="ignore"
                        )
                elif tlv_type == 2 and tlv_len > 1:  # Port ID
                    info["port"] = tlv_data[1:].decode("ascii", errors="ignore")
                elif tlv_type == 5:  # System name
                    info["name"] = tlv_data.decode("ascii", errors="ignore")
                elif tlv_type == 6:  # System description
                    info["desc"] = tlv_data.decode("ascii", errors="ignore")
                elif tlv_type == 7 and tlv_len >= 4:  # System capabilities
                    caps = struct.unpack('!H', tlv_data[:2])[0]
                    cap_names = []
                    if caps & 0x01: cap_names.append("Other")
                    if caps & 0x02: cap_names.append("Repeater")
                    if caps & 0x04: cap_names.append("Bridge")
                    if caps & 0x08: cap_names.append("WLAN-AP")
                    if caps & 0x10: cap_names.append("Router")
                    if caps & 0x20: cap_names.append("Telephone")
                    if cap_names:
                        info["capabilities"] = ",".join(cap_names)
            except (UnicodeDecodeError, struct.error):
                pass

            pos += tlv_len

        if info:
            log.info(f"[LLDP] discovered: {info}")
            return json.dumps(info)
        return ""
    except (struct.error, IndexError) as e:
        log.debug(f"[LLDP] parse error: {e}")
        return ""
