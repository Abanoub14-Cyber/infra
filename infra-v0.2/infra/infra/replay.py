"""PCAP replay engine — feed a captured PCAP file through the parsers.

Two main use cases:
1. Testing: validate parsers against known-good captures without a live
   network or root privileges.
2. Remote audit: a client emails you a 1h PCAP capture, you analyze it
   without ever touching their network.

Reuses the same packet-processing pipeline as the live capture engine.
"""

import logging
import struct
import time
from pathlib import Path

from .capture import CaptureEngine

log = logging.getLogger(__name__)

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_NS_MAGIC_LE = 0xA1B23C4D  # nanosecond resolution


class PcapReplay(CaptureEngine):
    """Replays a PCAP file as if it were live capture."""

    def __init__(self, pcap_path: str, db_path: str = "replay.db"):
        # Don't open a socket — we read from file
        super().__init__(db_path=db_path, interface=None, gateway=False)
        self.pcap_path = pcap_path

    def replay(self) -> int:
        """Read the PCAP and process every packet. Returns packet count."""
        path = Path(self.pcap_path)
        if not path.exists():
            log.critical(f"[REPLAY] File not found: {self.pcap_path}")
            return 0

        log.info(f"[REPLAY] Opening {self.pcap_path}")
        self.running = True
        self.t0 = time.time()

        # Start the flush thread so we don't accumulate everything in RAM
        import threading
        flusher = threading.Thread(target=self._flusher, daemon=True)
        flusher.start()

        try:
            with path.open("rb") as f:
                # PCAP global header is 24 bytes
                hdr = f.read(24)
                if len(hdr) < 24:
                    log.error("[REPLAY] File too short to be a PCAP")
                    return 0

                magic = struct.unpack("<I", hdr[:4])[0]
                if magic == PCAP_MAGIC_LE or magic == PCAP_NS_MAGIC_LE:
                    endian = "<"
                elif magic == PCAP_MAGIC_BE:
                    endian = ">"
                else:
                    log.error(
                        f"[REPLAY] Not a PCAP file (magic=0x{magic:08x}). "
                        "PCAPNG is not supported — convert with editcap."
                    )
                    return 0

                # Link-layer type at offset 20
                linktype = struct.unpack(f"{endian}I", hdr[20:24])[0]
                if linktype != 1:  # 1 = LINKTYPE_ETHERNET
                    log.warning(
                        f"[REPLAY] Link type {linktype} (not Ethernet). "
                        "Some parsers may fail."
                    )

                # Iterate packet records
                while True:
                    rec_hdr = f.read(16)
                    if len(rec_hdr) < 16:
                        break  # EOF
                    _ts_sec, _ts_us, incl_len, _orig_len = struct.unpack(
                        f"{endian}IIII", rec_hdr
                    )
                    if incl_len > 65535:
                        log.warning(f"[REPLAY] Suspicious record length {incl_len}, stopping")
                        break
                    pkt = f.read(incl_len)
                    if len(pkt) < incl_len:
                        break  # truncated
                    self._process_packet(pkt)
                    self.packets += 1
                    if self.packets % 10000 == 0:
                        log.info(f"[REPLAY] {self.packets:,} packets processed")
        except (OSError, struct.error) as e:
            log.error(f"[REPLAY] Read error after {self.packets} packets: {e}")

        # Flush and close cleanly
        self.running = False
        time.sleep(0.1)  # let flusher catch up
        self._flush_flows()
        self.db.flush_devices()
        self.db.close()
        log.info(f"[REPLAY] Done. {self.packets:,} packets processed")
        return self.packets
