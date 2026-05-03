"""Capture engine: raw socket -> parsers -> DB.

Major changes vs original:
- Devices are buffered in memory and flushed every 5s, not written per-packet
  (was a major perf issue with thousands of packets/sec)
- IPv6 fully supported
- JA4 instead of JA3 (more stable across browser updates)
- OUI lookup populates vendor field automatically
- Cloud provider lookup populates service field for external IPs
- Clean shutdown: signal handlers flush pending data before exit
"""

import logging
import os
import socket
import struct
import threading
import time
from datetime import timedelta
from typing import Callable

from .db import InfraDB
from .enrichment import identify_service, lookup_cloud, lookup_vendor
from .parsers.dhcp import extract_dhcp
from .parsers.dns import parse_dns_name
from .parsers.ipv6 import parse_ipv6, NH_ICMPV6, NH_TCP, NH_UDP
from .parsers.lldp import parse_lldp
from .parsers.mdns import parse_mdns
from .parsers.tls import extract_ja4, extract_sni

log = logging.getLogger(__name__)

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
ETH_LLDP = 0x88CC

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

FLUSH_INTERVAL = 5.0  # seconds


class CaptureEngine:
    """Sniffs raw frames and feeds parsed flows into the DB."""

    def __init__(
        self,
        db_path: str = "infra.db",
        interface: str | None = None,
        gateway: bool = False,
    ):
        self.db = InfraDB(db_path)
        self.interface = interface
        self.gateway_mode = gateway
        self.running = False
        self.packets = 0
        self.errors = 0
        self.t0 = 0.0

        self._flow_buf: list[dict] = []
        self._flow_lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._gateway_thread: threading.Thread | None = None
        self._flush_thread: threading.Thread | None = None
        self._stop_evt = threading.Event()

    # ------------------------------------------------------------------
    def start(self, on_status: Callable[[str], None] | None = None) -> None:
        """Open the socket and run the capture loop until stop() is called."""
        self.running = True
        self.t0 = time.time()

        # ---- create socket -------------------------------------------------
        log.info("[CAPTURE] Creating raw socket...")
        try:
            self._sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )
            mode = "L2"
            if self.interface:
                self._sock.bind((self.interface, 0))
                log.info(f"[CAPTURE] Bound to interface {self.interface}")
            log.info("[CAPTURE] L2 raw socket created")
        except AttributeError:
            log.critical("[CAPTURE] AF_PACKET unavailable — Linux required")
            raise
        except PermissionError:
            log.critical(
                "[CAPTURE] Permission denied. Run with sudo."
            )
            raise
        except OSError as e:
            log.critical(f"[CAPTURE] Socket error: {e}")
            raise

        self._sock.settimeout(1.0)

        # ---- start workers -------------------------------------------------
        self._flush_thread = threading.Thread(
            target=self._flusher, name="flusher", daemon=True
        )
        self._flush_thread.start()
        log.info(f"[CAPTURE] Flush thread started ({FLUSH_INTERVAL}s)")

        if self.gateway_mode:
            from .gateway import ArpGatewayThread
            self._gateway_thread = ArpGatewayThread(self.interface, self._stop_evt)
            self._gateway_thread.start()

        mode_name = (
            "GATEWAY (all traffic via ARP MITM)"
            if self.gateway_mode
            else "PASSIVE (broadcasts + own traffic)"
        )
        if on_status:
            on_status(
                f"  Mode: {mode_name} | Socket: {mode} | "
                f"Interface: {self.interface or 'all'}"
            )
            on_status("  Listening...\n")
        log.info(f"[CAPTURE] Started. Mode={mode_name}")

        # ---- main loop -----------------------------------------------------
        while self.running:
            try:
                raw, _ = self._sock.recvfrom(65535)
                self._process_packet(raw)
                self.packets += 1

                # Periodic status line every 5000 packets
                if on_status and self.packets % 5000 == 0:
                    elapsed = timedelta(seconds=int(time.time() - self.t0))
                    on_status(
                        f"  {self.packets:>10,} pkts | "
                        f"{self.db.count('devices'):>4} devs | "
                        f"{self.db.count_distinct_sni():>4} domains | "
                        f"{self.db.count('flows'):>8,} flows | "
                        f"{self.errors} errs | {elapsed}"
                    )
            except socket.timeout:
                continue
            except Exception as e:
                self.errors += 1
                if self.errors <= 10:
                    log.error(f"[CAPTURE] Recv error #{self.errors}: {e}")

        # ---- shutdown ------------------------------------------------------
        log.info("[CAPTURE] Main loop exited, cleaning up...")
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        self._flush_flows()
        self.db.flush_devices()
        if self._gateway_thread and self._gateway_thread.is_alive():
            log.info("[CAPTURE] Waiting for gateway thread to restore ARP...")
            self._gateway_thread.join(timeout=15)
        self.db.close()
        log.info(
            f"[CAPTURE] Stopped. {self.packets:,} packets, {self.errors} errors"
        )

    def stop(self) -> None:
        """Request graceful shutdown."""
        log.info("[CAPTURE] Stop requested")
        self.running = False
        self._stop_evt.set()

    # ------------------------------------------------------------------
    def _flusher(self) -> None:
        while self.running:
            time.sleep(FLUSH_INTERVAL)
            self._flush_flows()
            self.db.flush_devices()

    def _flush_flows(self) -> None:
        with self._flow_lock:
            if not self._flow_buf:
                return
            batch = self._flow_buf
            self._flow_buf = []
        self.db.insert_flows(batch)

    # ------------------------------------------------------------------
    # Packet processing
    # ------------------------------------------------------------------
    def _process_packet(self, raw: bytes) -> None:
        """Dispatch a raw frame through ethernet/IP/transport/app layers."""
        try:
            if len(raw) < 14:
                return

            # Ethernet header
            src_mac = raw[6:12].hex(":")
            eth_type = struct.unpack("!H", raw[12:14])[0]
            eth_off = 14
            vlan = 0

            # 802.1Q VLAN tag
            if eth_type == ETH_VLAN and len(raw) >= 18:
                vlan = struct.unpack("!H", raw[14:16])[0] & 0x0FFF
                eth_type = struct.unpack("!H", raw[16:18])[0]
                eth_off = 18

            # LLDP — switches announce themselves
            if eth_type == ETH_LLDP:
                lldp_info = parse_lldp(raw[eth_off:])
                if lldp_info:
                    vendor = lookup_vendor(src_mac)
                    self.db.buffer_device(
                        f"switch:{src_mac}",
                        mac=src_mac,
                        vendor=vendor,
                        lldp=lldp_info,
                    )
                return

            # ARP — passively learn MAC<->IP mappings
            if eth_type == ETH_ARP and len(raw) >= eth_off + 28:
                self._process_arp(raw, eth_off)
                return

            # IPv4
            if eth_type == ETH_IPV4:
                self._process_ipv4(raw, eth_off, vlan, src_mac)
                return

            # IPv6
            if eth_type == ETH_IPV6:
                self._process_ipv6(raw, eth_off, vlan, src_mac)
                return

            # Other protocols (LLDP non-standard EtherTypes, STP, etc.) — ignored

        except Exception as e:
            self.errors += 1
            if self.errors <= 20:
                log.debug(f"[PACKET] error: {e}")

    def _process_arp(self, raw: bytes, eth_off: int) -> None:
        try:
            sender_mac = raw[eth_off + 8:eth_off + 14].hex(":")
            sender_ip = socket.inet_ntoa(raw[eth_off + 14:eth_off + 18])
            vendor = lookup_vendor(sender_mac)
            self.db.buffer_device(sender_ip, mac=sender_mac, vendor=vendor)
        except (OSError, IndexError):
            pass

    def _process_ipv4(self, raw: bytes, eth_off: int, vlan: int, src_mac: str) -> None:
        if len(raw) < eth_off + 20:
            return
        iph = struct.unpack("!BBHHHBBH4s4s", raw[eth_off:eth_off + 20])
        ihl = (iph[0] & 0xF) * 4
        total_length = iph[2]
        ttl = iph[5]
        protocol_num = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        transport_off = eth_off + ihl
        self._process_transport(
            raw=raw,
            transport_off=transport_off,
            protocol_num=protocol_num,
            src_ip=src_ip,
            dst_ip=dst_ip,
            ttl=ttl,
            total_length=total_length,
            vlan=vlan,
            src_mac=src_mac,
            family=4,
        )

    def _process_ipv6(self, raw: bytes, eth_off: int, vlan: int, src_mac: str) -> None:
        info = parse_ipv6(raw, eth_off)
        if not info:
            return
        # IPv6 has no "TTL" but Hop Limit serves the same purpose
        self._process_transport(
            raw=raw,
            transport_off=info["payload_offset"],
            protocol_num=info["proto_num"],
            src_ip=info["src"],
            dst_ip=info["dst"],
            ttl=info["hop_limit"],
            total_length=info["payload_len"] + 40,
            vlan=vlan,
            src_mac=src_mac,
            family=6,
        )

    def _process_transport(
        self,
        raw: bytes,
        transport_off: int,
        protocol_num: int,
        src_ip: str,
        dst_ip: str,
        ttl: int,
        total_length: int,
        vlan: int,
        src_mac: str,
        family: int,
    ) -> None:
        src_port = dst_port = 0
        proto = "other"
        app_off = transport_off

        if protocol_num == PROTO_TCP and len(raw) >= transport_off + 20:
            src_port, dst_port = struct.unpack(
                "!HH", raw[transport_off:transport_off + 4]
            )
            # TCP data offset is in 4-byte units, in the upper 4 bits of byte 12
            data_off = (raw[transport_off + 12] >> 4) * 4
            app_off = transport_off + data_off
            proto = "tcp"
        elif protocol_num == PROTO_UDP and len(raw) >= transport_off + 8:
            src_port, dst_port = struct.unpack(
                "!HH", raw[transport_off:transport_off + 4]
            )
            app_off = transport_off + 8
            proto = "udp"
        elif protocol_num == PROTO_ICMP:
            proto = "icmp"
        elif protocol_num == NH_ICMPV6:
            proto = "icmp6"

        app_data = raw[app_off:] if len(raw) > app_off else b""

        # ---- Application-layer parsing -----------------------------------
        sni = ""
        ja4 = ""
        if app_data and len(app_data) > 5 and app_data[0] == 0x16:
            sni = extract_sni(app_data)
            ja4 = extract_ja4(app_data)

        dhcp_hostname = ""
        dhcp_fp = ""
        if dst_port in (67, 68) and app_data:
            dhcp_hostname, dhcp_fp = extract_dhcp(app_data)

        mdns_svcs = ""
        if dst_port == 5353 and app_data:
            found = parse_mdns(app_data, src_ip)
            if found:
                mdns_svcs = ",".join(found)

        hostname_from_proto = ""
        if dst_port in (5355, 137) and app_data:
            hostname_from_proto = parse_dns_name(app_data)

        dns = ""
        if dst_port == 53 and app_data:
            dns = parse_dns_name(app_data)

        http_host = ""
        if dst_port in (80, 8080, 8000) and len(app_data) >= 4 and app_data[:4] in (
            b"GET ", b"POST", b"PUT ", b"HEAD"
        ):
            try:
                head = app_data[:1500].decode("ascii", errors="ignore")
                for line in head.split("\r\n"):
                    if line.lower().startswith("host:"):
                        http_host = line[5:].strip()
                        break
            except UnicodeDecodeError:
                pass

        # Service identification: SaaS catalog -> ports -> cloud lookup
        service = identify_service(dst_port, sni, dns, http_host)
        if not service:
            service = lookup_cloud(dst_ip)

        # ---- Build and buffer the flow ----------------------------------
        flow = {
            "ts": time.time(),
            "src": src_ip, "dst": dst_ip,
            "sp": src_port, "dp": dst_port,
            "proto": proto, "bytes": total_length,
            "sni": sni, "dns": dns, "http": http_host,
            "ja4": ja4, "svc": service,
            "ttl": ttl, "vlan": vlan, "family": family,
        }
        with self._flow_lock:
            self._flow_buf.append(flow)

        # ---- Update device registry (buffered, not synchronous) ---------
        best_hostname = dhcp_hostname or hostname_from_proto
        vendor = lookup_vendor(src_mac) if src_mac else ""
        self.db.buffer_device(
            src_ip,
            mac=src_mac,
            vendor=vendor,
            hostname=best_hostname,
            dhcp_fp=dhcp_fp,
            mdns=mdns_svcs,
        )
