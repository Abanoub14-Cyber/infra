"""Unit tests for parsers — run without root, without network.

Run:
    cd infra/
    python3 -m pytest tests/ -v

Or without pytest:
    python3 tests/test_parsers.py
"""

import struct
import sys
import unittest
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from infra.parsers.tls import extract_sni, extract_ja4
from infra.parsers.dhcp import extract_dhcp
from infra.parsers.dns import parse_dns_name
from infra.parsers.mdns import parse_mdns
from infra.parsers.lldp import parse_lldp
from infra.parsers.ipv6 import parse_ipv6
from infra.enrichment import (
    lookup_vendor, lookup_cloud, identify_service, is_private_ip,
)


# ---------------------------------------------------------------------------
# TLS tests — uses a hand-crafted minimal ClientHello with SNI=example.com
# ---------------------------------------------------------------------------
def _build_clienthello(sni: bytes = b"example.com") -> bytes:
    """Build a minimal but valid TLS 1.2 ClientHello with optional SNI."""
    # Body: client_version(2) + random(32) + session_id_len(1)=0
    #       + cipher_suites_len(2)=2 + ciphers(2)=0xc02f
    #       + compression_len(1)=1 + compression(1)=0
    #       + extensions_len(2) + extensions
    sni_ext_inner = b"\x00" + len(sni).to_bytes(2, "big") + sni  # name_type=0 + len + name
    sni_list = len(sni_ext_inner).to_bytes(2, "big") + sni_ext_inner
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

    extensions = sni_ext if sni else b""
    body = (
        b"\x03\x03"               # client_version TLS 1.2
        + b"\x00" * 32             # random
        + b"\x00"                  # session_id_len
        + b"\x00\x02\xc0\x2f"      # cipher_suites_len + 1 cipher
        + b"\x01\x00"              # compression
        + len(extensions).to_bytes(2, "big") + extensions
    )

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
    return record


class TestTLS(unittest.TestCase):

    def test_sni_present(self):
        ch = _build_clienthello(b"example.com")
        self.assertEqual(extract_sni(ch), "example.com")

    def test_sni_absent(self):
        ch = _build_clienthello(b"")
        self.assertEqual(extract_sni(ch), "")

    def test_sni_garbage(self):
        self.assertEqual(extract_sni(b"not tls"), "")
        self.assertEqual(extract_sni(b""), "")
        self.assertEqual(extract_sni(b"\x16" + b"\x00" * 100), "")

    def test_ja4_format(self):
        ch = _build_clienthello(b"example.com")
        ja4 = extract_ja4(ch)
        # Format: txxdxxxxYY_<12hex>_<12hex>
        self.assertTrue(ja4.startswith("t"), f"got {ja4!r}")
        parts = ja4.split("_")
        self.assertEqual(len(parts), 3, f"got {ja4!r}")
        self.assertEqual(len(parts[1]), 12)
        self.assertEqual(len(parts[2]), 12)


# ---------------------------------------------------------------------------
# DHCP tests
# ---------------------------------------------------------------------------
class TestDHCP(unittest.TestCase):

    def _build_dhcp(self, hostname: bytes = b"", vendor: bytes = b"", prl: bytes = b"") -> bytes:
        """Build a minimal valid DHCP packet payload."""
        bootp = b"\x00" * 236  # zeroed BOOTP header
        magic = b"\x63\x82\x53\x63"
        options = b""
        if hostname:
            options += b"\x0c" + len(hostname).to_bytes(1, "big") + hostname
        if vendor:
            options += b"\x3c" + len(vendor).to_bytes(1, "big") + vendor
        if prl:
            options += b"\x37" + len(prl).to_bytes(1, "big") + prl
        options += b"\xff"
        return bootp + magic + options

    def test_hostname(self):
        pkt = self._build_dhcp(hostname=b"my-laptop")
        hn, fp = extract_dhcp(pkt)
        self.assertEqual(hn, "my-laptop")

    def test_vendor_msft(self):
        pkt = self._build_dhcp(vendor=b"MSFT 5.0")
        _, fp = extract_dhcp(pkt)
        self.assertIn("Windows", fp)

    def test_vendor_android(self):
        pkt = self._build_dhcp(vendor=b"android-dhcp-13")
        _, fp = extract_dhcp(pkt)
        self.assertIn("Android", fp)

    def test_garbage(self):
        self.assertEqual(extract_dhcp(b""), ("", ""))
        self.assertEqual(extract_dhcp(b"X" * 300), ("", ""))


# ---------------------------------------------------------------------------
# DNS tests
# ---------------------------------------------------------------------------
class TestDNS(unittest.TestCase):

    def test_simple_name(self):
        # DNS header (12 bytes) + qname: 7example3com0
        pkt = b"\x00" * 12 + b"\x07example\x03com\x00\x00\x01\x00\x01"
        self.assertEqual(parse_dns_name(pkt), "example.com")

    def test_subdomain(self):
        pkt = b"\x00" * 12 + b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
        self.assertEqual(parse_dns_name(pkt), "www.example.com")

    def test_truncated(self):
        self.assertEqual(parse_dns_name(b"\x00" * 12 + b"\x07exa"), "")


# ---------------------------------------------------------------------------
# mDNS tests
# ---------------------------------------------------------------------------
class TestMDNS(unittest.TestCase):

    def test_response_with_printer(self):
        # Header: response flag set
        flags = (1 << 15).to_bytes(2, "big")
        pkt = b"\x00\x00" + flags + b"\x00" * 8 + b"_printer._tcp.local"
        services = parse_mdns(pkt, "192.168.1.5")
        self.assertIn("_printer._tcp", services)

    def test_query_ignored(self):
        # QR bit = 0 -> query, should return []
        pkt = b"\x00\x00\x00\x00" + b"\x00" * 8 + b"_printer._tcp.local"
        self.assertEqual(parse_mdns(pkt, "1.1.1.1"), [])


# ---------------------------------------------------------------------------
# LLDP tests
# ---------------------------------------------------------------------------
class TestLLDP(unittest.TestCase):

    def _tlv(self, tlv_type: int, data: bytes) -> bytes:
        hdr = (tlv_type << 9) | len(data)
        return struct.pack("!H", hdr) + data

    def test_basic(self):
        # Chassis ID (subtype 4 = MAC) + Port ID + System Name + End
        chassis = self._tlv(1, b"\x04\xaa\xbb\xcc\xdd\xee\xff")
        port = self._tlv(2, b"\x05GigabitEthernet1/0/24")
        name = self._tlv(5, b"core-switch-01")
        end = self._tlv(0, b"")
        info = parse_lldp(chassis + port + name + end)
        self.assertIn("core-switch-01", info)
        self.assertIn("aa:bb:cc:dd:ee:ff", info)


# ---------------------------------------------------------------------------
# IPv6 tests
# ---------------------------------------------------------------------------
class TestIPv6(unittest.TestCase):

    def test_basic(self):
        # version=6, traffic=0, flow=0, payload_len=20, next=6 (TCP), hop=64
        ver_tc_fl = (6 << 28).to_bytes(4, "big")
        hdr = (
            ver_tc_fl
            + (20).to_bytes(2, "big")  # payload len
            + b"\x06"                    # next header = TCP
            + b"\x40"                    # hop limit = 64
            + b"\x20\x01\x0d\xb8" + b"\x00" * 12  # src 2001:db8::
            + b"\xfe\x80\x00\x00\x00\x00\x00\x00" + b"\x00" * 8  # dst fe80::
        )
        # Plus a fake 20-byte TCP header
        pkt = b"\x00" * 14 + hdr + b"\x00" * 20
        info = parse_ipv6(pkt, 14)
        self.assertIsNotNone(info)
        self.assertEqual(info["proto_num"], 6)
        self.assertEqual(info["family"], 6)
        self.assertTrue(info["src"].startswith("2001:db8"))


# ---------------------------------------------------------------------------
# Enrichment tests
# ---------------------------------------------------------------------------
class TestEnrichment(unittest.TestCase):

    def test_oui_apple(self):
        self.assertEqual(lookup_vendor("00:03:93:aa:bb:cc"), "Apple")

    def test_oui_raspberry(self):
        self.assertEqual(lookup_vendor("b8:27:eb:11:22:33"), "Raspberry Pi")

    def test_oui_unknown(self):
        self.assertEqual(lookup_vendor("ff:ff:ff:ff:ff:ff"), "")

    def test_oui_short(self):
        self.assertEqual(lookup_vendor(""), "")
        self.assertEqual(lookup_vendor("00:00"), "")

    def test_cloud_aws(self):
        self.assertEqual(lookup_cloud("3.5.140.10"), "AWS")

    def test_cloud_apple(self):
        self.assertEqual(lookup_cloud("17.253.144.10"), "Apple")

    def test_cloud_private(self):
        self.assertEqual(lookup_cloud("192.168.1.1"), "")

    def test_service_saas(self):
        self.assertEqual(identify_service(443, "slack.com"), "Slack")
        self.assertEqual(identify_service(443, "drive.google.com"), "Google Drive")

    def test_service_port_fallback(self):
        self.assertEqual(identify_service(22), "SSH")
        self.assertEqual(identify_service(3389), "RDP")
        self.assertEqual(identify_service(502), "Modbus")  # OT support

    def test_private_ip(self):
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.1"))
        self.assertTrue(is_private_ip("172.16.5.5"))
        self.assertFalse(is_private_ip("8.8.8.8"))


# ---------------------------------------------------------------------------
# DB tests — requires temp file
# ---------------------------------------------------------------------------
class TestDB(unittest.TestCase):

    def test_full_cycle(self):
        import tempfile
        import time
        from infra.db import InfraDB

        with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as f:
            db_path = f.name
        # File is now deleted; create fresh
        db = InfraDB(db_path)
        try:
            # Insert a flow
            db.insert_flows([{
                "ts": time.time(), "src": "192.168.1.10", "dst": "1.1.1.1",
                "sp": 12345, "dp": 443, "proto": "tcp", "bytes": 1500,
                "sni": "example.com", "dns": "", "http": "",
                "ja4": "t13d1234abcd_aaa_bbb", "svc": "Cloudflare",
                "ttl": 64, "vlan": 0, "family": 4,
            }])
            self.assertEqual(db.count("flows"), 1)
            self.assertEqual(db.count_distinct_sni(), 1)

            # Buffer + flush devices
            db.buffer_device("192.168.1.10", mac="aa:bb:cc:11:22:33", vendor="Apple")
            db.flush_devices()
            self.assertEqual(db.count("devices"), 1)

            # Time range
            first, last = db.time_range()
            self.assertIsNotNone(first)
        finally:
            db.close()
            Path(db_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
