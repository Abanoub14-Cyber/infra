"""SQLite layer with WAL mode, long-lived connection, and batched writes.

This module replaces the original per-call open/close pattern that caused
'database is locked' errors under concurrent writers (capture loop +
flush thread + device upsert on every packet).

Design:
- ONE connection, opened once, closed at shutdown.
- WAL journal mode -> readers don't block writers.
- check_same_thread=False + a single threading.Lock around all writes.
- Devices and flows are buffered in-memory and flushed in batches.
- DB file is chmod'd to 0600 (sensitive metadata).
"""

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    sp INTEGER DEFAULT 0,
    dp INTEGER DEFAULT 0,
    proto TEXT DEFAULT '',
    bytes INTEGER DEFAULT 0,
    sni TEXT DEFAULT '',
    dns TEXT DEFAULT '',
    http TEXT DEFAULT '',
    ja4 TEXT DEFAULT '',
    svc TEXT DEFAULT '',
    ttl INTEGER DEFAULT 0,
    vlan INTEGER DEFAULT 0,
    family INTEGER DEFAULT 4
);

CREATE TABLE IF NOT EXISTS devices (
    ip TEXT PRIMARY KEY,
    mac TEXT DEFAULT '',
    vendor TEXT DEFAULT '',
    hostname TEXT DEFAULT '',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    dhcp_fp TEXT DEFAULT '',
    mdns TEXT DEFAULT '',
    lldp TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS i_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS i_flows_src ON flows(src);
CREATE INDEX IF NOT EXISTS i_flows_dst ON flows(dst);
CREATE INDEX IF NOT EXISTS i_flows_sni ON flows(sni);
CREATE INDEX IF NOT EXISTS i_flows_dp ON flows(dp);
"""


class InfraDB:
    """Thread-safe SQLite wrapper with batched writes."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._device_buf: dict[str, dict] = {}  # ip -> aggregated fields
        self._device_lock = threading.Lock()

        is_new = not Path(path).exists()
        log.info(f"[DB] Opening database at {path}")

        # check_same_thread=False because we're explicitly synchronizing via _lock.
        # timeout=30 so writers wait rather than fail under contention.
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30.0)

        # WAL is the key improvement: concurrent readers + 1 writer without locking.
        # synchronous=NORMAL is safe with WAL and ~5x faster than FULL.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

        if is_new:
            try:
                os.chmod(path, 0o600)
                log.info(f"[DB] File permissions set to 0600 (owner-only)")
            except OSError as e:
                log.warning(f"[DB] Could not chmod 0600: {e}")

        log.info("[DB] Database ready (WAL mode)")

    # ------------------------------------------------------------------
    # Flows: buffered externally (in CaptureEngine), inserted in batches
    # ------------------------------------------------------------------
    def insert_flows(self, flows: Iterable[dict]) -> int:
        flows = list(flows)
        if not flows:
            return 0

        rows = [
            (
                f["ts"], f["src"], f["dst"], f.get("sp", 0), f.get("dp", 0),
                f.get("proto", ""), f.get("bytes", 0), f.get("sni", ""),
                f.get("dns", ""), f.get("http", ""), f.get("ja4", ""),
                f.get("svc", ""), f.get("ttl", 0), f.get("vlan", 0),
                f.get("family", 4),
            )
            for f in flows
        ]
        try:
            with self._lock:
                self.conn.executemany(
                    "INSERT INTO flows(ts,src,dst,sp,dp,proto,bytes,sni,dns,http,"
                    "ja4,svc,ttl,vlan,family) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    rows,
                )
                self.conn.commit()
            log.debug(f"[DB] Inserted {len(rows)} flows")
            return len(rows)
        except sqlite3.Error as e:
            log.error(f"[DB] Insert failed for {len(rows)} flows: {e}")
            return 0

    # ------------------------------------------------------------------
    # Devices: in-memory aggregation, periodic flush
    # ------------------------------------------------------------------
    def buffer_device(
        self,
        ip: str,
        mac: str = "",
        vendor: str = "",
        hostname: str = "",
        dhcp_fp: str = "",
        mdns: str = "",
        lldp: str = "",
    ) -> None:
        """Aggregate device updates in memory; flush_devices() persists them."""
        if not ip or ip.startswith(("0.", "255.", "224.", "239.")):
            return
        with self._device_lock:
            d = self._device_buf.setdefault(ip, {
                "first_seen": time.time(),
                "last_seen": time.time(),
                "mac": "", "vendor": "", "hostname": "",
                "dhcp_fp": "", "mdns": set(), "lldp": "",
            })
            d["last_seen"] = time.time()
            if mac and not d["mac"]:
                d["mac"] = mac
            if vendor and not d["vendor"]:
                d["vendor"] = vendor
            if hostname and not d["hostname"]:
                d["hostname"] = hostname
            if dhcp_fp and not d["dhcp_fp"]:
                d["dhcp_fp"] = dhcp_fp
            if mdns:
                d["mdns"].add(mdns)
            if lldp and not d["lldp"]:
                d["lldp"] = lldp

    def flush_devices(self) -> int:
        """Persist buffered devices via UPSERT. Called periodically."""
        with self._device_lock:
            if not self._device_buf:
                return 0
            snapshot = self._device_buf
            self._device_buf = {}

        try:
            with self._lock:
                for ip, d in snapshot.items():
                    mdns_str = ",".join(sorted(d["mdns"])) if d["mdns"] else ""
                    self.conn.execute(
                        """
                        INSERT INTO devices(ip,mac,vendor,hostname,first_seen,
                            last_seen,dhcp_fp,mdns,lldp)
                        VALUES(?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(ip) DO UPDATE SET
                            last_seen = excluded.last_seen,
                            mac      = CASE WHEN devices.mac      = '' THEN excluded.mac      ELSE devices.mac      END,
                            vendor   = CASE WHEN devices.vendor   = '' THEN excluded.vendor   ELSE devices.vendor   END,
                            hostname = CASE WHEN devices.hostname = '' THEN excluded.hostname ELSE devices.hostname END,
                            dhcp_fp  = CASE WHEN devices.dhcp_fp  = '' THEN excluded.dhcp_fp  ELSE devices.dhcp_fp  END,
                            lldp     = CASE WHEN devices.lldp     = '' THEN excluded.lldp     ELSE devices.lldp     END,
                            mdns     = CASE
                                WHEN devices.mdns = '' THEN excluded.mdns
                                WHEN excluded.mdns = '' THEN devices.mdns
                                ELSE devices.mdns || ',' || excluded.mdns
                            END
                        """,
                        (ip, d["mac"], d["vendor"], d["hostname"],
                         d["first_seen"], d["last_seen"],
                         d["dhcp_fp"], mdns_str, d["lldp"]),
                    )
                self.conn.commit()
            log.debug(f"[DB] Upserted {len(snapshot)} devices")
            return len(snapshot)
        except sqlite3.Error as e:
            log.error(f"[DB] Device flush failed: {e}")
            # Re-buffer so we don't lose data
            with self._device_lock:
                for ip, d in snapshot.items():
                    if ip not in self._device_buf:
                        self._device_buf[ip] = d
            return 0

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------
    def count(self, table: str) -> int:
        if table not in ("flows", "devices"):
            raise ValueError(f"Invalid table: {table}")
        try:
            with self._lock:
                return self.conn.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
        except sqlite3.Error:
            return 0

    def count_distinct_sni(self) -> int:
        try:
            with self._lock:
                return self.conn.execute(
                    "SELECT COUNT(DISTINCT sni) FROM flows WHERE sni != ''"
                ).fetchone()[0]
        except sqlite3.Error:
            return 0

    def time_range(self) -> tuple[float | None, float | None]:
        try:
            with self._lock:
                row = self.conn.execute(
                    "SELECT MIN(ts), MAX(ts) FROM flows"
                ).fetchone()
            return row if row else (None, None)
        except sqlite3.Error:
            return None, None

    def close(self) -> None:
        """Flush pending devices and close connection."""
        try:
            self.flush_devices()
            with self._lock:
                self.conn.close()
            log.info("[DB] Closed cleanly")
        except sqlite3.Error as e:
            log.error(f"[DB] Close error: {e}")
