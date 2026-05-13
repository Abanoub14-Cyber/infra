"""Intelligence engine — turns raw flows into a business-readable report.

Improvements over original:
- Schedule detection uses statistical regularity (CoV) instead of narrow ranges
- Business hours are computed in the LOCAL timezone (was UTC before)
- Adds external/internal flow split, top destinations, IPv6/IPv4 split
- Anomaly detection includes new heuristics (rare ports, scanning behavior)
- Device role inference is more nuanced
"""

import logging
import sqlite3
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .enrichment import is_private_ip

log = logging.getLogger(__name__)


class IntelligenceEngine:
    def __init__(self, db_path: str):
        self.path = db_path
        if not Path(db_path).exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
        # Read-only connection — no writes during analysis
        self.conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    def __del__(self):
        try:
            self.conn.close()
        except (sqlite3.Error, AttributeError):
            pass

    # ------------------------------------------------------------------
    def analyze(self) -> dict:
        log.info("[INTEL] Starting analysis")
        c = self.conn

        meta = self._meta(c)
        log.info(
            f"[INTEL] {meta['flows']:,} flows, {meta['devices']} devices, "
            f"{meta['hours']}h capture"
        )

        report = {
            "meta": meta,
            "devices": self._devices(c),
            "saas_inventory": self._saas(c),
            "data_flows": self._flows(c),
            "recurring_patterns": self._patterns(c),
            "critical_dependencies": self._deps(c),
            "anomalies": self._anomalies(c),
            "business_hours": self._hours(c),
            "network_topology": self._topology(c),
            "ja4_applications": self._ja4(c),
            "external_destinations": self._external_destinations(c),
            "ipv4_vs_ipv6": self._family_split(c),
        }
        log.info("[INTEL] Analysis complete")
        return report

    # ------------------------------------------------------------------
    def _meta(self, c) -> dict:
        first, last = c.execute(
            "SELECT MIN(ts), MAX(ts) FROM flows"
        ).fetchone() or (None, None)
        return {
            "start": datetime.fromtimestamp(first).isoformat() if first else "",
            "end": datetime.fromtimestamp(last).isoformat() if last else "",
            "hours": round((last - first) / 3600, 2) if first and last else 0,
            "flows": c.execute("SELECT COUNT(*) FROM flows").fetchone()[0],
            "devices": c.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "bytes": c.execute(
                "SELECT COALESCE(SUM(bytes),0) FROM flows"
            ).fetchone()[0],
            "report_generated": datetime.now().isoformat(),
        }

    def _devices(self, c) -> list[dict]:
        rows = c.execute("SELECT * FROM devices").fetchall()
        cols = [d[0] for d in c.execute("SELECT * FROM devices LIMIT 0").description]
        devices = []
        for row in rows:
            d = dict(zip(cols, row))
            ip = d["ip"]

            sent_bytes, sent_count = c.execute(
                "SELECT COALESCE(SUM(bytes),0), COUNT(*) FROM flows WHERE src=?",
                (ip,),
            ).fetchone() or (0, 0)
            recv_bytes, recv_count = c.execute(
                "SELECT COALESCE(SUM(bytes),0), COUNT(*) FROM flows WHERE dst=?",
                (ip,),
            ).fetchone() or (0, 0)
            in_peers = c.execute(
                "SELECT COUNT(DISTINCT src) FROM flows WHERE dst=?", (ip,)
            ).fetchone()[0]
            out_peers = c.execute(
                "SELECT COUNT(DISTINCT dst) FROM flows WHERE src=?", (ip,)
            ).fetchone()[0]
            server_ports = c.execute(
                "SELECT COUNT(DISTINCT dp) FROM flows WHERE dst=? "
                "AND dp IN (22,25,80,389,443,445,1433,3306,3389,5432,8080)",
                (ip,),
            ).fetchone()[0]
            top_sni = c.execute(
                "SELECT sni, COUNT(*) n FROM flows WHERE src=? AND sni!='' "
                "GROUP BY sni ORDER BY n DESC LIMIT 10",
                (ip,),
            ).fetchall()

            # Role inference — more nuanced than original
            if server_ports >= 2 or (in_peers > 5 and in_peers > out_peers * 2):
                role = "server"
            elif out_peers > in_peers and sent_count > 10:
                role = "workstation"
            elif in_peers == 0 and out_peers <= 2:
                role = "endpoint"
            elif in_peers > 0 and out_peers <= 2:
                role = "infrastructure"
            else:
                role = "unknown"

            devices.append({
                **d,
                "role": role,
                "bytes_sent": sent_bytes,
                "bytes_received": recv_bytes,
                "connections_out": sent_count,
                "connections_in": recv_count,
                "unique_peers_in": in_peers,
                "unique_peers_out": out_peers,
                "top_domains": [
                    {"domain": s, "count": n} for s, n in top_sni
                ],
            })
        return devices

    def _saas(self, c) -> list[dict]:
        return [
            {
                "domain": d, "service": svc or "Unknown",
                "connections": n, "unique_users": u, "bytes": b,
            }
            for d, svc, n, u, b in c.execute("""
                SELECT sni,
                       (SELECT svc FROM flows f2 WHERE f2.sni=flows.sni AND f2.svc!='' LIMIT 1) AS svc,
                       COUNT(*) n,
                       COUNT(DISTINCT src) u,
                       COALESCE(SUM(bytes),0)
                FROM flows
                WHERE sni != ''
                GROUP BY sni
                HAVING n > 3
                ORDER BY n DESC
            """).fetchall()
        ]

    def _flows(self, c) -> list[dict]:
        return [
            {"source": s, "target": d, "bytes": b, "connections": n,
             "services": (sv or "").split(",")}
            for s, d, b, n, sv in c.execute("""
                SELECT src, dst, COALESCE(SUM(bytes),0) b, COUNT(*) n,
                       GROUP_CONCAT(DISTINCT svc) sv
                FROM flows
                WHERE src != dst AND svc != ''
                GROUP BY src, dst
                HAVING n > 5
                ORDER BY b DESC
                LIMIT 100
            """).fetchall()
        ]

    def _patterns(self, c) -> list[dict]:
        """Detect recurring connections by statistical regularity."""
        patterns = []
        candidates = c.execute("""
            SELECT src, dst, dp, COUNT(*) n, AVG(bytes), MIN(ts), MAX(ts)
            FROM flows WHERE dp > 0
            GROUP BY src, dst, dp HAVING n > 10
            ORDER BY n DESC LIMIT 80
        """).fetchall()

        for src, dst, dp, cnt, avg_b, first_ts, last_ts in candidates:
            timestamps = [
                t[0] for t in c.execute(
                    "SELECT ts FROM flows WHERE src=? AND dst=? AND dp=? ORDER BY ts",
                    (src, dst, dp),
                ).fetchall()
            ]
            schedule = self._classify_schedule(timestamps)
            if schedule["regular"]:
                patterns.append({
                    "source": src, "target": dst, "port": dp,
                    "schedule_label": schedule["label"],
                    "median_interval_seconds": schedule["median_s"],
                    "regularity_score": schedule["score"],
                    "occurrences": cnt,
                    "avg_bytes": int(avg_b or 0),
                    "first_seen": datetime.fromtimestamp(first_ts).isoformat(),
                    "last_seen": datetime.fromtimestamp(last_ts).isoformat(),
                })
        return patterns

    @staticmethod
    def _classify_schedule(ts: list[float]) -> dict:
        """Statistical regularity detection.

        Uses coefficient of variation (CoV = stdev/mean) of intervals.
        - CoV < 0.3 → very regular (cron-like)
        - CoV < 0.7 → loosely regular
        - CoV >= 0.7 → irregular

        Returns {regular: bool, label: str, median_s: float, score: float}
        """
        if len(ts) < 5:
            return {"regular": False, "label": "too few samples", "median_s": 0, "score": 0}

        intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        if not intervals or min(intervals) <= 0:
            return {"regular": False, "label": "irregular", "median_s": 0, "score": 0}

        median = statistics.median(intervals)
        try:
            stdev = statistics.stdev(intervals)
        except statistics.StatisticsError:
            stdev = 0.0
        cov = stdev / median if median > 0 else 999

        regular = cov < 0.7

        # Human-readable label based on median interval
        if median < 60:
            label = "continuous"
        elif median < 600:
            label = f"every ~{int(median)}s"
        elif median < 3600:
            label = f"every ~{int(median // 60)}min"
        elif median < 86400:
            label = f"every ~{round(median / 3600, 1)}h"
        elif median < 604800:
            label = f"every ~{round(median / 86400, 1)}d"
        else:
            label = f"every ~{round(median / 604800, 1)}w"

        if not regular:
            label = f"{label} (irregular, CoV={cov:.2f})"

        return {
            "regular": regular, "label": label,
            "median_s": round(median, 2),
            "score": round(1 - min(cov, 1.0), 3),
        }

    def _deps(self, c) -> list[dict]:
        deps = []
        for server_ip, client_count in c.execute("""
            SELECT dst, COUNT(DISTINCT src) nc FROM flows WHERE dp > 0
            GROUP BY dst HAVING nc > 2 ORDER BY nc DESC LIMIT 30
        """).fetchall():
            services = [
                s[0] for s in c.execute(
                    "SELECT DISTINCT svc FROM flows WHERE dst=? AND svc != ''",
                    (server_ip,),
                ).fetchall()
            ]
            deps.append({
                "server": server_ip,
                "client_count": client_count,
                "services": services,
                "is_internal": is_private_ip(server_ip),
                "impact": (
                    f"If {server_ip} fails, {client_count} devices lose access "
                    f"to: {', '.join(services) if services else 'connectivity'}"
                ),
            })
        return deps

    def _anomalies(self, c) -> list[dict]:
        anomalies = []

        # 1. Night traffic (uses LOCAL timezone via SQLite's localtime modifier)
        for src, dst, sni, count, total_bytes in c.execute("""
            SELECT src, dst, sni, COUNT(*), COALESCE(SUM(bytes),0)
            FROM flows
            WHERE CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) NOT BETWEEN 7 AND 19
              AND dp NOT IN (53, 123, 5353, 5355, 137, 138, 0)
            GROUP BY src, dst HAVING COUNT(*) > 50
        """).fetchall():
            anomalies.append({
                "type": "night_activity", "severity": "medium",
                "description": (
                    f"{src} → {dst} ({sni or '?'}): {count} connections "
                    f"outside business hours"
                ),
                "bytes": total_bytes,
            })

        # 2. Large external transfers
        for src, dst, sni, total_bytes in c.execute("""
            SELECT src, dst, sni, COALESCE(SUM(bytes),0) FROM flows
            WHERE dst NOT LIKE '192.168.%' AND dst NOT LIKE '10.%'
              AND dst NOT LIKE '172.1_.%' AND dst NOT LIKE '172.2_.%'
              AND dst NOT LIKE 'fe80%' AND dst NOT LIKE 'fc%'
            GROUP BY src, dst HAVING SUM(bytes) > 50_000_000
            ORDER BY SUM(bytes) DESC
        """).fetchall():
            mb = total_bytes / 1_000_000
            anomalies.append({
                "type": "large_external_transfer",
                "severity": "high" if mb > 500 else "medium",
                "description": f"{src} sent {mb:.0f} MB to {sni or dst}",
                "bytes": total_bytes,
            })

        # 3. Scanning behavior (one source, many distinct destination ports)
        for src, distinct_ports in c.execute("""
            SELECT src, COUNT(DISTINCT dp) dp_count FROM flows
            WHERE dp > 0 GROUP BY src HAVING dp_count > 30
        """).fetchall():
            anomalies.append({
                "type": "port_scan_suspect", "severity": "high",
                "description": (
                    f"{src} contacted {distinct_ports} distinct ports — "
                    "possible internal scan or vulnerability scanner"
                ),
                "bytes": 0,
            })

        # 4. Suspicious legacy ports active
        for dp, count in c.execute("""
            SELECT dp, COUNT(*) FROM flows
            WHERE dp IN (23, 21, 110, 143, 1433, 3306, 5900, 6667)
            GROUP BY dp
        """).fetchall():
            anomalies.append({
                "type": "legacy_or_cleartext_port", "severity": "medium",
                "description": (
                    f"Port {dp} active ({count} flows) — cleartext or "
                    "legacy protocol exposed on the network"
                ),
                "bytes": 0,
            })

        return anomalies

    def _hours(self, c) -> dict:
        """Business hours in the LOCAL timezone of the capture host."""
        rows = c.execute("""
            SELECT CAST(strftime('%H', ts, 'unixepoch', 'localtime') AS INTEGER) h,
                   COUNT(*) n
            FROM flows GROUP BY h ORDER BY h
        """).fetchall()
        if not rows:
            return {}
        hourly = {int(h): int(n) for h, n in rows}
        peak = max(hourly, key=hourly.get)
        threshold = hourly[peak] * 0.15
        active = sorted(h for h, n in hourly.items() if n > threshold)
        return {
            "timezone": "local (capture host)",
            "start": f"{active[0]:02d}:00" if active else "?",
            "end": f"{active[-1]:02d}:00" if active else "?",
            "peak": f"{peak:02d}:00",
            "distribution": hourly,
        }

    def _topology(self, c) -> dict:
        vlans = [v[0] for v in c.execute(
            "SELECT DISTINCT vlan FROM flows WHERE vlan > 0"
        ).fetchall()]
        switches = [
            {"id": ip, "info": lldp}
            for ip, lldp in c.execute(
                "SELECT ip, lldp FROM devices WHERE lldp != ''"
            ).fetchall()
        ]
        return {"vlans": vlans, "switches": switches}

    def _ja4(self, c) -> list[dict]:
        from .parsers.tls import JA4_KNOWN
        return [
            {
                "ja4": j,
                "application": JA4_KNOWN.get(j, f"Unknown ({j[:18]}...)"),
                "connections": n,
            }
            for j, n in c.execute(
                "SELECT ja4, COUNT(*) n FROM flows WHERE ja4 != '' "
                "GROUP BY ja4 ORDER BY n DESC LIMIT 30"
            ).fetchall()
        ]

    def _external_destinations(self, c) -> list[dict]:
        """Top external IPs by bytes — useful for quick triage."""
        return [
            {"ip": ip, "service": svc or "Unknown", "bytes": b, "connections": n}
            for ip, svc, b, n in c.execute("""
                SELECT dst,
                       (SELECT svc FROM flows f2 WHERE f2.dst=flows.dst AND f2.svc!='' LIMIT 1) AS svc,
                       COALESCE(SUM(bytes),0) b, COUNT(*) n
                FROM flows
                WHERE dst NOT LIKE '192.168.%' AND dst NOT LIKE '10.%'
                  AND dst NOT LIKE '172.1_.%' AND dst NOT LIKE '172.2_.%'
                  AND dst NOT LIKE 'fe80%' AND dst NOT LIKE 'fc%'
                  AND dst NOT LIKE '224.%' AND dst NOT LIKE 'ff02%'
                GROUP BY dst
                ORDER BY b DESC LIMIT 50
            """).fetchall()
        ]

    def _family_split(self, c) -> dict:
        rows = c.execute(
            "SELECT family, COUNT(*) n, COALESCE(SUM(bytes),0) b "
            "FROM flows GROUP BY family"
        ).fetchall()
        return {
            f"ipv{family}": {"flows": n, "bytes": b} for family, n, b in rows
        }
