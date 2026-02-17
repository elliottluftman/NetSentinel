"""SQLite database storage for packets, alerts, and analytics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
import sqlite3
import threading
from typing import Any

logger = logging.getLogger(__name__)


class NetSentinelDB:
    """Thread-safe SQLite wrapper for NetSentinel data."""

    def __init__(self, db_path: str) -> None:
        """Create SQLite connection and initialize tables."""
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._packet_insert_count = 0
        self._closed = False

        self._initialize()

    def _initialize(self) -> None:
        """Create required tables and indexes when absent."""
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT,
                    src_port INTEGER,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    size INTEGER,
                    flags TEXT,
                    dns_query TEXT,
                    summary TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    target_ip TEXT,
                    description TEXT NOT NULL,
                    details_json TEXT NOT NULL
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)")
            self.conn.commit()

    def store_packet(self, packet_dict: dict[str, Any]) -> None:
        """Insert one packet row and periodically prune old packet records."""
        with self.lock:
            if self._closed:
                return
            self.conn.execute(
                """
                INSERT INTO packets (
                    timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                    size, flags, dns_query, summary
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet_dict.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    packet_dict.get("src_ip"),
                    packet_dict.get("src_port"),
                    packet_dict.get("dst_ip"),
                    packet_dict.get("dst_port"),
                    packet_dict.get("protocol"),
                    packet_dict.get("size", 0),
                    packet_dict.get("flags"),
                    packet_dict.get("dns_query"),
                    packet_dict.get("summary"),
                ),
            )
            self.conn.commit()

            self._packet_insert_count += 1
            if self._packet_insert_count % 100 == 0:
                self._prune_old_packets()

    def store_alert(self, alert_dict: dict[str, Any]) -> None:
        """Insert one alert row if it does not already exist."""
        with self.lock:
            if self._closed:
                return
            self.conn.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    id, timestamp, alert_type, severity, source_ip,
                    target_ip, description, details_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_dict["id"],
                    alert_dict["timestamp"],
                    alert_dict["alert_type"],
                    alert_dict["severity"],
                    alert_dict.get("source_ip"),
                    alert_dict.get("target_ip"),
                    alert_dict["description"],
                    json.dumps(alert_dict.get("details", {}), sort_keys=True),
                ),
            )
            self.conn.commit()

    def get_recent_packets(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return newest packet entries up to limit."""
        limit = max(1, min(limit, 1000))
        with self.lock:
            if self._closed:
                return []
            rows = self.conn.execute(
                """
                SELECT timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                       size, flags, dns_query, summary
                FROM packets
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [dict(row) for row in rows]

    def get_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return newest alerts up to limit with parsed details."""
        limit = max(1, min(limit, 500))
        with self.lock:
            if self._closed:
                return []
            rows = self.conn.execute(
                """
                SELECT id, timestamp, alert_type, severity, source_ip,
                       target_ip, description, details_json
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        alerts: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["details"] = json.loads(item.pop("details_json"))
            alerts.append(item)
        return alerts

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate dashboard metrics and distributions."""
        now = datetime.now(timezone.utc)
        since_30s = (now - timedelta(seconds=30)).isoformat()

        with self.lock:
            if self._closed:
                return {
                    "total_packets": 0,
                    "total_alerts": 0,
                    "packets_per_second": 0,
                    "protocol_distribution": {},
                    "top_source_ips": [],
                    "top_destination_ips": [],
                    "alert_counts_by_type": {},
                }
            total_packets = self._fetch_value("SELECT COUNT(*) FROM packets")
            total_alerts = self._fetch_value("SELECT COUNT(*) FROM alerts")
            packets_30s = self._fetch_value(
                "SELECT COUNT(*) FROM packets WHERE timestamp >= ?", (since_30s,)
            )

            protocol_rows = self.conn.execute(
                """
                SELECT COALESCE(protocol, 'Other') AS protocol, COUNT(*) AS count
                FROM packets
                GROUP BY protocol
                ORDER BY count DESC
                """
            ).fetchall()

            top_sources = self.conn.execute(
                """
                SELECT src_ip, COUNT(*) AS count
                FROM packets
                WHERE src_ip IS NOT NULL
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 10
                """
            ).fetchall()

            top_destinations = self.conn.execute(
                """
                SELECT dst_ip, COUNT(*) AS count
                FROM packets
                WHERE dst_ip IS NOT NULL
                GROUP BY dst_ip
                ORDER BY count DESC
                LIMIT 10
                """
            ).fetchall()

            alert_counts = self.conn.execute(
                """
                SELECT alert_type, COUNT(*) AS count
                FROM alerts
                GROUP BY alert_type
                ORDER BY count DESC
                """
            ).fetchall()

        packets_per_second = round(packets_30s / 30.0, 2)

        return {
            "total_packets": total_packets,
            "total_alerts": total_alerts,
            "packets_per_second": packets_per_second,
            "protocol_distribution": {row["protocol"]: row["count"] for row in protocol_rows},
            "top_source_ips": [dict(row) for row in top_sources],
            "top_destination_ips": [dict(row) for row in top_destinations],
            "alert_counts_by_type": {row["alert_type"]: row["count"] for row in alert_counts},
        }

    def _fetch_value(self, query: str, params: tuple[Any, ...] = ()) -> int:
        """Execute scalar COUNT-like query and return int value."""
        if self._closed:
            return 0
        row = self.conn.execute(query, params).fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    def _prune_old_packets(self) -> None:
        """Delete packet rows older than one hour to prevent unbounded growth."""
        if self._closed:
            return
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self.conn.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
        self.conn.commit()

    def close(self) -> None:
        """Close SQLite connection."""
        with self.lock:
            if self._closed:
                return
            self._closed = True
            self.conn.close()
            logger.info("SQLite connection closed")
