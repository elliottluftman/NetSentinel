"""Threat detection engine for NetSentinel."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
import ipaddress
import time
import uuid
from typing import Any


class ThreatAnalyzer:
    """Analyzes packet dictionaries and returns matching threat alerts."""

    def __init__(self, thresholds: dict[str, Any]) -> None:
        """Initialize analyzer state using threshold configuration."""
        self.thresholds = thresholds

        self.port_history: dict[str, deque[tuple[float, int, str]]] = defaultdict(deque)
        self.bruteforce_history: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)
        self.exfil_history: dict[str, deque[tuple[float, int, str]]] = defaultdict(deque)

        self.last_alert_by_key: dict[tuple[str, str], float] = {}
        self.cooldown_seconds = 60

    def analyze(self, packet: dict[str, Any]) -> list[dict[str, Any]]:
        """Run all detection rules against one packet and return generated alerts."""
        now = time.time()
        alerts: list[dict[str, Any]] = []

        port_scan_alert = self._detect_port_scan(packet, now)
        if port_scan_alert:
            alerts.append(port_scan_alert)

        brute_force_alert = self._detect_bruteforce(packet, now)
        if brute_force_alert:
            alerts.append(brute_force_alert)

        dns_tunnel_alert = self._detect_dns_tunneling(packet, now)
        if dns_tunnel_alert:
            alerts.append(dns_tunnel_alert)

        exfil_alert = self._detect_data_exfiltration(packet, now)
        if exfil_alert:
            alerts.append(exfil_alert)

        return alerts

    def _detect_port_scan(self, packet: dict[str, Any], now: float) -> dict[str, Any] | None:
        """Detect a source IP probing many unique destination ports in a short window."""
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")

        if not src_ip or not dst_ip or not isinstance(dst_port, int):
            return None

        config = self.thresholds["port_scan"]
        time_window = config["time_window"]
        threshold = config["unique_ports"]

        history = self.port_history[src_ip]
        history.append((now, dst_port, dst_ip))

        while history and now - history[0][0] > time_window:
            history.popleft()

        unique_ports = {entry[1] for entry in history}
        if len(unique_ports) < threshold:
            return None

        details = {
            "unique_ports": len(unique_ports),
            "time_window_seconds": time_window,
            "target_ips": sorted({entry[2] for entry in history}),
            "ports": sorted(unique_ports),
        }
        return self._build_alert(
            alert_type="PORT_SCAN",
            severity="HIGH",
            source_ip=src_ip,
            target_ip=dst_ip,
            description=(
                f"Potential port scan detected from {src_ip}: "
                f"{len(unique_ports)} unique ports in {time_window}s"
            ),
            details=details,
            now=now,
        )

    def _detect_bruteforce(self, packet: dict[str, Any], now: float) -> dict[str, Any] | None:
        """Detect repeated connection attempts to sensitive authentication ports."""
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        flags = (packet.get("flags") or "").upper()

        if not src_ip or not dst_ip or not isinstance(dst_port, int):
            return None

        config = self.thresholds["brute_force"]
        target_ports = set(config["target_ports"])
        if dst_port not in target_ports:
            return None

        # Prefer failed/retried TCP handshakes as brute-force signal.
        looks_like_attempt = any(token in flags for token in ("S", "R", "F")) or not flags
        if not looks_like_attempt:
            return None

        key = f"{src_ip}->{dst_ip}"
        history = self.bruteforce_history[key]
        history.append((now, dst_ip, dst_port))

        time_window = config["time_window"]
        attempts_threshold = config["attempts"]
        while history and now - history[0][0] > time_window:
            history.popleft()

        attempts = len(history)
        if attempts < attempts_threshold:
            return None

        targeted_ports = sorted({entry[2] for entry in history})
        return self._build_alert(
            alert_type="BRUTE_FORCE",
            severity="CRITICAL",
            source_ip=src_ip,
            target_ip=dst_ip,
            description=(
                f"Potential brute force activity from {src_ip} to {dst_ip}: "
                f"{attempts} attempts in {time_window}s"
            ),
            details={
                "attempts": attempts,
                "time_window_seconds": time_window,
                "target_ports": targeted_ports,
            },
            now=now,
        )

    def _detect_dns_tunneling(self, packet: dict[str, Any], now: float) -> dict[str, Any] | None:
        """Detect abnormally long DNS query subdomains often used for tunneling."""
        protocol = (packet.get("protocol") or "").upper()
        dns_query = packet.get("dns_query")

        if protocol != "DNS" or not isinstance(dns_query, str):
            return None

        config = self.thresholds["dns_tunneling"]
        threshold = config["subdomain_length"]

        first_label = dns_query.split(".")[0] if dns_query else ""
        if len(first_label) <= threshold:
            return None

        return self._build_alert(
            alert_type="DNS_TUNNELING",
            severity="HIGH",
            source_ip=packet.get("src_ip", "unknown"),
            target_ip=packet.get("dst_ip", "unknown"),
            description=(
                f"Potential DNS tunneling query detected from {packet.get('src_ip')}: "
                f"label length {len(first_label)}"
            ),
            details={
                "query": dns_query,
                "subdomain_length": len(first_label),
                "threshold": threshold,
            },
            now=now,
        )

    def _detect_data_exfiltration(self, packet: dict[str, Any], now: float) -> dict[str, Any] | None:
        """Detect large outbound byte volumes from private to public addresses."""
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        size = packet.get("size")

        if not src_ip or not dst_ip or not isinstance(size, int):
            return None

        if not self._is_private_ip(src_ip) or self._is_private_ip(dst_ip):
            return None

        config = self.thresholds["data_exfiltration"]
        time_window = config["time_window"]
        bytes_threshold = config["bytes_threshold"]

        history = self.exfil_history[src_ip]
        history.append((now, size, dst_ip))

        while history and now - history[0][0] > time_window:
            history.popleft()

        total_bytes = sum(entry[1] for entry in history)
        if total_bytes < bytes_threshold:
            return None

        return self._build_alert(
            alert_type="DATA_EXFILTRATION",
            severity="CRITICAL",
            source_ip=src_ip,
            target_ip=dst_ip,
            description=(
                f"Potential data exfiltration from {src_ip}: "
                f"{total_bytes / (1024 * 1024):.2f} MB outbound in {time_window}s"
            ),
            details={
                "bytes_outbound": total_bytes,
                "bytes_threshold": bytes_threshold,
                "time_window_seconds": time_window,
                "destination_ips": sorted({entry[2] for entry in history}),
            },
            now=now,
        )

    def _build_alert(
        self,
        alert_type: str,
        severity: str,
        source_ip: str,
        target_ip: str,
        description: str,
        details: dict[str, Any],
        now: float,
    ) -> dict[str, Any] | None:
        """Build a normalized alert dict with cooldown suppression."""
        cooldown_key = (alert_type, source_ip)
        last_seen = self.last_alert_by_key.get(cooldown_key)
        if last_seen is not None and now - last_seen < self.cooldown_seconds:
            return None

        self.last_alert_by_key[cooldown_key] = now

        return {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "description": description,
            "details": details,
        }

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Return True if the IP belongs to a private network range."""
        try:
            return ipaddress.ip_address(ip_str).is_private
        except ValueError:
            return False
