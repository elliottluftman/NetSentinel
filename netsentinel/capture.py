"""Scapy-backed packet capture engine."""

from __future__ import annotations

from datetime import datetime, timezone
import threading
from typing import Any, Callable

try:
    from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, sniff
except Exception:  # pragma: no cover - handled at runtime for simulation-only environments
    DNS = DNSQR = ICMP = IP = TCP = UDP = None
    sniff = None


PacketHandler = Callable[[dict[str, Any]], None]


class PacketCapture:
    """Captures live packets from an interface and emits parsed packet dictionaries."""

    def __init__(self, interface: str, handler: PacketHandler) -> None:
        """Initialize capture engine with interface and packet callback."""
        self.interface = interface
        self.handler = handler
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        """Start packet sniffing in a daemon thread."""
        if sniff is None:
            raise RuntimeError(
                "Scapy is not available. Install dependencies or run in simulation mode."
            )

        if self.thread and self.thread.is_alive():
            return

        self.thread = threading.Thread(target=self._run, name="PacketCapture", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        """Main sniff loop using stop filter for graceful shutdown."""
        print(f"[*] Starting live packet capture on interface: {self.interface}")

        def should_stop(_: Any) -> bool:
            return self.stop_event.is_set()

        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=should_stop,
        )

    def _handle_packet(self, packet: Any) -> None:
        """Parse and emit a captured packet dictionary."""
        parsed = self._parse_packet(packet)
        if parsed is not None:
            self.handler(parsed)

    def _parse_packet(self, packet: Any) -> dict[str, Any] | None:
        """Extract relevant fields from one scapy packet."""
        if IP is None or not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port: int | None = None
        dst_port: int | None = None
        flags = ""
        dns_query = None

        protocol = "Other"
        if packet.haslayer(TCP):
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            flags = str(packet[TCP].flags)
            protocol = self._infer_tcp_protocol(src_port, dst_port)
        elif packet.haslayer(UDP):
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
            protocol = "UDP"

        if packet.haslayer(ICMP):
            protocol = "ICMP"

        if packet.haslayer(DNS):
            protocol = "DNS"
            if packet.haslayer(DNSQR) and packet[DNSQR].qname:
                dns_query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")

        timestamp = datetime.now(timezone.utc).isoformat()
        size = len(packet)

        summary = packet.summary()
        if len(summary) > 200:
            summary = summary[:197] + "..."

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "size": size,
            "flags": flags,
            "dns_query": dns_query,
            "summary": summary,
        }

    @staticmethod
    def _infer_tcp_protocol(src_port: int, dst_port: int) -> str:
        """Map common TCP ports to human-readable protocols."""
        ports = {src_port, dst_port}
        if 53 in ports:
            return "DNS"
        if 80 in ports:
            return "HTTP"
        if 443 in ports:
            return "HTTPS"
        if 22 in ports:
            return "SSH"
        return "TCP"

    def stop(self) -> None:
        """Signal capture loop to stop and wait for thread exit."""
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
