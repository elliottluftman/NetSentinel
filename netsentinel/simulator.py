"""Synthetic traffic generator for NetSentinel demo mode."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import random
import string
import threading
import time
from typing import Any, Callable


PacketHandler = Callable[[dict[str, Any]], None]


class TrafficSimulator:
    """Generates realistic normal and malicious traffic for dashboard demos."""

    def __init__(
        self,
        handler: PacketHandler,
        packets_per_second: int = 15,
        attack_probability: float = 0.08,
    ) -> None:
        """Initialize simulator behavior, IP pools, and scheduler queues."""
        self.handler = handler
        self.packets_per_second = max(1, packets_per_second)
        self.attack_probability = max(0.0, min(1.0, attack_probability))
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

        self.internal_ips = [f"192.168.1.{i}" for i in range(10, 40)]
        self.external_ips = [
            f"{a}.{b}.{c}.{d}"
            for a, b, c, d in (
                (8, 8, 8, 8),
                (1, 1, 1, 1),
                (142, 250, 190, 14),
                (140, 82, 121, 4),
                (52, 95, 110, 1),
                (104, 16, 133, 229),
                (13, 107, 42, 16),
                (31, 13, 71, 36),
                (151, 101, 193, 140),
                (172, 217, 3, 110),
            )
        ]
        while len(self.external_ips) < 50:
            self.external_ips.append(
                f"{random.randint(11, 223)}.{random.randint(0, 255)}."
                f"{random.randint(0, 255)}.{random.randint(1, 254)}"
            )

        self.domains = [
            "google.com",
            "github.com",
            "aws.amazon.com",
            "microsoft.com",
            "stackoverflow.com",
            "docs.python.org",
            "api.openai.com",
            "cloudflare.com",
            "pypi.org",
            "linkedin.com",
            "youtube.com",
            "apple.com",
            "npmjs.com",
        ]

        self.scheduled_packets: deque[tuple[float, dict[str, Any]]] = deque()

    def start(self) -> None:
        """Start simulator loop in daemon thread."""
        if self.thread and self.thread.is_alive():
            return

        self.thread = threading.Thread(target=self._run, name="TrafficSimulator", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        """Main loop emitting baseline traffic plus scheduled attack bursts."""
        print(
            f"[*] Traffic simulator started ({self.packets_per_second} pps, "
            f"attack probability {self.attack_probability:.2f})"
        )

        interval = 1.0 / float(self.packets_per_second)
        next_attack_check = time.time() + 1.0

        # Seed startup traffic immediately for first dashboard refresh.
        for _ in range(20):
            self.handler(self._generate_normal_packet())

        while not self.stop_event.is_set():
            now = time.time()
            if now >= next_attack_check:
                next_attack_check = now + 1.0
                if random.random() < self.attack_probability:
                    self._schedule_attack_pattern(now)

            emitted = False
            while self.scheduled_packets and self.scheduled_packets[0][0] <= now:
                _, packet = self.scheduled_packets.popleft()
                self.handler(packet)
                emitted = True

            if not emitted:
                self.handler(self._generate_normal_packet())

            time.sleep(interval)

    def _schedule_attack_pattern(self, start_ts: float) -> None:
        """Randomly pick and schedule one attack scenario over time."""
        attack_type = random.choice(
            ["port_scan", "brute_force", "dns_tunneling", "data_exfiltration"]
        )

        if attack_type == "port_scan":
            self._schedule_port_scan(start_ts)
        elif attack_type == "brute_force":
            self._schedule_bruteforce(start_ts)
        elif attack_type == "dns_tunneling":
            self._schedule_dns_tunneling(start_ts)
        else:
            self._schedule_data_exfiltration(start_ts)

    def _schedule_port_scan(self, start_ts: float) -> None:
        """Schedule a rapid multi-port scan burst from one external host."""
        src_ip = random.choice(self.external_ips)
        dst_ip = random.choice(self.internal_ips)
        num_ports = random.randint(15, 25)
        ports = random.sample(range(20, 1000), num_ports)

        for idx, port in enumerate(ports):
            packet = self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(1024, 65535),
                dst_port=port,
                protocol="TCP",
                size=random.randint(60, 120),
                flags="S",
                summary=f"Simulated scan attempt {src_ip}:{port} -> {dst_ip}:{port}",
            )
            self.scheduled_packets.append((start_ts + (idx * 0.8), packet))

        print(f"[SIM] Injected PORT_SCAN scenario from {src_ip} targeting {dst_ip}")

    def _schedule_bruteforce(self, start_ts: float) -> None:
        """Schedule repeated authentication attempts against SSH/RDP."""
        src_ip = random.choice(self.external_ips)
        dst_ip = random.choice(self.internal_ips)
        target_port = random.choice([22, 3389])
        attempts = random.randint(25, 40)

        for idx in range(attempts):
            packet = self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(1024, 65535),
                dst_port=target_port,
                protocol="SSH" if target_port == 22 else "TCP",
                size=random.randint(60, 140),
                flags="S",
                summary=f"Simulated brute-force attempt {idx + 1} from {src_ip} to {dst_ip}:{target_port}",
            )
            self.scheduled_packets.append((start_ts + (idx * 3.0), packet))

        print(f"[SIM] Injected BRUTE_FORCE scenario from {src_ip} to {dst_ip}:{target_port}")

    def _schedule_dns_tunneling(self, start_ts: float) -> None:
        """Schedule suspicious long DNS query labels that mimic exfil traffic."""
        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(self.external_ips)

        for idx in range(random.randint(8, 15)):
            payload = "".join(random.choices(string.ascii_letters + string.digits, k=64))
            payload2 = "".join(random.choices(string.ascii_letters + string.digits, k=58))
            dns_query = f"{payload}.{payload2}.exfil.evil.com"

            packet = self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(49152, 65535),
                dst_port=53,
                protocol="DNS",
                size=random.randint(100, 240),
                flags="",
                dns_query=dns_query,
                summary=f"Simulated DNS query {dns_query}",
            )
            self.scheduled_packets.append((start_ts + (idx * 1.2), packet))

        print(f"[SIM] Injected DNS_TUNNELING scenario from {src_ip}")

    def _schedule_data_exfiltration(self, start_ts: float) -> None:
        """Schedule large outbound packets representing bulk data transfer."""
        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(self.external_ips)
        total_mb = random.randint(10, 50)
        packet_count = random.randint(18, 35)

        bytes_remaining = total_mb * 1024 * 1024
        for idx in range(packet_count):
            if idx == packet_count - 1:
                size = max(1200, bytes_remaining)
            else:
                size = max(1200, min(bytes_remaining // (packet_count - idx), random.randint(150000, 1200000)))
            bytes_remaining -= size

            packet = self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(40000, 65535),
                dst_port=443,
                protocol="HTTPS",
                size=size,
                flags="PA",
                summary=f"Simulated outbound transfer chunk {idx + 1}/{packet_count}",
            )
            self.scheduled_packets.append((start_ts + (idx * 1.5), packet))

        print(f"[SIM] Injected DATA_EXFILTRATION scenario {total_mb}MB from {src_ip} -> {dst_ip}")

    def _generate_normal_packet(self) -> dict[str, Any]:
        """Generate one packet from weighted everyday enterprise traffic."""
        pattern = random.choices(
            ["web", "dns", "ssh", "email", "udp", "icmp"],
            weights=[42, 22, 10, 10, 12, 4],
            k=1,
        )[0]

        if pattern == "web":
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.external_ips)
            dst_port = random.choice([80, 443])
            protocol = "HTTP" if dst_port == 80 else "HTTPS"
            return self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(49152, 65535),
                dst_port=dst_port,
                protocol=protocol,
                size=random.randint(350, 3000),
                flags="PA",
                summary=f"{protocol} request to {dst_ip}",
            )

        if pattern == "dns":
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.external_ips)
            host = random.choice(["www", "api", "cdn", "auth", "assets", "mail"])
            domain = random.choice(self.domains)
            dns_query = f"{host}.{domain}"
            return self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(49152, 65535),
                dst_port=53,
                protocol="DNS",
                size=random.randint(80, 220),
                dns_query=dns_query,
                summary=f"DNS lookup {dns_query}",
            )

        if pattern == "ssh":
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.internal_ips + self.external_ips[:8])
            return self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(49152, 65535),
                dst_port=22,
                protocol="SSH",
                size=random.randint(90, 1400),
                flags=random.choice(["S", "PA", "A"]),
                summary=f"SSH session traffic {src_ip} -> {dst_ip}",
            )

        if pattern == "email":
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.external_ips)
            dst_port = random.choice([25, 587, 993])
            return self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=random.randint(1024, 65535),
                dst_port=dst_port,
                protocol="TCP",
                size=random.randint(400, 10000),
                flags="PA",
                summary=f"Email traffic on port {dst_port}",
            )

        if pattern == "icmp":
            src_ip = random.choice(self.internal_ips)
            dst_ip = random.choice(self.internal_ips + self.external_ips)
            return self._build_packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=None,
                dst_port=None,
                protocol="ICMP",
                size=random.randint(60, 180),
                summary=f"ICMP echo request {src_ip} -> {dst_ip}",
            )

        src_ip = random.choice(self.internal_ips)
        dst_ip = random.choice(self.external_ips)
        return self._build_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65535),
            dst_port=random.randint(1024, 65535),
            protocol="UDP",
            size=random.randint(70, 1400),
            summary=f"Generic UDP traffic {src_ip} -> {dst_ip}",
        )

    @staticmethod
    def _build_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int | None,
        dst_port: int | None,
        protocol: str,
        size: int,
        summary: str,
        flags: str = "",
        dns_query: str | None = None,
    ) -> dict[str, Any]:
        """Build one normalized packet dictionary."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "size": int(size),
            "flags": flags,
            "dns_query": dns_query,
            "summary": summary,
        }

    def stop(self) -> None:
        """Signal simulator loop to stop and wait briefly for shutdown."""
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
