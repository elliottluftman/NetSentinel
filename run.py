"""Entry point for NetSentinel capture engine and dashboard server."""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
import signal
import threading
import time
from typing import Any

import yaml

from netsentinel.analyzer import ThreatAnalyzer
from netsentinel.api import create_app
from netsentinel.capture import PacketCapture
from netsentinel.database import NetSentinelDB
from netsentinel.simulator import TrafficSimulator


BANNER = r"""
    _   __     __  _____            __  _            __
   / | / /__  / /_/ ___/___  ____  / /_(_)___  ___  / /
  /  |/ / _ \/ __/\__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /
 / /|  /  __/ /_ ___/ /  __/ / / / /_/ / / / /  __/ /
/_/ |_|\___/\__//____/\___/_/ /_/\__/_/_/ /_/\___/_/
"""


def configure_logging(level: str) -> None:
    """Configure process-wide logging."""
    normalized = level.upper().strip()
    log_level = getattr(logging, normalized, logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


logger = logging.getLogger("netsentinel")


class RuntimeContext:
    """Coordinates packet processing, alerting, and shutdown across components."""

    def __init__(self, db: NetSentinelDB, analyzer: ThreatAnalyzer) -> None:
        """Store shared objects and counters used by callback processing."""
        self.db = db
        self.analyzer = analyzer
        self.packet_count = 0
        self.start_time = time.time()
        self.lock = threading.Lock()

    def handle_packet(self, packet: dict[str, Any]) -> None:
        """Store packet, run detections, and persist generated alerts."""
        self.db.store_packet(packet)

        alerts = self.analyzer.analyze(packet)
        for alert in alerts:
            self.db.store_alert(alert)
            logger.warning(
                "ALERT severity=%s type=%s source=%s target=%s description=%s",
                alert["severity"],
                alert["alert_type"],
                alert["source_ip"],
                alert["target_ip"],
                alert["description"],
            )

        with self.lock:
            self.packet_count += 1
            if self.packet_count % 100 == 0:
                elapsed = max(1.0, time.time() - self.start_time)
                pps = self.packet_count / elapsed
                logger.info("Processed packets=%s avg_pps=%.2f", self.packet_count, pps)


def load_config(config_path: Path) -> dict[str, Any]:
    """Load YAML config file into dictionary."""
    with config_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def parse_args() -> argparse.Namespace:
    """Parse CLI options overriding config defaults."""
    parser = argparse.ArgumentParser(description="NetSentinel network monitoring tool")
    parser.add_argument("--mode", choices=["simulation", "live"], help="Runtime mode")
    parser.add_argument("--interface", help="Network interface for live capture")
    parser.add_argument("--port", type=int, help="Flask API/dashboard port")
    parser.add_argument("--api-key", help="API key for /api/* endpoints")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log level")
    return parser.parse_args()


def resolve_runtime_settings(config: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Merge YAML config, environment variables, and CLI args."""
    mode = args.mode or os.getenv("NETSENTINEL_MODE") or config.get("mode", "simulation")
    interface = args.interface or os.getenv("NETSENTINEL_INTERFACE") or config.get("interface", "eth0")

    env_port = os.getenv("NETSENTINEL_API_PORT")
    port = args.port or (int(env_port) if env_port else int(config.get("api_port", 5000)))

    api_key = (
        args.api_key
        or os.getenv("NETSENTINEL_API_KEY")
        or config.get("security", {}).get("api_key")
        or None
    )

    log_level = (
        args.log_level
        or os.getenv("NETSENTINEL_LOG_LEVEL")
        or config.get("runtime", {}).get("log_level", "INFO")
    )

    enable_cors = bool(config.get("runtime", {}).get("enable_cors", True))

    return {
        "mode": mode,
        "interface": interface,
        "port": port,
        "api_key": api_key,
        "log_level": log_level,
        "enable_cors": enable_cors,
    }


def main() -> None:
    """Initialize components and run dashboard server with capture engine."""
    project_root = Path(__file__).resolve().parent
    config_path = project_root / "config.yaml"
    args = parse_args()

    config = load_config(config_path)
    runtime_cfg = resolve_runtime_settings(config, args)

    configure_logging(runtime_cfg["log_level"])

    db_path = project_root / config.get("database", "netsentinel.db")
    db = NetSentinelDB(str(db_path))
    analyzer = ThreatAnalyzer(config["thresholds"])
    runtime = RuntimeContext(db=db, analyzer=analyzer)

    mode = runtime_cfg["mode"]
    if mode == "simulation":
        sim_cfg = config.get("simulation", {})
        engine: Any = TrafficSimulator(
            handler=runtime.handle_packet,
            packets_per_second=int(sim_cfg.get("packets_per_second", 15)),
            attack_probability=float(sim_cfg.get("attack_probability", 0.08)),
        )
    else:
        engine = PacketCapture(interface=runtime_cfg["interface"], handler=runtime.handle_packet)

    stop_event = threading.Event()

    def shutdown_handler(_sig: int, _frame: Any) -> None:
        """Handle Ctrl+C and system stop signals."""
        if stop_event.is_set():
            return
        stop_event.set()
        logger.info("Stopping NetSentinel...")
        engine.stop()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print(BANNER)
    print(f"[*] Mode: {mode.capitalize()}")
    print(f"[*] Dashboard: http://localhost:{runtime_cfg['port']}")
    if mode == "live":
        print(f"[*] Interface: {runtime_cfg['interface']}")
    if runtime_cfg["api_key"]:
        print("[*] API key protection enabled for /api/* endpoints")
    print("[*] Press Ctrl+C to stop")

    engine.start()

    app = create_app(
        db=db,
        dashboard_dir=project_root / "dashboard",
        api_key=runtime_cfg["api_key"],
        enable_cors=runtime_cfg["enable_cors"],
    )
    try:
        app.run(host="0.0.0.0", port=int(runtime_cfg["port"]), debug=False, use_reloader=False)
    finally:
        if not stop_event.is_set():
            stop_event.set()
            engine.stop()
        db.close()


if __name__ == "__main__":
    main()
