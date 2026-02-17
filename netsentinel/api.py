"""Flask REST API and static dashboard serving for NetSentinel."""

from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from .database import NetSentinelDB


def create_app(
    db: NetSentinelDB,
    dashboard_dir: str | Path,
    api_key: str | None = None,
    enable_cors: bool = True,
) -> Flask:
    """Create and configure the Flask application instance."""
    app = Flask(__name__, static_folder=None)
    if enable_cors:
        CORS(app)

    dashboard_path = Path(dashboard_dir).resolve()

    @app.before_request
    def enforce_api_key() -> Any:
        """Require X-API-Key for API endpoints when api_key is configured."""
        if not api_key:
            return None
        if request.path.startswith("/api/"):
            presented = request.headers.get("X-API-Key", "")
            if not hmac.compare_digest(presented, api_key):
                return jsonify({"error": "unauthorized"}), 401
        return None

    @app.route("/")
    def index() -> Any:
        """Serve dashboard HTML."""
        return send_from_directory(dashboard_path, "index.html")

    @app.route("/style.css")
    def style() -> Any:
        """Serve dashboard CSS."""
        return send_from_directory(dashboard_path, "style.css")

    @app.route("/app.js")
    def app_js() -> Any:
        """Serve dashboard JavaScript."""
        return send_from_directory(dashboard_path, "app.js")

    @app.get("/healthz")
    def healthz() -> Any:
        """Liveness endpoint."""
        return jsonify({"status": "ok"})

    @app.get("/readyz")
    def readyz() -> Any:
        """Readiness endpoint with lightweight DB probe."""
        stats = db.get_stats()
        return jsonify({"status": "ready", "total_packets": stats["total_packets"]})

    @app.get("/api/traffic")
    def traffic() -> Any:
        """Return recent network traffic packet records."""
        limit = _parse_limit(request.args.get("limit"), default=100, maximum=1000)
        return jsonify(db.get_recent_packets(limit=limit))

    @app.get("/api/alerts")
    def alerts() -> Any:
        """Return recent alerts."""
        limit = _parse_limit(request.args.get("limit"), default=50, maximum=500)
        return jsonify(db.get_alerts(limit=limit))

    @app.get("/api/stats")
    def stats() -> Any:
        """Return aggregate dashboard statistics."""
        return jsonify(db.get_stats())

    return app


def _parse_limit(raw: str | None, default: int, maximum: int) -> int:
    """Parse integer limit query values with fallback and cap."""
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(1, min(value, maximum))
