"""API tests for auth and route behavior."""

from __future__ import annotations

from pathlib import Path

from netsentinel.api import create_app
from netsentinel.database import NetSentinelDB


def test_health_and_ready_endpoints(tmp_path: Path):
    db = NetSentinelDB(str(tmp_path / "test.db"))
    app = create_app(db=db, dashboard_dir=tmp_path, api_key=None)
    client = app.test_client()

    health = client.get("/healthz")
    ready = client.get("/readyz")

    assert health.status_code == 200
    assert ready.status_code == 200
    assert health.get_json()["status"] == "ok"


def test_api_key_required(tmp_path: Path):
    dashboard_dir = tmp_path / "dashboard"
    dashboard_dir.mkdir(parents=True, exist_ok=True)
    (dashboard_dir / "index.html").write_text("ok", encoding="utf-8")
    (dashboard_dir / "style.css").write_text("", encoding="utf-8")
    (dashboard_dir / "app.js").write_text("", encoding="utf-8")

    db = NetSentinelDB(str(tmp_path / "test.db"))
    app = create_app(db=db, dashboard_dir=dashboard_dir, api_key="secret")
    client = app.test_client()

    denied = client.get("/api/stats")
    allowed = client.get("/api/stats", headers={"X-API-Key": "secret"})

    assert denied.status_code == 401
    assert allowed.status_code == 200
