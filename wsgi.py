"""WSGI entrypoint for production deployments."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from netsentinel.api import create_app
from netsentinel.database import NetSentinelDB

PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_ROOT / "config.yaml"

with CONFIG_PATH.open("r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

db_path = PROJECT_ROOT / config.get("database", "netsentinel.db")
db = NetSentinelDB(str(db_path))
api_key = os.getenv("NETSENTINEL_API_KEY") or config.get("security", {}).get("api_key") or None
enable_cors = bool(config.get("runtime", {}).get("enable_cors", True))

app = create_app(db=db, dashboard_dir=PROJECT_ROOT / "dashboard", api_key=api_key, enable_cors=enable_cors)
