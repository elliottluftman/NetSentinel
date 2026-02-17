# NetSentinel

[![CI](https://github.com/elliottluftman/NetSentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/elliottluftman/NetSentinel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/elliottluftman/NetSentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/elliottluftman/NetSentinel/actions/workflows/codeql.yml)
[![Release](https://github.com/elliottluftman/NetSentinel/actions/workflows/release.yml/badge.svg)](https://github.com/elliottluftman/NetSentinel/actions/workflows/release.yml)

Real-time network traffic analyzer and threat detection dashboard built with Python, Flask, SQLite, and Chart.js.

## What This Project Is

NetSentinel captures (or simulates) network traffic, applies threat-detection rules in real time, stores telemetry in SQLite, and visualizes everything in a SOC-style web dashboard.

## Features

- Real-time packet ingestion in `live` mode with Scapy
- High-signal demo mode (`simulation`) without root access
- Threat detections:
  - Port scan
  - Brute force attempts
  - DNS tunneling patterns
  - Data exfiltration spikes
- Sliding-window analytics and alert cooldown controls
- SQLite persistence with automatic packet retention pruning
- REST API + live dashboard updates every 2 seconds
- Health endpoints for deployment checks: `/healthz`, `/readyz`
- Optional API-key protection for `/api/*`
- Production scaffolding: CI, CodeQL, dependency review, Docker, Gunicorn, release automation

## Project Structure

```text
NetSentinel/
├── .github/workflows/
│   ├── ci.yml
│   ├── codeql.yml
│   ├── dependency-review.yml
│   └── release.yml
├── dashboard/
├── netsentinel/
├── tests/
├── config.yaml
├── run.py
├── wsgi.py
├── gunicorn.conf.py
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

## Local Development

### 1. Setup

```bash
cd /Users/elliottluftman/NetSentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run (simulation)

```bash
python run.py --mode simulation --port 5050
```

Open `http://localhost:5050`.

### 3. Run (live capture)

```bash
sudo python run.py --mode live --interface en0 --port 5050
```

## Production Run

### Gunicorn

```bash
export NETSENTINEL_API_KEY="change-me"
export NETSENTINEL_LOG_LEVEL="INFO"

gunicorn -c gunicorn.conf.py wsgi:app
```

### Docker

```bash
docker compose up --build
```

## Release Process

Tag a release to trigger automated GitHub Release + GHCR image publish:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Published image:

```text
ghcr.io/elliottluftman/netsentinel:v1.0.0
```

## Configuration

`config.yaml` controls thresholds, runtime behavior, and simulation profile.

Runtime env variables:

- `NETSENTINEL_MODE`
- `NETSENTINEL_INTERFACE`
- `NETSENTINEL_API_PORT`
- `NETSENTINEL_LOG_LEVEL`
- `NETSENTINEL_API_KEY`

Use `.env.example` as a template.

## Testing

```bash
pytest -q
```

## API Endpoints

- `GET /healthz`
- `GET /readyz`
- `GET /api/traffic?limit=100`
- `GET /api/alerts?limit=50`
- `GET /api/stats`

If `NETSENTINEL_API_KEY` is set, include header:

```text
X-API-Key: <value>
```

## Security Notes

- Only monitor networks you own or are authorized to test.
- For Internet exposure, run behind TLS reverse proxy (Nginx/Caddy/Cloudflare Tunnel).
- Keep API key in environment variables, not committed config files.

## Portfolio Positioning

This repository is a production-ready baseline with deploy/test/release scaffolding, designed to show practical security engineering and full-stack system design.

## Project Website

A dedicated project website is included in `site/`.

### Run locally

```bash
cd site
python3 -m http.server 8080
```

Open `http://localhost:8080`.

### Deploy (Vercel)

1. Import the GitHub repo in Vercel.
2. Set **Root Directory** to `site`.
3. Deploy.
