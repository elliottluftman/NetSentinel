"""Unit tests for threat analyzer behavior."""

from __future__ import annotations

from datetime import datetime, timezone

from netsentinel.analyzer import ThreatAnalyzer


def _thresholds() -> dict:
    return {
        "port_scan": {"unique_ports": 3, "time_window": 60},
        "brute_force": {"attempts": 3, "time_window": 300, "target_ports": [22, 3389]},
        "dns_tunneling": {"subdomain_length": 10},
        "data_exfiltration": {"bytes_threshold": 1024, "time_window": 60},
    }


def _packet(**kwargs):
    base = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "8.8.8.8",
        "src_port": 44444,
        "dst_ip": "192.168.1.10",
        "dst_port": 80,
        "protocol": "TCP",
        "size": 100,
        "flags": "S",
        "dns_query": None,
        "summary": "test",
    }
    base.update(kwargs)
    return base


def test_port_scan_detected():
    analyzer = ThreatAnalyzer(_thresholds())
    alerts = []
    for port in [22, 23, 24]:
        alerts.extend(analyzer.analyze(_packet(dst_port=port)))
    assert any(a["alert_type"] == "PORT_SCAN" for a in alerts)


def test_dns_tunnel_detected():
    analyzer = ThreatAnalyzer(_thresholds())
    packet = _packet(protocol="DNS", dst_port=53, dns_query="averyverylonglabel.exfil.com")
    alerts = analyzer.analyze(packet)
    assert any(a["alert_type"] == "DNS_TUNNELING" for a in alerts)


def test_data_exfiltration_detected():
    analyzer = ThreatAnalyzer(_thresholds())
    packet = _packet(src_ip="192.168.1.20", dst_ip="8.8.8.8", protocol="HTTPS", dst_port=443, size=2048)
    alerts = analyzer.analyze(packet)
    assert any(a["alert_type"] == "DATA_EXFILTRATION" for a in alerts)
