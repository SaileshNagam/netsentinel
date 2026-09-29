import pytest
from datetime import datetime, timezone
from app.detection.rule_engine import (
    rule_a_unusual_outbound_port,
    rule_b_suspicious_process_network,
    rule_c_port_scan_behavior,
    rule_d_brute_force,
    rule_e_beaconing,
    rule_f_unusual_destination
)
from app.detection.threat_scoring import score_alerts

def utc_now():
    return datetime.now(timezone.utc)

def test_rule_a_unusual_port():
    connections = [
        {"remote_ip": "8.8.8.8", "remote_port": 443, "state": "ESTABLISHED", "process_name": "chrome"}, # normal
        {"remote_ip": "10.0.0.5", "remote_port": 4444, "state": "ESTABLISHED", "process_name": "nc"},   # suspicious
    ]
    alerts = rule_a_unusual_outbound_port(connections)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "RULE_A_UNUSUAL_OUTBOUND_PORT"
    assert alerts[0]["evidence"]["remote_port"] == 4444

def test_rule_b_suspicious_process():
    connections = [
        {"remote_ip": "1.1.1.1", "remote_port": 80, "state": "ESTABLISHED", "process_name": "notepad.exe"},
        {"remote_ip": "1.1.1.1", "remote_port": 80, "state": "ESTABLISHED", "process_name": "firefox"},
    ]
    alerts = rule_b_suspicious_process_network(connections)
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["process_name"] == "notepad.exe"

def test_rule_c_port_scan():
    base_time = utc_now().isoformat()
    # 15 distinct ports from same source
    connections = [
        {"local_ip": "192.168.1.100", "remote_ip": "192.168.1.5", "remote_port": p, "timestamp": base_time}
        for p in range(1, 16)
    ]
    alerts = rule_c_port_scan_behavior(connections, threshold=10)
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["distinct_ports_hit"] == 15

def test_rule_d_brute_force():
    base_time = utc_now().isoformat()
    # 6 failed logins for same user/ip
    events = [
        {"event_type": "FAILED_LOGIN", "user": "admin", "source_ip": "10.0.0.2", "timestamp": base_time}
        for _ in range(6)
    ]
    alerts = rule_d_brute_force(events, threshold=5)
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["failure_count"] == 6

def test_rule_f_test_network():
    connections = [
        {"remote_ip": "198.51.100.5", "remote_port": 80}, # RFC 5737
        {"remote_ip": "8.8.8.8", "remote_port": 53}       # Normal
    ]
    alerts = rule_f_unusual_destination(connections)
    assert len(alerts) == 1
    assert alerts[0]["evidence"]["remote_ip"] == "198.51.100.5"

def test_threat_scoring():
    alerts = [
        {"rule_id": "RULE_A_UNUSUAL_OUTBOUND_PORT", "score_contribution": 20},
        {"rule_id": "RULE_B_SUSPICIOUS_PROCESS_NETWORK", "score_contribution": 25},
    ]
    result = score_alerts(alerts)
    assert result["risk_score"] == 45
    assert result["severity"] == "MEDIUM"
    assert len(result["factors"]) == 2
