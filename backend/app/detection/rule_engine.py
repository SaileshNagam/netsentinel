"""
NetSentinel Threat Detection Rule Engine
Deterministic, explainable detection rules for connection-level and process-level threats.
All rules use evidence-based language: 'Observed', 'Unusual', 'Possible', 'Potential'.
NEVER claims 'Malware Detected' without strong corroborating evidence.

Rules:
  A - Unusual Outbound Port
  B - Suspicious Process/Network Relationship
  C - Port-Scan-Like Behavior
  D - Repeated Authentication Failures
  E - C2-Like Periodic Beaconing
  F - Unusual Outbound Destination (Threat-Test IP Ranges)
"""
import logging
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("NetSentinel.Detection.RuleEngine")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION (defaults — override via environment/settings)
# ─────────────────────────────────────────────────────────────────────────────

# Rule A: Ports that are unusual for standard outbound traffic
HIGH_RISK_OUTBOUND_PORTS = {
    4444, 4445, 4446,            # Metasploit default listeners
    5555, 5556,                  # Android ADB / common RAT ports
    6666, 6667, 6668, 6669,      # IRC often used for botnets
    7777, 8888,                  # Common RAT / test listener ports
    9001, 9002,                  # Tor / proxy ports
    1080,                        # SOCKS proxy
    31337,                       # Elite / historical malware port
    12345, 54321,                # Classic backdoor ports
}

# Rule B: Processes that should NOT initiate outbound network connections
SUSPICIOUS_PROCESS_NAMES = {
    # Windows processes that should not open external sockets
    "notepad.exe", "notepad", "calc.exe", "calc", "mspaint.exe", "mspaint",
    "wordpad.exe", "wordpad", "explorer.exe",
    # Common document readers that shouldn't beacon out
    "acrobat.exe", "acrord32.exe",
}

# Rule C: Port scan thresholds
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 10    # ports hit from same source within window
PORT_SCAN_WINDOW_SECONDS = 5

# Rule D: Brute force thresholds
BRUTE_FORCE_FAILURES_THRESHOLD = 5        # failures within window
BRUTE_FORCE_WINDOW_SECONDS = 10

# Rule E: Beaconing detection
BEACON_MIN_SAMPLES = 4                   # need at least N samples to detect pattern
BEACON_INTERVAL_CV_THRESHOLD = 0.25      # coefficient of variation ≤ 0.25 = very regular

# Rule F: Documentation/test IP ranges that should not appear in production traffic
THREAT_TEST_RANGES = {
    "198.51.100.",    # TEST-NET-2 (RFC 5737) — used in academic security demos
    "203.0.113.",     # TEST-NET-3 (RFC 5737)
    "192.0.2.",       # TEST-NET-1 (RFC 5737)
}

# Standard outbound ports to ignore (avoid false positives on normal HTTPS/HTTP)
STANDARD_OUTBOUND_PORTS = {
    80, 443, 8080, 8443,        # HTTP/HTTPS
    53,                          # DNS
    587, 465, 25, 993, 995, 143, # Email
    22,                          # SSH
    21, 990,                     # FTP/FTPS
    123,                         # NTP
    5228, 5229, 5230,            # Google services
    1194, 1195,                  # OpenVPN
    51820,                       # WireGuard
}


def _make_rule_hash(rule_id: str, context: str) -> str:
    """Create a SHA-256 deduplication hash for alert cooldown."""
    return hashlib.sha256(f"{rule_id}:{context}".encode()).hexdigest()


def _alert(rule_id: str, title: str, description: str, severity: str,
           evidence: Dict[str, Any], score: int = 20) -> Dict[str, Any]:
    """Create a structured alert dict."""
    context_key = f"{rule_id}:{evidence.get('pid', '')}:{evidence.get('remote_ip', '')}:{evidence.get('remote_port', '')}"
    return {
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "score_contribution": score,
        "evidence": evidence,
        "dedup_hash": _make_rule_hash(rule_id, context_key),
        "confidence": "MEDIUM",
        "simulation": evidence.get("simulation", False),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# RULE A — Unusual Outbound Port
# ─────────────────────────────────────────────────────────────────────────────

def rule_a_unusual_outbound_port(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect outbound connections to configurable suspicious/uncommon ports.
    Does NOT assume a port alone proves malicious activity.
    Excludes standard well-known outbound ports.
    """
    alerts = []
    for conn in connections:
        remote_port = conn.get("remote_port")
        remote_ip = conn.get("remote_ip")
        state = conn.get("state", "")

        if not remote_ip or not remote_port:
            continue
        if state not in ("ESTABLISHED", "SYN_SENT", "NONE", ""):
            continue
        if remote_port in STANDARD_OUTBOUND_PORTS:
            continue
        if remote_port not in HIGH_RISK_OUTBOUND_PORTS:
            continue

        proc = conn.get("process_name", "UNKNOWN")
        pid = conn.get("pid")

        alerts.append(_alert(
            rule_id="RULE_A_UNUSUAL_OUTBOUND_PORT",
            title="Unusual Outbound Connection Observed",
            description=(
                f"Unusual outbound connection detected. "
                f"Process: {proc} (PID {pid}) connected to {remote_ip}:{remote_port}. "
                f"Reason: Destination port {remote_port} matches configured high-risk port list. "
                f"This requires investigation — port membership alone does not confirm malicious activity."
            ),
            severity="HIGH",
            evidence={
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "process_name": proc,
                "pid": pid,
                "protocol": conn.get("protocol"),
                "state": state,
                "simulation": conn.get("simulation", False),
            },
            score=20,
        ))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# RULE B — Suspicious Process / Network Relationship
# ─────────────────────────────────────────────────────────────────────────────

def rule_b_suspicious_process_network(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect processes that normally do not require external network connectivity
    but are observed creating outbound connections.
    """
    alerts = []
    for conn in connections:
        proc = (conn.get("process_name") or "").lower()
        remote_ip = conn.get("remote_ip")
        state = conn.get("state", "")

        if not remote_ip or not proc:
            continue
        if state not in ("ESTABLISHED", "SYN_SENT", "NONE"):
            continue
        if proc not in SUSPICIOUS_PROCESS_NAMES:
            continue

        pid = conn.get("pid")
        alerts.append(_alert(
            rule_id="RULE_B_SUSPICIOUS_PROCESS_NETWORK",
            title="Unusual Process-to-Network Relationship Observed",
            description=(
                f"Unusual process-to-network relationship detected. "
                f"Process '{proc}' (PID {pid}) does not typically require external network connectivity "
                f"but was observed connecting to {remote_ip}:{conn.get('remote_port')}. "
                f"This may indicate process injection or misuse — manual investigation recommended."
            ),
            severity="HIGH",
            evidence={
                "remote_ip": remote_ip,
                "remote_port": conn.get("remote_port"),
                "process_name": proc,
                "pid": pid,
                "simulation": conn.get("simulation", False),
            },
            score=25,
        ))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# RULE C — Port-Scan-Like Behavior
# ─────────────────────────────────────────────────────────────────────────────

def rule_c_port_scan_behavior(
    connections: List[Dict[str, Any]],
    window_seconds: int = PORT_SCAN_WINDOW_SECONDS,
    threshold: int = PORT_SCAN_DISTINCT_PORTS_THRESHOLD,
) -> List[Dict[str, Any]]:
    """
    Detect when a single source IP contacts many distinct destination ports
    within a short sliding time window.
    Configurable threshold and window.
    """
    # Group connections by (source_ip → set of destination ports) within window
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)

    port_hits: Dict[str, set] = defaultdict(set)

    for conn in connections:
        local_ip = conn.get("local_ip")
        remote_port = conn.get("remote_port")
        ts_raw = conn.get("timestamp")
        if not local_ip or not remote_port:
            continue
        try:
            if isinstance(ts_raw, str):
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            else:
                ts = now
            if ts < cutoff:
                continue
        except Exception:
            pass
        port_hits[local_ip].add(remote_port)

    alerts = []
    for source_ip, ports in port_hits.items():
        if len(ports) >= threshold:
            alerts.append(_alert(
                rule_id="RULE_C_PORT_SCAN",
                title="Possible Port-Scan-Like Activity Observed",
                description=(
                    f"Possible port-scan-like behavior detected from {source_ip}. "
                    f"{len(ports)} distinct destination ports were contacted within {window_seconds} seconds "
                    f"(threshold: {threshold}). Ports: {sorted(ports)[:20]}{'...' if len(ports) > 20 else ''}. "
                    f"This may be a port scanner or aggressive service discovery — manual investigation recommended."
                ),
                severity="MEDIUM",
                evidence={
                    "source_ip": source_ip,
                    "distinct_ports_hit": len(ports),
                    "ports_sample": list(sorted(ports))[:20],
                    "window_seconds": window_seconds,
                    "threshold": threshold,
                    "simulation": any(c.get("simulation") for c in connections if c.get("local_ip") == source_ip),
                },
                score=15,
            ))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# RULE D — Repeated Authentication Failures
# ─────────────────────────────────────────────────────────────────────────────

def rule_d_brute_force(
    security_events: List[Dict[str, Any]],
    window_seconds: int = BRUTE_FORCE_WINDOW_SECONDS,
    threshold: int = BRUTE_FORCE_FAILURES_THRESHOLD,
) -> List[Dict[str, Any]]:
    """
    Detect repeated authentication failures from the same source/user within a time window.
    Configurable threshold and window.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)

    # Group by (user, source_ip)
    failure_buckets: Dict[Tuple, List[Dict]] = defaultdict(list)

    for event in security_events:
        if event.get("event_type") != "FAILED_LOGIN":
            continue
        user = event.get("user", "UNKNOWN")
        src_ip = event.get("source_ip") or "UNKNOWN"
        ts_raw = event.get("timestamp", "")
        try:
            if isinstance(ts_raw, str) and len(ts_raw) > 4:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            elif isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                ts = now  # recent
                
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            ts = now
        if ts >= cutoff:
            failure_buckets[(user, src_ip)].append(event)

    alerts = []
    for (user, src_ip), events in failure_buckets.items():
        if len(events) >= threshold:
            alerts.append(_alert(
                rule_id="RULE_D_BRUTE_FORCE",
                title="Possible Brute-Force Authentication Activity Observed",
                description=(
                    f"Repeated authentication failures detected for user '{user}' from source '{src_ip}'. "
                    f"{len(events)} failures observed within {window_seconds} seconds "
                    f"(threshold: {threshold}). "
                    f"This may indicate a credential guessing attempt — manual investigation recommended."
                ),
                severity="HIGH",
                evidence={
                    "user": user,
                    "source_ip": src_ip,
                    "failure_count": len(events),
                    "window_seconds": window_seconds,
                    "threshold": threshold,
                    "simulation": any(e.get("simulation") for e in events),
                },
                score=25,
            ))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# RULE E — C2-Like Periodic Beaconing
# ─────────────────────────────────────────────────────────────────────────────

def rule_e_beaconing(
    connection_history: List[Dict[str, Any]],
    min_samples: int = BEACON_MIN_SAMPLES,
    cv_threshold: float = BEACON_INTERVAL_CV_THRESHOLD,
) -> List[Dict[str, Any]]:
    """
    Detect repetitive periodic outbound communication by analyzing connection timestamps.
    Uses statistical analysis: mean interval, std deviation, coefficient of variation (CV).
    Low CV = very regular = possible C2-like beaconing pattern.
    """
    import statistics

    # Group by (process_name, remote_ip, remote_port)
    groups: Dict[Tuple, List[datetime]] = defaultdict(list)

    for conn in connection_history:
        remote_ip = conn.get("remote_ip")
        remote_port = conn.get("remote_port")
        proc = conn.get("process_name", "UNKNOWN")
        ts_raw = conn.get("timestamp")
        if not remote_ip or not remote_port or not ts_raw:
            continue
        try:
            if isinstance(ts_raw, str):
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            elif isinstance(ts_raw, datetime):
                ts = ts_raw
            else:
                continue
                
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        groups[(proc, remote_ip, remote_port)].append(ts)

    alerts = []
    for (proc, remote_ip, remote_port), timestamps in groups.items():
        if len(timestamps) < min_samples:
            continue

        sorted_ts = sorted(timestamps)
        intervals = [(sorted_ts[i+1] - sorted_ts[i]).total_seconds()
                     for i in range(len(sorted_ts) - 1)]

        if not intervals:
            continue

        mean_interval = statistics.mean(intervals)
        if mean_interval < 1:
            continue  # Sub-second intervals are likely normal rapid retries, skip

        try:
            std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        except Exception:
            std_dev = 0.0

        cv = std_dev / mean_interval if mean_interval > 0 else 1.0

        if cv <= cv_threshold:
            alerts.append(_alert(
                rule_id="RULE_E_BEACONING",
                title="Possible C2-Like Periodic Communication Observed",
                description=(
                    f"Possible C2-like periodic communication detected. "
                    f"Process '{proc}' contacted {remote_ip}:{remote_port} "
                    f"{len(timestamps)} times at approximately regular intervals "
                    f"(mean interval: {mean_interval:.1f}s, CV: {cv:.3f}). "
                    f"A very low coefficient of variation suggests automated, scheduled communication. "
                    f"This requires investigation — periodic communication alone does not confirm C2 activity."
                ),
                severity="HIGH",
                evidence={
                    "process_name": proc,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "sample_count": len(timestamps),
                    "mean_interval_seconds": round(mean_interval, 2),
                    "std_dev_seconds": round(std_dev, 2),
                    "coefficient_of_variation": round(cv, 4),
                    "cv_threshold": cv_threshold,
                    "simulation": any(c.get("simulation") for c in connection_history
                                      if c.get("remote_ip") == remote_ip),
                },
                score=35,
            ))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# RULE F — Unusual Outbound Destination (Threat-Test Ranges)
# ─────────────────────────────────────────────────────────────────────────────

def rule_f_unusual_destination(connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flag connections to documentation/test IP ranges or configured threat-test destinations.
    Uses only local reputation logic — does NOT fabricate or assume reputation from external feeds.
    If no reputation provider exists, reputation_status = UNKNOWN.
    """
    alerts = []
    for conn in connections:
        remote_ip = conn.get("remote_ip")
        if not remote_ip:
            continue

        matched_range = None
        for prefix in THREAT_TEST_RANGES:
            if remote_ip.startswith(prefix):
                matched_range = prefix
                break

        if not matched_range:
            continue

        proc = conn.get("process_name", "UNKNOWN")
        pid = conn.get("pid")

        alerts.append(_alert(
            rule_id="RULE_F_UNUSUAL_DESTINATION",
            title="Connection to Documentation/Test IP Range Observed",
            description=(
                f"Connection to {remote_ip}:{conn.get('remote_port')} observed from process "
                f"'{proc}' (PID {pid}). "
                f"The destination IP falls within an RFC 5737 documentation/test range ({matched_range}0/24) "
                f"which should not appear in normal production traffic. "
                f"reputation_status: UNKNOWN (no external reputation feed configured). "
                f"In an academic security demonstration, this indicates a simulated threat indicator."
            ),
            severity="MEDIUM",
            evidence={
                "remote_ip": remote_ip,
                "remote_port": conn.get("remote_port"),
                "matched_range": matched_range,
                "process_name": proc,
                "pid": pid,
                "reputation_status": "UNKNOWN",
                "simulation": conn.get("simulation", False),
            },
            score=15,
        ))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# Unified Rule Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_all_rules(
    connections: List[Dict[str, Any]],
    connection_history: List[Dict[str, Any]],
    security_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Run all detection rules against the current telemetry snapshot.
    Returns a deduplicated list of alert dicts, sorted by score_contribution descending.
    """
    all_alerts = []
    all_alerts.extend(rule_a_unusual_outbound_port(connections))
    all_alerts.extend(rule_b_suspicious_process_network(connections))
    all_alerts.extend(rule_c_port_scan_behavior(connections))
    all_alerts.extend(rule_d_brute_force(security_events))
    all_alerts.extend(rule_e_beaconing(connection_history))
    all_alerts.extend(rule_f_unusual_destination(connections))

    # Deduplicate by dedup_hash (keep highest score if duplicated)
    seen_hashes: Dict[str, Dict] = {}
    for alert in all_alerts:
        h = alert["dedup_hash"]
        if h not in seen_hashes or alert["score_contribution"] > seen_hashes[h]["score_contribution"]:
            seen_hashes[h] = alert

    deduplicated = sorted(seen_hashes.values(), key=lambda a: a["score_contribution"], reverse=True)
    logger.info(f"Detection run: {len(connections)} connections, {len(security_events)} log events → {len(deduplicated)} alerts")
    return deduplicated
