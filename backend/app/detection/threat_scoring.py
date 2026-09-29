"""
NetSentinel Threat Scoring Engine
Explainable additive risk scoring model.
Every score includes a full factor breakdown — no black-box scores.
"""
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger("NetSentinel.Detection.ThreatScoring")

# Weight table: rule_id → (base_score, severity_label, description)
RULE_SCORE_MAP: Dict[str, Tuple[int, str, str]] = {
    "RULE_A_UNUSUAL_OUTBOUND_PORT":    (20, "HIGH",     "Unusual outbound port connection"),
    "RULE_B_SUSPICIOUS_PROCESS_NETWORK": (25, "HIGH",   "Suspicious process-to-network relationship"),
    "RULE_C_PORT_SCAN":                (15, "MEDIUM",   "Port-scan-like behavior"),
    "RULE_D_BRUTE_FORCE":              (25, "HIGH",     "Repeated authentication failures"),
    "RULE_E_BEACONING":                (35, "HIGH",     "Possible C2-like periodic beaconing"),
    "RULE_F_UNUSUAL_DESTINATION":      (15, "MEDIUM",   "Connection to unusual/test IP range"),
}

SEVERITY_THRESHOLD = {
    "CRITICAL": 80,
    "HIGH":     60,
    "MEDIUM":   30,
    "LOW":      0,
}

def score_alerts(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute an explainable composite threat risk score from a list of alerts.
    
    Returns:
        {
            "risk_score": int (0-100),
            "severity": str,
            "factors": [ { "rule": str, "score": int, "description": str } ],
            "alert_count": int,
        }
    
    Every score includes a factor breakdown for full explainability.
    """
    factors = []
    total_score = 0

    for alert in alerts:
        rule_id = alert.get("rule_id", "UNKNOWN")
        contribution = alert.get("score_contribution", 0)
        _, _, desc = RULE_SCORE_MAP.get(rule_id, (0, "INFO", "Unknown rule"))

        factors.append({
            "rule": rule_id,
            "score": contribution,
            "description": desc,
            "evidence_summary": _summarize_evidence(alert.get("evidence", {})),
        })
        total_score += contribution

    # Clamp to 0–100
    risk_score = min(100, max(0, total_score))

    # Determine severity label
    severity = "LOW"
    for label, threshold in sorted(SEVERITY_THRESHOLD.items(), key=lambda x: -x[1]):
        if risk_score >= threshold:
            severity = label
            break

    return {
        "risk_score": risk_score,
        "severity": severity,
        "factors": factors,
        "alert_count": len(alerts),
    }


def _summarize_evidence(evidence: Dict[str, Any]) -> str:
    """Create a one-line human-readable evidence summary."""
    parts = []
    if evidence.get("process_name"):
        parts.append(f"process={evidence['process_name']}")
    if evidence.get("pid"):
        parts.append(f"pid={evidence['pid']}")
    if evidence.get("remote_ip"):
        parts.append(f"dest={evidence['remote_ip']}:{evidence.get('remote_port', '?')}")
    if evidence.get("source_ip"):
        parts.append(f"src={evidence['source_ip']}")
    if evidence.get("failure_count"):
        parts.append(f"failures={evidence['failure_count']}")
    if evidence.get("mean_interval_seconds"):
        parts.append(f"interval={evidence['mean_interval_seconds']}s")
    return ", ".join(parts) if parts else "no additional evidence"
