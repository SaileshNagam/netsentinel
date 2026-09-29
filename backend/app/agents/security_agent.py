"""
NetSentinel Agentic Security Engine
Implements the 6-stage autonomous reasoning workflow:
OBSERVE → ANALYZE → INVESTIGATE → DECIDE → RESPOND → REPORT

This is the central intelligence of the NetSentinel platform.
The agent NEVER executes disruptive actions automatically.
All defensive actions require explicit human approval.
"""
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger("NetSentinel.SecurityAgent")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Stage Result Containers
# ─────────────────────────────────────────────────────────────────────────────

class AgentStageResult:
    def __init__(self, stage: str):
        self.stage = stage
        self.status = "PENDING"
        self.evidence: Dict[str, Any] = {}
        self.narrative: str = ""
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None

    def start(self):
        self.status = "RUNNING"
        self.started_at = utc_now()

    def complete(self, evidence: Dict[str, Any], narrative: str):
        self.status = "COMPLETE"
        self.evidence = evidence
        self.narrative = narrative
        self.completed_at = utc_now()

    def fail(self, reason: str):
        self.status = "ERROR"
        self.narrative = f"Stage failed: {reason}"
        self.completed_at = utc_now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "status": self.status,
            "evidence": self.evidence,
            "narrative": self.narrative,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class AgentInvestigation:
    """Holds the full investigation chain for one incident."""

    def __init__(self, incident_id: str, trigger_alert: Dict[str, Any]):
        self.incident_id = incident_id
        self.trigger_alert = trigger_alert
        self.stages: List[AgentStageResult] = []
        self.recommended_action: Optional[str] = None
        self.recommended_target: Optional[str] = None
        self.final_severity: str = "INFO"
        self.final_risk_score: int = 0
        self.confidence: str = "MEDIUM"
        self.report_narrative: str = ""
        self.created_at: datetime = utc_now()
        self.simulation: bool = trigger_alert.get("simulation", False)

    def add_stage(self, stage: AgentStageResult):
        self.stages.append(stage)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "trigger_alert_rule": self.trigger_alert.get("rule_id"),
            "stages": [s.to_dict() for s in self.stages],
            "recommended_action": self.recommended_action,
            "recommended_target": self.recommended_target,
            "final_severity": self.final_severity,
            "final_risk_score": self.final_risk_score,
            "confidence": self.confidence,
            "report_narrative": self.report_narrative,
            "simulation": self.simulation,
            "created_at": self.created_at.isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# NetSentinel Security Agent
# ─────────────────────────────────────────────────────────────────────────────

class NetSentinelSecurityAgent:
    """
    The core agentic security reasoning engine.
    Processes alerts through a structured 6-stage reasoning chain.
    Produces human-readable incident explanations and recommendations.
    NEVER executes defensive actions automatically.
    """

    def __init__(self):
        self.agent_name = "NetSentinel Security Agent v2.0"
        self.total_investigations = 0
        logger.info(f"{self.agent_name} initialized. SIMULATION_MODE=True by default.")

    async def investigate(
        self,
        alerts: List[Dict[str, Any]],
        connections: List[Dict[str, Any]],
        processes: List[Dict[str, Any]],
        security_events: List[Dict[str, Any]],
        connection_history: List[Dict[str, Any]],
        risk_score_result: Dict[str, Any],
        existing_device_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[AgentInvestigation]:
        """
        Full 6-stage investigation workflow.
        Returns an AgentInvestigation object or None if no actionable findings.
        """
        if not alerts:
            return None

        # Use the highest-scoring alert as the primary trigger
        primary_alert = max(alerts, key=lambda a: a.get("score_contribution", 0))
        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

        investigation = AgentInvestigation(incident_id=incident_id, trigger_alert=primary_alert)
        self.total_investigations += 1

        logger.info(f"[{incident_id}] Investigation started. Primary rule: {primary_alert.get('rule_id')}")

        # ── Stage 1: OBSERVE ──────────────────────────────────────────────────
        obs_stage = AgentStageResult("OBSERVE")
        obs_stage.start()
        try:
            obs_stage.complete(
                evidence={
                    "alerts_count": len(alerts),
                    "connections_count": len(connections),
                    "security_events_count": len(security_events),
                    "primary_rule_triggered": primary_alert.get("rule_id"),
                    "primary_severity": primary_alert.get("severity"),
                    "alerts": [{"rule_id": a["rule_id"], "severity": a["severity"]} for a in alerts],
                    "simulation": primary_alert.get("simulation", False),
                },
                narrative=(
                    f"NetSentinel observed {len(alerts)} detection rule(s) triggered during this monitoring cycle. "
                    f"Primary alert: {primary_alert.get('title', 'Unknown')} (rule: {primary_alert.get('rule_id')}). "
                    f"Current host state: {len(connections)} active connections, "
                    f"{len(security_events)} recent security log events. "
                    f"{'[SIMULATION] All data is simulated for demonstration.' if investigation.simulation else ''}"
                )
            )
        except Exception as e:
            obs_stage.fail(str(e))
        investigation.add_stage(obs_stage)

        # ── Stage 2: ANALYZE ─────────────────────────────────────────────────
        analyze_stage = AgentStageResult("ANALYZE")
        analyze_stage.start()
        try:
            evidence_summary = primary_alert.get("evidence", {})
            rule_id = primary_alert.get("rule_id", "UNKNOWN")
            rule_characteristics = _describe_rule_characteristics(rule_id, evidence_summary)

            analyze_stage.complete(
                evidence={
                    "rule_id": rule_id,
                    "risk_score": risk_score_result.get("risk_score", 0),
                    "severity": risk_score_result.get("severity", "INFO"),
                    "score_factors": risk_score_result.get("factors", []),
                    "alert_count": len(alerts),
                    "rules_triggered": [a["rule_id"] for a in alerts],
                    "characteristics": rule_characteristics,
                },
                narrative=(
                    f"Analysis of {len(alerts)} alert(s) yielded a composite risk score of "
                    f"{risk_score_result.get('risk_score', 0)}/100 (severity: {risk_score_result.get('severity', 'INFO')}). "
                    f"Score breakdown: {_format_score_factors(risk_score_result.get('factors', []))}. "
                    f"{rule_characteristics}"
                )
            )
        except Exception as e:
            analyze_stage.fail(str(e))
        investigation.add_stage(analyze_stage)

        # ── Stage 3: INVESTIGATE ─────────────────────────────────────────────
        investigate_stage = AgentStageResult("INVESTIGATE")
        investigate_stage.start()
        try:
            evidence = primary_alert.get("evidence", {})
            pid = evidence.get("pid")
            remote_ip = evidence.get("remote_ip")
            proc_name = evidence.get("process_name", "UNKNOWN")

            # Find process details from process snapshot
            matching_process = next(
                (p for p in processes if p.get("pid") == pid and pid is not None), None
            )

            # Count historical connections to same destination
            hist_count = sum(
                1 for c in connection_history
                if c.get("remote_ip") == remote_ip and remote_ip
            )

            # Check related alerts
            related_rules = [a["rule_id"] for a in alerts if a.get("rule_id") != primary_alert.get("rule_id")]

            investigate_stage.complete(
                evidence={
                    "pid": pid,
                    "process_name": proc_name,
                    "process_details": matching_process,
                    "remote_ip": remote_ip,
                    "remote_port": evidence.get("remote_port"),
                    "historical_connections_to_dest": hist_count,
                    "related_alert_rules": related_rules,
                    "device_trust_status": (existing_device_info or {}).get("trust_status"),
                    "recent_security_events": len(security_events),
                },
                narrative=(
                    f"Investigation gathered: "
                    f"Process '{proc_name}' (PID {pid}){_describe_process(matching_process)} "
                    f"was responsible for the suspicious activity. "
                    f"Historical analysis found {hist_count} previous connection(s) to "
                    f"{remote_ip or 'unknown destination'}. "
                    f"{'Additional correlated rules: ' + ', '.join(related_rules) + '.' if related_rules else 'No additional rule correlations.'} "
                    f"{'Device trust status: ' + str((existing_device_info or {}).get('trust_status')) + '.' if existing_device_info else ''}"
                )
            )
        except Exception as e:
            investigate_stage.fail(str(e))
        investigation.add_stage(investigate_stage)

        # ── Stage 4: DECIDE ──────────────────────────────────────────────────
        decide_stage = AgentStageResult("DECIDE")
        decide_stage.start()
        try:
            risk_score = risk_score_result.get("risk_score", 0)
            severity = risk_score_result.get("severity", "LOW")
            rules = [a["rule_id"] for a in alerts]

            recommended_action, confidence, reason = _decide_action(rules, risk_score, severity)

            investigation.final_severity = severity
            investigation.final_risk_score = risk_score
            investigation.confidence = confidence
            investigation.recommended_action = recommended_action
            investigation.recommended_target = (
                primary_alert.get("evidence", {}).get("remote_ip") or
                str(primary_alert.get("evidence", {}).get("pid", ""))
            )

            decide_stage.complete(
                evidence={
                    "risk_score": risk_score,
                    "severity": severity,
                    "confidence": confidence,
                    "recommended_action": recommended_action,
                    "decision_reason": reason,
                },
                narrative=(
                    f"Decision: Risk score {risk_score}/100, Severity: {severity}, Confidence: {confidence}. "
                    f"Recommended action: {recommended_action}. "
                    f"Rationale: {reason}. "
                    f"NOTE: No defensive action has been executed. Operator approval is required."
                )
            )
        except Exception as e:
            decide_stage.fail(str(e))
        investigation.add_stage(decide_stage)

        # ── Stage 5: RESPOND ─────────────────────────────────────────────────
        respond_stage = AgentStageResult("RESPOND")
        respond_stage.start()
        try:
            respond_stage.complete(
                evidence={
                    "action": investigation.recommended_action,
                    "target": investigation.recommended_target,
                    "status": "PENDING_APPROVAL",
                    "requires_human_approval": True,
                    "simulation_mode": True,
                    "auto_execute": False,
                },
                narrative=(
                    f"Recommended Response: {investigation.recommended_action} on target '{investigation.recommended_target}'. "
                    f"Status: PENDING_APPROVAL. "
                    f"This action has been queued for human operator review. "
                    f"The action will NOT be executed until explicitly approved. "
                    f"Simulation mode is ACTIVE — even if approved, the system will simulate the action and log the intended outcome."
                )
            )
        except Exception as e:
            respond_stage.fail(str(e))
        investigation.add_stage(respond_stage)

        # ── Stage 6: REPORT ──────────────────────────────────────────────────
        report_stage = AgentStageResult("REPORT")
        report_stage.start()
        try:
            narrative = _generate_report(
                incident_id=incident_id,
                primary_alert=primary_alert,
                investigation=investigation,
                risk_score_result=risk_score_result,
                connection_history=connection_history,
            )
            investigation.report_narrative = narrative
            report_stage.complete(
                evidence={"incident_id": incident_id, "report_length_chars": len(narrative)},
                narrative=narrative
            )
        except Exception as e:
            report_stage.fail(str(e))
        investigation.add_stage(report_stage)

        logger.info(
            f"[{incident_id}] Investigation complete. "
            f"Score={investigation.final_risk_score}, Severity={investigation.final_severity}, "
            f"Action={investigation.recommended_action}"
        )
        return investigation


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _describe_rule_characteristics(rule_id: str, evidence: Dict[str, Any]) -> str:
    """Generate a human-readable description of the triggered rule's characteristics."""
    descriptions = {
        "RULE_A_UNUSUAL_OUTBOUND_PORT": (
            f"The connection used a destination port ({evidence.get('remote_port', '?')}) "
            f"that appears on the configured high-risk port list, which may be associated with "
            f"remote access tools or unauthorized services."
        ),
        "RULE_B_SUSPICIOUS_PROCESS_NETWORK": (
            f"The process '{evidence.get('process_name', '?')}' is not a standard network application "
            f"and is not expected to initiate outbound socket connections."
        ),
        "RULE_C_PORT_SCAN": (
            f"A single source contacted {evidence.get('distinct_ports_hit', '?')} distinct destination "
            f"ports within {evidence.get('window_seconds', '?')} seconds, consistent with port scanning behavior."
        ),
        "RULE_D_BRUTE_FORCE": (
            f"{evidence.get('failure_count', '?')} authentication failures observed from "
            f"'{evidence.get('source_ip', '?')}' within {evidence.get('window_seconds', '?')} seconds, "
            f"consistent with credential guessing behavior."
        ),
        "RULE_E_BEACONING": (
            f"Communication to {evidence.get('remote_ip', '?')}:{evidence.get('remote_port', '?')} "
            f"occurred {evidence.get('sample_count', '?')} times at mean interval "
            f"{evidence.get('mean_interval_seconds', '?')}s (CV={evidence.get('coefficient_of_variation', '?')}), "
            f"indicating highly regular, possibly automated communication."
        ),
        "RULE_F_UNUSUAL_DESTINATION": (
            f"The destination IP {evidence.get('remote_ip', '?')} falls within a documentation/test range "
            f"({evidence.get('matched_range', '?')}) that should not appear in normal traffic."
        ),
    }
    return descriptions.get(rule_id, "No specific characteristic description available for this rule.")


def _describe_process(proc: Optional[Dict[str, Any]]) -> str:
    if not proc:
        return " (process details unavailable)"
    parts = []
    if proc.get("username"):
        parts.append(f"running as '{proc['username']}'")
    if proc.get("exe"):
        parts.append(f"from '{proc['exe']}'")
    if proc.get("cpu_percent", 0) > 20:
        parts.append(f"consuming {proc['cpu_percent']}% CPU")
    return f" ({', '.join(parts)})" if parts else ""


def _format_score_factors(factors: List[Dict[str, Any]]) -> str:
    if not factors:
        return "no factors recorded"
    return "; ".join(f"{f.get('rule', '?')} +{f.get('score', 0)}" for f in factors)


def _decide_action(rules: List[str], risk_score: int, severity: str) -> tuple:
    """
    Deterministic decision logic.
    Returns (recommended_action, confidence, reason).
    """
    if "RULE_E_BEACONING" in rules and risk_score >= 60:
        return (
            "TEMPORARY_BLOCK",
            "HIGH",
            "Repeated periodic communication to an unusual destination with high risk score suggests possible C2-like activity."
        )
    if "RULE_D_BRUTE_FORCE" in rules and risk_score >= 50:
        return (
            "ALERT_OPERATOR",
            "HIGH",
            "Repeated authentication failures suggest a credential attack is in progress. Manual investigation required."
        )
    if "RULE_A_UNUSUAL_OUTBOUND_PORT" in rules and "RULE_B_SUSPICIOUS_PROCESS_NETWORK" in rules:
        return (
            "TEMPORARY_BLOCK",
            "MEDIUM",
            "Combination of suspicious process and unusual port warrants temporary blocking pending investigation."
        )
    if "RULE_F_UNUSUAL_DESTINATION" in rules:
        return (
            "ALERT_OPERATOR",
            "MEDIUM",
            "Connection to a documentation/test IP range requires investigation to determine if it is a simulated event or real anomaly."
        )
    if risk_score >= 60:
        return (
            "ALERT_OPERATOR",
            "MEDIUM",
            f"High composite risk score ({risk_score}/100) warrants operator review."
        )
    return (
        "MONITOR",
        "LOW",
        f"Risk score ({risk_score}/100) is below critical threshold. Continuous monitoring recommended."
    )


def _generate_report(
    incident_id: str,
    primary_alert: Dict[str, Any],
    investigation: "AgentInvestigation",
    risk_score_result: Dict[str, Any],
    connection_history: List[Dict[str, Any]],
) -> str:
    """Generate the final human-readable incident report narrative."""
    evidence = primary_alert.get("evidence", {})
    proc = evidence.get("process_name", "UNKNOWN")
    pid = evidence.get("pid", "N/A")
    remote_ip = evidence.get("remote_ip", "unknown destination")
    remote_port = evidence.get("remote_port", "N/A")
    hist_count = sum(1 for c in connection_history if c.get("remote_ip") == remote_ip)
    factors_text = _format_score_factors(risk_score_result.get("factors", []))
    sim_tag = "\n\n[SIMULATION] All data in this report was generated by the NetSentinel Demo Generator for academic demonstration purposes." if investigation.simulation else ""

    return (
        f"INCIDENT REPORT: {incident_id}\n"
        f"{'═' * 60}\n\n"
        f"NetSentinel observed suspicious activity involving "
        f"process {proc} (PID {pid}), which was detected making "
        f"unusual network connections to {remote_ip}:{remote_port}.\n\n"
        f"DETECTION DETAILS:\n"
        f"  • Primary rule triggered: {primary_alert.get('rule_id')}\n"
        f"  • Alert: {primary_alert.get('title')}\n"
        f"  • {primary_alert.get('description', '')}\n\n"
        f"RISK ASSESSMENT:\n"
        f"  • Composite risk score: {risk_score_result.get('risk_score', 0)}/100\n"
        f"  • Severity: {investigation.final_severity}\n"
        f"  • Confidence: {investigation.confidence}\n"
        f"  • Score breakdown: {factors_text}\n\n"
        f"INVESTIGATION FINDINGS:\n"
        f"  • {hist_count} historical connection(s) to {remote_ip} found in connection history.\n"
        f"  • {len(connection_history)} total connection records analyzed.\n\n"
        f"RECOMMENDED RESPONSE:\n"
        f"  • Action: {investigation.recommended_action}\n"
        f"  • Target: {investigation.recommended_target or remote_ip}\n\n"
        f"IMPORTANT: No defensive action has been executed.\n"
        f"Operator approval is required before any system modifications are made.\n"
        f"Simulation mode is ACTIVE.{sim_tag}"
    )


# Singleton instance
security_agent = NetSentinelSecurityAgent()
