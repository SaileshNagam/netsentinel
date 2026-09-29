"""
NetSentinel Safe Demo Generator
Generates completely safe, internal mock telemetry to demonstrate detection capabilities
without actually attacking or scanning external machines.
"""
import hashlib
import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession
from app.models.telemetry import ConnectionEvent, ProcessSnapshot, SecurityEvent
from app.detection.rule_engine import run_all_rules
from app.detection.threat_scoring import score_alerts
from app.agents.security_agent import security_agent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.response import DefensiveAction

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def generate_c2_beacon_demo(db: AsyncSession) -> Dict[str, Any]:
    """
    Scenario A: C2-Like Beacon Simulation
    Simulates a process consistently beaconing out to an uncommon port.
    """
    pid = random.randint(10000, 20000)
    process_name = "demo_client.exe"
    remote_ip = "198.51.100.50" # TEST-NET-2
    remote_port = 4444
    
    # 1. Create fake process
    proc = ProcessSnapshot(
        pid=pid,
        name=process_name,
        exe="C:\\Windows\\Temp\\demo_client.exe",
        username="STUDENT-PC\\User",
        cpu_percent=1.2,
        simulation=True,
        timestamp=utc_now()
    )
    db.add(proc)
    
    # 2. Create historical beacon connections (very regular interval)
    base_time = utc_now() - timedelta(minutes=5)
    for i in range(10):
        # exactly 30s interval
        ts = base_time + timedelta(seconds=i * 30)
        conn = ConnectionEvent(
            protocol="TCP",
            local_ip="192.168.1.100",
            local_port=random.randint(50000, 60000),
            remote_ip=remote_ip,
            remote_port=remote_port,
            state="ESTABLISHED",
            pid=pid,
            process_name=process_name,
            simulation=True,
            timestamp=ts
        )
        db.add(conn)
        
    await db.commit()
    
    return await _trigger_detection_pipeline(db)


async def generate_port_scan_demo(db: AsyncSession) -> Dict[str, Any]:
    """
    Scenario B: Port-Scan Simulation
    Simulates a single source IP hitting many ports rapidly.
    """
    src_ip = "192.168.1.200"
    target_ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080]
    
    base_time = utc_now()
    
    for i, port in enumerate(target_ports):
        conn = ConnectionEvent(
            protocol="TCP",
            local_ip=src_ip,
            local_port=random.randint(40000, 60000),
            remote_ip="192.168.1.5",
            remote_port=port,
            state="SYN_SENT",
            simulation=True,
            timestamp=base_time + timedelta(milliseconds=i*100)
        )
        db.add(conn)
        
    await db.commit()
    return await _trigger_detection_pipeline(db)


async def generate_brute_force_demo(db: AsyncSession) -> Dict[str, Any]:
    """
    Scenario C: Brute-Force Simulation
    Simulates repeated failed logins.
    """
    base_time = utc_now() - timedelta(seconds=5)
    src_ip = "203.0.113.15" # TEST-NET-3
    
    for i in range(6):
        evt = SecurityEvent(
            platform="linux",
            event_type="FAILED_LOGIN",
            user="root",
            source_ip=src_ip,
            severity="MEDIUM",
            raw_source="auth.log (SIMULATED)",
            simulation=True,
            timestamp=base_time + timedelta(seconds=i)
        )
        db.add(evt)
        
    await db.commit()
    return await _trigger_detection_pipeline(db)


async def _trigger_detection_pipeline(db: AsyncSession) -> Dict[str, Any]:
    """
    Helper that extracts recent events, runs the detection engine, and triggers the agent.
    """
    from sqlalchemy import select
    
    # Get last 5 minutes of data
    cutoff = utc_now() - timedelta(minutes=10)
    
    conns_result = await db.execute(select(ConnectionEvent).where(ConnectionEvent.timestamp >= cutoff))
    conns_objs = conns_result.scalars().all()
    conns = [c.__dict__ for c in conns_objs]
    for c in conns:
        if isinstance(c.get('timestamp'), datetime):
            c['timestamp'] = c['timestamp'].isoformat()
    
    procs_result = await db.execute(select(ProcessSnapshot).where(ProcessSnapshot.timestamp >= cutoff))
    procs = [p.__dict__ for p in procs_result.scalars().all()]
    
    sec_result = await db.execute(select(SecurityEvent).where(SecurityEvent.timestamp >= cutoff))
    secs_objs = sec_result.scalars().all()
    secs = [s.__dict__ for s in secs_objs]
    for s in secs:
        if isinstance(s.get('timestamp'), datetime):
            s['timestamp'] = s['timestamp'].isoformat()
            
    # RUN DETECTION
    alerts = run_all_rules(connections=conns, connection_history=conns, security_events=secs)
    
    if not alerts:
        return {"status": "success", "message": "Demo generated, but no alerts triggered."}
        
    risk_res = score_alerts(alerts)
    
    # RUN AGENT
    investigation = await security_agent.investigate(
        alerts=alerts,
        connections=conns,
        processes=procs,
        security_events=secs,
        connection_history=conns,
        risk_score_result=risk_res
    )
    
    if investigation:
        # Save incident to DB
        incident = Incident(
            id=investigation.incident_id,
            device_id="UNKNOWN",
            title=f"Agent Investigation: {investigation.trigger_alert.get('title')}",
            severity=investigation.final_severity,
            status="INVESTIGATING",
            recommended_action=investigation.recommended_action,
            summary=investigation.report_narrative,
            evidence_package_hash=hashlib.sha256(str(investigation.to_dict()).encode()).hexdigest()
        )
        db.add(incident)
        
        # Save recommended action to DB
        action = DefensiveAction(
            incident_id=investigation.incident_id,
            action_type=investigation.recommended_action,
            target=investigation.recommended_target,
            status="PENDING_APPROVAL",
            simulation_mode=True,
            reason=f"Agent Recommendation ({investigation.confidence} Confidence)"
        )
        db.add(action)
        
        await db.commit()
        return {
            "status": "success", 
            "incident_id": investigation.incident_id,
            "report": investigation.report_narrative
        }
        
    return {"status": "success", "message": "Demo generated, but agent did not create an incident."}
