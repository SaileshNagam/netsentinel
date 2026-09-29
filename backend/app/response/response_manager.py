"""
NetSentinel Defensive Response Manager
Orchestrates the safe execution or simulation of defensive actions.
Strictly routes all requests through the Safety Gate.
"""
import hashlib
import logging
import platform
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any

import psutil
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.response import DefensiveAction, ActionStatus, ActionType, BlocklistEntry
from app.models.audit import AuditEvent
from app.response.safety_gate import safety_gate, SafetyGateViolation

# For Windows firewall integration
from app.monitoring.windows_monitor import block_ip_windows, IS_WINDOWS

logger = logging.getLogger("NetSentinel.ResponseManager")
IS_LINUX = platform.system() == "Linux"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ResponseManager:
    """
    Executes defensive actions after human approval.
    Defaults to simulation mode.
    """

    async def execute_action(
        self,
        db: AsyncSession,
        action_id: int,
        operator: str = "SOC_OPERATOR",
        force_dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Attempt to execute an approved DefensiveAction.
        Passes through Safety Gate. Returns execution results and updates the DB.
        """
        # 1. Fetch action
        result = await db.execute(select(DefensiveAction).where(DefensiveAction.id == action_id))
        action = result.scalars().first()

        if not action:
            return {"success": False, "error": "Action not found."}

        # 2. Safety Gate Validation
        try:
            safety_gate.validate_action_request(
                action_type=action.action_type,
                target=action.target,
                action_status=action.status,
                operator=operator
            )
        except SafetyGateViolation as e:
            action.status = ActionStatus.FAILED.value
            action.execution_result = f"Safety Gate Blocked: {e}"
            action.executed_at = utc_now()
            await self._log_audit(db, action, operator, "SAFETY_GATE_BLOCKED", str(e))
            await db.commit()
            return {"success": False, "error": str(e), "safety_block": True}

        # 3. Determine Execution Mode
        # If the platform globally enforces simulation, or the action is marked simulation,
        # or the caller requested a dry run -> we simulate.
        is_simulation = safety_gate.simulation_mode or action.simulation_mode or force_dry_run

        exec_result: Dict[str, Any] = {}

        # 4. Route to specific handler
        try:
            if action.action_type == ActionType.BLOCK_IP.value:
                exec_result = await self._handle_block_ip(action.target, is_simulation)
            
            elif action.action_type == ActionType.KILL_PROCESS.value:
                exec_result = await self._handle_kill_process(int(action.target), is_simulation)
            
            elif action.action_type == ActionType.TEMPORARY_BLOCKLIST.value:
                exec_result = await self._handle_temp_blocklist(db, action.target, action.incident_id, operator, is_simulation)
            
            elif action.action_type in (ActionType.MONITOR_ONLY.value, ActionType.MARK_SUSPICIOUS.value):
                exec_result = {"success": True, "message": "Metadata updated successfully.", "simulation": False}
            
            else:
                exec_result = {"success": False, "error": f"Unknown action type: {action.action_type}"}

        except Exception as e:
            logger.error(f"Execution error for action {action.id}: {e}")
            exec_result = {"success": False, "error": f"Unexpected execution failure: {e}"}

        # 5. Update Database Record
        if exec_result.get("success"):
            action.status = ActionStatus.SIMULATED.value if is_simulation else ActionStatus.EXECUTED.value
            if is_simulation:
                action.dry_run_result = json_dumps_safe(exec_result)
            else:
                action.execution_result = json_dumps_safe(exec_result)
        else:
            action.status = ActionStatus.FAILED.value
            action.execution_result = json_dumps_safe(exec_result)

        action.executed_at = utc_now()
        
        # 6. Audit Logging
        audit_event_type = f"ACTION_{action.status}"
        audit_details = (
            f"Type: {action.action_type}, Target: {action.target}, "
            f"Simulation: {is_simulation}, Result: {exec_result.get('message', exec_result.get('error', 'Unknown'))}"
        )
        await self._log_audit(db, action, operator, audit_event_type, audit_details)
        
        await db.commit()
        return exec_result


    async def _handle_block_ip(self, ip: str, is_simulation: bool) -> Dict[str, Any]:
        """OS-specific IP blocking via host firewall."""
        if IS_WINDOWS:
            return block_ip_windows(ip, direction="both", dry_run=is_simulation)
        elif IS_LINUX:
            return self._block_ip_linux(ip, is_simulation)
        else:
            return {
                "success": is_simulation, 
                "simulation": is_simulation,
                "message": f"[SIMULATION] Would block {ip}. (Firewall integration not implemented for macOS/Darwin)"
            }


    def _block_ip_linux(self, ip: str, is_simulation: bool) -> Dict[str, Any]:
        """Linux iptables wrapper (Safe array execution, no shell=True)."""
        cmds = [
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
        ]
        
        if is_simulation:
            return {
                "success": True,
                "simulation": True,
                "intended_commands": [" ".join(c) for c in cmds],
                "message": f"[SIMULATION] Would execute iptables DROP rules for {ip}."
            }
            
        # Real execution
        results = []
        all_success = True
        for cmd in cmds:
            try:
                # Requires root; will fail gracefully if NetSentinel runs as normal user
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                results.append({"command": " ".join(cmd), "returncode": res.returncode, "stderr": res.stderr})
                if res.returncode != 0:
                    all_success = False
            except Exception as e:
                results.append({"command": " ".join(cmd), "error": str(e)})
                all_success = False
                
        return {
            "success": all_success,
            "simulation": False,
            "results": results,
            "message": "iptables rules applied successfully." if all_success else "iptables execution failed. Check privileges."
        }


    async def _handle_kill_process(self, pid: int, is_simulation: bool) -> Dict[str, Any]:
        """Safely terminates a process using psutil."""
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
        except psutil.NoSuchProcess:
            return {"success": False, "error": f"Process {pid} no longer exists."}
            
        if is_simulation:
            return {
                "success": True,
                "simulation": True,
                "message": f"[SIMULATION] Would terminate process '{proc_name}' (PID {pid}) gracefully."
            }
            
        # Real execution
        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill() # Force kill if graceful termination fails
            return {
                "success": True,
                "simulation": False,
                "message": f"Successfully terminated process '{proc_name}' (PID {pid})."
            }
        except psutil.AccessDenied:
            return {"success": False, "error": f"Access Denied: Insufficient privileges to terminate PID {pid}."}
        except Exception as e:
            return {"success": False, "error": f"Failed to terminate PID {pid}: {e}"}


    async def _handle_temp_blocklist(self, db: AsyncSession, ip: str, incident_id: str, operator: str, is_simulation: bool) -> Dict[str, Any]:
        """Adds an IP to the persistent NetSentinel blocklist with a TTL."""
        if is_simulation:
            return {
                "success": True,
                "simulation": True,
                "message": f"[SIMULATION] Would add {ip} to temporary blocklist."
            }
            
        from datetime import timedelta
        # 300 seconds (5 mins) temporary block
        expires = utc_now() + timedelta(seconds=300)
        
        entry = BlocklistEntry(
            ip=ip,
            reason="Added via Agentic Response Approval",
            incident_id=incident_id,
            operator=operator,
            simulation=False,
            expires_at=expires
        )
        db.add(entry)
        # We don't commit here; execute_action commits at the end
        
        return {
            "success": True,
            "simulation": False,
            "message": f"Added {ip} to NetSentinel temporary blocklist (expires in 5 minutes)."
        }


    async def _log_audit(self, db: AsyncSession, action: DefensiveAction, operator: str, event_type: str, details: str):
        """Create a cryptographic audit log for the action."""
        # Generate tamper-resistant hash
        raw = f"{action.id}:{action.status}:{operator}:{utc_now().isoformat()}"
        event_hash = hashlib.sha256(raw.encode()).hexdigest()
        
        audit = AuditEvent(
            action=event_type,
            actor=operator,
            target_resource=f"defensive_action:{action.id}",
            details=details,
            timestamp=utc_now(),
            event_hash=event_hash
        )
        db.add(audit)


def json_dumps_safe(data: Dict) -> str:
    import json
    try:
        return json.dumps(data)
    except Exception:
        return "{}"

# Singleton
response_manager = ResponseManager()
