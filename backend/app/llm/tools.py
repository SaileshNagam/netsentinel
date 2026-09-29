"""
NetSentinel LLM Tools
Structured tools for an optional local/cloud LLM to integrate with NetSentinel safely.
No arbitrary command execution is permitted.
"""
from typing import Dict, Any, List
from pydantic import BaseModel, Field

class GetActiveConnectionsTool(BaseModel):
    """Fetch active network connections from the host."""
    pass

class GetProcessDetailsTool(BaseModel):
    """Fetch details about a running process."""
    pid: int = Field(..., description="The Process ID (PID) to investigate.")

class GetSecurityLogsTool(BaseModel):
    """Fetch recent normalized security events (logins, privileges)."""
    limit: int = Field(50, description="Max number of logs to fetch.")

class GetIncidentTool(BaseModel):
    """Fetch details of an active security incident by ID."""
    incident_id: str = Field(..., description="The Incident ID to lookup (e.g. INC-...).")

class RecommendMitigationTool(BaseModel):
    """Recommend a mitigation action for a specific incident. Requires human approval."""
    incident_id: str = Field(..., description="The Incident ID to mitigate.")
    action: str = Field(..., description="Action to recommend: BLOCK_IP, KILL_PROCESS, TEMPORARY_BLOCKLIST, MARK_SUSPICIOUS, MONITOR_ONLY")
    target: str = Field(..., description="The target IP address or PID.")
    reason: str = Field(..., description="Justification for the action.")


def register_llm_tools() -> List[Dict[str, Any]]:
    """
    Returns the JSON-Schema tool definitions to bind to an LLM provider (e.g. Ollama, Gemini).
    """
    return [
        {
            "name": "get_active_connections",
            "description": "Fetch active TCP/UDP network connections from the host.",
            "parameters": GetActiveConnectionsTool.model_json_schema()
        },
        {
            "name": "get_process_details",
            "description": "Fetch details about a specific running process by PID.",
            "parameters": GetProcessDetailsTool.model_json_schema()
        },
        {
            "name": "get_security_logs",
            "description": "Fetch recent normalized security log events from the OS.",
            "parameters": GetSecurityLogsTool.model_json_schema()
        },
        {
            "name": "get_incident",
            "description": "Fetch detailed context about a specific security incident.",
            "parameters": GetIncidentTool.model_json_schema()
        },
        {
            "name": "recommend_mitigation",
            "description": "Recommend a defensive action. This will create a pending action for human review.",
            "parameters": RecommendMitigationTool.model_json_schema()
        }
    ]
