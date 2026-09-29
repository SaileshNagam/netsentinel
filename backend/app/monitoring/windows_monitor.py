"""
NetSentinel Windows Platform Monitor
Windows-specific network and system monitoring using psutil and win32 APIs.
Falls back gracefully when not running on Windows or without elevated privileges.
"""
import logging
import platform
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger("NetSentinel.WindowsMonitor")

IS_WINDOWS = platform.system() == "Windows"


def _run_powershell(script: str, timeout: int = 10) -> Optional[str]:
    """
    Safely run a PowerShell script without shell=True.
    Only used for Windows-specific telemetry when psutil is insufficient.
    """
    if not IS_WINDOWS:
        return None
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except FileNotFoundError:
        logger.warning("PowerShell not found.")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"PowerShell command timed out.")
        return None
    except Exception as e:
        logger.debug(f"PowerShell error: {e}")
        return None


def get_windows_event_log_events(
    log_name: str = "Security",
    event_ids: Optional[List[int]] = None,
    max_events: int = 50
) -> List[Dict[str, Any]]:
    """
    Read Windows Security Event Log entries using PowerShell Get-WinEvent.
    Requires Administrator privileges for Security log.
    Falls back gracefully if unavailable.
    
    Common Security Event IDs:
    - 4624: Successful logon
    - 4625: Failed logon
    - 4672: Special privileges assigned to new logon
    - 4688: A new process has been created
    """
    if not IS_WINDOWS:
        return []

    if event_ids is None:
        event_ids = [4624, 4625, 4672, 4688]

    id_filter = ",".join(str(e) for e in event_ids)
    script = (
        f"try {{ Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} "
        f"| Where-Object {{ $_.Id -in @({id_filter}) }} "
        f"| Select-Object TimeCreated, Id, Message "
        f"| ConvertTo-Json -Depth 2 }} catch {{ Write-Output '[]' }}"
    )

    output = _run_powershell(script)
    if not output:
        logger.info("Insufficient privileges for Security Event Log — monitoring unavailable.")
        return []

    events: List[Dict[str, Any]] = []
    try:
        import json
        raw = json.loads(output) if output else []
        if isinstance(raw, dict):
            raw = [raw]
        for entry in raw:
            event_id = entry.get("Id", 0)
            event_type = _map_windows_event_id(event_id)
            events.append({
                "timestamp": str(entry.get("TimeCreated", "")),
                "platform": "windows",
                "event_type": event_type,
                "event_id": event_id,
                "user": _extract_windows_user(entry.get("Message", "")),
                "source_ip": _extract_windows_ip(entry.get("Message", "")),
                "severity": _map_windows_severity(event_id),
                "raw_source": f"Windows Event Log: {log_name}",
                "simulation": False,
            })
    except Exception as e:
        logger.warning(f"Windows event log parse error: {e}")
        logger.info("Insufficient privileges for Security Event Log — monitoring unavailable.")

    return events


def _map_windows_event_id(event_id: int) -> str:
    mapping = {
        4624: "SUCCESSFUL_LOGIN",
        4625: "FAILED_LOGIN",
        4672: "PRIVILEGE_ESCALATION_EVENT",
        4688: "PROCESS_CREATED",
        4634: "LOGOFF",
        4648: "LOGON_USING_EXPLICIT_CREDENTIALS",
    }
    return mapping.get(event_id, "SECURITY_WARNING")


def _map_windows_severity(event_id: int) -> str:
    if event_id in (4625,):
        return "MEDIUM"
    elif event_id in (4672, 4648):
        return "LOW"
    elif event_id in (4624, 4688):
        return "INFO"
    return "INFO"


def _extract_windows_user(message: str) -> str:
    """Extract username from Windows event log message text."""
    import re
    match = re.search(r"Account Name:\s+(\S+)", message)
    if match:
        return match.group(1)
    return "UNKNOWN"


def _extract_windows_ip(message: str) -> Optional[str]:
    """Extract source IP address from Windows event log message text."""
    import re
    match = re.search(r"Source Network Address:\s+([\d.]+)", message)
    if match and match.group(1) not in ("-", "::1", "127.0.0.1"):
        return match.group(1)
    return None


def get_windows_firewall_status() -> Dict[str, Any]:
    """Check Windows Defender Firewall status via PowerShell."""
    if not IS_WINDOWS:
        return {"available": False, "reason": "Not running on Windows"}

    output = _run_powershell(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json"
    )
    if output:
        try:
            import json
            profiles = json.loads(output)
            return {"available": True, "profiles": profiles}
        except Exception:
            pass
    return {"available": False, "reason": "Insufficient privileges or PowerShell error"}


def block_ip_windows(ip: str, direction: str = "both", dry_run: bool = True) -> Dict[str, Any]:
    """
    Add Windows Defender Firewall block rule for an IP address.
    ALWAYS defaults to dry_run=True.
    direction: "in", "out", or "both"
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"success": False, "error": f"Invalid IP address: {ip}"}

    # Safety: reject loopback and link-local
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_loopback or ip_obj.is_link_local:
        return {"success": False, "error": f"Refusing to block reserved address: {ip}"}

    rule_name = f"NetSentinel-Block-{ip}"
    cmds = []
    if direction in ("in", "both"):
        cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                      f"name={rule_name}-IN", "dir=in", "action=block",
                      f"remoteip={ip}", "enable=yes"])
    if direction in ("out", "both"):
        cmds.append(["netsh", "advfirewall", "firewall", "add", "rule",
                      f"name={rule_name}-OUT", "dir=out", "action=block",
                      f"remoteip={ip}", "enable=yes"])

    intended_commands = [" ".join(c) for c in cmds]

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "simulation": True,
            "intended_commands": intended_commands,
            "message": f"[SIMULATION] Would block {ip} via Windows Defender Firewall.",
        }

    if not IS_WINDOWS:
        return {"success": False, "error": "Not running on Windows. Cannot execute firewall rule."}

    results = []
    for cmd in cmds:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            results.append({"command": " ".join(cmd), "returncode": result.returncode,
                            "stdout": result.stdout, "stderr": result.stderr})
        except Exception as e:
            results.append({"command": " ".join(cmd), "error": str(e)})

    return {
        "success": all(r.get("returncode", 1) == 0 for r in results),
        "dry_run": False,
        "simulation": False,
        "results": results,
    }
