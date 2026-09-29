"""
NetSentinel Linux Platform Monitor
Linux-specific network and system monitoring.
Parses /proc, ss, ip, journalctl, /var/log/auth.log.
"""
import logging
import re
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("NetSentinel.LinuxMonitor")


def _run_cmd(args: List[str], timeout: int = 5) -> Optional[str]:
    """Run a subprocess command safely (no shell=True) and return stdout."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout
    except FileNotFoundError:
        logger.debug(f"Command not found: {args[0]}")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {args}")
        return None
    except Exception as e:
        logger.debug(f"Command error {args}: {e}")
        return None


def get_ss_connections() -> List[Dict[str, Any]]:
    """
    Parse active TCP/UDP connections from `ss -tunpH` output.
    Supplements psutil with kernel-level socket info.
    """
    if not shutil.which("ss"):
        return []

    output = _run_cmd(["ss", "-tunpH"])
    if not output:
        return []

    results = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            proto = parts[0].upper()
            state = parts[1] if proto == "TCP" else "STATELESS"
            local = parts[4]
            remote = parts[5] if len(parts) > 5 else "*:*"

            def parse_addr(addr: str):
                if addr.startswith("["):
                    # IPv6: [::1]:port
                    match = re.match(r'\[(.+)\]:(\d+|\*)', addr)
                    if match:
                        return match.group(1), int(match.group(2)) if match.group(2) != '*' else None
                elif ":" in addr:
                    parts_ = addr.rsplit(":", 1)
                    ip = parts_[0]
                    port_s = parts_[1]
                    return ip, int(port_s) if port_s.isdigit() else None
                return addr, None

            local_ip, local_port = parse_addr(local)
            remote_ip, remote_port = parse_addr(remote)

            # Extract PID from process column if present
            pid = None
            process_name = "UNKNOWN"
            if len(parts) > 6:
                pid_match = re.search(r'pid=(\d+)', parts[-1])
                name_match = re.search(r'users:\(\("([^"]+)"', parts[-1])
                if pid_match:
                    pid = int(pid_match.group(1))
                if name_match:
                    process_name = name_match.group(1)

            results.append({
                "source": "ss",
                "protocol": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip if remote_ip not in ("*", "0.0.0.0") else None,
                "remote_port": remote_port,
                "state": state,
                "pid": pid,
                "process_name": process_name,
            })
        except Exception:
            continue

    return results


def parse_auth_log(max_lines: int = 500) -> List[Dict[str, Any]]:
    """
    Parse /var/log/auth.log for security events.
    Returns normalized list of FAILED_LOGIN, SUCCESSFUL_LOGIN, PRIVILEGE_ESCALATION_EVENT events.
    Degrades gracefully if log is unreadable.
    """
    auth_log_paths = [
        Path("/var/log/auth.log"),
        Path("/var/log/secure"),
        Path("/var/log/syslog"),
    ]

    log_path: Optional[Path] = None
    for p in auth_log_paths:
        if p.exists() and p.is_file():
            log_path = p
            break

    if not log_path:
        logger.info("No auth log found at standard paths. Security log monitoring unavailable.")
        return []

    events: List[Dict[str, Any]] = []
    try:
        with open(log_path, "r", errors="replace") as f:
            lines = f.readlines()[-max_lines:]
    except PermissionError:
        logger.warning("Security log monitoring unavailable — elevated privileges required.")
        return []
    except Exception as e:
        logger.warning(f"Auth log read error: {e}")
        return []

    for line in lines:
        event = _parse_auth_line(line.strip())
        if event:
            events.append(event)

    return events


# Patterns for common auth log events
_FAILED_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"),
    re.compile(r"authentication failure.*user=(\S+)"),
    re.compile(r"pam_unix.*auth.*failure.*user=(\S+)"),
]
_SUCCESS_PATTERNS = [
    re.compile(r"Accepted (?:password|publickey|keyboard-interactive) for (\S+) from ([\d.]+)"),
    re.compile(r"session opened for user (\S+)"),
]
_SUDO_PATTERNS = [
    re.compile(r"sudo:.*?(\S+)\s*:.*COMMAND=(.+)"),
    re.compile(r"su\[.*\]: \+ .* (\S+)"),
]


def _parse_auth_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single auth log line into a normalized security event."""
    if not line:
        return None

    # Extract timestamp if present (syslog format: Month Day HH:MM:SS)
    ts_match = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
    timestamp = ts_match.group(1) if ts_match else "UNKNOWN"

    for pat in _FAILED_PATTERNS:
        m = pat.search(line)
        if m:
            groups = m.groups()
            return {
                "timestamp": timestamp,
                "platform": "linux",
                "event_type": "FAILED_LOGIN",
                "user": groups[0] if groups else "UNKNOWN",
                "source_ip": groups[1] if len(groups) > 1 else None,
                "severity": "MEDIUM",
                "raw_source": "auth.log",
                "simulation": False,
            }

    for pat in _SUCCESS_PATTERNS:
        m = pat.search(line)
        if m:
            groups = m.groups()
            return {
                "timestamp": timestamp,
                "platform": "linux",
                "event_type": "SUCCESSFUL_LOGIN",
                "user": groups[0] if groups else "UNKNOWN",
                "source_ip": groups[1] if len(groups) > 1 else None,
                "severity": "INFO",
                "raw_source": "auth.log",
                "simulation": False,
            }

    for pat in _SUDO_PATTERNS:
        m = pat.search(line)
        if m:
            groups = m.groups()
            return {
                "timestamp": timestamp,
                "platform": "linux",
                "event_type": "PRIVILEGE_ESCALATION_EVENT",
                "user": groups[0] if groups else "UNKNOWN",
                "source_ip": None,
                "severity": "LOW",
                "raw_source": "auth.log",
                "details": groups[1] if len(groups) > 1 else None,
                "simulation": False,
            }

    return None


def get_journalctl_events(unit: str = "sshd", max_lines: int = 100) -> List[Dict[str, Any]]:
    """
    Attempt to read recent systemd journal entries for a service.
    Falls back gracefully if journalctl is unavailable.
    """
    if not shutil.which("journalctl"):
        return []

    output = _run_cmd(["journalctl", "-u", unit, "-n", str(max_lines), "--no-pager", "-o", "short"])
    if not output:
        return []

    events = []
    for line in output.splitlines():
        event = _parse_auth_line(line)
        if event:
            event["raw_source"] = f"journalctl:{unit}"
            events.append(event)
    return events
