"""
NetSentinel Common Monitor
Cross-platform host telemetry collection using psutil.
Provides live TCP/UDP connections, process inventory, and resource metrics.
"""
import logging
import platform
import socket
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

import psutil

logger = logging.getLogger("NetSentinel.Monitor")

PLATFORM = platform.system()  # "Windows", "Linux", "Darwin"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────────────────────
# Connection Collection
# ─────────────────────────────────────────────────────────────────────────────

def _get_process_info(pid: Optional[int]) -> Dict[str, Any]:
    """Safely retrieve process name and executable for a given PID."""
    if pid is None:
        return {"process_name": "UNKNOWN", "exe": None, "username": None}
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            return {
                "process_name": proc.name(),
                "exe": proc.exe() if proc.is_running() else None,
                "username": proc.username(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return {"process_name": "UNKNOWN", "exe": None, "username": None}


def collect_connections(simulation: bool = False) -> List[Dict[str, Any]]:
    """
    Collect all active TCP/UDP connections on the host using psutil.net_connections().
    Returns normalized list of connection records.
    Handles AccessDenied and disappeared processes gracefully.
    """
    results: List[Dict[str, Any]] = []
    seen: set = set()

    try:
        raw_conns = psutil.net_connections(kind="all")
    except psutil.AccessDenied:
        logger.warning("psutil.net_connections() requires elevated privileges on this platform. Retrying with 'inet'.")
        try:
            raw_conns = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.error(f"Cannot collect connections: {e}")
            return []

    for conn in raw_conns:
        try:
            laddr = conn.laddr
            raddr = conn.raddr

            local_ip = laddr.ip if laddr else None
            local_port = laddr.port if laddr else None
            remote_ip = raddr.ip if raddr else None
            remote_port = raddr.port if raddr else None

            # Determine protocol string
            if conn.type == socket.SOCK_STREAM:
                proto = "TCP"
            elif conn.type == socket.SOCK_DGRAM:
                proto = "UDP"
            else:
                proto = "OTHER"

            state = conn.status if conn.status else "NONE"
            pid = conn.pid

            # Deduplication key
            dedup_key = (proto, local_ip, local_port, remote_ip, remote_port, pid)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Skip pure loopback-to-loopback unless both ends are localhost (still useful for local analysis)
            proc_info = _get_process_info(pid)

            record = {
                "protocol": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": state,
                "pid": pid,
                "process_name": proc_info["process_name"],
                "exe": proc_info["exe"],
                "username": proc_info["username"],
                "timestamp": utc_now().isoformat(),
                "simulation": simulation,
            }
            results.append(record)

        except Exception as e:
            logger.debug(f"Skipping connection record due to error: {e}")
            continue

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Process Collection
# ─────────────────────────────────────────────────────────────────────────────

def collect_processes(simulation: bool = False) -> List[Dict[str, Any]]:
    """
    Collect the running process inventory.
    Returns normalized list. Handles AccessDenied and disappeared processes.
    """
    results: List[Dict[str, Any]] = []

    for proc in psutil.process_iter(["pid", "name", "ppid", "exe", "username",
                                      "cpu_percent", "memory_percent",
                                      "create_time", "status", "num_threads"]):
        try:
            info = proc.info
            results.append({
                "pid": info["pid"],
                "name": info["name"] or "UNKNOWN",
                "ppid": info["ppid"],
                "exe": info["exe"],
                "username": info["username"],
                "cpu_percent": round(info["cpu_percent"] or 0.0, 2),
                "memory_percent": round(info["memory_percent"] or 0.0, 3),
                "create_time": datetime.fromtimestamp(info["create_time"], tz=timezone.utc).isoformat() if info["create_time"] else None,
                "status": info["status"],
                "num_threads": info["num_threads"],
                "timestamp": utc_now().isoformat(),
                "simulation": simulation,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            logger.debug(f"Process iter error: {e}")
            continue

    return results


# ─────────────────────────────────────────────────────────────────────────────
# System Resource Telemetry
# ─────────────────────────────────────────────────────────────────────────────

def collect_system_telemetry() -> Dict[str, Any]:
    """
    Collect host resource telemetry: CPU, Memory, Network throughput, OS info.
    """
    try:
        cpu_pct = psutil.cpu_percent(interval=None)
    except Exception:
        cpu_pct = 0.0

    try:
        mem = psutil.virtual_memory()
        mem_pct = round(mem.percent, 1)
        mem_total_gb = round(mem.total / (1024 ** 3), 2)
        mem_available_gb = round(mem.available / (1024 ** 3), 2)
    except Exception:
        mem_pct = 0.0
        mem_total_gb = 0.0
        mem_available_gb = 0.0

    try:
        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent
        bytes_recv = net_io.bytes_recv
    except Exception:
        bytes_sent = 0
        bytes_recv = 0

    try:
        active_conns = len(psutil.net_connections(kind="inet"))
    except Exception:
        active_conns = 0

    try:
        process_count = len(psutil.pids())
    except Exception:
        process_count = 0

    return {
        "platform": PLATFORM,
        "hostname": socket.gethostname(),
        "cpu_percent": cpu_pct,
        "memory_percent": mem_pct,
        "memory_total_gb": mem_total_gb,
        "memory_available_gb": mem_available_gb,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "active_connections": active_conns,
        "process_count": process_count,
        "timestamp": utc_now().isoformat(),
    }
