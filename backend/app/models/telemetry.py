"""
NetSentinel Connection & Process Database Models
"""
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Float, Text, Index
from app.core.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class ConnectionEvent(Base):
    """
    Records a single observed host network connection.
    Stored as time-series snapshots for correlation and threat analysis.
    """
    __tablename__ = "connection_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    protocol = Column(String(8), nullable=False, index=True)         # TCP, UDP
    local_ip = Column(String(64), nullable=True)
    local_port = Column(Integer, nullable=True)
    remote_ip = Column(String(64), nullable=True, index=True)
    remote_port = Column(Integer, nullable=True, index=True)
    state = Column(String(32), nullable=True, index=True)            # ESTABLISHED, TIME_WAIT, etc.
    pid = Column(Integer, nullable=True, index=True)
    process_name = Column(String(256), nullable=True, index=True)
    exe = Column(Text, nullable=True)
    username = Column(String(128), nullable=True)
    simulation = Column(Boolean, default=False, nullable=False, index=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_ce_remote_ip_port", "remote_ip", "remote_port"),
        Index("ix_ce_pid_ts", "pid", "timestamp"),
        Index("ix_ce_proc_ts", "process_name", "timestamp"),
    )


class ProcessSnapshot(Base):
    """
    Records the running process inventory at a point in time.
    Used to correlate processes with network connections.
    """
    __tablename__ = "process_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    pid = Column(Integer, nullable=False, index=True)
    name = Column(String(256), nullable=False, index=True)
    ppid = Column(Integer, nullable=True)
    exe = Column(Text, nullable=True)
    username = Column(String(128), nullable=True)
    cpu_percent = Column(Float, default=0.0)
    memory_percent = Column(Float, default=0.0)
    create_time = Column(DateTime, nullable=True)
    status = Column(String(32), nullable=True)
    num_threads = Column(Integer, nullable=True)
    simulation = Column(Boolean, default=False, nullable=False, index=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_ps_pid_ts", "pid", "timestamp"),
        Index("ix_ps_name_ts", "name", "timestamp"),
    )


class SecurityEvent(Base):
    """
    Normalized cross-platform security log event.
    Populated from Linux auth.log / Windows Event Log.
    """
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    platform = Column(String(16), nullable=False, index=True)        # "linux", "windows", "darwin"
    event_type = Column(String(64), nullable=False, index=True)      # FAILED_LOGIN, SUCCESSFUL_LOGIN, etc.
    user = Column(String(128), nullable=True, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    severity = Column(String(16), default="INFO", index=True)        # INFO, LOW, MEDIUM, HIGH, CRITICAL
    details = Column(Text, nullable=True)
    raw_source = Column(String(128), nullable=True)
    simulation = Column(Boolean, default=False, nullable=False, index=True)
    timestamp = Column(DateTime, default=utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_se_type_ts", "event_type", "timestamp"),
        Index("ix_se_user_ts", "user", "timestamp"),
        Index("ix_se_ip_ts", "source_ip", "timestamp"),
    )
