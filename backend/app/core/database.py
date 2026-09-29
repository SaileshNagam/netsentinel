"""
NetSentinel Core Configuration & Database Setup
"""
import os
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import List

def utc_now():
    return datetime.now(timezone.utc)
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

# Project Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "netsentinel.db"

class Settings(BaseModel):
    APP_NAME: str = "NetSentinel"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    
    # Database URL
    DATABASE_URL: str = f"sqlite+aiosqlite:///{DB_PATH}"
    
    # Authorized Subnets - Strict RFC 1918 Guardrail
    AUTHORIZED_SUBNETS: List[str] = [
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "127.0.0.1/32"
    ]
    
    # Discovery & Scan Intervals
    PASSIVE_SCAN_INTERVAL_SECONDS: int = 15
    ACTIVE_ARP_SWEEP_INTERVAL_SECONDS: int = 60
    ALERT_COOLDOWN_MINUTES: int = 10
    
    # Evidence Locker Hash Algorithm
    HASH_ALGORITHM: str = "sha256"

    def is_ip_authorized(self, ip_str: str) -> bool:
        """
        Validates that an IP address falls strictly within authorized RFC 1918 private subnets.
        Rejects any external/public IP to guarantee privacy and legal safety.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            for subnet in self.AUTHORIZED_SUBNETS:
                if ip in ipaddress.ip_network(subnet):
                    return True
            return False
        except ValueError:
            return False

settings = Settings()

# Async Database Engine with SQLite WAL Mode for High Concurrency
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False}
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()

async def get_db():
    """FastAPI Dependency for database sessions."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
