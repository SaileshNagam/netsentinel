"""
NetSentinel Core FastAPI Application Entrypoint
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.database import engine, Base, AsyncSessionLocal
from app.core.seed_data import seed_initial_inventory
from app.api.devices import router as devices_router
from app.api.alerts import router as alerts_router
from app.api.posture import router as posture_router
from app.api.incidents import router as incidents_router
from app.api.discovery import router as discovery_router
from app.api.enrichment import router as enrichment_router
from app.api.websocket import router as websocket_router
from app.api.connections import router as connections_router
from app.api.processes import router as processes_router
from app.api.security_events import router as security_events_router
from app.api.actions import router as actions_router
from app.api.system import router as system_router
from app.api.demo import router as demo_router


# Setup structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("NetSentinel")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager: sets up DB schemas and seeds baseline devices."""
    logger.info("Initializing NetSentinel Database Engine (SQLite WAL Mode)...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("Checking baseline device inventory...")
    async with AsyncSessionLocal() as session:
        await seed_initial_inventory(session)
    logger.info("NetSentinel Engine Armed and Ready.")
    
    yield
    
    logger.info("NetSentinel Engine shutting down gracefully.")
    await engine.dispose()

app = FastAPI(
    title="NetSentinel API",
    description="Agentic Network Access Monitoring & Rogue Device Detection Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration for modern SOC frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, lock to frontend origin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
app.include_router(devices_router)
app.include_router(alerts_router)
app.include_router(posture_router)
app.include_router(incidents_router)
app.include_router(discovery_router)
app.include_router(enrichment_router)
app.include_router(websocket_router)
app.include_router(connections_router)
app.include_router(processes_router)
app.include_router(security_events_router)
app.include_router(actions_router)
app.include_router(system_router)
app.include_router(demo_router)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "NetSentinel Core",
        "version": "1.0.0",
        "guardrail": "RFC 1918 Private Subnets Only"
    }

@app.get("/")
async def root():
    return {
        "name": "NetSentinel: Agentic Network Access Monitoring & Rogue Device Detection Platform",
        "status": "ARMED",
        "docs": "/docs",
        "version": "1.0.0"
    }
