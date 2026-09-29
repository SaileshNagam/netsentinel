"""
NetSentinel Pytest Configuration & Fixtures
Ensures test isolation with freshly seeded schema for every test run.
"""
import pytest
import pytest_asyncio
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.seed_data import seed_initial_inventory
from app.main import app, lifespan

@pytest_asyncio.fixture(autouse=True)
async def init_test_db():
    """Resets database schema and seeds initial baseline for clean test isolation."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    
    async with AsyncSessionLocal() as session:
        await seed_initial_inventory(session)

    yield

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        await seed_initial_inventory(session)
