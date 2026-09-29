import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.core.database import Base
from app.demo.event_generator import generate_c2_beacon_demo, generate_port_scan_demo, generate_brute_force_demo

@pytest_asyncio.fixture
async def async_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with Session() as session:
        yield session

@pytest.mark.asyncio
async def test_generate_c2_beacon_demo(async_db):
    result = await generate_c2_beacon_demo(async_db)
    assert result["status"] == "success"
    assert "incident_id" in result
    assert "report" in result
    assert "[SIMULATION]" in result["report"]
    assert "RULE_E_BEACONING" in result["report"] or "RULE_F_UNUSUAL_DESTINATION" in result["report"]

@pytest.mark.asyncio
async def test_generate_port_scan_demo(async_db):
    result = await generate_port_scan_demo(async_db)
    assert result["status"] == "success"
    assert "incident_id" in result
    assert "RULE_C_PORT_SCAN" in result["report"]

@pytest.mark.asyncio
async def test_generate_brute_force_demo(async_db):
    result = await generate_brute_force_demo(async_db)
    assert result["status"] == "success"
    assert "incident_id" in result
    assert "RULE_D_BRUTE_FORCE" in result["report"]
