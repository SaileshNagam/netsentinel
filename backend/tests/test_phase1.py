"""
NetSentinel Phase 1 Comprehensive Automated Test Suite
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.core.oui_database import is_locally_administered, resolve_mac_vendor

@pytest.mark.asyncio
async def test_oui_and_mac_randomization():
    # Apple MAC (UAA - Universal)
    apple_mac = "3c:22:fb:18:90:bc"
    assert not is_locally_administered(apple_mac)
    vendor, is_rand, conf = resolve_mac_vendor(apple_mac)
    assert vendor == "Apple, Inc."
    assert not is_rand
    assert conf == "CONFIRMED"

    # Cisco MAC (UAA)
    cisco_mac = "00:01:42:ab:34:11"
    assert not is_locally_administered(cisco_mac)
    vendor, is_rand, _ = resolve_mac_vendor(cisco_mac)
    assert vendor == "Cisco Systems"
    assert not is_rand

    # Randomized MAC (LAA bit set: 2nd hex digit is 2, 6, A, or E)
    random_mac = "da:a1:19:33:44:aa"
    assert is_locally_administered(random_mac)
    vendor, is_rand, conf = resolve_mac_vendor(random_mac)
    assert is_rand
    assert "Randomized" in vendor
    assert conf == "CONFIRMED"

@pytest.mark.asyncio
async def test_api_health():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert "RFC 1918" in data["guardrail"]

@pytest.mark.asyncio
async def test_api_devices_and_posture():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/devices")
        assert res.status_code == 200
        devices = res.json()
        assert len(devices) >= 7

        # Verify Rogue Device D-019
        d019 = next((d for d in devices if d["id"] == "D-019"), None)
        assert d019 is not None
        assert d019["current_ip"] == "192.168.1.27"
        assert d019["is_mac_randomized"] is True
        assert d019["risk_score"] == 72
        assert d019["risk_severity"] == "HIGH"
        
        # Check services on D-019
        ports = [s["port"] for s in d019["services"]]
        assert 445 in ports
        assert 135 in ports

        # Verify Posture summary
        posture_res = await client.get("/api/posture")
        assert posture_res.status_code == 200
        posture = posture_res.json()
        assert posture["total_connected"] >= 7
        assert posture["trusted_devices"] >= 6
        assert posture["high_risk_devices"] >= 1
        assert posture["active_alerts_count"] >= 1

@pytest.mark.asyncio
async def test_device_timeline_and_classification():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test timeline
        res = await client.get("/api/devices/D-019/timeline")
        assert res.status_code == 200
        timeline = res.json()
        assert len(timeline) >= 3
        types = [e["event_type"] for e in timeline]
        assert "CONNECTION" in types
        assert "SERVICE_FOUND" in types

        # Classify device to TRUSTED and verify risk drops
        classify_res = await client.post("/api/devices/D-019/classify", json={
            "trust_status": "TRUSTED",
            "notes": "Verified as authorized security research workstation by SOC analyst."
        })
        assert classify_res.status_code == 200
        updated = classify_res.json()
        assert updated["trust_status"] == "TRUSTED"
        assert updated["risk_score"] < 72 # Risk decreased due to trust classification
