"""
NetSentinel Phase 2 Automated Test Suite: Real Network Discovery Engine
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.discovery.arp_collector import parse_macos_arp
from app.discovery.ndp_collector import parse_macos_ndp
from app.discovery.discovery_engine import infer_device_type

def test_arp_cache_parser():
    sample_arp_output = """
? (192.168.1.1) at 20:c:86:20:9b:da on en0 ifscope [ethernet]
? (192.168.1.147) at 0:92:35:3d:d9:4c on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
? (8.8.8.8) at 00:11:22:33:44:55 on en0 ifscope [ethernet]
"""
    results = parse_macos_arp(sample_arp_output)
    
    # Verify incomplete, broadcast, multicast, and non-RFC1918 are excluded
    ips = [r["ip"] for r in results]
    assert "192.168.1.1" in ips
    assert "192.168.1.147" in ips
    assert "192.168.1.255" not in ips # Broadcast excluded
    assert "224.0.0.251" not in ips   # Multicast excluded
    assert "192.168.1.50" not in ips   # Incomplete excluded
    assert "8.8.8.8" not in ips        # Public non-RFC1918 excluded by guardrails

    # Verify MAC normalization pads leading zero
    gw = next(r for r in results if r["ip"] == "192.168.1.1")
    assert gw["mac"] == "20:0c:86:20:9b:da" # 20:c:86 properly padded to 20:0c:86

def test_ndp_cache_parser():
    sample_ndp_output = """
Neighbor Linklayer Address Netif Expire St Flgs Prbs
fe80::cff:a7a8:3c8b:f640%en0 90:cd:e8:d4:13:be en0 23h59m30s S
2402:e280:215f::a05 16:8:56:15:91:c4 en0 permanent R
fe80::1%lo0 (incomplete) lo0 permanent R
"""
    results = parse_macos_ndp(sample_ndp_output)
    assert len(results) == 2
    assert results[0]["ipv6"] == "fe80::cff:a7a8:3c8b:f640"
    assert results[0]["mac"] == "90:cd:e8:d4:13:be"
    assert results[1]["mac"] == "16:08:56:15:91:c4" # 16:8:56 padded to 16:08:56

def test_device_type_inference():
    assert infer_device_type("TP-Link Technologies", False, True, "gateway.home.arpa") == "ROUTER"
    assert infer_device_type("Apple, Inc.", True, False, "iPhone-Personal") == "MOBILE"
    assert infer_device_type("Apple, Inc.", False, False, "Dev-MacBook-Pro") == "LAPTOP"
    assert infer_device_type("Samsung Electronics", False, False, "Samsung-QLED-TV") == "SMART_TV"
    assert infer_device_type("Raspberry Pi Foundation", False, False, "sensor-pi") == "IOT_DEVICE"

@pytest.mark.asyncio
async def test_discovery_api_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test status
        status_res = await client.get("/api/discovery/status")
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert status_data["agent"] == "Discovery Agent"
        assert "KERNEL_ARP_CACHE" in status_data["vectors_enabled"]

        # 2. Test interfaces
        iface_res = await client.get("/api/discovery/interfaces")
        assert iface_res.status_code == 200
        iface_data = iface_res.json()
        assert "active_interfaces" in iface_data
        assert "default_gateway" in iface_data

        # 3. Test triggering real scan
        scan_res = await client.post("/api/discovery/scan")
        assert scan_res.status_code == 200
        scan_data = scan_res.json()
        assert scan_data["status"] == "SUCCESS"
        assert "endpoints_observed" in scan_data["details"]
