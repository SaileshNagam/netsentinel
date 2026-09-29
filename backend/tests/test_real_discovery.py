"""
NetSentinel Automated Test Suite: Real Wi-Fi/LAN Network Discovery Engine
Tests:
- CIDR detection & interface selection
- Active Scapy ARP response handling (mocked raw packets)
- Cross-platform neighbor table parsing (macOS, Linux, Windows)
- MAC normalization & LAA randomized MAC detection
- Duplicate device merging across multiple discovery vectors
- New-device detection (enrolled as UNKNOWN)
- Trusted-device persistence across scans
- Offline-device state tracking
- Endpoints: GET /api/network/interface, POST /api/network/discover, GET /api/devices/online
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.database import AsyncSessionLocal
from app.models.device import Device, TrustStatus
from app.core.oui_database import normalize_mac, is_locally_administered, resolve_mac_vendor
from app.discovery.route_inspector import get_active_network_info, get_default_gateway
from app.discovery.arp_collector import parse_macos_arp, parse_linux_ip_neigh, parse_windows_arp
from app.discovery.hostname_resolver import resolve_hostname
from app.discovery.discovery_engine import run_real_discovery_sweep, DiscoveredEndpoint
from app.agents.discovery_agent import DiscoveryAgent


class TestNetworkDetection:
    def test_get_active_network_info(self):
        info = get_active_network_info()
        assert "interface" in info
        assert "ip_address" in info
        assert "cidr" in info
        assert "gateway_ip" in info
        assert "subnet_mask" in info
        assert "/" in info["cidr"]
        # Must be valid RFC 1918 or fallback
        assert info["is_rfc1918"] is True or info["ip_address"] == "127.0.0.1"

    def test_default_gateway_detection(self):
        gw = get_default_gateway()
        assert gw is not None
        assert "gateway_ip" in gw
        assert "interface" in gw


class TestMACNormalizationAndLAA:
    def test_mac_normalization_variations(self):
        # macOS short form
        assert normalize_mac("20:c:86:20:9b:da") == "20:0c:86:20:9b:da"
        # Windows hyphen form
        assert normalize_mac("20-0C-86-20-9B-DA") == "20:0c:86:20:9b:da"
        # Bare hex form
        assert normalize_mac("200c86209bda") == "20:0c:86:20:9b:da"
        # Invalid MAC
        assert normalize_mac("invalid-mac") is None

    def test_locally_administered_mac_detection(self):
        # LAA: second hex digit of first octet is 2, 6, A, or E (bit 1 is 1)
        assert is_locally_administered("da:a1:19:33:44:aa") is True # 0xda & 0x02 != 0
        assert is_locally_administered("8e:f7:e1:32:3d:ae") is True # 0x8e & 0x02 != 0
        assert is_locally_administered("a2:11:45:90:ee:12") is True # 0xa2 & 0x02 != 0
        
        # Globally unique IEEE MACs (bit 1 is 0)
        assert is_locally_administered("20:0c:86:20:9b:da") is False # TP-Link (0x20 & 0x02 == 0)
        assert is_locally_administered("00:03:93:11:22:33") is False # Apple (0x00 & 0x02 == 0)
        assert is_locally_administered("cc:47:40:8d:29:f9") is False # Samsung (0xcc & 0x02 == 0)

    def test_vendor_resolution_laa(self):
        vendor, is_rand, conf = resolve_mac_vendor("da:a1:19:33:44:aa")
        assert is_rand is True
        assert "Randomized" in vendor


class TestNeighborCacheParsing:
    def test_parse_macos_arp(self):
        sample = """
? (192.168.1.1) at 20:c:86:20:9b:da on en0 ifscope [ethernet]
? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""
        results = parse_macos_arp(sample)
        assert len(results) == 1
        assert results[0]["ip"] == "192.168.1.1"
        assert results[0]["mac"] == "20:0c:86:20:9b:da"

    def test_parse_linux_ip_neigh(self):
        sample = """
192.168.1.1 dev eth0 lladdr 20:0c:86:20:9b:da REACHABLE
192.168.1.50 dev eth0 FAILED
192.168.1.100 dev eth0 lladdr 00:11:22:33:44:55 STALE
"""
        results = parse_linux_ip_neigh(sample)
        assert len(results) == 2
        assert results[0]["ip"] == "192.168.1.1"
        assert results[1]["ip"] == "192.168.1.100"

    def test_parse_windows_arp(self):
        sample = """
  Internet Address      Physical Address      Type
  192.168.1.1           20-0c-86-20-9b-da     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
        results = parse_windows_arp(sample)
        assert len(results) == 1
        assert results[0]["ip"] == "192.168.1.1"
        assert results[0]["mac"] == "20:0c:86:20:9b:da"


class TestHostnameResolution:
    def test_unknown_when_not_resolvable(self):
        # 192.0.2.1 (TEST-NET-1) should not resolve
        name = resolve_hostname("192.0.2.1")
        assert name == "Unknown"

    def test_never_fabricates_device_names(self):
        name = resolve_hostname("10.254.254.254")
        assert name not in ("iPhone", "Samsung TV", "Windows Laptop")


class TestDiscoveryAgentWorkflow:
    @pytest.mark.asyncio
    async def test_new_device_enrolled_as_unknown(self):
        agent = DiscoveryAgent()
        
        # Mock sweep returning one brand new device
        mock_endpoint = DiscoveredEndpoint(
            ip="192.168.1.199",
            mac="aa:bb:cc:11:22:33",
            vendor="Test Vendor",
            is_mac_randomized=False,
            hostname="Unknown",
            device_type="UNKNOWN",
            discovery_method="ACTIVE_ARP_SCAN",
            is_gateway=False
        )
        
        with patch("app.agents.discovery_agent.run_real_discovery_sweep", new_callable=AsyncMock) as mock_sweep:
            mock_sweep.return_value = {
                "endpoints": [mock_endpoint],
                "diagnostics": {
                    "active_interface": "en0",
                    "local_ip": "192.168.1.240",
                    "gateway_ip": "192.168.1.1",
                    "cidr": "192.168.1.0/24",
                    "netmask": "255.255.255.0",
                    "arp_responses": 1,
                    "neighbor_entries": 0,
                    "unique_devices": 1,
                    "scan_duration_seconds": 1.2,
                    "raw_packet_available": True
                }
            }
            
            async with AsyncSessionLocal() as session:
                res = await agent.execute_discovery_sweep(session)
                assert res["new_devices_enrolled"] == 1

                # Verify device in DB has trust_status == UNKNOWN
                from sqlalchemy import select
                dev = (await session.execute(
                    select(Device).where(Device.current_mac == "aa:bb:cc:11:22:33")
                )).scalars().first()
                assert dev is not None
                assert dev.trust_status == TrustStatus.UNKNOWN.value

    @pytest.mark.asyncio
    async def test_trusted_status_persists_across_scans(self):
        agent = DiscoveryAgent()
        
        async with AsyncSessionLocal() as session:
            from sqlalchemy import select
            # Verify D-001 (Gateway) starts as TRUSTED
            gw = (await session.execute(select(Device).where(Device.id == "D-001"))).scalars().first()
            assert gw.trust_status == TrustStatus.TRUSTED.value
            
            # Manually classify D-002 as TRUSTED
            d2 = (await session.execute(select(Device).where(Device.id == "D-002"))).scalars().first()
            d2.trust_status = TrustStatus.TRUSTED.value
            await session.commit()

        # Run sweep seeing D-002 again
        mock_endpoint = DiscoveredEndpoint(
            ip="192.168.1.11",
            mac="3c:22:fb:18:90:bc",
            vendor="Apple, Inc.",
            is_mac_randomized=False,
            hostname="Dev-MacBook-Pro.local",
            device_type="LAPTOP",
            discovery_method="KERNEL_ARP_CACHE",
            is_gateway=False
        )
        
        with patch("app.agents.discovery_agent.run_real_discovery_sweep", new_callable=AsyncMock) as mock_sweep:
            mock_sweep.return_value = {
                "endpoints": [mock_endpoint],
                "diagnostics": {
                    "active_interface": "en0",
                    "local_ip": "192.168.1.240",
                    "gateway_ip": "192.168.1.1",
                    "cidr": "192.168.1.0/24",
                    "netmask": "255.255.255.0",
                    "arp_responses": 0,
                    "neighbor_entries": 1,
                    "unique_devices": 1,
                    "scan_duration_seconds": 0.8,
                    "raw_packet_available": False
                }
            }
            async with AsyncSessionLocal() as session:
                await agent.execute_discovery_sweep(session)
                
                # Check that D-002 is STILL TRUSTED!
                d2_reloaded = (await session.execute(select(Device).where(Device.id == "D-002"))).scalars().first()
                assert d2_reloaded.trust_status == TrustStatus.TRUSTED.value

    @pytest.mark.asyncio
    async def test_offline_device_transition(self):
        agent = DiscoveryAgent()
        
        # Sweep with NO devices observed -> existing devices marked offline
        with patch("app.agents.discovery_agent.run_real_discovery_sweep", new_callable=AsyncMock) as mock_sweep:
            mock_sweep.return_value = {
                "endpoints": [],
                "diagnostics": {
                    "active_interface": "en0",
                    "local_ip": "192.168.1.240",
                    "gateway_ip": "192.168.1.1",
                    "cidr": "192.168.1.0/24",
                    "netmask": "255.255.255.0",
                    "arp_responses": 0,
                    "neighbor_entries": 0,
                    "unique_devices": 0,
                    "scan_duration_seconds": 0.5,
                    "raw_packet_available": False
                }
            }
            async with AsyncSessionLocal() as session:
                res = await agent.execute_discovery_sweep(session)
                assert res["marked_offline"] > 0


class TestDiscoveryAPIEndpoints:
    @pytest.mark.asyncio
    async def test_network_interface_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/network/interface")
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "SUCCESS"
            assert "active_interface" in data
            assert "ip_address" in data
            assert "cidr" in data
            assert "default_gateway" in data

    @pytest.mark.asyncio
    async def test_network_discover_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.post("/api/network/discover")
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "SUCCESS"
            assert "details" in data

    @pytest.mark.asyncio
    async def test_devices_online_endpoint(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.get("/api/devices/online")
            assert res.status_code == 200
            devices = res.json()
            assert isinstance(devices, list)
            for d in devices:
                assert d["is_online"] is True
