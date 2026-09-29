"""
NetSentinel Agent 1: Network Discovery Agent
Responsible for identifying devices on the authorized local network,
tracking online/offline state, preserving user classifications, and ingesting telemetry.
Supports both on-demand sweeps and background periodic scanning (default: 30s) in Live Mode.
"""
import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.device import Device, TrustStatus, RiskSeverity, ConfidenceLevel
from app.models.address import DeviceAddress
from app.models.identity import DeviceIdentity
from app.discovery.discovery_engine import run_real_discovery_sweep, DiscoveredEndpoint
from app.core.websocket_hub import ws_hub

logger = logging.getLogger("NetSentinel.DiscoveryAgent")

class DiscoveryAgent:
    def __init__(self):
        self.agent_name = "Discovery Agent"
        self.last_scan_time: datetime = datetime.utcnow()
        self.total_scans_performed: int = 0
        self.last_discovered_count: int = 0
        self.last_diagnostics: Dict[str, Any] = {}
        self._scan_lock = asyncio.Lock()
        
        # Periodic Live Mode attributes
        self.periodic_running: bool = False
        self.periodic_interval: int = 30  # seconds
        self._periodic_task: Optional[asyncio.Task] = None

    async def execute_discovery_sweep(self, session: AsyncSession) -> Dict[str, Any]:
        """
        Runs multi-vector discovery sweep, updates database inventory, and emits real-time WebSocket events.
        Guarantees that overlapping scans are serialized via async lock.
        """
        if self._scan_lock.locked():
            logger.info("Scan already in progress. Waiting for lock...")

        async with self._scan_lock:
            return await self._run_sweep_internal(session)

    async def _run_sweep_internal(self, session: AsyncSession) -> Dict[str, Any]:
        logger.info("Discovery Agent executing Layer 2/3 local network sweep...")
        
        # 1. Broadcast scan started event
        await ws_hub.broadcast("network.scan.started", {
            "agent_name": self.agent_name,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "SCANNING"
        })

        # 2. Run multi-vector engine
        sweep_result = await run_real_discovery_sweep()
        raw_endpoints: List[DiscoveredEndpoint] = sweep_result["endpoints"]
        diagnostics: Dict[str, Any] = sweep_result["diagnostics"]

        now = datetime.utcnow()
        self.last_scan_time = now
        self.total_scans_performed += 1
        self.last_discovered_count = len(raw_endpoints)
        self.last_diagnostics = diagnostics

        new_devices = []
        updated_devices = []
        observed_device_ids = set()

        # 3. Load all existing devices with addresses and identities
        existing_devices = (await session.execute(
            select(Device).options(
                selectinload(Device.addresses),
                selectinload(Device.identities)
            )
        )).scalars().all()

        mac_map = {d.current_mac.lower(): d for d in existing_devices if d.current_mac}
        ip_map = {d.current_ip: d for d in existing_devices}

        for ep in raw_endpoints:
            # Correlate by MAC first, then by IP
            matched_device: Optional[Device] = None
            if ep.mac and ep.mac.lower() in mac_map:
                matched_device = mac_map[ep.mac.lower()]
            elif ep.ip in ip_map:
                matched_device = ip_map[ep.ip]

            if matched_device:
                observed_device_ids.add(matched_device.id)
                matched_device.is_online = True
                matched_device.last_seen = now
                
                # Check for IP churn on known MAC
                if matched_device.current_ip != ep.ip:
                    logger.info("IP change observed for %s: %s -> %s", matched_device.id, matched_device.current_ip, ep.ip)
                    matched_device.current_ip = ep.ip
                    new_addr = DeviceAddress(
                        device_id=matched_device.id,
                        address_type="IPV4",
                        address_value=ep.ip,
                        first_seen=now,
                        last_seen=now
                    )
                    session.add(new_addr)

                # Check for hostname resolution
                if ep.hostname and ep.hostname != "Unknown" and matched_device.hostname != ep.hostname:
                    matched_device.hostname = ep.hostname
                    new_id = DeviceIdentity(
                        device_id=matched_device.id,
                        identity_type="HOSTNAME",
                        identity_value=ep.hostname,
                        confidence="HIGH",
                        first_seen=now,
                        last_seen=now
                    )
                    session.add(new_id)

                updated_devices.append(matched_device)
                
                # Broadcast updated event
                await ws_hub.broadcast("device.updated", {
                    "id": matched_device.id,
                    "ip": matched_device.current_ip,
                    "mac": matched_device.current_mac,
                    "is_online": True,
                    "last_seen": now.isoformat()
                })

            else:
                # 4. New Device Discovered! Enroll into inventory
                count = len(existing_devices) + len(new_devices) + 1
                device_id = f"D-{count:03d}"
                observed_device_ids.add(device_id)

                # Always classify new devices as UNKNOWN unless it is the gateway
                trust = TrustStatus.TRUSTED.value if ep.is_gateway else TrustStatus.UNKNOWN.value
                risk = 0 if ep.is_gateway else (25 if ep.is_mac_randomized else 20)
                sev = RiskSeverity.LOW.value if risk < 30 else RiskSeverity.MEDIUM.value
                conf = ConfidenceLevel.CONFIRMED.value if ep.mac else ConfidenceLevel.MEDIUM.value

                friendly_name = (
                    "Gateway Router" if ep.is_gateway else
                    ep.hostname if ep.hostname and ep.hostname != "Unknown" else
                    f"{ep.vendor} Device" if ep.vendor and "Unknown" not in ep.vendor and "Randomized" not in ep.vendor else
                    f"Unknown Device {device_id}"
                )

                new_dev = Device(
                    id=device_id,
                    user_label=friendly_name,
                    current_ip=ep.ip,
                    current_mac=ep.mac,
                    mac_vendor=ep.vendor,
                    is_mac_randomized=ep.is_mac_randomized,
                    hostname=ep.hostname if ep.hostname != "Unknown" else None,
                    device_type=ep.device_type,
                    os_hint="Generic Network Stack",
                    trust_status=trust,
                    is_online=True,
                    first_seen=now,
                    last_seen=now,
                    risk_score=risk,
                    risk_severity=sev,
                    confidence_level=conf,
                    in_baseline=False,
                    notes=f"Discovered on {now.strftime('%Y-%m-%d %H:%M:%S')} via {ep.discovery_method}."
                )
                session.add(new_dev)
                await session.flush()

                # Add initial IP & MAC address records
                session.add(DeviceAddress(
                    device_id=new_dev.id,
                    address_type="IPV4",
                    address_value=ep.ip,
                    first_seen=now,
                    last_seen=now
                ))
                if ep.mac:
                    session.add(DeviceAddress(
                        device_id=new_dev.id,
                        address_type="MAC",
                        address_value=ep.mac,
                        first_seen=now,
                        last_seen=now
                    ))

                if ep.hostname and ep.hostname != "Unknown":
                    session.add(DeviceIdentity(
                        device_id=new_dev.id,
                        identity_type="HOSTNAME",
                        identity_value=ep.hostname,
                        confidence="CONFIRMED",
                        first_seen=now,
                        last_seen=now
                    ))

                new_devices.append(new_dev)

                # Broadcast new device events
                await ws_hub.broadcast("DEVICE_DISCOVERED", {
                    "id": new_dev.id,
                    "ip": new_dev.current_ip,
                    "mac": new_dev.current_mac,
                    "vendor": new_dev.mac_vendor,
                    "is_mac_randomized": new_dev.is_mac_randomized,
                    "trust_status": new_dev.trust_status,
                    "risk_score": new_dev.risk_score
                })
                await ws_hub.broadcast("device.new", {
                    "type": "device.new",
                    "device_id": new_dev.id,
                    "ip": new_dev.current_ip,
                    "mac": new_dev.current_mac,
                    "vendor": new_dev.mac_vendor,
                    "timestamp": now.isoformat()
                })

        # 5. Handle Offline Devices (devices previously seen but not observed in this sweep)
        offline_count = 0
        for d in existing_devices:
            if d.id not in observed_device_ids and d.is_online:
                d.is_online = False
                offline_count += 1
                await ws_hub.broadcast("device.offline", {
                    "device_id": d.id,
                    "ip": d.current_ip,
                    "mac": d.current_mac,
                    "last_seen": d.last_seen.isoformat()
                })

        await session.commit()

        # 6. Broadcast scan completed & agent activity events
        await ws_hub.broadcast("network.scan.completed", {
            "status": "COMPLETED",
            "endpoints_observed": len(raw_endpoints),
            "new_devices": len(new_devices),
            "active_refreshed": len(updated_devices),
            "marked_offline": offline_count,
            "scan_duration_seconds": diagnostics["scan_duration_seconds"],
            "diagnostics": diagnostics
        })

        await ws_hub.broadcast("AGENT_ACTIVITY", {
            "agent_name": self.agent_name,
            "action": f"Layer 2/3 Sweep: {diagnostics['cidr']} ({diagnostics['active_interface']})",
            "result": f"{len(raw_endpoints)} endpoints observed ({len(new_devices)} new, {offline_count} offline)",
            "evidence": f"Scapy ARP replies: {diagnostics['arp_responses']}, OS neighbor cache: {diagnostics['neighbor_entries']}",
            "confidence": "CONFIRMED"
        })

        return {
            "scan_timestamp": self.last_scan_time.isoformat(),
            "endpoints_observed": len(raw_endpoints),
            "new_devices_enrolled": len(new_devices),
            "active_devices_refreshed": len(updated_devices),
            "marked_offline": offline_count,
            "diagnostics": diagnostics
        }

discovery_agent = DiscoveryAgent()
