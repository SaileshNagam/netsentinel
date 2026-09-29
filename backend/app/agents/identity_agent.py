"""
NetSentinel Agent 2: Device Identity & Fingerprinting Agent

Enriches devices discovered by the Discovery Agent with:
- Multi-vector OS/type fingerprinting (OUI, hostname, service banners)
- Safe TCP port scanning for exposed service detection
- Hostname mutation tracking (new DeviceIdentity records)
- Vendor OUI identity logging
- Confidence-rated results stored back to the Device model

Design invariants:
- Never claims OS or device type without corroborating evidence
- Always stores confidence level alongside assertions
- Broadcasts AGENT_ACTIVITY + DEVICE_ENRICHED WebSocket events
- Designed to be idempotent: re-running does NOT create duplicate identities
"""
import logging
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.device import Device, ConfidenceLevel, RiskSeverity
from app.models.identity import DeviceIdentity
from app.models.service import DeviceService
from app.discovery.fingerprinter import fingerprint_endpoint
from app.discovery.port_scanner import scan_host_ports, extract_banners
from app.core.websocket_hub import ws_hub

logger = logging.getLogger("NetSentinel.IdentityAgent")


# Map fingerprinter confidence strings to ConfidenceLevel enum values
_CONFIDENCE_MAP = {
    "CONFIRMED": ConfidenceLevel.CONFIRMED.value,
    "HIGH":      ConfidenceLevel.HIGH.value,
    "MEDIUM":    ConfidenceLevel.MEDIUM.value,
    "LOW":       ConfidenceLevel.LOW.value,
    "UNKNOWN":   ConfidenceLevel.UNKNOWN.value,
}


class IdentityAgent:
    """
    Agent 2: Device Identity & Enrichment Pipeline.

    For each device provided, this agent:
    1. Performs a safe TCP port scan to detect exposed services
    2. Fingerprints the device using OUI + hostname + service banners
    3. Updates Device model fields (device_type, os_hint, confidence_level)
    4. Persists new DeviceIdentity records when new hostnames are observed
    5. Persists DeviceService records for open ports with change detection
    6. Broadcasts real-time WebSocket events
    """

    def __init__(self):
        self.agent_name = "Identity Agent"
        self.total_enrichments: int = 0

    async def enrich_device(
        self,
        device: Device,
        session: AsyncSession,
        skip_port_scan: bool = False
    ) -> Dict[str, Any]:
        """
        Enrich a single device. Loads existing services/identities for dedup.

        Args:
            device: The ORM Device object (must be attached to session)
            session: Active async DB session
            skip_port_scan: If True, skip TCP probing (useful for batch enrichment)

        Returns: Summary dict of what was discovered
        """
        ip = device.current_ip
        mac = device.current_mac
        hostname = device.hostname
        now = datetime.utcnow()

        logger.info("Identity Agent enriching %s (%s)...", device.id, ip)
        await ws_hub.broadcast("AGENT_ACTIVITY", {
            "agent_name": self.agent_name,
            "action": f"Fingerprinting device {device.id} @ {ip}",
            "result": "In progress",
            "evidence": "Passive OUI + hostname analysis initiated",
            "confidence": "MEDIUM"
        })

        # ── 1. TCP Port Scan (async, non-blocking) ──────────────────────────
        open_ports: Dict = {}
        if not skip_port_scan:
            try:
                open_ports = await asyncio.wait_for(
                    scan_host_ports(ip, max_concurrent=5),
                    timeout=15.0  # hard cap per host
                )
            except asyncio.TimeoutError:
                logger.warning("Port scan timed out for %s — proceeding without service data", ip)
            except Exception as exc:
                logger.warning("Port scan error for %s: %s", ip, exc)

        banners = extract_banners(open_ports)

        # ── 2. Fingerprint ──────────────────────────────────────────────────
        fp = fingerprint_endpoint(
            ip=ip,
            mac=mac,
            hostname=hostname,
            banners=banners if banners else None,
            is_gateway=device.device_type == "ROUTER"
        )

        # ── 3. Update Device model fields ───────────────────────────────────
        fp_confidence = _CONFIDENCE_MAP.get(fp["device_type_confidence"], ConfidenceLevel.UNKNOWN.value)

        # Only upgrade confidence level, never downgrade an existing CONFIRMED record
        current_conf_rank = list(_CONFIDENCE_MAP.values()).index(
            device.confidence_level if device.confidence_level in _CONFIDENCE_MAP.values()
            else ConfidenceLevel.UNKNOWN.value
        )
        new_conf_rank = list(_CONFIDENCE_MAP.values()).index(fp_confidence)
        if new_conf_rank < current_conf_rank:  # lower index = higher confidence
            device.confidence_level = fp_confidence

        device.mac_vendor = fp["vendor"]
        device.is_mac_randomized = fp["is_mac_randomized"]

        # Only overwrite device_type if current is UNKNOWN or new confidence is higher
        if device.device_type in ("UNKNOWN", None) or fp["device_type_confidence"] in ("CONFIRMED", "HIGH"):
            device.device_type = fp["device_type"]

        device.os_hint = fp["os_hint"]
        device.last_seen = now

        # ── 4. Persist Hostname Identity (dedup by value) ───────────────────
        identity_changes = []
        if hostname:
            existing_hostnames = {
                i.identity_value for i in device.identities
                if i.identity_type == "HOSTNAME"
            }
            if hostname not in existing_hostnames:
                new_identity = DeviceIdentity(
                    device_id=device.id,
                    identity_type="HOSTNAME",
                    identity_value=hostname,
                    confidence=fp["device_type_confidence"],
                    first_seen=now,
                    last_seen=now
                )
                session.add(new_identity)
                identity_changes.append(f"HOSTNAME:{hostname}")
                logger.info("New hostname identity recorded for %s: %s", device.id, hostname)
            else:
                # Update last_seen for the existing record
                for ident in device.identities:
                    if ident.identity_type == "HOSTNAME" and ident.identity_value == hostname:
                        ident.last_seen = now

        # ── 5. Persist Vendor OUI Identity (dedup by value) ─────────────────
        if fp["vendor"] and fp["vendor"] != "Unknown":
            existing_ouis = {
                i.identity_value for i in device.identities
                if i.identity_type == "VENDOR_OUI"
            }
            if fp["vendor"] not in existing_ouis:
                session.add(DeviceIdentity(
                    device_id=device.id,
                    identity_type="VENDOR_OUI",
                    identity_value=fp["vendor"],
                    confidence="HIGH" if not fp["is_mac_randomized"] else "LOW",
                    first_seen=now,
                    last_seen=now
                ))
                identity_changes.append(f"VENDOR_OUI:{fp['vendor']}")

        # ── 6. Persist OS Hint Identity ──────────────────────────────────────
        if fp["os_hint"] and fp["os_confidence"] not in ("UNKNOWN", "LOW"):
            existing_os_hints = {
                i.identity_value for i in device.identities
                if i.identity_type == "OS_HINT"
            }
            if fp["os_hint"] not in existing_os_hints:
                session.add(DeviceIdentity(
                    device_id=device.id,
                    identity_type="OS_HINT",
                    identity_value=fp["os_hint"],
                    confidence=fp["os_confidence"],
                    first_seen=now,
                    last_seen=now
                ))
                identity_changes.append(f"OS_HINT:{fp['os_hint']}")

        # ── 7. Persist DeviceService records for open ports ─────────────────
        service_changes = []
        if open_ports:
            existing_ports = {svc.port for svc in device.services}
            for port, info in open_ports.items():
                if port not in existing_ports:
                    is_unexpected = _is_service_unexpected(device.device_type, port)
                    svc = DeviceService(
                        device_id=device.id,
                        port=port,
                        protocol="TCP",
                        service_name=info["service"],
                        banner=info.get("banner"),
                        is_unexpected=is_unexpected,
                        first_observed=now,
                        last_observed=now
                    )
                    session.add(svc)
                    service_changes.append(f"{port}/{info['service']}")
                    if is_unexpected:
                        logger.warning(
                            "UNEXPECTED SERVICE: %s port %d/%s (%s)",
                            device.id, port, info["service"], ip
                        )
                else:
                    # Update last_observed
                    for svc in device.services:
                        if svc.port == port:
                            svc.last_observed = now

        self.total_enrichments += 1

        # ── 8. Broadcast enrichment completion event ─────────────────────────
        evidence_parts = []
        if banners:
            evidence_parts.append(f"{len(banners)} service banner(s)")
        if open_ports:
            evidence_parts.append(f"{len(open_ports)} open port(s)")
        if mac:
            evidence_parts.append("OUI lookup")
        if hostname:
            evidence_parts.append("hostname analysis")
        evidence_str = ", ".join(evidence_parts) if evidence_parts else "passive OUI analysis only"

        await ws_hub.broadcast("AGENT_ACTIVITY", {
            "agent_name": self.agent_name,
            "action": f"Fingerprint complete for {device.id}",
            "result": (
                f"Classified as {fp['device_type']} ({fp['device_type_confidence']} confidence). "
                f"OS: {fp['os_hint']}. "
                f"{len(open_ports)} ports probed, {len(service_changes)} new services."
            ),
            "evidence": evidence_str,
            "confidence": fp["device_type_confidence"]
        })

        await ws_hub.broadcast("DEVICE_UPDATED", {
            "device_id": device.id,
            "device_type": device.device_type,
            "os_hint": device.os_hint,
            "confidence_level": device.confidence_level,
            "mac_vendor": device.mac_vendor,
            "is_mac_randomized": device.is_mac_randomized,
            "open_ports": list(open_ports.keys()),
        })

        return {
            "device_id": device.id,
            "ip": ip,
            "fingerprint": fp,
            "open_ports": list(open_ports.keys()),
            "new_services": service_changes,
            "new_identities": identity_changes,
        }

    async def enrich_all_devices(
        self,
        session: AsyncSession,
        device_ids: Optional[List[str]] = None,
        skip_port_scan: bool = False
    ) -> Dict[str, Any]:
        """
        Batch enrichment pass. If device_ids is None, enriches all online devices.

        Devices are processed sequentially to avoid flooding the local network.
        """
        query = select(Device).options(
            selectinload(Device.identities),
            selectinload(Device.services)
        ).where(Device.is_online == True)

        if device_ids:
            query = query.where(Device.id.in_(device_ids))

        result = await session.execute(query)
        devices = result.scalars().all()

        if not devices:
            logger.info("Identity Agent: no online devices to enrich.")
            return {"enriched": 0, "results": []}

        logger.info("Identity Agent starting batch enrichment of %d devices...", len(devices))

        results = []
        for device in devices:
            try:
                r = await self.enrich_device(device, session, skip_port_scan=skip_port_scan)
                results.append(r)
            except Exception as exc:
                logger.error("Enrichment failed for %s: %s", device.id, exc, exc_info=True)

        await session.commit()

        await ws_hub.broadcast("AGENT_ACTIVITY", {
            "agent_name": self.agent_name,
            "action": "Batch Enrichment Pipeline Complete",
            "result": f"Enriched {len(results)}/{len(devices)} devices successfully.",
            "evidence": "Multi-vector fingerprinting: OUI + hostname + TCP banner analysis",
            "confidence": "HIGH"
        })

        return {
            "enriched": len(results),
            "total": len(devices),
            "results": results
        }


def _is_service_unexpected(device_type: str, port: int) -> bool:
    """
    Returns True if an open port is unexpected for the given device type.
    E.g., SMB on a SMART_TV is a red flag. SSH on a SERVER is normal.
    """
    expected_by_type = {
        "SERVER":      {22, 80, 443, 8080, 8443, 25, 110, 143},
        "WORKSTATION": {80, 443, 8080},
        "LAPTOP":      {80, 443, 8080},
        "ROUTER":      {80, 443, 22, 23},
        "PRINTER":     {9100, 80, 443},
        "SMART_TV":    {80, 443},
        "MOBILE":      {80, 443},
        "IOT_DEVICE":  {80, 443, 1883, 8080},
        "NAS_STORAGE": {22, 80, 443, 445, 21},
        "UNKNOWN":     set(),
    }
    allowed = expected_by_type.get(device_type, set())
    return port not in allowed


identity_agent = IdentityAgent()
