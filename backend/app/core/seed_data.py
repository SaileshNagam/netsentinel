"""
NetSentinel Database Initial Seed Data
Provides a realistic baseline of authorized local network devices and a sample investigation.
"""
from datetime import datetime, timedelta
import json
import hashlib
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.device import Device, TrustStatus, DeviceType, RiskSeverity, ConfidenceLevel
from app.models.address import DeviceAddress
from app.models.identity import DeviceIdentity
from app.models.service import DeviceService
from app.models.baseline import BehaviorBaseline
from app.models.alert import Alert, AlertStatus
from app.models.risk import RiskScoreLog
from app.models.incident import Incident, IncidentStatus, RecommendedAction, ActionStatus
from app.models.evidence import EvidencePackage
from app.models.audit import AuditEvent

async def seed_initial_inventory(session: AsyncSession):
    """Populates initial realistic network inventory if database is empty."""
    result = await session.execute(select(Device))
    if result.scalars().first() is not None:
        return # Already seeded

    now = datetime.utcnow()
    three_days_ago = now - timedelta(days=3)
    one_day_ago = now - timedelta(days=1)
    two_hours_ago = now - timedelta(hours=2)

    # 1. Default Gateway Router
    router = Device(
        id="D-001",
        user_label="Core Gateway Router",
        current_ip="192.168.1.1",
        current_mac="00:01:42:ab:34:11",
        mac_vendor="Cisco Systems",
        is_mac_randomized=False,
        hostname="gateway.home.arpa",
        device_type=DeviceType.ROUTER.value,
        os_hint="Embedded Linux (Cisco IOS-XE)",
        trust_status=TrustStatus.TRUSTED.value,
        is_online=True,
        first_seen=three_days_ago,
        last_seen=now,
        risk_score=0,
        risk_severity=RiskSeverity.LOW.value,
        confidence_level=ConfidenceLevel.CONFIRMED.value,
        in_baseline=True,
        notes="Primary L3 Gateway and DHCP authoritative server."
    )

    # 2. Workstation MacBook Pro
    laptop = Device(
        id="D-002",
        user_label="Admin MacBook Pro",
        current_ip="192.168.1.11",
        current_mac="3c:22:fb:18:90:bc",
        mac_vendor="Apple, Inc.",
        is_mac_randomized=False,
        hostname="Dev-MacBook-Pro.local",
        device_type=DeviceType.LAPTOP.value,
        os_hint="macOS Sonoma (Darwin 23.x)",
        trust_status=TrustStatus.TRUSTED.value,
        is_online=True,
        first_seen=three_days_ago,
        last_seen=now,
        risk_score=4,
        risk_severity=RiskSeverity.LOW.value,
        confidence_level=ConfidenceLevel.CONFIRMED.value,
        in_baseline=True,
        notes="Authorized developer machine."
    )

    # 3. Mobile iPhone (with Private MAC Randomization)
    iphone = Device(
        id="D-003",
        user_label="Personal iPhone 15",
        current_ip="192.168.1.10",
        current_mac="a2:11:45:90:ee:12", # LAA bit set
        mac_vendor="Randomized / Private MAC (LAA)",
        is_mac_randomized=True,
        hostname="Apple-iPhone.local",
        device_type=DeviceType.MOBILE.value,
        os_hint="iOS 17.x",
        trust_status=TrustStatus.TRUSTED.value,
        is_online=True,
        first_seen=three_days_ago,
        last_seen=now,
        risk_score=2,
        risk_severity=RiskSeverity.LOW.value,
        confidence_level=ConfidenceLevel.HIGH.value,
        in_baseline=True,
        notes="Uses iOS Private Wi-Fi MAC address."
    )

    # 4. Samsung Smart TV
    tv = Device(
        id="D-004",
        user_label="Living Room Smart TV",
        current_ip="192.168.1.13",
        current_mac="5c:49:7d:aa:bb:04",
        mac_vendor="Samsung Electronics",
        is_mac_randomized=False,
        hostname="Samsung-QLED-TV",
        device_type=DeviceType.SMART_TV.value,
        os_hint="Tizen OS",
        trust_status=TrustStatus.TRUSTED.value,
        is_online=True,
        first_seen=three_days_ago,
        last_seen=now,
        risk_score=8,
        risk_severity=RiskSeverity.LOW.value,
        confidence_level=ConfidenceLevel.CONFIRMED.value,
        in_baseline=True,
        notes="Smart TV running media streaming apps."
    )

    # 5. Synology NAS
    nas = Device(
        id="D-005",
        user_label="Backup Synology NAS",
        current_ip="192.168.1.20",
        current_mac="00:11:32:ee:aa:19",
        mac_vendor="Synology Incorporated",
        is_mac_randomized=False,
        hostname="Synology-DiskStation.local",
        device_type=DeviceType.NAS_STORAGE.value,
        os_hint="Synology DSM 7.x",
        trust_status=TrustStatus.TRUSTED.value,
        is_online=True,
        first_seen=three_days_ago,
        last_seen=now,
        risk_score=12,
        risk_severity=RiskSeverity.LOW.value,
        confidence_level=ConfidenceLevel.CONFIRMED.value,
        in_baseline=True,
        notes="Local network storage with SMB and HTTPS management."
    )

    # 6. Raspberry Pi Sensor
    rpi = Device(
        id="D-006",
        user_label="Environment Sensor Pi",
        current_ip="192.168.1.45",
        current_mac="b8:27:eb:11:22:33",
        mac_vendor="Raspberry Pi Foundation",
        is_mac_randomized=False,
        hostname="sensor-pi4.local",
        device_type=DeviceType.IOT_DEVICE.value,
        os_hint="Debian Linux (Raspbian)",
        trust_status=TrustStatus.TRUSTED.value,
        is_online=True,
        first_seen=three_days_ago,
        last_seen=now,
        risk_score=5,
        risk_severity=RiskSeverity.LOW.value,
        confidence_level=ConfidenceLevel.CONFIRMED.value,
        in_baseline=True,
        notes="Telemetry sensor in server cabinet."
    )

    # 7. Suspicious / Rogue Device D-019
    rogue = Device(
        id="D-019",
        user_label="Unknown Device D-019",
        current_ip="192.168.1.27",
        current_mac="da:a1:19:33:44:aa", # LAA bit set (randomized)
        mac_vendor="Randomized / Private MAC (LAA)",
        is_mac_randomized=True,
        hostname="DESKTOP-X51",
        device_type=DeviceType.UNKNOWN.value,
        os_hint="Windows 10/11 Heuristic",
        trust_status=TrustStatus.SUSPICIOUS.value,
        is_online=True,
        first_seen=two_hours_ago,
        last_seen=now,
        risk_score=72,
        risk_severity=RiskSeverity.HIGH.value,
        confidence_level=ConfidenceLevel.HIGH.value,
        in_baseline=False,
        notes="First connected at 02:31 off-baseline. Announced Windows hostname and exposed SMB."
    )

    session.add_all([router, laptop, iphone, tv, nas, rpi, rogue])
    await session.flush()

    # Add Services
    services = [
        DeviceService(device_id="D-001", port=53, protocol="UDP", service_name="DNS", banner="dnsmasq-2.86", is_unexpected=False, first_observed=three_days_ago, last_observed=now),
        DeviceService(device_id="D-001", port=80, protocol="TCP", service_name="HTTP", banner="Cisco Router Web UI", is_unexpected=False, first_observed=three_days_ago, last_observed=now),
        DeviceService(device_id="D-001", port=443, protocol="TCP", service_name="HTTPS", banner="TLS 1.3 / OpenSSL", is_unexpected=False, first_observed=three_days_ago, last_observed=now),
        
        DeviceService(device_id="D-002", port=22, protocol="TCP", service_name="SSH", banner="OpenSSH_9.6p1, LibreSSL 3.3.6", is_unexpected=False, first_observed=three_days_ago, last_observed=now),
        
        DeviceService(device_id="D-004", port=8000, protocol="TCP", service_name="HTTP", banner="Samsung SmartTV Media Receiver", is_unexpected=False, first_observed=three_days_ago, last_observed=now),
        
        DeviceService(device_id="D-005", port=445, protocol="TCP", service_name="SMB", banner="Samba 4.15 (Synology DSM)", is_unexpected=False, first_observed=three_days_ago, last_observed=now),
        DeviceService(device_id="D-005", port=5001, protocol="TCP", service_name="HTTPS", banner="Synology DSM Portal", is_unexpected=False, first_observed=three_days_ago, last_observed=now),
        
        DeviceService(device_id="D-019", port=445, protocol="TCP", service_name="SMB", banner="Microsoft Windows SMBv2/v3", is_unexpected=True, first_observed=two_hours_ago, last_observed=now),
        DeviceService(device_id="D-019", port=135, protocol="TCP", service_name="MSRPC", banner="Microsoft RPC Endpoint Mapper", is_unexpected=True, first_observed=two_hours_ago, last_observed=now),
    ]
    session.add_all(services)

    # Add Addresses
    addresses = [
        DeviceAddress(device_id="D-001", address_type="IPV4", address_value="192.168.1.1", first_seen=three_days_ago, last_seen=now),
        DeviceAddress(device_id="D-002", address_type="IPV4", address_value="192.168.1.11", first_seen=three_days_ago, last_seen=now),
        DeviceAddress(device_id="D-003", address_type="IPV4", address_value="192.168.1.10", first_seen=three_days_ago, last_seen=now),
        DeviceAddress(device_id="D-004", address_type="IPV4", address_value="192.168.1.13", first_seen=three_days_ago, last_seen=now),
        DeviceAddress(device_id="D-005", address_type="IPV4", address_value="192.168.1.20", first_seen=three_days_ago, last_seen=now),
        DeviceAddress(device_id="D-006", address_type="IPV4", address_value="192.168.1.45", first_seen=three_days_ago, last_seen=now),
        DeviceAddress(device_id="D-019", address_type="IPV4", address_value="192.168.1.27", first_seen=two_hours_ago, last_seen=now),
    ]
    session.add_all(addresses)

    # Add Identities
    identities = [
        DeviceIdentity(device_id="D-001", identity_type="HOSTNAME", identity_value="gateway.home.arpa", confidence="CONFIRMED", first_seen=three_days_ago, last_seen=now),
        DeviceIdentity(device_id="D-002", identity_type="MDNS_NAME", identity_value="Dev-MacBook-Pro.local", confidence="CONFIRMED", first_seen=three_days_ago, last_seen=now),
        DeviceIdentity(device_id="D-003", identity_type="MDNS_NAME", identity_value="Apple-iPhone.local", confidence="HIGH", first_seen=three_days_ago, last_seen=now),
        DeviceIdentity(device_id="D-004", identity_type="SSDP_NAME", identity_value="Samsung-QLED-TV", confidence="CONFIRMED", first_seen=three_days_ago, last_seen=now),
        DeviceIdentity(device_id="D-005", identity_type="HOSTNAME", identity_value="Synology-DiskStation.local", confidence="CONFIRMED", first_seen=three_days_ago, last_seen=now),
        DeviceIdentity(device_id="D-006", identity_type="MDNS_NAME", identity_value="sensor-pi4.local", confidence="CONFIRMED", first_seen=three_days_ago, last_seen=now),
        DeviceIdentity(device_id="D-019", identity_type="HOSTNAME", identity_value="DESKTOP-X51", confidence="HIGH", first_seen=two_hours_ago, last_seen=now),
    ]
    session.add_all(identities)

    # Add Behavioral Baselines
    baselines = [
        BehaviorBaseline(device_id="D-001", typical_active_hours_mask="111111111111111111111111", is_baseline_locked=True, created_at=three_days_ago, updated_at=now),
        BehaviorBaseline(device_id="D-002", typical_active_hours_mask="000000001111111111111100", is_baseline_locked=True, created_at=three_days_ago, updated_at=now),
        BehaviorBaseline(device_id="D-003", typical_active_hours_mask="000000011111111111111110", is_baseline_locked=True, created_at=three_days_ago, updated_at=now),
        BehaviorBaseline(device_id="D-004", typical_active_hours_mask="000000000000111111111000", is_baseline_locked=True, created_at=three_days_ago, updated_at=now),
        BehaviorBaseline(device_id="D-005", typical_active_hours_mask="111111111111111111111111", is_baseline_locked=True, created_at=three_days_ago, updated_at=now),
        BehaviorBaseline(device_id="D-006", typical_active_hours_mask="111111111111111111111111", is_baseline_locked=True, created_at=three_days_ago, updated_at=now),
    ]
    session.add_all(baselines)

    # Add Explainable Risk Factors for Rogue Device D-019
    factors = [
        {"rule": "RISK-NEW-UNKNOWN", "delta": 25, "reason": "New unknown device not present in authorized baseline", "evidence": "No prior inventory record"},
        {"rule": "RISK-OFF-HOURS", "delta": 20, "reason": "First connected during abnormal window (02:31 AM)", "evidence": "Timestamp 02:31 is outside typical 08:00-23:00 baseline"},
        {"rule": "RISK-SMB-EXPOSED", "delta": 20, "reason": "Exposes SMB (port 445) on unauthorized endpoint", "evidence": "TCP port 445 handshake succeeded"},
        {"rule": "RISK-RANDOM-MAC", "delta": 15, "reason": "Locally Administered Address (LAA) detected", "evidence": "MAC da:a1:19:33:44:aa has U/L bit = 1"}
    ]
    risk_log = RiskScoreLog(
        device_id="D-019",
        score=72,
        severity=RiskSeverity.HIGH.value,
        factors_json=json.dumps(factors),
        calculated_at=two_hours_ago
    )
    session.add(risk_log)

    # Add Alert for Rogue Device
    alert = Alert(
        id="ALT-2026-001",
        device_id="D-019",
        rule_id="DETECT-NEW-UNKNOWN-SMB",
        title="Suspicious Rogue Device with Exposed SMB",
        description="Unknown device D-019 joined at 02:31 AM, presents randomized MAC, announced hostname 'DESKTOP-X51', and has open port 445 (SMB).",
        severity="HIGH",
        status=AlertStatus.ACTIVE.value,
        confidence="HIGH",
        evidence_data=json.dumps({
            "ip": "192.168.1.27",
            "mac": "da:a1:19:33:44:aa",
            "hostname": "DESKTOP-X51",
            "exposed_ports": [445, 135],
            "risk_score": 72
        }),
        deduplication_hash=hashlib.sha256(b"D-019-DETECT-NEW-UNKNOWN-SMB").hexdigest(),
        created_at=two_hours_ago
    )
    session.add(alert)

    # Add Incident NS-2026-019
    incident_summary = (
        "Device D-019 first appeared at 02:31 on 9 September. "
        "It has not previously existed in the trusted device inventory. "
        "The device announced hostname 'DESKTOP-X51' and exposed SMB (port 445). "
        "No evidence currently proves malicious activity."
    )
    incident = Incident(
        id="NS-2026-019",
        device_id="D-019",
        title="Unclassified Host with Exposed SMB Service",
        severity="HIGH",
        status=IncidentStatus.INVESTIGATING.value,
        recommended_action=RecommendedAction.INVESTIGATE.value,
        action_status=ActionStatus.PENDING_APPROVAL.value,
        summary=incident_summary,
        evidence_package_hash=hashlib.sha256(incident_summary.encode()).hexdigest(),
        created_at=two_hours_ago,
        updated_at=now
    )
    session.add(incident)

    # Evidence Package
    evidence = EvidencePackage(
        id="EV-2026-001",
        incident_id="NS-2026-019",
        device_id="D-019",
        evidence_type="FULL_DOSSIER",
        data_blob=json.dumps({
            "incident_id": "NS-2026-019",
            "device": {"id": "D-019", "ip": "192.168.1.27", "mac": "da:a1:19:33:44:aa"},
            "factors": factors,
            "services": [{"port": 445, "name": "SMB"}, {"port": 135, "name": "MSRPC"}]
        }),
        sha256_hash=hashlib.sha256(b"EV-2026-001-DOSSIER-INTEGRITY").hexdigest(),
        captured_at=two_hours_ago
    )
    session.add(evidence)

    # Audit log
    audit = AuditEvent(
        action="SYSTEM_INIT_BASELINE",
        actor="SYSTEM_INITIALIZER",
        target_resource="NETWORK_INVENTORY",
        details="Seeded initial 6 trusted baseline devices and 1 suspicious unclassified endpoint for verification.",
        timestamp=now,
        event_hash=hashlib.sha256(b"AUDIT-INIT-2026").hexdigest()
    )
    session.add(audit)

    await session.commit()
