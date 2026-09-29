export type TrustStatus = 'TRUSTED' | 'UNKNOWN' | 'GUEST' | 'SUSPICIOUS' | 'BLOCKLISTED';
export type DeviceType = 'WORKSTATION' | 'LAPTOP' | 'MOBILE' | 'SMART_TV' | 'ROUTER' | 'IOT_DEVICE' | 'NAS_STORAGE' | 'PRINTER' | 'UNKNOWN';
export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ConfidenceLevel = 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface DeviceService {
  id: number;
  port: number;
  protocol: string;
  service_name: string;
  banner?: string;
  is_unexpected: boolean;
  first_observed: string;
  last_observed: string;
}

export interface DeviceAddress {
  id: number;
  address_type: string;
  address_value: string;
  first_seen: string;
  last_seen: string;
}

export interface DeviceIdentity {
  id: number;
  identity_type: string;
  identity_value: string;
  confidence: string;
  first_seen: string;
  last_seen: string;
}

export interface Device {
  id: string;
  user_label?: string;
  current_ip: string;
  current_mac?: string;
  mac_vendor?: string;
  is_mac_randomized: boolean;
  hostname?: string;
  device_type: DeviceType;
  os_hint: string;
  trust_status: TrustStatus;
  is_online: boolean;
  first_seen: string;
  last_seen: string;
  risk_score: number;
  risk_severity: RiskSeverity;
  confidence_level: ConfidenceLevel;
  in_baseline: boolean;
  notes?: string;
  services?: DeviceService[];
  addresses?: DeviceAddress[];
  identities?: DeviceIdentity[];
}

export interface TimelineEvent {
  timestamp: string;
  event_type: 'CONNECTION' | 'ADDRESS_CHANGE' | 'SERVICE_FOUND' | 'RISK_UPDATE' | 'ALERT' | 'USER_ACTION' | 'IDENTITY';
  title: string;
  description: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'WARNING';
}

export interface AlertItem {
  id: string;
  device_id?: string;
  rule_id: string;
  title: string;
  description: string;
  severity: RiskSeverity;
  status: 'ACTIVE' | 'ACKNOWLEDGED' | 'RESOLVED' | 'IGNORED';
  confidence: string;
  evidence_data: string;
  deduplication_hash: string;
  created_at: string;
}

export interface SecurityPostureStats {
  total_connected: number;
  trusted_devices: number;
  unknown_devices: number;
  suspicious_devices: number;
  blocklisted_devices: number;
  high_risk_devices: number;
  devices_seen_today: number;
  open_services_total: number;
  active_alerts_count: number;
  network_risk_score: number;
  learn_baseline_active: boolean;
  baseline_device_count: number;
}

export interface AgentActivity {
  agent_name: string;
  status: 'ACTIVE' | 'IDLE' | 'ANALYZING' | 'ALERTING';
  last_action: string;
  evidence_summary: string;
  confidence: string;
  timestamp: string;
}

export interface ConnectionEvent {
  id: number;
  protocol: string;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  state: string;
  pid: number | null;
  process_name: string | null;
  simulation: boolean;
  timestamp: string;
}

export interface ProcessSnapshot {
  id: number;
  pid: number;
  name: string;
  username: string | null;
  cpu_percent: number;
  memory_percent: number;
  status: string;
  simulation: boolean;
  timestamp: string;
}

export interface DefensiveAction {
  id: number;
  incident_id: string;
  action_type: string;
  target: string;
  status: string;
  operator: string;
  reason: string;
  simulation_mode: boolean;
  dry_run_result?: string;
  execution_result?: string;
  created_at: string;
  decided_at?: string;
}
