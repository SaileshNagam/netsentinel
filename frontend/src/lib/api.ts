import { Device, AlertItem, SecurityPostureStats, TimelineEvent, TrustStatus } from '../types';

const API_BASE = '/api';

export async function fetchDevices(params?: { status?: string; search?: string; online_only?: boolean }): Promise<Device[]> {
  const query = new URLSearchParams();
  if (params?.status) query.append('status', params.status);
  if (params?.search) query.append('search', params.search);
  if (params?.online_only) query.append('online_only', 'true');

  const res = await fetch(`${API_BASE}/devices?${query.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch devices');
  return res.json();
}

export async function fetchDevice(deviceId: string): Promise<Device> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}`);
  if (!res.ok) throw new Error(`Failed to fetch device ${deviceId}`);
  return res.json();
}

export async function classifyDevice(deviceId: string, trustStatus: TrustStatus, notes?: string): Promise<Device> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/classify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ trust_status: trustStatus, notes })
  });
  if (!res.ok) throw new Error('Failed to classify device');
  return res.json();
}

export async function fetchDeviceTimeline(deviceId: string): Promise<TimelineEvent[]> {
  const res = await fetch(`${API_BASE}/devices/${deviceId}/timeline`);
  if (!res.ok) throw new Error('Failed to fetch device timeline');
  return res.json();
}

export async function fetchAlerts(): Promise<AlertItem[]> {
  const res = await fetch(`${API_BASE}/alerts`);
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return res.json();
}

export async function updateAlertStatus(alertId: string, status: 'ACKNOWLEDGED' | 'RESOLVED' | 'IGNORED'): Promise<AlertItem> {
  const res = await fetch(`${API_BASE}/alerts/${alertId}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status })
  });
  if (!res.ok) throw new Error('Failed to update alert');
  return res.json();
}

export async function fetchPosture(): Promise<SecurityPostureStats> {
  const res = await fetch(`${API_BASE}/posture`);
  if (!res.ok) throw new Error('Failed to fetch posture');
  return res.json();
}

export async function triggerDiscoveryScan(): Promise<any> {
  const res = await fetch(`${API_BASE}/discovery/scan`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to trigger discovery scan');
  return res.json();
}

export async function fetchDiscoveryInterfaces(): Promise<any> {
  const res = await fetch(`${API_BASE}/discovery/interfaces`);
  if (!res.ok) throw new Error('Failed to fetch interfaces');
  return res.json();
}

export async function fetchActiveNetwork(): Promise<any> {
  const res = await fetch(`${API_BASE}/network/interface`);
  if (!res.ok) throw new Error('Failed to fetch active network');
  return res.json();
}

export const fetchLiveConnections = async (): Promise<any[]> => {
  const res = await fetch(`${API_BASE}/connections/live`);
  if (!res.ok) throw new Error('Failed to fetch connections');
  return res.json();
};

export const fetchLiveProcesses = async (): Promise<any[]> => {
  const res = await fetch(`${API_BASE}/processes`);
  if (!res.ok) throw new Error('Failed to fetch processes');
  return res.json();
};

export const fetchDefensiveActions = async (): Promise<any[]> => {
  const res = await fetch(`${API_BASE}/actions`);
  if (!res.ok) throw new Error('Failed to fetch actions');
  return res.json();
};

export const executeDefensiveAction = async (actionId: number, type: 'approve' | 'reject' | 'simulate', payload: { operator: string; notes: string }): Promise<any> => {
  const res = await fetch(`${API_BASE}/actions/${actionId}/${type}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Failed to ${type} action`);
  return res.json();
};

export const triggerDemoScenario = async (scenario: 'c2' | 'port_scan' | 'brute_force'): Promise<any> => {
  const res = await fetch(`${API_BASE}/demo/trigger?scenario=${scenario}`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error(`Failed to trigger demo scenario`);
  return res.json();
};
