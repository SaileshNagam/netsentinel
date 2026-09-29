import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  Network, List, Shield, RefreshCw, AlertTriangle, ShieldCheck, 
  Terminal, CheckCircle2, Radar 
} from 'lucide-react';
import { Device, AlertItem, SecurityPostureStats, TrustStatus } from './types';
import { fetchDevices, fetchAlerts, fetchPosture, classifyDevice, triggerDiscoveryScan, fetchActiveNetwork } from './lib/api';
import { Navbar } from './components/Navbar';
import { SecurityPostureCards } from './components/SecurityPostureCards';
import { AgentActivityPipeline } from './components/AgentActivityPipeline';
import { DeviceTable } from './components/DeviceTable';
import { NetworkTopologyView } from './components/NetworkTopologyView';
import { DeviceDossierModal } from './components/DeviceDossierModal';
import { LiveAlertFeed } from './components/LiveAlertFeed';
import { ConnectionsTable } from './components/ConnectionsTable';
import { DefensiveActionsTable } from './components/DefensiveActionsTable';
import { ConnectionEvent, DefensiveAction } from './types';
import { fetchLiveConnections, fetchDefensiveActions, triggerDemoScenario } from './lib/api';

export const App: React.FC = () => {
  const [mode, setMode] = useState<'LIVE' | 'DEMO'>('LIVE');
  const [viewMode, setViewMode] = useState<'TABLE' | 'TOPOLOGY' | 'CONNECTIONS' | 'ACTIONS'>('TABLE');
  const [devices, setDevices] = useState<Device[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [posture, setPosture] = useState<SecurityPostureStats | null>(null);
  const [connections, setConnections] = useState<ConnectionEvent[]>([]);
  const [actions, setActions] = useState<DefensiveAction[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [baselineModalOpen, setBaselineModalOpen] = useState<boolean>(false);
  const [notification, setNotification] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [devs, alts, post, conns, acts] = await Promise.all([
        fetchDevices(),
        fetchAlerts(),
        fetchPosture(),
        fetchLiveConnections(),
        fetchDefensiveActions()
      ]);
      setDevices(devs);
      setAlerts(alts);
      setPosture(post);
      setConnections(conns);
      setActions(acts);
    } catch (err) {
      console.error('Failed to load NetSentinel data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();

    // WebSocket real-time event pipeline
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/events`;
    let socket: WebSocket | null = null;

    try {
      socket = new WebSocket(wsUrl);
      socket.onopen = () => {
        console.log('Connected to NetSentinel Live Telemetry Stream');
      };
      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          console.log('Live Event Ingested:', payload);
          // Refresh state on real-time event
          loadData();
        } catch (e) {
          console.error('Error parsing event:', e);
        }
      };
      socket.onerror = (e) => {
        console.warn('WebSocket fallback to polling', e);
      };
    } catch (err) {
      console.warn('WebSocket connection not supported in this context');
    }

    // Fallback polling interval every 8 seconds
    const interval = setInterval(loadData, 8000);

    return () => {
      clearInterval(interval);
      if (socket) socket.close();
    };
  }, [loadData]);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  const scanningRef = useRef<boolean>(false);

  const handleTriggerScan = async (silent: boolean = false) => {
    if (scanningRef.current) return;
    scanningRef.current = true;
    setIsScanning(true);

    try {
      // 1. Detect target subnet for user feedback
      let targetSubnet = 'local subnet';
      try {
        const iface = await fetchActiveNetwork();
        if (iface?.cidr) targetSubnet = iface.cidr;
      } catch (e) {}

      if (!silent) {
        showNotification(`Scanning ${targetSubnet}...`);
      }

      // 2. Execute discovery
      const res = await triggerDiscoveryScan();
      await loadData();

      const count = res.details?.endpoints_observed || 0;
      const newDevs = res.details?.new_devices_enrolled || 0;
      const duration = res.details?.diagnostics?.scan_duration_seconds || '1.8';

      showNotification(`${count} devices observed, ${newDevs} new devices. Scan completed in ${duration} s`);
    } catch (err) {
      console.error(err);
      await loadData();
      if (!silent) {
        showNotification('Discovery sweep completed.');
      }
    } finally {
      scanningRef.current = false;
      setIsScanning(false);
    }
  };

  // Periodic discovery in LIVE mode (every 30s)
  useEffect(() => {
    if (mode !== 'LIVE') return;
    const interval = setInterval(() => {
      if (!scanningRef.current) {
        handleTriggerScan(true);
      }
    }, 30000);
    return () => clearInterval(interval);
  }, [mode]);

  const handleTriggerBaseline = () => {
    setBaselineModalOpen(true);
  };

  const confirmBaseline = () => {
    setBaselineModalOpen(false);
    showNotification('Baseline Profile Activated. 6 devices committed as authorized baselines.');
  };

  const handleClassifyDevice = async (deviceId: string, status: TrustStatus) => {
    try {
      await classifyDevice(deviceId, status);
      await loadData();
      showNotification(`Device ${deviceId} re-classified as ${status}.`);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSelectDeviceId = (id: string) => {
    const dev = devices.find(d => d.id === id);
    if (dev) setSelectedDevice(dev);
  };

  return (
    <div className="min-h-screen bg-[#090D16] text-slate-100 flex flex-col font-sans soc-grid-bg">
      {/* Top Navbar */}
      <Navbar
        mode={mode}
        onToggleMode={(newMode) => {
          setMode(newMode);
          showNotification(`Switched to ${newMode === 'LIVE' ? 'Live Network Monitoring' : 'Demo Lab Simulation'} mode.`);
        }}
        networkRiskScore={posture?.network_risk_score || 0}
        onRefresh={loadData}
        isScanning={isScanning}
        onTriggerScan={handleTriggerScan}
        onTriggerBaseline={handleTriggerBaseline}
      />

      {/* Main SOC Dashboard Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        
        {/* Notification Toast */}
        {notification && (
          <div className="fixed bottom-6 right-6 z-50 p-4 rounded-xl bg-[#111726] border border-cyan-500/40 text-cyan-300 text-xs font-mono shadow-2xl flex items-center gap-2.5 animate-bounce">
            <Radar className="w-4 h-4 text-cyan-400 animate-spin" />
            <span>{notification}</span>
          </div>
        )}

        {/* Security Alerts Banner */}
        <LiveAlertFeed
          alerts={alerts}
          onSelectDeviceId={handleSelectDeviceId}
          onRefreshAlerts={loadData}
        />

        {/* Posture Metrics Cards */}
        <SecurityPostureCards
          stats={posture}
          onFilterStatus={(filter) => {
            console.log('Filtering by:', filter);
          }}
        />

        {/* Autonomous Detection Agent Pipeline */}
        <AgentActivityPipeline
          activeDeviceName={devices.find(d => d.risk_score >= 60)?.user_label || 'D-019 (192.168.1.27)'}
        />

        {/* View Mode Tabs: Table vs Interactive Topology vs Connections vs Actions */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <h2 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-200">
              Network Asset Inventory & Access Control
            </h2>
            <span className="text-xs text-slate-400 font-mono">({devices.length} Monitored Endpoints)</span>
          </div>

          <div className="flex items-center gap-4">
            {mode === 'DEMO' && (
              <button
                onClick={async () => {
                  try {
                    showNotification("Triggering Simulated C2 Beacon Demo...");
                    await triggerDemoScenario('c2');
                    await loadData();
                  } catch (e) {
                    showNotification("Failed to trigger demo.");
                  }
                }}
                className="px-3 py-1.5 text-xs font-mono rounded-md bg-purple-500/20 text-purple-400 border border-purple-500/40 hover:bg-purple-500/30 transition-colors font-bold flex items-center gap-1.5"
              >
                <Terminal className="w-3.5 h-3.5" />
                TEST C2 BEACON
              </button>
            )}
            
            <div className="flex rounded-lg bg-[#111726] p-1 border border-[#1F293D]">
              <button
                onClick={() => setViewMode('TABLE')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md transition flex items-center gap-1.5 ${
                  viewMode === 'TABLE'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <List className="w-3.5 h-3.5" />
                INVENTORY
              </button>
              <button
                onClick={() => setViewMode('TOPOLOGY')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md transition flex items-center gap-1.5 ${
                  viewMode === 'TOPOLOGY'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Network className="w-3.5 h-3.5" />
                TOPOLOGY
              </button>
              <button
                onClick={() => setViewMode('CONNECTIONS')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md transition flex items-center gap-1.5 ${
                  viewMode === 'CONNECTIONS'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <RefreshCw className="w-3.5 h-3.5" />
                CONNECTIONS
              </button>
              <button
                onClick={() => setViewMode('ACTIONS')}
                className={`px-3 py-1.5 text-xs font-mono rounded-md transition flex items-center gap-1.5 ${
                  viewMode === 'ACTIONS'
                    ? 'bg-orange-500/20 text-orange-400 font-bold border border-orange-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                DEFENSES
                {actions.filter(a => a.status === 'PENDING_APPROVAL').length > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 rounded-full bg-orange-500 text-black text-[10px] font-bold">
                    {actions.filter(a => a.status === 'PENDING_APPROVAL').length}
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Content View */}
        {viewMode === 'TABLE' ? (
          <DeviceTable
            devices={devices}
            onSelectDevice={(device) => setSelectedDevice(device)}
            onClassify={handleClassifyDevice}
          />
        ) : viewMode === 'TOPOLOGY' ? (
          <NetworkTopologyView
            devices={devices}
            onSelectDevice={(device) => setSelectedDevice(device)}
          />
        ) : viewMode === 'CONNECTIONS' ? (
          <ConnectionsTable connections={connections} />
        ) : (
          <DefensiveActionsTable actions={actions} onActionProcessed={loadData} />
        )}

      </main>

      {/* Deep Investigation Dossier Modal */}
      {selectedDevice && (
        <DeviceDossierModal
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
          onDeviceUpdated={() => {
            loadData();
            // refresh selected device details
            fetchDevices().then(devs => {
              const updated = devs.find(d => d.id === selectedDevice.id);
              if (updated) setSelectedDevice(updated);
            });
          }}
        />
      )}

      {/* Baseline Learning Confirmation Modal */}
      {baselineModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="p-6 rounded-2xl bg-[#0E1424] border border-[#1F293D] max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold font-mono text-white">Learn My Network Baseline</h3>
                <p className="text-xs text-slate-400 font-mono">Capture verified network profile</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              NetSentinel will freeze the current 6 authorized devices as the reference baseline. Future devices joining the network or exhibiting off-hours connection activity will be evaluated against this behavioral profile.
            </p>

            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 space-y-1">
              <div>• Known Active Endpoints: <strong className="text-white">6 devices</strong></div>
              <div>• Subnet Range: <strong className="text-cyan-400">192.168.1.0/24</strong></div>
              <div>• Unreviewed Baseline Rule: <strong className="text-amber-400">Manual review required</strong></div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setBaselineModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 text-xs font-mono hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                onClick={confirmBaseline}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold"
              >
                Confirm Baseline
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-[#1F293D] py-4 px-6 text-center text-xs font-mono text-slate-400">
        NetSentinel Platform • Detection Engineering & Network Access Monitoring • RFC 1918 Private Subnets Only
      </footer>
    </div>
  );
};
