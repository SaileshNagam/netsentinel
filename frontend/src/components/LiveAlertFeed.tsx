import React from 'react';
import { AlertTriangle, ShieldAlert, CheckCircle, Eye, Clock } from 'lucide-react';
import { AlertItem } from '../types';
import { updateAlertStatus } from '../lib/api';

interface LiveAlertFeedProps {
  alerts: AlertItem[];
  onSelectDeviceId: (deviceId: string) => void;
  onRefreshAlerts: () => void;
}

export const LiveAlertFeed: React.FC<LiveAlertFeedProps> = ({ alerts, onSelectDeviceId, onRefreshAlerts }) => {
  const activeAlerts = alerts.filter(a => a.status === 'ACTIVE');

  const handleAcknowledge = async (id: string) => {
    try {
      await updateAlertStatus(id, 'ACKNOWLEDGED');
      onRefreshAlerts();
    } catch (err) {
      console.error(err);
    }
  };

  if (activeAlerts.length === 0) {
    return null;
  }

  return (
    <div className="mb-6 rounded-xl bg-gradient-to-r from-red-950/40 via-[#111726] to-[#111726] border border-red-500/30 p-4 shadow-lg">
      <div className="flex items-center justify-between mb-3 border-b border-red-500/20 pb-2.5">
        <div className="flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-red-400 animate-pulse" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-red-300">
            Active Security Alerts Requiring Attention ({activeAlerts.length})
          </h3>
        </div>
        <span className="text-[11px] font-mono text-slate-400">
          Deduplicated & Rate-Limited
        </span>
      </div>

      <div className="space-y-2.5">
        {activeAlerts.map(alert => (
          <div
            key={alert.id}
            className="p-3 rounded-lg bg-[#0B0F19] border border-red-500/30 flex flex-col md:flex-row md:items-center md:justify-between gap-3"
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-white font-mono">{alert.title}</span>
                <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-red-500/20 text-red-400 border border-red-500/30 font-bold">
                  {alert.severity}
                </span>
                <span className="text-[10px] font-mono text-slate-400">
                  Rule: {alert.rule_id}
                </span>
              </div>
              <p className="text-xs text-slate-300 font-sans">{alert.description}</p>
              <div className="text-[10px] font-mono text-slate-400 flex items-center gap-2">
                <Clock className="w-3 h-3 text-slate-500" />
                <span>Detected: {new Date(alert.created_at).toLocaleTimeString()}</span>
                <span>•</span>
                <span>Target: <strong className="text-cyan-400">{alert.device_id || 'Unknown Host'}</strong></span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {alert.device_id && (
                <button
                  onClick={() => onSelectDeviceId(alert.device_id!)}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono transition flex items-center gap-1.5"
                >
                  <Eye className="w-3.5 h-3.5" />
                  Investigate
                </button>
              )}
              <button
                onClick={() => handleAcknowledge(alert.id)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-mono transition flex items-center gap-1.5"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Acknowledge
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
