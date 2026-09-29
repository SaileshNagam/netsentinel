import React from 'react';
import { Shield, Radar, Wifi, RefreshCw, Database, AlertTriangle, ShieldCheck } from 'lucide-react';

interface NavbarProps {
  mode: 'LIVE' | 'DEMO';
  onToggleMode: (mode: 'LIVE' | 'DEMO') => void;
  networkRiskScore: number;
  onRefresh: () => void;
  isScanning: boolean;
  onTriggerScan: () => void;
  onTriggerBaseline: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  mode,
  onToggleMode,
  networkRiskScore,
  onRefresh,
  isScanning,
  onTriggerScan,
  onTriggerBaseline,
}) => {
  // Determine health color
  const getRiskBadge = (score: number) => {
    if (score >= 60) return { bg: 'bg-red-500/20 text-red-400 border-red-500/40', text: 'ELEVATED RISK' };
    if (score >= 30) return { bg: 'bg-amber-500/20 text-amber-400 border-amber-500/40', text: 'MODERATE RISK' };
    return { bg: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40', text: 'NOMINAL HEALTH' };
  };

  const riskInfo = getRiskBadge(networkRiskScore);

  return (
    <header className="sticky top-0 z-40 border-b border-[#1F293D] bg-[#0B0F19]/90 backdrop-blur-md px-6 py-3.5">
      <div className="flex items-center justify-between">
        {/* Brand & System Status */}
        <div className="flex items-center space-x-4">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-600 shadow-lg shadow-cyan-500/20 border border-cyan-400/30">
            <Shield className="w-5 h-5 text-white" />
            <span className="absolute -top-1 -right-1 flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
            </span>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold tracking-tight text-white font-mono">NET<span className="text-cyan-400">SENTINEL</span></h1>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono border border-slate-700">v1.0.0</span>
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-1.5">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              <span className="font-mono text-emerald-400">SYSTEM ARMED</span>
              <span className="text-slate-600">•</span>
              <span className="font-mono">RFC 1918 PRIVATE ONLY</span>
            </p>
          </div>
        </div>

        {/* Global Security Risk Gauge */}
        <div className="hidden md:flex items-center space-x-3 px-4 py-1.5 rounded-lg bg-[#111726] border border-[#1F293D]">
          <div className="text-right">
            <div className="text-[10px] uppercase font-mono tracking-wider text-slate-400">Network Threat Level</div>
            <div className="text-xs font-bold text-slate-200 flex items-center justify-end gap-1.5">
              <span>Risk:</span>
              <span className="font-mono text-white text-sm">{networkRiskScore}</span>
              <span className="text-slate-500">/ 100</span>
            </div>
          </div>
          <div className="w-20 bg-slate-800 h-2 rounded-full overflow-hidden border border-slate-700">
            <div
              className={`h-full transition-all duration-500 ${
                networkRiskScore >= 60 ? 'bg-red-500' : networkRiskScore >= 30 ? 'bg-amber-400' : 'bg-emerald-400'
              }`}
              style={{ width: `${Math.min(100, Math.max(5, networkRiskScore))}%` }}
            />
          </div>
          <span className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${riskInfo.bg}`}>
            {riskInfo.text}
          </span>
        </div>

        {/* Controls & Mode Toggles */}
        <div className="flex items-center space-x-3">
          {/* Mode Switcher */}
          <div className="flex rounded-lg bg-[#111726] p-1 border border-[#1F293D]">
            <button
              onClick={() => onToggleMode('LIVE')}
              className={`px-3 py-1 text-xs font-mono rounded-md transition-all flex items-center gap-1.5 ${
                mode === 'LIVE'
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Wifi className="w-3.5 h-3.5" />
              LIVE NETWORK
            </button>
            <button
              onClick={() => onToggleMode('DEMO')}
              className={`px-3 py-1 text-xs font-mono rounded-md transition-all flex items-center gap-1.5 ${
                mode === 'DEMO'
                  ? 'bg-purple-500/20 text-purple-300 font-bold border border-purple-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              DEMO LAB
            </button>
          </div>

          {/* Learn My Network Baseline Button */}
          <button
            onClick={onTriggerBaseline}
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono transition-all"
            title="Freeze current inventory as known network baseline"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            LEARN BASELINE
          </button>

          {/* Quick Scan Prober */}
          <button
            onClick={onTriggerScan}
            disabled={isScanning}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-semibold transition-all shadow-md shadow-cyan-600/20"
          >
            <Radar className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin' : ''}`} />
            {isScanning ? 'SCANNING...' : 'PROBE NETWORK'}
          </button>

          {/* Refresh Button */}
          <button
            onClick={onRefresh}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg bg-[#111726] border border-[#1F293D] hover:bg-slate-800 transition"
            title="Refresh SOC Dashboard"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
