import React from 'react';
import { Radio, Search, Fingerprint, Activity, AlertTriangle, ShieldAlert, FileText, CheckCircle2, ChevronRight } from 'lucide-react';

interface AgentStep {
  name: string;
  role: string;
  status: 'ACTIVE' | 'DONE' | 'MONITORING';
  action: string;
  result: string;
  evidence: string;
  confidence: 'CONFIRMED' | 'HIGH' | 'MEDIUM' | 'LOW';
  icon: any;
}

interface AgentActivityPipelineProps {
  activeDeviceName?: string;
}

export const AgentActivityPipeline: React.FC<AgentActivityPipelineProps> = ({ activeDeviceName = 'D-019 (192.168.1.27)' }) => {
  const agents: AgentStep[] = [
    {
      name: 'Discovery Agent',
      role: 'Layer 2/3 Reachability',
      status: 'DONE',
      action: 'Active ARP Sweep & Cache Ingestion',
      result: `Host observed at 192.168.1.27`,
      evidence: 'Kernel ARP entry present (da:a1:19:33:44:aa)',
      confidence: 'CONFIRMED',
      icon: Search
    },
    {
      name: 'Identity Agent',
      role: 'Asset Fingerprinting',
      status: 'DONE',
      action: 'OUI & MAC Randomization Check',
      result: 'LAA Random MAC • Hostname DESKTOP-X51',
      evidence: 'U/L bit=1 (Locally Administered) • NetBIOS response',
      confidence: 'HIGH',
      icon: Fingerprint
    },
    {
      name: 'Behavior Agent',
      role: 'Baseline Profiling',
      status: 'DONE',
      action: 'Historical Comparison against Baseline',
      result: 'Deviation: Active at 02:31 AM off-hours',
      evidence: 'Baseline active mask shows 0 at hour 2',
      confidence: 'HIGH',
      icon: Activity
    },
    {
      name: 'Risk Engine',
      role: 'Explainable Scoring',
      status: 'DONE',
      action: 'Additive Multi-Factor Assessment',
      result: 'Score 72 / 100 • HIGH SEVERITY',
      evidence: '+25 New Unknown, +20 Off-Hours, +20 SMB, +15 LAA MAC',
      confidence: 'CONFIRMED',
      icon: ShieldAlert
    },
    {
      name: 'Alert Agent',
      role: 'SOC Triage Dispatcher',
      status: 'ACTIVE',
      action: 'Cooldown check & Notification Dispatch',
      result: 'Alert ALT-2026-001 Dispatched',
      evidence: 'Deduplication SHA-256 hash unique',
      confidence: 'HIGH',
      icon: AlertTriangle
    }
  ];

  const getConfBadge = (conf: string) => {
    switch (conf) {
      case 'CONFIRMED': return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
      case 'HIGH': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
      default: return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
    }
  };

  return (
    <div className="mb-6 rounded-xl bg-[#111726] border border-[#1F293D] p-4">
      <div className="flex items-center justify-between mb-3 border-b border-[#1F293D] pb-2.5">
        <div className="flex items-center space-x-2">
          <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
          <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-slate-200">
            Autonomous Detection Agent Pipeline
          </h2>
        </div>
        <div className="text-xs font-mono text-slate-400">
          Target Under Analysis: <span className="text-cyan-300 font-semibold">{activeDeviceName}</span>
        </div>
      </div>

      {/* Pipeline Grid */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-2.5">
        {agents.map((agent, index) => {
          const Icon = agent.icon;
          return (
            <div
              key={index}
              className="relative p-3 rounded-lg bg-[#0B0F19] border border-[#1F293D] hover:border-slate-600 transition"
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center space-x-1.5">
                  <Icon className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-xs font-bold text-slate-200">{agent.name}</span>
                </div>
                <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border ${getConfBadge(agent.confidence)}`}>
                  {agent.confidence}
                </span>
              </div>

              <div className="text-[11px] text-slate-400 font-mono mb-1 truncate">
                {agent.action}
              </div>

              <div className="text-[11px] font-medium text-slate-200 mb-1.5 line-clamp-1">
                {agent.result}
              </div>

              <div className="text-[10px] text-slate-400 font-mono bg-slate-900/60 p-1.5 rounded border border-slate-800/80">
                <span className="text-slate-400 uppercase">EVID:</span> {agent.evidence}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
