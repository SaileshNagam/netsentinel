import React from 'react';
import { Wifi, ShieldCheck, HelpCircle, AlertOctagon, Server, BellRing } from 'lucide-react';
import { SecurityPostureStats } from '../types';

interface SecurityPostureCardsProps {
  stats: SecurityPostureStats | null;
  onFilterStatus?: (status: string) => void;
}

export const SecurityPostureCards: React.FC<SecurityPostureCardsProps> = ({ stats, onFilterStatus }) => {
  if (!stats) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5 mb-6">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-24 rounded-xl bg-[#111726]/60 border border-[#1F293D] animate-pulse" />
        ))}
      </div>
    );
  }

  const cards = [
    {
      label: 'CONNECTED',
      value: stats.total_connected,
      subtext: `${stats.devices_seen_today} seen past 24h`,
      icon: Wifi,
      color: 'text-cyan-400',
      border: 'border-cyan-500/30',
      bg: 'bg-cyan-500/5',
      filter: 'ALL'
    },
    {
      label: 'TRUSTED',
      value: stats.trusted_devices,
      subtext: `${stats.baseline_device_count} in baseline`,
      icon: ShieldCheck,
      color: 'text-emerald-400',
      border: 'border-emerald-500/30',
      bg: 'bg-emerald-500/5',
      filter: 'TRUSTED'
    },
    {
      label: 'UNKNOWN',
      value: stats.unknown_devices,
      subtext: 'Unclassified endpoints',
      icon: HelpCircle,
      color: stats.unknown_devices > 0 ? 'text-amber-400' : 'text-slate-400',
      border: stats.unknown_devices > 0 ? 'border-amber-500/40 glow-amber' : 'border-[#1F293D]',
      bg: 'bg-amber-500/5',
      filter: 'UNKNOWN'
    },
    {
      label: 'HIGH RISK',
      value: stats.high_risk_devices,
      subtext: `${stats.suspicious_devices} flagged suspicious`,
      icon: AlertOctagon,
      color: stats.high_risk_devices > 0 ? 'text-red-400' : 'text-slate-400',
      border: stats.high_risk_devices > 0 ? 'border-red-500/50 glow-crimson' : 'border-[#1F293D]',
      bg: stats.high_risk_devices > 0 ? 'bg-red-500/10' : 'bg-red-500/5',
      filter: 'HIGH_RISK',
      alertPulse: stats.high_risk_devices > 0
    },
    {
      label: 'OPEN SERVICES',
      value: stats.open_services_total,
      subtext: 'Exposed TCP/UDP ports',
      icon: Server,
      color: 'text-blue-400',
      border: 'border-blue-500/30',
      bg: 'bg-blue-500/5',
      filter: 'ALL'
    },
    {
      label: 'ACTIVE ALERTS',
      value: stats.active_alerts_count,
      subtext: stats.active_alerts_count > 0 ? 'Immediate review needed' : 'Zero active threats',
      icon: BellRing,
      color: stats.active_alerts_count > 0 ? 'text-rose-400' : 'text-slate-400',
      border: stats.active_alerts_count > 0 ? 'border-rose-500/40' : 'border-[#1F293D]',
      bg: 'bg-rose-500/5',
      filter: 'ALERTS'
    }
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5 mb-6">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            onClick={() => onFilterStatus && onFilterStatus(card.filter)}
            className={`cursor-pointer group relative p-4 rounded-xl bg-[#111726] border transition-all duration-300 hover:scale-[1.02] hover:bg-[#151E32] ${card.border} ${card.bg}`}
          >
            {card.alertPulse && (
              <span className="absolute top-2 right-2 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500"></span>
              </span>
            )}
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                {card.label}
              </span>
              <Icon className={`w-4 h-4 ${card.color}`} />
            </div>
            <div className="flex items-baseline space-x-2">
              <span className="text-2xl font-bold font-mono tracking-tight text-white">
                {card.value}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 mt-1 truncate">
              {card.subtext}
            </div>
          </div>
        );
      })}
    </div>
  );
};
