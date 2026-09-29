import React, { useState } from 'react';
import { Globe, Router as RouterIcon, Laptop, Smartphone, Tv, Cpu, HardDrive, HelpCircle, ShieldAlert, Radio } from 'lucide-react';
import { Device } from '../types';

interface NetworkTopologyViewProps {
  devices: Device[];
  onSelectDevice: (device: Device) => void;
}

export const NetworkTopologyView: React.FC<NetworkTopologyViewProps> = ({ devices, onSelectDevice }) => {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  // Find Router / Gateway
  const routerDevice = devices.find(d => d.device_type === 'ROUTER' || d.current_ip.endsWith('.1')) || {
    id: 'GATEWAY-01',
    user_label: 'Gateway Router',
    current_ip: '192.168.1.1',
    trust_status: 'TRUSTED',
    risk_score: 0,
    device_type: 'ROUTER',
    is_online: true
  } as Device;

  // Client devices (excluding router)
  const clientDevices = devices.filter(d => d.id !== routerDevice.id);

  const getNodeColor = (device: Device) => {
    if (!device.is_online) return { border: 'border-slate-700', bg: 'bg-slate-900', ring: 'ring-slate-800', text: 'text-slate-500' };
    if (device.risk_score >= 60) return { border: 'border-red-500', bg: 'bg-red-500/20', ring: 'ring-red-500/40 glow-crimson', text: 'text-red-400' };
    if (device.trust_status === 'SUSPICIOUS' || device.risk_score >= 30) return { border: 'border-amber-500', bg: 'bg-amber-500/20', ring: 'ring-amber-500/40 glow-amber', text: 'text-amber-400' };
    if (device.trust_status === 'TRUSTED') return { border: 'border-emerald-500', bg: 'bg-emerald-500/20', ring: 'ring-emerald-500/40 glow-emerald', text: 'text-emerald-400' };
    return { border: 'border-slate-500', bg: 'bg-slate-800', ring: 'ring-slate-600', text: 'text-slate-300' };
  };

  const getIcon = (type: string) => {
    switch (type) {
      case 'LAPTOP':
      case 'WORKSTATION':
        return <Laptop className="w-5 h-5" />;
      case 'MOBILE':
        return <Smartphone className="w-5 h-5" />;
      case 'SMART_TV':
        return <Tv className="w-5 h-5" />;
      case 'NAS_STORAGE':
        return <HardDrive className="w-5 h-5" />;
      case 'IOT_DEVICE':
        return <Cpu className="w-5 h-5" />;
      default:
        return <HelpCircle className="w-5 h-5" />;
    }
  };

  return (
    <div className="rounded-xl bg-[#111726] border border-[#1F293D] p-6 shadow-xl relative overflow-hidden">
      {/* Header & Legend */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between pb-6 border-b border-[#1F293D] gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-mono font-bold tracking-wide uppercase text-white">
              Interactive Layer 2/3 Network Topology Map
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            Click any node to view device identity, risk factors, and investigation timeline
          </p>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400"></span>
            <span className="text-slate-300">Trusted</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-400"></span>
            <span className="text-slate-300">Unknown</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
            <span className="text-slate-300">Suspicious</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-400"></span>
            <span className="text-slate-300">High Risk</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-slate-700"></span>
            <span className="text-slate-300">Offline</span>
          </div>
        </div>
      </div>

      {/* SVG Canvas Topology */}
      <div className="py-8 flex flex-col items-center justify-center min-h-[380px] select-none">
        
        {/* Tier 1: Internet WAN */}
        <div className="flex flex-col items-center">
          <div className="w-12 h-12 rounded-2xl bg-blue-500/10 border border-blue-500/40 text-blue-400 flex items-center justify-center shadow-lg shadow-blue-500/10">
            <Globe className="w-6 h-6" />
          </div>
          <span className="text-[10px] font-mono font-bold text-slate-400 mt-1 uppercase tracking-wider">WAN Internet</span>
        </div>

        {/* Vertical Link 1 */}
        <div className="w-0.5 h-8 bg-gradient-to-b from-blue-500 to-cyan-500"></div>

        {/* Tier 2: Gateway / Router Node */}
        <div
          onClick={() => onSelectDevice(routerDevice)}
          className="group cursor-pointer flex flex-col items-center transition-transform hover:scale-105"
        >
          <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border-2 border-cyan-400 text-cyan-300 flex items-center justify-center ring-4 ring-cyan-500/20 shadow-xl glow-cyan">
            <RouterIcon className="w-7 h-7" />
          </div>
          <span className="text-xs font-mono font-bold text-white mt-1.5">{routerDevice.user_label || 'Default Gateway'}</span>
          <span className="text-[10px] font-mono text-cyan-400">{routerDevice.current_ip}</span>
        </div>

        {/* Vertical Link 2 */}
        <div className="w-0.5 h-8 bg-cyan-500/60"></div>

        {/* Horizontal Bus Spine */}
        <div className="relative w-full max-w-2xl flex items-center justify-center">
          <div className="absolute top-0 w-5/6 h-0.5 bg-slate-700"></div>
        </div>

        {/* Tier 3: Connected Subnet Clients */}
        <div className="w-full max-w-3xl pt-6 flex flex-wrap items-start justify-center gap-6 md:gap-8">
          {clientDevices.map(client => {
            const colors = getNodeColor(client);
            const isTarget = client.risk_score >= 60;
            return (
              <div
                key={client.id}
                onClick={() => onSelectDevice(client)}
                onMouseEnter={() => setHoveredNode(client.id)}
                onMouseLeave={() => setHoveredNode(null)}
                className="group cursor-pointer flex flex-col items-center transition-all duration-300 hover:scale-110"
              >
                {/* Connecting branch stub */}
                <div className="w-0.5 h-4 bg-slate-700 -mt-6 mb-2"></div>

                {/* Node Box */}
                <div className={`relative w-12 h-12 rounded-2xl border-2 flex items-center justify-center shadow-lg ring-2 transition-all ${colors.border} ${colors.bg} ${colors.ring} ${colors.text}`}>
                  {isTarget && (
                    <span className="absolute -top-1 -right-1 flex h-3 w-3">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
                    </span>
                  )}
                  {getIcon(client.device_type)}
                </div>

                {/* Node Label */}
                <div className="text-center mt-1.5 max-w-[100px]">
                  <div className="text-[11px] font-bold text-slate-200 truncate group-hover:text-cyan-300">
                    {client.user_label || client.hostname || client.id}
                  </div>
                  <div className="text-[10px] font-mono text-slate-400 truncate">
                    {client.current_ip}
                  </div>
                  <div className={`text-[9px] font-mono font-bold mt-0.5 ${colors.text}`}>
                    Risk: {client.risk_score}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

      </div>
    </div>
  );
};
