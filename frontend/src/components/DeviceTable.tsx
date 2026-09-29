import React, { useState } from 'react';
import { 
  Laptop, Smartphone, Tv, Router as RouterIcon, Cpu, HardDrive, 
  HelpCircle, ShieldCheck, ShieldAlert, ShieldX, Search, Filter, 
  ExternalLink, Eye, AlertCircle, ShieldQuestion 
} from 'lucide-react';
import { Device, TrustStatus } from '../types';

interface DeviceTableProps {
  devices: Device[];
  onSelectDevice: (device: Device) => void;
  onClassify: (deviceId: string, status: TrustStatus) => void;
}

export const DeviceTable: React.FC<DeviceTableProps> = ({ devices, onSelectDevice, onClassify }) => {
  const [filter, setFilter] = useState<string>('ALL');
  const [search, setSearch] = useState<string>('');

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'LAPTOP':
      case 'WORKSTATION':
        return <Laptop className="w-4 h-4 text-cyan-400" />;
      case 'MOBILE':
        return <Smartphone className="w-4 h-4 text-purple-400" />;
      case 'SMART_TV':
        return <Tv className="w-4 h-4 text-emerald-400" />;
      case 'ROUTER':
        return <RouterIcon className="w-4 h-4 text-amber-400" />;
      case 'NAS_STORAGE':
        return <HardDrive className="w-4 h-4 text-blue-400" />;
      case 'IOT_DEVICE':
        return <Cpu className="w-4 h-4 text-rose-400" />;
      default:
        return <HelpCircle className="w-4 h-4 text-slate-400" />;
    }
  };

  const getStatusBadge = (status: TrustStatus) => {
    switch (status) {
      case 'TRUSTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3 h-3" />
            TRUSTED
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <ShieldAlert className="w-3 h-3" />
            SUSPICIOUS
          </span>
        );
      case 'BLOCKLISTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-red-500/10 text-red-400 border border-red-500/30">
            <ShieldX className="w-3 h-3" />
            BLOCKED
          </span>
        );
      case 'GUEST':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/30">
            GUEST
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
            <ShieldQuestion className="w-3 h-3" />
            UNKNOWN
          </span>
        );
    }
  };

  const getRiskMeter = (score: number) => {
    const color = score >= 60 ? 'bg-red-500 text-red-400' : score >= 30 ? 'bg-amber-400 text-amber-400' : 'bg-emerald-400 text-emerald-400';
    return (
      <div className="flex items-center space-x-2">
        <div className="w-14 bg-slate-800 h-1.5 rounded-full overflow-hidden border border-slate-700/60">
          <div className={`h-full ${color.split(' ')[0]}`} style={{ width: `${Math.max(6, score)}%` }} />
        </div>
        <span className={`text-xs font-mono font-bold ${color.split(' ')[1]}`}>{score}</span>
      </div>
    );
  };

  const filteredDevices = devices.filter(dev => {
    const matchesFilter = 
      filter === 'ALL' ||
      (filter === 'TRUSTED' && dev.trust_status === 'TRUSTED') ||
      (filter === 'UNKNOWN' && dev.trust_status === 'UNKNOWN') ||
      (filter === 'SUSPICIOUS' && dev.trust_status === 'SUSPICIOUS') ||
      (filter === 'BLOCKLISTED' && dev.trust_status === 'BLOCKLISTED') ||
      (filter === 'HIGH_RISK' && dev.risk_score >= 60);

    const term = search.toLowerCase();
    const matchesSearch = 
      !search ||
      dev.current_ip.toLowerCase().includes(term) ||
      (dev.current_mac && dev.current_mac.toLowerCase().includes(term)) ||
      (dev.hostname && dev.hostname.toLowerCase().includes(term)) ||
      (dev.mac_vendor && dev.mac_vendor.toLowerCase().includes(term)) ||
      (dev.user_label && dev.user_label.toLowerCase().includes(term)) ||
      dev.id.toLowerCase().includes(term);

    return matchesFilter && matchesSearch;
  });

  return (
    <div className="rounded-xl bg-[#111726] border border-[#1F293D] overflow-hidden shadow-xl">
      {/* Controls & Filter Tabs */}
      <div className="p-4 border-b border-[#1F293D] flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, MAC, Hostname, Vendor, or ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 bg-[#090D16] border border-[#1F293D] rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
          />
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          {['ALL', 'TRUSTED', 'UNKNOWN', 'SUSPICIOUS', 'HIGH_RISK'].map(tab => (
            <button
              key={tab}
              onClick={() => setFilter(tab)}
              className={`px-3 py-1 rounded-lg text-xs font-mono transition ${
                filter === tab
                  ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200 bg-[#090D16] border border-transparent'
              }`}
            >
              {tab.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[#1F293D] bg-[#090D16]/50 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              <th className="py-3 px-4">Device Identity</th>
              <th className="py-3 px-4">IP Address</th>
              <th className="py-3 px-4">MAC & Vendor</th>
              <th className="py-3 px-4">Services</th>
              <th className="py-3 px-4">Trust Status</th>
              <th className="py-3 px-4">Risk</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1F293D]/60 text-xs">
            {filteredDevices.map(device => {
              const hasAlert = device.risk_score >= 60 || device.trust_status === 'SUSPICIOUS';
              return (
                <tr
                  key={device.id}
                  className={`group hover:bg-[#162035]/50 transition-colors ${
                    hasAlert ? 'bg-red-500/[0.02]' : ''
                  }`}
                >
                  {/* Device Identity */}
                  <td className="py-3.5 px-4">
                    <div className="flex items-center space-x-3">
                      <div className="p-2 rounded-lg bg-[#090D16] border border-[#1F293D] group-hover:border-cyan-500/40 transition">
                        {getDeviceIcon(device.device_type)}
                      </div>
                      <div>
                        <div className="font-semibold text-slate-200 flex items-center gap-2">
                          <span>{device.user_label || device.hostname || 'Unidentified Device'}</span>
                          <span className="text-[10px] font-mono text-slate-400 bg-slate-800/80 px-1.5 py-0.2 rounded border border-slate-700/60">
                            {device.id}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5 mt-0.5">
                          <span>{device.hostname || 'No mDNS hostname'}</span>
                          {device.in_baseline && (
                            <span className="text-emerald-400 text-[10px]">● baseline</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </td>

                  {/* IP Address */}
                  <td className="py-3.5 px-4 font-mono text-slate-300">
                    <div className="flex items-center gap-1.5">
                      <span className={`inline-block w-1.5 h-1.5 rounded-full ${device.is_online ? 'bg-emerald-400' : 'bg-slate-500'}`} title={device.is_online ? 'Online' : 'Offline'}></span>
                      <span className={device.is_online ? 'text-slate-200' : 'text-slate-500 line-through'}>{device.current_ip}</span>
                      {!device.is_online && (
                        <span className="text-[10px] font-mono text-slate-500 bg-slate-800/60 px-1 rounded">OFFLINE</span>
                      )}
                    </div>
                  </td>

                  {/* MAC & Vendor */}
                  <td className="py-3.5 px-4">
                    <div className="font-mono text-slate-300">{device.current_mac || 'Unknown'}</div>
                    <div className="text-[11px] text-slate-400 flex items-center gap-1.5 mt-0.5">
                      <span className="truncate max-w-[140px]">{device.mac_vendor || 'Unknown OUI'}</span>
                      {device.is_mac_randomized && (
                        <span className="px-1.5 py-0.2 text-[9px] font-mono rounded bg-purple-500/20 text-purple-300 border border-purple-500/30" title="Locally Administered Address (U/L Bit Set)">
                          RANDOM MAC
                        </span>
                      )}
                    </div>
                  </td>

                  {/* Services */}
                  <td className="py-3.5 px-4">
                    <div className="flex flex-wrap gap-1 max-w-[160px]">
                      {device.services && device.services.length > 0 ? (
                        device.services.map(svc => (
                          <span
                            key={svc.id}
                            className={`px-1.5 py-0.5 text-[10px] font-mono rounded border ${
                              svc.is_unexpected
                                ? 'bg-red-500/20 text-red-300 border-red-500/40'
                                : 'bg-slate-800 text-slate-300 border-slate-700'
                            }`}
                            title={`${svc.service_name} (${svc.port}/${svc.protocol})`}
                          >
                            {svc.port} {svc.service_name}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-400 font-mono text-[11px]">None detected</span>
                      )}
                    </div>
                  </td>

                  {/* Trust Status */}
                  <td className="py-3.5 px-4">
                    {getStatusBadge(device.trust_status)}
                  </td>

                  {/* Risk Score */}
                  <td className="py-3.5 px-4">
                    {getRiskMeter(device.risk_score)}
                  </td>

                  {/* Actions */}
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={() => onSelectDevice(device)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-mono font-medium transition"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      Investigate
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
