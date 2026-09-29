import React from 'react';
import { Network, Server, ArrowRight, Activity, ShieldAlert, Cpu } from 'lucide-react';
import { ConnectionEvent } from '../types';

interface ConnectionsTableProps {
  connections: ConnectionEvent[];
}

export const ConnectionsTable: React.FC<ConnectionsTableProps> = ({ connections }) => {
  if (!connections.length) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-slate-500 border border-[#1F293D] rounded-xl bg-[#0E1424]">
        <Activity className="w-12 h-12 mb-4 opacity-50" />
        <h3 className="text-lg font-mono mb-2">No Active Connections</h3>
        <p className="text-sm font-mono max-w-md text-center">NetSentinel is currently not tracking any active host connections.</p>
      </div>
    );
  }

  return (
    <div className="border border-[#1F293D] rounded-xl bg-[#0E1424] overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-[#111726] border-b border-[#1F293D] text-xs font-mono uppercase tracking-wider text-slate-400">
              <th className="p-4 font-medium">Protocol</th>
              <th className="p-4 font-medium">Local</th>
              <th className="p-4 font-medium"></th>
              <th className="p-4 font-medium">Remote</th>
              <th className="p-4 font-medium">State</th>
              <th className="p-4 font-medium">Process</th>
              <th className="p-4 font-medium">Simulated</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1F293D] text-sm">
            {connections.map((conn, idx) => (
              <tr 
                key={idx}
                className="hover:bg-[#111726] transition-colors group"
              >
                <td className="p-4">
                  <div className="flex items-center gap-2">
                    {conn.protocol.includes('TCP') ? (
                      <Server className="w-4 h-4 text-cyan-400" />
                    ) : (
                      <Network className="w-4 h-4 text-amber-400" />
                    )}
                    <span className="font-mono text-slate-200">{conn.protocol}</span>
                  </div>
                </td>
                
                <td className="p-4 font-mono text-slate-300">
                  {conn.local_ip}:{conn.local_port}
                </td>
                
                <td className="p-4 text-slate-500">
                  <ArrowRight className="w-4 h-4" />
                </td>
                
                <td className="p-4 font-mono text-slate-300">
                  {conn.remote_ip}:{conn.remote_port}
                </td>
                
                <td className="p-4">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-mono ${
                    conn.state === 'ESTABLISHED' 
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}>
                    {conn.state || 'UNKNOWN'}
                  </span>
                </td>
                
                <td className="p-4">
                  <div className="flex flex-col">
                    <span className="font-mono text-slate-200 flex items-center gap-1">
                      <Cpu className="w-3.5 h-3.5 text-slate-500" />
                      {conn.process_name || 'System/Unknown'}
                    </span>
                    <span className="text-xs font-mono text-slate-500">PID: {conn.pid || 'N/A'}</span>
                  </div>
                </td>
                
                <td className="p-4">
                  {conn.simulation && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 text-[10px] font-mono border border-indigo-500/20 uppercase">
                      <ShieldAlert className="w-3 h-3" /> DEMO
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
