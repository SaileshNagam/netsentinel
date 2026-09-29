import React, { useState } from 'react';
import { ShieldAlert, Crosshair, Ban, Terminal, PlayCircle, CheckCircle2, XCircle } from 'lucide-react';
import { DefensiveAction } from '../types';
import { executeDefensiveAction } from '../lib/api';

interface DefensiveActionsTableProps {
  actions: DefensiveAction[];
  onActionProcessed: () => void;
}

export const DefensiveActionsTable: React.FC<DefensiveActionsTableProps> = ({ actions, onActionProcessed }) => {
  const [processing, setProcessing] = useState<number | null>(null);

  const handleDecision = async (id: number, decision: 'approve' | 'reject' | 'simulate') => {
    setProcessing(id);
    try {
      await executeDefensiveAction(id, decision, {
        operator: "SOC_OPERATOR (UI)",
        notes: `Action ${decision}d via Dashboard`
      });
      onActionProcessed();
    } catch (e) {
      console.error(e);
    } finally {
      setProcessing(null);
    }
  };

  if (!actions.length) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-slate-500 border border-[#1F293D] rounded-xl bg-[#0E1424]">
        <ShieldAlert className="w-12 h-12 mb-4 opacity-50" />
        <h3 className="text-lg font-mono mb-2">No Pending Defensive Actions</h3>
        <p className="text-sm font-mono max-w-md text-center">NetSentinel Agent has not recommended any mitigations requiring human review.</p>
      </div>
    );
  }

  return (
    <div className="border border-[#1F293D] rounded-xl bg-[#0E1424] overflow-hidden">
      <div className="p-4 bg-[#111726] border-b border-[#1F293D] flex justify-between items-center">
        <h3 className="font-mono font-bold text-slate-200">Defensive Response Queue</h3>
        <span className="px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 text-xs font-mono border border-amber-500/20">
          Human Approval Required
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-[#111726] border-b border-[#1F293D] text-xs font-mono uppercase tracking-wider text-slate-400">
              <th className="p-4 font-medium">Incident</th>
              <th className="p-4 font-medium">Action Type</th>
              <th className="p-4 font-medium">Target</th>
              <th className="p-4 font-medium">Agent Rationale</th>
              <th className="p-4 font-medium text-right">Decision Engine</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1F293D] text-sm">
            {actions.map((act) => (
              <tr 
                key={act.id}
                className={`transition-colors ${act.status === 'PENDING_APPROVAL' ? 'bg-[#151B2B]' : 'bg-[#0E1424] opacity-70'}`}
              >
                <td className="p-4 font-mono text-xs text-slate-300">
                  {act.incident_id}
                </td>
                
                <td className="p-4">
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-bold ${
                    act.action_type.includes('BLOCK') 
                      ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                      : 'bg-orange-500/10 text-orange-400 border border-orange-500/20'
                  }`}>
                    {act.action_type.includes('BLOCK') ? <Ban className="w-3.5 h-3.5" /> : <Crosshair className="w-3.5 h-3.5" />}
                    {act.action_type}
                  </span>
                </td>
                
                <td className="p-4 font-mono text-slate-200 font-bold">
                  {act.target}
                </td>
                
                <td className="p-4 text-xs font-mono text-slate-400 max-w-xs truncate" title={act.reason}>
                  {act.reason}
                </td>
                
                <td className="p-4 text-right">
                  {act.status === 'PENDING_APPROVAL' ? (
                    <div className="flex justify-end gap-2">
                      <button
                        disabled={processing === act.id}
                        onClick={() => handleDecision(act.id, 'simulate')}
                        className="px-3 py-1.5 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-400 border border-indigo-500/30 text-xs font-mono font-bold flex items-center gap-1 transition-colors"
                      >
                        <PlayCircle className="w-3.5 h-3.5" /> SIMULATE
                      </button>
                      <button
                        disabled={processing === act.id}
                        onClick={() => handleDecision(act.id, 'reject')}
                        className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-600 text-xs font-mono font-bold transition-colors"
                      >
                        REJECT
                      </button>
                      <button
                        disabled={processing === act.id}
                        onClick={() => handleDecision(act.id, 'approve')}
                        className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-mono font-bold flex items-center gap-1 transition-colors"
                      >
                        <Terminal className="w-3.5 h-3.5" /> EXECUTE
                      </button>
                    </div>
                  ) : (
                    <div className="flex justify-end">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-mono ${
                        act.status === 'EXECUTED' ? 'text-red-400' :
                        act.status === 'SIMULATED' ? 'text-indigo-400' : 'text-slate-500'
                      }`}>
                        {act.status === 'EXECUTED' && <CheckCircle2 className="w-3.5 h-3.5" />}
                        {act.status === 'SIMULATED' && <PlayCircle className="w-3.5 h-3.5" />}
                        {act.status === 'REJECTED' && <XCircle className="w-3.5 h-3.5" />}
                        {act.status}
                      </span>
                    </div>
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
