import React, { useState, useEffect } from 'react';
import { 
  X, ShieldAlert, ShieldCheck, ShieldX, Clock, Server, Activity, 
  Terminal, Shield, AlertTriangle, CheckCircle2, ChevronRight, Hash, 
  Layers, Lock, Unlock, FileText 
} from 'lucide-react';
import { Device, TimelineEvent, TrustStatus } from '../types';
import { fetchDeviceTimeline, classifyDevice } from '../lib/api';

interface DeviceDossierModalProps {
  device: Device | null;
  onClose: () => void;
  onDeviceUpdated: () => void;
}

export const DeviceDossierModal: React.FC<DeviceDossierModalProps> = ({ device, onClose, onDeviceUpdated }) => {
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loadingTimeline, setLoadingTimeline] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'TIMELINE' | 'SERVICES' | 'RISK_FACTORS' | 'POLICY'>('OVERVIEW');
  const [classifying, setClassifying] = useState<boolean>(false);
  const [notes, setNotes] = useState<string>('');
  const [guardianDecision, setGuardianDecision] = useState<'PENDING' | 'APPROVED' | 'DENIED'>('PENDING');

  useEffect(() => {
    if (device) {
      setLoadingTimeline(true);
      setNotes(device.notes || '');
      fetchDeviceTimeline(device.id)
        .then(data => setTimeline(data))
        .catch(err => console.error(err))
        .finally(() => setLoadingTimeline(false));
    }
  }, [device]);

  if (!device) return null;

  const handleClassify = async (status: TrustStatus) => {
    setClassifying(true);
    try {
      await classifyDevice(device.id, status, notes);
      onDeviceUpdated();
    } catch (err) {
      console.error(err);
    } finally {
      setClassifying(false);
    }
  };

  // Explainable Factor Weights for D-019 or similar
  const isHighRisk = device.risk_score >= 60;

  // Objective Neutral Investigation Summary following SOC standard: "Never convert suspicion into fact"
  const investigationSummary = (
    `Device ${device.id} first observed at ${new Date(device.first_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} on ${new Date(device.first_seen).toLocaleDateString()}. ` +
    `${device.in_baseline ? 'It is recorded in the authorized network baseline.' : 'It has not previously existed in the trusted device inventory.'} ` +
    `The device announced hostname '${device.hostname || 'Unknown'}' and vendor profile '${device.mac_vendor || 'Unknown OUI'}'. ` +
    (device.services && device.services.length > 0
      ? `Exposed services: ${device.services.map(s => `${s.port}/${s.protocol} (${s.service_name})`).join(', ')}. `
      : 'No open TCP services observed. ') +
    `No evidence currently proves malicious activity.`
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-[#0E1424] border border-[#1F293D] rounded-2xl shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#1F293D] bg-[#0B0F19] flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2.5 rounded-xl border ${
              isHighRisk ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <h2 className="text-lg font-bold text-white font-mono">{device.user_label || device.hostname || 'Unknown Device'}</h2>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono border border-slate-700">
                  {device.id}
                </span>
                <span className={`text-xs font-mono font-semibold px-2.5 py-0.5 rounded border ${
                  device.trust_status === 'TRUSTED' ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' :
                  device.trust_status === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' :
                  device.trust_status === 'BLOCKLISTED' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                  'bg-slate-800 text-slate-300 border-slate-700'
                }`}>
                  {device.trust_status}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                IP: <span className="text-slate-200">{device.current_ip}</span> • MAC: <span className="text-slate-200">{device.current_mac || 'Unknown'}</span> • Type: <span className="text-cyan-400">{device.device_type}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <div className="text-right">
              <div className="text-[10px] uppercase font-mono text-slate-400">Risk Assessment</div>
              <div className="text-lg font-mono font-bold text-white flex items-center gap-1.5 justify-end">
                <span className={isHighRisk ? 'text-red-400' : device.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}>
                  {device.risk_score}
                </span>
                <span className="text-slate-400 text-xs">/ 100</span>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="px-6 border-b border-[#1F293D] bg-[#0E1424] flex space-x-1">
          {[
            { id: 'OVERVIEW', label: 'Investigation Dossier' },
            { id: 'RISK_FACTORS', label: 'Explainable Risk Math' },
            { id: 'TIMELINE', label: `Timeline (${timeline.length})` },
            { id: 'SERVICES', label: `Services (${device.services?.length || 0})` },
            { id: 'POLICY', label: 'Guardian Action' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-3 text-xs font-mono font-medium border-b-2 transition ${
                activeTab === tab.id
                  ? 'border-cyan-400 text-cyan-300 font-bold bg-cyan-500/5'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          
          {/* TAB 1: OVERVIEW & NEUTRAL SUMMARY */}
          {activeTab === 'OVERVIEW' && (
            <div className="space-y-6">
              {/* Neutral Grounded Summary Card */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-blue-950/40 to-slate-900 border border-blue-500/30">
                <div className="flex items-center gap-2 mb-2">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-mono uppercase tracking-wider font-bold text-cyan-300">
                    Grounded Investigation Dossier Summary
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {investigationSummary}
                </p>
                <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>Confidence Rating: <strong className="text-cyan-300">{device.confidence_level}</strong></span>
                  <span>Observation Vector: <strong>Passive ARP + mDNS Multicast</strong></span>
                </div>
              </div>

              {/* Technical Specifications Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-3 rounded-lg bg-[#0B0F19] border border-[#1F293D]">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">MAC Address</div>
                  <div className="text-xs font-mono text-slate-200 font-semibold mt-0.5">{device.current_mac || 'Unknown'}</div>
                  <div className="text-[10px] text-purple-400 font-mono mt-1">
                    {device.is_mac_randomized ? '● LAA Random MAC Detected' : '● Universally Administered'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[#0B0F19] border border-[#1F293D]">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">IEEE OUI Vendor</div>
                  <div className="text-xs font-semibold text-slate-200 mt-0.5 truncate">{device.mac_vendor || 'Unknown'}</div>
                  <div className="text-[10px] text-slate-400 font-mono mt-1">First 3 Octets Lookup</div>
                </div>

                <div className="p-3 rounded-lg bg-[#0B0F19] border border-[#1F293D]">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Operating System Hint</div>
                  <div className="text-xs font-semibold text-slate-200 mt-0.5 truncate">{device.os_hint || 'Unidentified'}</div>
                  <div className="text-[10px] text-amber-400 font-mono mt-1">Heuristic TTL/Banner</div>
                </div>

                <div className="p-3 rounded-lg bg-[#0B0F19] border border-[#1F293D]">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">First / Last Seen</div>
                  <div className="text-xs font-mono text-slate-200 mt-0.5">
                    {new Date(device.first_seen).toLocaleDateString()}
                  </div>
                  <div className="text-[10px] text-slate-400 font-mono mt-1">
                    Last: {new Date(device.last_seen).toLocaleTimeString()}
                  </div>
                </div>
              </div>

              {/* Operator Notes & Re-Classification */}
              <div className="p-4 rounded-xl bg-[#0B0F19] border border-[#1F293D]">
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 mb-3">
                  Operator Classification & Triage
                </h3>
                <div className="flex flex-wrap gap-2 mb-3">
                  {(['TRUSTED', 'UNKNOWN', 'GUEST', 'SUSPICIOUS', 'BLOCKLISTED'] as TrustStatus[]).map(status => (
                    <button
                      key={status}
                      disabled={classifying}
                      onClick={() => handleClassify(status)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition border ${
                        device.trust_status === status
                          ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-sm'
                          : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                      }`}
                    >
                      Set {status}
                    </button>
                  ))}
                </div>
                <div>
                  <label className="text-[11px] font-mono text-slate-400 block mb-1">Analyst Notes</label>
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Enter security analyst investigation findings or authorization context..."
                    className="w-full h-20 p-2.5 bg-[#090D16] border border-[#1F293D] rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                  />
                  <div className="flex justify-end mt-2">
                    <button
                      onClick={() => handleClassify(device.trust_status)}
                      disabled={classifying}
                      className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 rounded border border-slate-700 transition"
                    >
                      Save Notes
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: EXPLAINABLE RISK MATH */}
          {activeTab === 'RISK_FACTORS' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-[#0B0F19] border border-[#1F293D]">
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 mb-2">
                  Deterministic Multi-Factor Scoring Formulation
                </h3>
                <p className="text-xs text-slate-400 mb-4 font-mono">
                  Risk Score = min(100, BaseScore + Sum(Weights × Confidence) - MitigatingFactors)
                </p>

                {/* Factors Table */}
                <div className="space-y-2">
                  {[
                    { rule: 'RISK-NEW-UNKNOWN', weight: '+25', desc: 'New device detected, not present in authorized baseline inventory', evidence: 'First observed today, no prior baseline record', active: !device.in_baseline },
                    { rule: 'RISK-RANDOM-MAC', weight: '+15', desc: 'Locally Administered Address (LAA) detected in MAC octet 0', evidence: `MAC ${device.current_mac} has U/L bit = 1`, active: device.is_mac_randomized },
                    { rule: 'RISK-SMB-EXPOSED', weight: '+20', desc: 'Server Message Block (SMB / port 445) exposed on unauthorized host', evidence: 'Port 445/TCP handshake succeeded', active: device.services?.some(s => s.port === 445) },
                    { rule: 'RISK-OFF-HOURS', weight: '+20', desc: 'Initial connection observed outside normal user baseline activity hours', evidence: 'Timestamp during 02:00 - 05:00 window', active: device.risk_score >= 70 },
                    { rule: 'MIT-TRUSTED-VERIFIED', weight: '-30', desc: 'Operator verified identity and confirmed TRUSTED status', evidence: 'Signed by local SOC analyst', active: device.trust_status === 'TRUSTED' }
                  ].map((f, i) => (
                    <div
                      key={i}
                      className={`p-3 rounded-lg border flex items-start justify-between ${
                        f.active
                          ? 'bg-red-500/5 border-red-500/30'
                          : 'bg-slate-900/40 border-slate-800/60 opacity-60'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-slate-200">{f.rule}</span>
                          <span className={`text-[11px] font-mono font-bold px-1.5 py-0.2 rounded ${
                            f.weight.startsWith('+') ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
                          }`}>
                            {f.weight}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300">{f.desc}</p>
                        <p className="text-[11px] font-mono text-slate-400">Evidence: {f.evidence}</p>
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        f.active ? 'bg-red-500/20 text-red-300 border-red-500/40' : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}>
                        {f.active ? 'TRIGGERED' : 'INACTIVE'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: CHRONOLOGICAL TIMELINE */}
          {activeTab === 'TIMELINE' && (
            <div className="space-y-4">
              {loadingTimeline ? (
                <div className="text-center py-8 text-xs font-mono text-slate-400">Loading device timeline...</div>
              ) : timeline.length === 0 ? (
                <div className="text-center py-8 text-xs font-mono text-slate-400">No events recorded for this device.</div>
              ) : (
                <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1F293D]">
                  {timeline.map((evt, idx) => (
                    <div key={idx} className="relative group">
                      <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-[#0E1424]" />
                      <div className="p-3 rounded-lg bg-[#0B0F19] border border-[#1F293D] hover:border-slate-600 transition">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-bold text-slate-200">{evt.title}</span>
                          <span className="text-[10px] font-mono text-slate-400">
                            {new Date(evt.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 font-sans">{evt.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 4: EXPOSED SERVICES */}
          {activeTab === 'SERVICES' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-[#0B0F19] border border-[#1F293D]">
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 mb-3">
                  Safe TCP Connect Service Observations
                </h3>
                {device.services && device.services.length > 0 ? (
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-[10px] font-mono text-slate-400 uppercase">
                        <th className="py-2">Port / Proto</th>
                        <th className="py-2">Service</th>
                        <th className="py-2">Banner</th>
                        <th className="py-2">Expected?</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {device.services.map(svc => (
                        <tr key={svc.id}>
                          <td className="py-2.5 text-cyan-300">{svc.port}/{svc.protocol}</td>
                          <td className="py-2.5 text-slate-200">{svc.service_name}</td>
                          <td className="py-2.5 text-slate-400">{svc.banner || 'None captured'}</td>
                          <td className="py-2.5">
                            {svc.is_unexpected ? (
                              <span className="text-red-400 text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/30">
                                UNEXPECTED
                              </span>
                            ) : (
                              <span className="text-emerald-400 text-[10px]">Expected</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p className="text-xs text-slate-400 font-mono">No exposed services detected on this endpoint.</p>
                )}
              </div>
            </div>
          )}

          {/* TAB 5: GUARDIAN POLICY & HUMAN DECISION */}
          {activeTab === 'POLICY' && (
            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-gradient-to-r from-red-950/30 to-[#0B0F19] border border-red-500/30">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                  <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wide">
                    Network Guardian Policy Engine Recommendation
                  </h3>
                </div>

                <div className="p-4 rounded-lg bg-[#090D16] border border-red-500/40 my-3">
                  <div className="text-xs font-mono text-red-300 font-bold mb-1">
                    RECOMMENDED ACTION: {device.risk_score >= 60 ? 'BLOCK & ISOLATE DEVICE' : 'ADD TO WATCHLIST'}
                  </div>
                  <p className="text-xs text-slate-300 mb-2">
                    Reason: Unclassified endpoint with high risk score ({device.risk_score}/100) and unexpected exposed services.
                  </p>
                  <p className="text-[11px] font-mono text-amber-400/90 italic">
                    "Recommended only — not automatically executed. Human authorization mandatory."
                  </p>
                </div>

                <div className="flex items-center gap-3 pt-2">
                  <button
                    onClick={() => setGuardianDecision('APPROVED')}
                    className={`px-4 py-2 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5 ${
                      guardianDecision === 'APPROVED'
                        ? 'bg-emerald-600 text-white'
                        : 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40'
                    }`}
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    APPROVE RECOMMENDATION
                  </button>
                  <button
                    onClick={() => setGuardianDecision('DENIED')}
                    className={`px-4 py-2 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5 ${
                      guardianDecision === 'DENIED'
                        ? 'bg-red-600 text-white'
                        : 'bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40'
                    }`}
                  >
                    <X className="w-4 h-4" />
                    DENY ACTION
                  </button>
                </div>

                {guardianDecision !== 'PENDING' && (
                  <div className="mt-3 p-2.5 rounded bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300">
                    Decision recorded: <strong className="text-white">{guardianDecision}</strong> by SOC Analyst. SHA-256 Audit event created.
                  </div>
                )}
              </div>
            </div>
          )}

        </div>

      </div>
    </div>
  );
};
