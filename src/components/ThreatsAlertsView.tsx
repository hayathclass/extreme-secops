import React, { useState } from 'react';
import { ThreatDetection, Target } from '../types/security';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Trash2,
  Loader2,
} from 'lucide-react';

interface ThreatsAlertsViewProps {
  threats: ThreatDetection[];
  target: Target;
  onNavigateToRemediation: (threatId?: string) => void;
  onNavigateToIncident: (threatId: string) => void;
  onDeleteThreat?: (threatId: string) => void;
  onClearAllThreats?: () => void;
}

export const ThreatsAlertsView: React.FC<ThreatsAlertsViewProps> = ({
  threats,
  target,
  onNavigateToRemediation,
  onNavigateToIncident,
  onDeleteThreat,
  onClearAllThreats,
}) => {
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmClearAll, setConfirmClearAll] = useState(false);

  const handleDelete = (threatId: string) => {
    if (!onDeleteThreat) return;
    setDeletingId(threatId);
    onDeleteThreat(threatId);
    setDeletingId(null);
  };

  const handleClearAll = () => {
    if (!onClearAllThreats) return;
    if (!confirmClearAll) {
      setConfirmClearAll(true);
      return;
    }
    onClearAllThreats();
    setConfirmClearAll(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-rose-400" />
              <h1 className="text-base font-bold text-slate-100">Threat Detection & Security Alerts</h1>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Correlated multi-event attack signatures, anomalous behavior patterns, and verified evidence.
            </p>
          </div>

          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
              Active Alerts: <span className="font-bold text-rose-400">{threats.length}</span>
            </span>

            {threats.length > 0 && onClearAllThreats && (
              <div className="flex items-center space-x-2">
                {confirmClearAll ? (
                  <div className="flex items-center space-x-1.5 animate-fade-in font-sans">
                    <button
                      type="button"
                      onClick={handleClearAll}
                      className="px-2.5 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold text-xs flex items-center space-x-1 transition shadow-sm"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Confirm Delete All</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmClearAll(false)}
                      className="px-2 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    type="button"
                    onClick={() => setConfirmClearAll(true)}
                    className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-rose-500/50 hover:bg-rose-950/20 text-slate-300 hover:text-rose-300 font-bold text-xs flex items-center space-x-1.5 transition font-sans"
                    title="Delete all previous threats and active alerts"
                  >
                    <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                    <span>Delete All Previous Threats</span>
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Threats List */}
      {threats.length === 0 ? (
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-12 text-center space-y-3 shadow-lg">
          <div className="w-12 h-12 rounded-full bg-emerald-950/40 border border-emerald-500/40 mx-auto flex items-center justify-center text-emerald-400">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <h2 className="text-base font-bold text-slate-200">No Active Security Alerts</h2>
          <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
            All previous threats have been resolved or deleted. Telemetry ingestion is nominal for{' '}
            <span className="font-mono text-cyan-300 font-semibold">{target.hostname}</span>.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {threats.map((threat) => {
            const isDeleting = deletingId === threat.id;
            return (
              <div
                key={threat.id}
                className="bg-[#0f172a] border border-slate-800 hover:border-slate-700 rounded-xl overflow-hidden shadow-xl transition"
              >
                {/* Alert Header */}
                <div
                  className={`p-4 border-b flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                    threat.severity === 'CRITICAL'
                      ? 'bg-rose-950/30 border-rose-500/30'
                      : threat.severity === 'HIGH'
                      ? 'bg-rose-950/20 border-rose-500/20'
                      : 'bg-amber-950/20 border-amber-500/20'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <span
                      className={`px-2.5 py-1 rounded text-[11px] font-extrabold font-mono uppercase tracking-wider border ${
                        threat.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/50'
                          : threat.severity === 'HIGH'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      }`}
                    >
                      {threat.severity} SEVERITY
                    </span>
                    <div>
                      <h2 className="text-sm font-bold text-slate-100">{threat.threatName}</h2>
                      <span className="text-[11px] text-slate-400 font-mono">Rule ID: {threat.ruleId}</span>
                    </div>
                  </div>

                  {/* Metadata and Single Delete Button */}
                  <div className="flex items-center space-x-4 text-xs font-mono text-slate-300">
                    <div>
                      <span className="text-slate-500 uppercase text-[10px] block">Confidence</span>
                      <span className="font-bold text-rose-400">{threat.confidence}%</span>
                    </div>
                    <div>
                      <span className="text-slate-500 uppercase text-[10px] block">Detected</span>
                      <span>{threat.displayTime}</span>
                    </div>
                    {onDeleteThreat && (
                      <button
                        type="button"
                        disabled={isDeleting}
                        onClick={() => handleDelete(threat.id)}
                        className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-rose-500 hover:bg-rose-950/40 text-slate-400 hover:text-rose-300 transition"
                        title="Delete this threat"
                      >
                        {isDeleting ? (
                          <Loader2 className="w-3.5 h-3.5 animate-spin text-rose-400" />
                        ) : (
                          <Trash2 className="w-3.5 h-3.5" />
                        )}
                      </button>
                    )}
                  </div>
                </div>

                {/* Alert Body */}
                <div className="p-5 space-y-4 text-xs">
                  {/* Target & Endpoint */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono">
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 font-bold block">TARGET</span>
                      <span className="text-slate-200">{target.hostname}</span>
                    </div>
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 font-bold block">AFFECTED ENDPOINT</span>
                      <span className="text-cyan-400 font-semibold">{threat.affectedEndpoint}</span>
                    </div>
                  </div>

                  {/* Explanation Sections */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* WHAT HAPPENED? */}
                    <div className="space-y-1.5 p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                        WHAT HAPPENED?
                      </span>
                      <p className="text-slate-300 leading-relaxed">{threat.whatHappened}</p>
                    </div>

                    {/* WHY WAS IT FLAGGED? */}
                    <div className="space-y-1.5 p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                        WHY WAS IT FLAGGED?
                      </span>
                      <p className="text-slate-300 leading-relaxed">{threat.whyFlagged}</p>
                    </div>
                  </div>

                  {/* EVIDENCE */}
                  <div className="space-y-2">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block">
                      EVIDENCE
                    </span>
                    <div className="space-y-1.5">
                      {threat.evidence.map((item, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 font-mono text-[11px] flex items-start space-x-2"
                        >
                          <span className="text-cyan-400 font-bold shrink-0">[{idx + 1}]</span>
                          <span className="break-all">{item}</span>
                        </div>
                      ))}
                    </div>

                    {/* Trigger Logs mini table */}
                    {threat.triggerLogs && threat.triggerLogs.length > 0 && (
                      <div className="pt-2">
                        <span className="text-[10px] uppercase font-mono text-slate-400 font-bold block mb-1">
                          CORRELATED LOG ENTRIES ({threat.triggerLogs.length})
                        </span>
                        <div className="rounded-lg bg-black/40 border border-slate-800 overflow-hidden font-mono text-[11px]">
                          {threat.triggerLogs.slice(0, 4).map((l) => (
                            <div
                              key={l.id}
                              className="p-2 border-b border-slate-800/60 last:border-0 flex items-center justify-between text-slate-300 hover:bg-slate-800/40"
                            >
                              <div className="flex items-center space-x-2 truncate">
                                <span className="text-slate-500">{l.displayTime}</span>
                                <span className="text-cyan-400 font-bold">{l.method}</span>
                                <span className="text-slate-200 truncate">{l.endpoint}</span>
                              </div>
                              <div className="flex items-center space-x-2 shrink-0">
                                <span
                                  className={`font-bold ${
                                    l.status >= 400 ? 'text-amber-400' : 'text-emerald-400'
                                  }`}
                                >
                                  {l.status}
                                </span>
                                <span className="text-slate-500 text-[10px]">{l.sourceIp}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Footer Action - only investigation and remediation */}
                  <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 font-sans">
                    <button
                      type="button"
                      onClick={() => onNavigateToIncident(threat.id)}
                      className="text-xs text-slate-400 hover:text-slate-200 flex items-center space-x-1 font-semibold"
                    >
                      <span>View Incident Investigation</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>

                    <button
                      type="button"
                      onClick={() => onNavigateToRemediation(threat.id)}
                      className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold flex items-center space-x-1.5 transition shadow-sm shadow-cyan-950"
                    >
                      <span>View Recommended Solution</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
