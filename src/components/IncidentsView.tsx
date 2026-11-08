import React, { useState } from 'react';
import { Incident } from '../types/security';
import {
  FolderGit2,
  Clock,
  CheckCircle,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

interface IncidentsViewProps {
  incidents: Incident[];
  onUpdateStatus: (incidentId: string, status: Incident['status']) => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  incidents,
  onUpdateStatus,
}) => {
  const [filter, setFilter] = useState<'ALL' | 'OPEN' | 'INVESTIGATING' | 'MITIGATED' | 'RESOLVED'>('ALL');
  const [expandedIncidentId, setExpandedIncidentId] = useState<string | null>(
    incidents[0]?.id || null
  );

  const filteredIncidents = incidents.filter((inc) => {
    if (filter === 'ALL') return true;
    return inc.status === filter;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center space-x-2">
              <FolderGit2 className="w-5 h-5 text-cyan-400" />
              <h1 className="text-base font-bold text-slate-100">Security Incident Investigation</h1>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Correlated security timelines from first observed request to alert, investigation, and mitigation.
            </p>
          </div>

          {/* Filter Pills */}
          <div className="flex items-center space-x-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs font-mono">
            {(['ALL', 'OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED'] as const).map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => setFilter(status)}
                className={`px-2.5 py-1 rounded text-[10px] font-bold transition ${
                  filter === status
                    ? 'bg-cyan-600 text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Incidents List */}
      {filteredIncidents.length === 0 ? (
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-12 text-center space-y-3 shadow-lg">
          <div className="w-12 h-12 rounded-full bg-slate-800 border border-slate-700 mx-auto flex items-center justify-center text-slate-400">
            <CheckCircle className="w-6 h-6 text-emerald-400" />
          </div>
          <h2 className="text-base font-bold text-slate-200">No Incidents Matching Filter</h2>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            All security findings are either resolved or no incidents have been recorded in this status.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredIncidents.map((incident) => {
            const isExpanded = expandedIncidentId === incident.id;
            return (
              <div
                key={incident.id}
                className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-xl transition"
              >
                {/* Incident Card Header */}
                <div
                  onClick={() => setExpandedIncidentId(isExpanded ? null : incident.id)}
                  className="p-4 cursor-pointer hover:bg-slate-800/40 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3 select-none"
                >
                  <div className="flex items-center space-x-3">
                    <span
                      className={`px-2.5 py-1 rounded font-mono text-[10px] font-extrabold uppercase tracking-wider border ${
                        incident.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/50'
                          : incident.severity === 'HIGH'
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      }`}
                    >
                      {incident.severity}
                    </span>
                    <div>
                      <div className="flex items-center space-x-2">
                        <h2 className="text-sm font-bold text-slate-100 font-mono">{incident.title}</h2>
                        <span className="text-xs text-slate-400 font-mono">({incident.id})</span>
                      </div>
                      <div className="flex items-center space-x-3 text-xs text-slate-400 font-mono mt-0.5">
                        <span>Target: {incident.target}</span>
                        <span>•</span>
                        <span>Endpoint: {incident.affectedEndpoint}</span>
                        <span>•</span>
                        <span>{incident.displayTime}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    {/* Status Badge */}
                    <span
                      className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold uppercase ${
                        incident.status === 'OPEN'
                          ? 'bg-rose-950/40 text-rose-400 border border-rose-500/40'
                          : incident.status === 'INVESTIGATING'
                          ? 'bg-amber-950/40 text-amber-400 border border-amber-500/40'
                          : incident.status === 'MITIGATED'
                          ? 'bg-cyan-950/40 text-cyan-400 border border-cyan-500/40'
                          : 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/40'
                      }`}
                    >
                      {incident.status}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Details & Timeline */}
                {isExpanded && (
                  <div className="p-5 border-t border-slate-800 space-y-6 text-xs bg-slate-950/40">
                    {/* Timeline Flow */}
                    <div>
                      <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center space-x-2">
                        <Clock className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Incident Timeline Sequence</span>
                      </h3>
                      <div className="relative pl-6 space-y-3 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                        {incident.timeline.map((step, idx) => (
                          <div key={idx} className="relative">
                            <div
                              className={`absolute -left-6 top-1 w-4 h-4 rounded-full border-2 bg-[#0f172a] flex items-center justify-center ${
                                step.type === 'ALERT'
                                  ? 'border-rose-500 text-rose-500'
                                  : step.type === 'DETECTION'
                                  ? 'border-amber-500 text-amber-500'
                                  : step.type === 'EVENT'
                                  ? 'border-cyan-500 text-cyan-500'
                                  : 'border-slate-600 text-slate-400'
                              }`}
                            >
                              <div className="w-1.5 h-1.5 rounded-full bg-current" />
                            </div>
                            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono">
                              <div className="flex items-center justify-between text-[11px]">
                                <span className="font-bold text-slate-200">{step.step}</span>
                                <span className="text-slate-500">{step.displayTime}</span>
                              </div>
                              <p className="text-slate-300 font-sans text-xs mt-1">{step.description}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Associated Evidence Logs */}
                    <div>
                      <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">
                        Associated Evidence Logs
                      </h3>
                      <div className="rounded-lg bg-black/40 border border-slate-800 overflow-hidden font-mono text-[11px]">
                        {incident.evidenceLogs.map((log) => (
                          <div
                            key={log.id}
                            className="p-2.5 border-b border-slate-800/60 last:border-0 flex items-center justify-between hover:bg-slate-800/40"
                          >
                            <div className="flex items-center space-x-2 truncate">
                              <span className="text-slate-500">{log.displayTime}</span>
                              <span className="text-cyan-400 font-bold">{log.method}</span>
                              <span className="text-slate-200 truncate">{log.endpoint}</span>
                            </div>
                            <div className="flex items-center space-x-3 shrink-0">
                              <span
                                className={`font-bold ${
                                  log.status >= 400 ? 'text-amber-400' : 'text-emerald-400'
                                }`}
                              >
                                {log.status}
                              </span>
                              <span className="text-slate-400 text-[10px]">{log.sourceIp}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Status Management & Jump to Solution */}
                    <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-sans">
                      <div className="flex items-center space-x-2">
                        <span className="text-[11px] text-slate-400 font-semibold">Update Status:</span>
                        <select
                          value={incident.status}
                          onChange={(e) =>
                            onUpdateStatus(incident.id, e.target.value as Incident['status'])
                          }
                          className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
                        >
                          <option value="OPEN">OPEN</option>
                          <option value="INVESTIGATING">INVESTIGATING</option>
                          <option value="MITIGATED">MITIGATED</option>
                          <option value="RESOLVED">RESOLVED</option>
                        </select>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
