import React from 'react';
import { Target, SecurityReport } from '../types/security';
import { securityStore } from '../services/securityStore';
import {
  FileText,
  Printer,
} from 'lucide-react';

interface ReportViewProps {
  target: Target;
}

export const ReportView: React.FC<ReportViewProps> = ({ target }) => {
  const report: SecurityReport = securityStore.generateReport(target.id);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Action Bar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 print:hidden shadow-lg">
        <div>
          <div className="flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h1 className="text-base font-bold text-slate-100">EXTREME Security Report</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Generated security assessment, detected threats, timeline audit, and mitigation specifications.
          </p>
        </div>

        <button
          type="button"
          onClick={handlePrint}
          className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center space-x-1.5 transition shadow-sm shadow-cyan-950"
        >
          <Printer className="w-3.5 h-3.5" />
          <span>Print / Export PDF</span>
        </button>
      </div>

      {/* Printable Report Document Card */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-6 sm:p-8 space-y-8 text-xs text-slate-200 shadow-xl print:bg-white print:text-black print:border-none print:shadow-none">
        {/* Document Header */}
        <div className="border-b border-slate-800 print:border-black pb-6 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="text-2xl font-extrabold font-mono tracking-wider text-slate-100 print:text-black">
                EXTREME
              </div>
              <p className="text-[11px] text-slate-400 print:text-gray-600 font-mono">
                SECURITY MONITORING & INCIDENT RESPONSE REPORT
              </p>
            </div>

            {/* REAL DATA vs DEMO DATA Badge */}
            <div
              className={`px-3 py-1.5 rounded-lg border font-mono text-xs font-bold tracking-wider uppercase inline-block ${
                report.isLab
                  ? 'bg-amber-950/40 text-amber-400 border-amber-500/50 print:bg-amber-100 print:text-amber-800'
                  : 'bg-emerald-950/40 text-emerald-400 border-emerald-500/50 print:bg-emerald-100 print:text-emerald-800'
              }`}
            >
              {report.isLab ? 'DEMO SIMULATED DATA' : 'REAL CONNECTED DATA'}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 text-[11px] font-mono text-slate-400 print:text-gray-700">
            <div>
              <span className="text-slate-400 font-bold uppercase block">TARGET</span>
              <span className="text-slate-200 print:text-black font-semibold">{report.target.hostname}</span>
            </div>
            <div>
              <span className="text-slate-400 font-bold uppercase block">URL</span>
              <span className="text-slate-200 print:text-black truncate block">{report.target.url}</span>
            </div>
            <div>
              <span className="text-slate-400 font-bold uppercase block">GENERATED AT</span>
              <span className="text-slate-200 print:text-black">
                {new Date(report.generatedAt).toLocaleString()}
              </span>
            </div>
            <div>
              <span className="text-slate-400 font-bold uppercase block">HEALTH POSTURE</span>
              <span
                className={`font-bold ${
                  report.summary.healthStatus === 'HEALTHY'
                    ? 'text-emerald-400'
                    : report.summary.healthStatus === 'CRITICAL_THREAT'
                    ? 'text-rose-400'
                    : 'text-amber-400'
                }`}
              >
                {report.summary.healthStatus}
              </span>
            </div>
          </div>
        </div>

        {/* Section 1: Security Summary */}
        <div className="space-y-3">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100 print:text-black border-b border-slate-800/80 pb-1">
            1. Security Summary
          </h2>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono text-xs">
            <div className="p-3 rounded-lg bg-slate-900 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-[10px] uppercase text-slate-400 font-bold block">REQUESTS MONITORED</span>
              <span className="text-lg font-bold text-slate-100 print:text-black">
                {report.summary.totalMonitoredRequests}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-[10px] uppercase text-slate-400 font-bold block">SECURITY EVENTS</span>
              <span className="text-lg font-bold text-amber-400">{report.summary.securityEvents}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-[10px] uppercase text-slate-400 font-bold block">THREATS DETECTED</span>
              <span className="text-lg font-bold text-rose-400">{report.summary.threatsDetected}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-[10px] uppercase text-slate-400 font-bold block">OPEN INCIDENTS</span>
              <span className="text-lg font-bold text-cyan-400">{report.summary.openIncidents}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900 print:bg-gray-100 border border-slate-800 print:border-gray-300">
              <span className="text-[10px] uppercase text-slate-400 font-bold block">RESOLVED INCIDENTS</span>
              <span className="text-lg font-bold text-emerald-400">{report.summary.resolvedIncidents}</span>
            </div>
          </div>
        </div>

        {/* Section 2: Detected Threats & Evidence */}
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100 print:text-black border-b border-slate-800/80 pb-1">
            2. Detected Threats & Verified Evidence
          </h2>
          {report.threats.length === 0 ? (
            <p className="text-slate-400 print:text-gray-600">No active threats detected in monitoring telemetry.</p>
          ) : (
            <div className="space-y-4">
              {report.threats.map((threat, idx) => (
                <div
                  key={threat.id}
                  className="p-4 rounded-lg bg-slate-900/60 print:bg-gray-50 border border-slate-800 print:border-gray-300 space-y-2.5"
                >
                  <div className="flex items-center justify-between font-mono text-xs">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-slate-100 print:text-black">
                        {idx + 1}. {threat.threatName}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40">
                        {threat.severity}
                      </span>
                    </div>
                    <span className="text-slate-400 text-[11px]">Confidence: {threat.confidence}%</span>
                  </div>
                  <div className="text-[11px] text-slate-300 print:text-gray-700">
                    <span className="font-bold uppercase text-slate-400 print:text-black">What Happened: </span>
                    {threat.whatHappened}
                  </div>
                  <div className="text-[11px] text-slate-300 print:text-gray-700">
                    <span className="font-bold uppercase text-slate-400 print:text-black">Why Flagged: </span>
                    {threat.whyFlagged}
                  </div>
                  <div className="space-y-1 pt-1">
                    <span className="text-[10px] uppercase font-mono font-bold text-slate-400">EVIDENCE:</span>
                    <ul className="list-disc pl-5 font-mono text-[11px] text-slate-400 print:text-gray-600 space-y-0.5">
                      {threat.evidence.map((ev, i) => (
                        <li key={i}>{ev}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Section 3: Incident Timeline Audit */}
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100 print:text-black border-b border-slate-800/80 pb-1">
            3. Incident Timeline Audit
          </h2>
          {report.incidents.length === 0 ? (
            <p className="text-slate-400 print:text-gray-600">No active incidents recorded.</p>
          ) : (
            <div className="space-y-4">
              {report.incidents.map((inc) => (
                <div
                  key={inc.id}
                  className="p-4 rounded-lg bg-slate-900/60 print:bg-gray-50 border border-slate-800 print:border-gray-300 space-y-3 font-mono text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-100 print:text-black">
                      Incident {inc.id} — {inc.title}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-[10px]">{inc.status}</span>
                  </div>
                  <div className="space-y-2 pl-3 border-l border-slate-700">
                    {inc.timeline.map((step, i) => (
                      <div key={i} className="text-[11px]">
                        <span className="text-cyan-400 font-bold">{step.step}</span> ({step.displayTime}):{' '}
                        <span className="text-slate-300 print:text-gray-700 font-sans">{step.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Section 4: Recommended Remediation Solutions */}
        <div className="space-y-4">
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100 print:text-black border-b border-slate-800/80 pb-1">
            4. Recommended Remediation Solutions
          </h2>
          {report.remediations.length === 0 ? (
            <p className="text-slate-400 print:text-gray-600">No open remediations required.</p>
          ) : (
            <div className="space-y-4">
              {report.remediations.map((rem) => (
                <div
                  key={rem.id}
                  className="p-4 rounded-lg bg-slate-900/60 print:bg-gray-50 border border-slate-800 print:border-gray-300 space-y-3"
                >
                  <div className="font-bold text-sm text-slate-100 print:text-black">{rem.title}</div>
                  <div className="text-xs text-cyan-400 font-mono">Affected: {rem.affectedEndpoint}</div>
                  <div className="space-y-1.5 text-xs text-slate-300 print:text-gray-800">
                    <span className="font-bold uppercase text-[11px] text-slate-400 print:text-black block">
                      Recommended Mitigation:
                    </span>
                    <p>{rem.mitigationToApply.summary}</p>
                  </div>
                  <div className="space-y-1 text-xs">
                    <span className="font-bold uppercase text-[11px] text-slate-400 print:text-black block">
                      Verification Procedure:
                    </span>
                    <ul className="list-disc pl-5 font-mono text-[11px] text-slate-300 print:text-gray-700 space-y-0.5">
                      {rem.howToVerify.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
