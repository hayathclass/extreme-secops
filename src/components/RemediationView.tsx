import React, { useState } from 'react';
import { Remediation, Incident } from '../types/security';
import {
  Wrench,
  CheckCircle2,
  Copy,
  Check,
} from 'lucide-react';

interface RemediationViewProps {
  incidents: Incident[];
  selectedThreatId?: string;
}

export const RemediationView: React.FC<RemediationViewProps> = ({
  incidents,
  selectedThreatId,
}) => {
  const remediations: Remediation[] = incidents
    .map((i) => i.remediation)
    .filter(Boolean);

  const [activeRemediationId, setActiveRemediationId] = useState<string>(
    remediations.find((r) => r.threatId === selectedThreatId)?.id ||
      remediations[0]?.id ||
      ''
  );
  const [copiedSnippet, setCopiedSnippet] = useState(false);

  const currentRemediation =
    remediations.find((r) => r.id === activeRemediationId) || remediations[0];

  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedSnippet(true);
    setTimeout(() => setCopiedSnippet(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center space-x-2">
              <Wrench className="w-5 h-5 text-cyan-400" />
              <h1 className="text-base font-bold text-slate-100">RECOMMENDED REMEDIATION</h1>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Engineering solutions, configuration reviews, code patches, and verification procedures.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-500/30 text-amber-300 text-[11px] max-w-sm">
            <span className="font-bold block">Operator Notice:</span>
            EXTREME delivers actionable remediation guidance. Defensive patches should be verified and deployed in
            your authorized environment.
          </div>
        </div>
      </div>

      {remediations.length === 0 ? (
        <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-12 text-center space-y-3 shadow-lg">
          <div className="w-12 h-12 rounded-full bg-emerald-950/40 border border-emerald-500/40 mx-auto flex items-center justify-center text-emerald-400">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <h2 className="text-base font-bold text-slate-200">No Open Remediation Tasks</h2>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            No active threat alerts require engineering mitigation at this time. Telemetry monitoring is nominal.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Finding Selector Sidebar */}
          <div className="space-y-2 lg:col-span-1">
            <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400 block px-1">
              Active Findings ({remediations.length})
            </span>
            <div className="space-y-1.5">
              {remediations.map((rem) => {
                const isSelected = currentRemediation?.id === rem.id;
                return (
                  <button
                    key={rem.id}
                    type="button"
                    onClick={() => setActiveRemediationId(rem.id)}
                    className={`w-full text-left p-3.5 rounded-xl border text-xs transition ${
                      isSelected
                        ? 'bg-cyan-950/40 border-cyan-500/50 text-cyan-200 shadow-md shadow-cyan-950/40'
                        : 'bg-[#0f172a] border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
                          rem.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : rem.severity === 'HIGH'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        }`}
                      >
                        {rem.severity}
                      </span>
                    </div>
                    <div className="font-bold text-slate-100 truncate">{rem.threatName}</div>
                    <div className="text-[10px] text-slate-400 font-mono truncate mt-0.5">
                      {rem.affectedEndpoint}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Remediation Details */}
          {currentRemediation && (
            <div className="lg:col-span-3 space-y-6">
              {/* Finding Title & Endpoint */}
              <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-2 shadow-lg">
                <div className="flex items-center space-x-2">
                  <span
                    className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase ${
                      currentRemediation.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                        : currentRemediation.severity === 'HIGH'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    {currentRemediation.severity}
                  </span>
                  <h2 className="text-base font-bold text-slate-100">{currentRemediation.title}</h2>
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Target Endpoint: <span className="text-cyan-400 font-semibold">{currentRemediation.affectedEndpoint}</span>
                </div>
              </div>

              {/* 4-Step Remediation Framework */}
              <div className="space-y-4">
                {/* 1. What should be checked? */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-2.5 shadow-lg">
                  <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400">
                    <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-[11px] text-cyan-400 font-mono">
                      1
                    </span>
                    <span>WHAT SHOULD BE CHECKED?</span>
                  </div>
                  <ul className="space-y-2 text-xs text-slate-300 pl-7 list-disc">
                    {currentRemediation.whatToCheck.map((item, idx) => (
                      <li key={idx} className="leading-relaxed">
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* 2. What configuration/code should be reviewed? */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-2.5 shadow-lg">
                  <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400">
                    <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-[11px] text-cyan-400 font-mono">
                      2
                    </span>
                    <span>WHAT CONFIGURATION/CODE SHOULD BE REVIEWED?</span>
                  </div>
                  <ul className="space-y-2 text-xs text-slate-300 pl-7 list-disc">
                    {currentRemediation.configToReview.map((item, idx) => (
                      <li key={idx} className="leading-relaxed">
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* 3. What mitigation can be applied? */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-3 shadow-lg">
                  <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-cyan-400">
                    <span className="w-5 h-5 rounded-full bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-[11px] text-cyan-400 font-mono">
                      3
                    </span>
                    <span>WHAT MITIGATION CAN BE APPLIED?</span>
                  </div>
                  <p className="text-xs text-slate-200 pl-7 leading-relaxed font-semibold">
                    {currentRemediation.mitigationToApply.summary}
                  </p>

                  {/* Code / Configuration Snippet */}
                  {currentRemediation.mitigationToApply.codeSnippet && (
                    <div className="ml-7 rounded-xl bg-black/60 border border-slate-800 overflow-hidden font-mono text-xs">
                      <div className="px-3.5 py-2 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-slate-400 text-[11px]">
                        <span>{currentRemediation.mitigationToApply.filename || 'remediation-patch'}</span>
                        <button
                          type="button"
                          onClick={() => copyCode(currentRemediation.mitigationToApply.codeSnippet!)}
                          className="flex items-center space-x-1 hover:text-slate-200 transition font-sans text-xs font-semibold"
                        >
                          {copiedSnippet ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                          <span>{copiedSnippet ? 'Copied' : 'Copy Snippet'}</span>
                        </button>
                      </div>
                      <pre className="p-4 overflow-x-auto text-cyan-300 leading-relaxed">
                        {currentRemediation.mitigationToApply.codeSnippet}
                      </pre>
                    </div>
                  )}
                </div>

                {/* 4. How should the fix be verified? */}
                <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 space-y-2.5 shadow-lg">
                  <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-emerald-400">
                    <span className="w-5 h-5 rounded-full bg-emerald-950 border border-emerald-500/40 flex items-center justify-center text-[11px] text-emerald-400 font-mono">
                      4
                    </span>
                    <span>HOW SHOULD THE FIX BE VERIFIED?</span>
                  </div>
                  <ul className="space-y-2 text-xs text-slate-300 pl-7 list-disc">
                    {currentRemediation.howToVerify.map((item, idx) => (
                      <li key={idx} className="leading-relaxed font-mono text-[11px]">
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
