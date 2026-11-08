import React, { useState, useRef, useEffect } from 'react';
import { Target, LogEvent, ThreatDetection, Incident, AnalystMessage } from '../types/security';
import { analystService } from '../services/analystService';
import {
  Bot,
  Send,
  ShieldCheck,
  AlertCircle,
  CheckCircle,
  Terminal,
  Zap,
  Copy,
  Check,
  FileCode,
  ShieldAlert,
  Sparkles,
  ArrowRight,
} from 'lucide-react';

interface ExtremeAnalystViewProps {
  target: Target;
  logs: LogEvent[];
  threats: ThreatDetection[];
  incidents: Incident[];
}

export const ExtremeAnalystView: React.FC<ExtremeAnalystViewProps> = ({
  target,
  logs,
  threats,
  incidents,
}) => {
  const topThreat = threats[0];
  const [copiedPatchId, setCopiedPatchId] = useState<string | null>(null);
  const [copiedCurlId, setCopiedCurlId] = useState<string | null>(null);

  const [messages, setMessages] = useState<AnalystMessage[]>([
    {
      id: 'welcome',
      sender: 'analyst',
      text: `Hello Operator. I am EXTREME ANALYST — your principal cyber defense and incident response commander.
I am actively monitoring ${target.hostname}. If ANY anomaly, attack, breach, or failure occurs, I identify the root cause and provide a next-level engineering solution, complete with production-ready code patches, WAF rules, and verification tests.`,
      timestamp: new Date().toLocaleTimeString(),
      structured: {
        observed: [
          `Monitored Target: ${target.hostname} (${target.url})`,
          `Live Telemetry Pipeline: Connected & Streaming to knowledge engine`,
          `Current Active Alerts: ${threats.length} | Open Incidents: ${incidents.length}`,
        ],
        inferred: [
          threats.length > 0
            ? `Immediate Action Required: Target has ${threats.length} active threats flagged.`
            : `All monitoring parameters nominal. Continuous real-time telemetry active.`,
        ],
        recommended: [
          threats.length > 0
            ? `Click "Solve Active Issue Now" above to generate a next-level code patch for ${threats[0].threatName}.`
            : `Select any defense topic below or ask any security question to audit your stack.`,
        ],
      },
    },
  ]);

  const [inputQuery, setInputQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const targetPrompts = [
    `⚡ Solve active threat on ${target.hostname}`,
    `🛡️ Generate Next.js security headers (CSP & HSTS)`,
    `🔒 Add Rate Limiting & Brute-Force shield`,
    `🛑 Block malicious scanner bots (sqlmap, nikto)`,
    `🚫 Lock down sensitive dotfiles (.env, .git)`,
  ];

  const topicPrompts = [
    'How to prevent SQL Injection in Next.js/React?',
    'Explain how to mitigate Layer 7 DDoS on Render/Vercel',
    'How should JWT authentication be securely implemented?',
    'What is the OWASP Top 10 breakdown for 2026?',
  ];

  const handleSend = async (queryText?: string) => {
    const q = (queryText || inputQuery).trim();
    if (!q || loading) return;

    const userMsg: AnalystMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: q,
      timestamp: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setLoading(true);

    try {
      const response = await analystService.askAnalyst(q, {
        target,
        logs,
        threats,
        incidents,
      });

      const analystMsg: AnalystMessage = {
        id: `analyst-${Date.now()}`,
        sender: 'analyst',
        text: response.answer,
        timestamp: new Date().toLocaleTimeString(),
        structured: response.structured,
        insufficientEvidence: response.insufficientEvidence,
      };
      setMessages((prev) => [...prev, analystMsg]);
    } catch (err: any) {
      const errorMsg: AnalystMessage = {
        id: `error-${Date.now()}`,
        sender: 'analyst',
        text: 'An error occurred while evaluating security query. Please retry.',
        timestamp: new Date().toLocaleTimeString(),
        insufficientEvidence: true,
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const copyCodePatch = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedPatchId(id);
    setTimeout(() => setCopiedPatchId(null), 2500);
  };

  const copyVerificationCurl = (curl: string, id: string) => {
    navigator.clipboard.writeText(curl);
    setCopiedCurlId(id);
    setTimeout(() => setCopiedCurlId(null), 2500);
  };

  return (
    <div className="space-y-4 font-sans">
      {/* Monster Target Problem Alert Bar */}
      {topThreat ? (
        <div className="bg-gradient-to-r from-rose-950/60 via-slate-900 to-slate-900 border border-rose-500/50 rounded-xl p-4 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-3 animate-pulse-subtle">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-rose-950 border border-rose-500/60 flex items-center justify-center text-rose-400 shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400">
                  ACTIVE PROBLEM DETECTED ON {target.hostname}
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-700 font-bold">
                  {topThreat.severity}
                </span>
              </div>
              <p className="text-xs text-slate-200 font-semibold mt-0.5">
                {topThreat.threatName} on endpoint <code className="text-rose-300 font-mono bg-black/40 px-1 py-0.5 rounded">{topThreat.affectedEndpoint}</code>
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => handleSend(`Solve active problem: ${topThreat.threatName} detected on endpoint ${topThreat.affectedEndpoint}`)}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-gradient-to-r from-rose-600 to-red-600 hover:from-rose-500 hover:to-red-500 text-white font-bold text-xs flex items-center justify-center space-x-2 transition shadow-lg shadow-rose-950 shrink-0 active:scale-95 disabled:opacity-50"
          >
            <Zap className="w-4 h-4 text-amber-300 fill-amber-300" />
            <span>⚡ Generate Next-Level Solution & Patch</span>
          </button>
        </div>
      ) : (
        <div className="bg-gradient-to-r from-emerald-950/40 via-slate-900 to-slate-900 border border-emerald-500/30 rounded-xl p-3.5 px-4 shadow flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center space-x-2.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="text-xs text-slate-300 font-medium">
              Monitoring <span className="font-bold font-mono text-cyan-300">{target.hostname}</span> — Telemetry Nominal (0 Active Threats, Status: {target.lastProbeStatus || 'UP'})
            </span>
          </div>
          <button
            type="button"
            onClick={() => handleSend(`Audit security posture and hardening checklist for ${target.hostname}`)}
            disabled={loading}
            className="text-xs font-bold text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 shrink-0"
          >
            <span>Run Hardening Audit</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Main Chat Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-600/30 to-blue-600/30 border border-cyan-500/50 flex items-center justify-center text-cyan-400 shadow-md">
              <Bot className="w-5 h-5 text-cyan-300" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-base font-extrabold text-slate-100 tracking-tight">EXTREME ANALYST</h1>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-cyan-950 border border-cyan-600 text-cyan-300 font-bold shadow-sm">
                  MONSTER DEFENSE ENGINE
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time incident solver, root cause analysis, and production-ready code patches for <span className="text-slate-200 font-mono">{target.hostname}</span>.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800 shrink-0">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Target:</span>
            <span className="text-slate-200 font-bold">{target.hostname}</span>
          </div>
        </div>

        {/* Suggestion Chips */}
        <div className="pt-3 border-t border-slate-800/80 space-y-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] font-mono uppercase font-bold text-amber-400/90 mr-1 flex items-center gap-1">
              <Zap className="w-3 h-3 text-amber-400" />
              <span>Target Solutions:</span>
            </span>
            {targetPrompts.map((prompt, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSend(prompt)}
                disabled={loading}
                className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-700/80 hover:border-cyan-400 hover:bg-cyan-950/30 text-[11px] text-slate-200 font-semibold transition active:scale-95 disabled:opacity-50"
              >
                {prompt}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] font-mono uppercase font-bold text-cyan-400/80 mr-1 flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-cyan-400" />
              <span>Cyber Concepts:</span>
            </span>
            {topicPrompts.map((prompt, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSend(prompt)}
                disabled={loading}
                className="px-2.5 py-1 rounded-md bg-cyan-950/40 border border-cyan-800/60 hover:border-cyan-400 hover:bg-cyan-900/40 text-[11px] text-cyan-200 font-medium transition active:scale-95 disabled:opacity-50"
              >
                {prompt}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Chat Messages Container */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 sm:p-5 min-h-[500px] max-h-[700px] flex flex-col justify-between shadow-2xl">
        <div className="overflow-y-auto space-y-4 pr-1">
          {messages.map((msg) => {
            const isUser = msg.sender === 'user';
            return (
              <div key={msg.id} className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
                <div
                  className={`w-full max-w-3xl rounded-xl p-4 sm:p-5 space-y-4 shadow-lg ${
                    isUser
                      ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-tr-none ml-8'
                      : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-tl-none mr-4'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] opacity-80 border-b border-white/10 pb-2">
                    <span className="font-extrabold uppercase tracking-wider flex items-center gap-1.5">
                      {!isUser && <Bot className="w-3.5 h-3.5 text-cyan-400" />}
                      <span>{isUser ? 'Security Operator' : 'EXTREME ANALYST — PRINCIPAL COMMANDER'}</span>
                    </span>
                    <span className="font-mono">{msg.timestamp}</span>
                  </div>

                  {isUser ? (
                    <p className="text-xs sm:text-sm font-medium leading-relaxed">{msg.text}</p>
                  ) : (
                    <div className="space-y-4 text-xs">
                      {msg.structured ? (
                        <>
                          {/* 1. OBSERVED / ANATOMY */}
                          {msg.structured.observed && msg.structured.observed.length > 0 && (
                            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2">
                              <div className="flex items-center space-x-1.5 text-cyan-400 font-bold text-xs uppercase tracking-wider">
                                <Terminal className="w-4 h-4 text-cyan-400" />
                                <span>[1. INCIDENT ANATOMY & TELEMETRY OBSERVATIONS]</span>
                              </div>
                              <ul className="space-y-1.5 text-slate-300 text-xs pl-1">
                                {msg.structured.observed.map((item, idx) => (
                                  <li key={idx} className="leading-relaxed font-mono text-[11px] flex items-start space-x-2">
                                    <span className="text-cyan-400 font-bold shrink-0">•</span>
                                    <span>{item}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* 2. INFERRED / ROOT CAUSE */}
                          {msg.structured.inferred && msg.structured.inferred.length > 0 && (
                            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-amber-500/30 space-y-2">
                              <div className="flex items-center space-x-1.5 text-amber-400 font-bold text-xs uppercase tracking-wider">
                                <AlertCircle className="w-4 h-4 text-amber-400" />
                                <span>[2. ROOT CAUSE ANALYSIS & BLAST RADIUS]</span>
                              </div>
                              <ul className="space-y-1.5 text-slate-300 text-xs pl-1">
                                {msg.structured.inferred.map((item, idx) => (
                                  <li key={idx} className="leading-relaxed font-sans text-xs flex items-start space-x-2">
                                    <span className="text-amber-400 font-bold shrink-0">⚠</span>
                                    <span>{item}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* 3. RECOMMENDED / STRATEGY */}
                          {msg.structured.recommended && msg.structured.recommended.length > 0 && (
                            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-emerald-500/30 space-y-2">
                              <div className="flex items-center space-x-1.5 text-emerald-400 font-bold text-xs uppercase tracking-wider">
                                <CheckCircle className="w-4 h-4 text-emerald-400" />
                                <span>[3. ARCHITECTURAL DEFENSE STRATEGY]</span>
                              </div>
                              <ul className="space-y-1.5 text-slate-300 text-xs pl-1">
                                {msg.structured.recommended.map((item, idx) => (
                                  <li key={idx} className="leading-relaxed font-sans text-xs flex items-start space-x-2">
                                    <span className="text-emerald-400 font-bold shrink-0">✓</span>
                                    <span>{item}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* 4. PRODUCTION CODE PATCH */}
                          {msg.structured.codePatch && (
                            <div className="rounded-lg bg-[#050811] border border-cyan-500/40 overflow-hidden shadow-xl space-y-0">
                              <div className="px-4 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs">
                                <div className="flex items-center space-x-2">
                                  <FileCode className="w-4 h-4 text-cyan-400" />
                                  <span className="font-mono font-bold text-slate-100">
                                    {msg.structured.codePatch.filename}
                                  </span>
                                  <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                                    {msg.structured.codePatch.language}
                                  </span>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => copyCodePatch(msg.structured!.codePatch!.code, msg.id)}
                                  className="px-2.5 py-1 rounded bg-cyan-950/80 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/50 text-xs font-bold flex items-center space-x-1.5 transition active:scale-95 shadow-sm"
                                >
                                  {copiedPatchId === msg.id ? (
                                    <>
                                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                                      <span className="text-emerald-300">✓ Code Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3.5 h-3.5" />
                                      <span>Copy Code Patch</span>
                                    </>
                                  )}
                                </button>
                              </div>

                              <div className="p-3 bg-black/40 text-[11px] text-slate-400 font-sans border-b border-slate-800">
                                <span className="font-bold text-slate-300">Deployment Target: </span>
                                {msg.structured.codePatch.description}
                              </div>

                              <pre className="p-4 overflow-x-auto font-mono text-[11px] leading-relaxed text-cyan-300 max-h-[360px] bg-[#050811]">
                                <code>{msg.structured.codePatch.code}</code>
                              </pre>
                            </div>
                          )}

                          {/* 5. STEP-BY-STEP MITIGATION CHECKLIST */}
                          {msg.structured.mitigationSteps && msg.structured.mitigationSteps.length > 0 && (
                            <div className="p-3.5 rounded-lg bg-slate-950/90 border border-indigo-500/30 space-y-2">
                              <div className="flex items-center space-x-1.5 text-indigo-400 font-bold text-xs uppercase tracking-wider">
                                <Zap className="w-4 h-4 text-indigo-400" />
                                <span>[4. IMMEDIATE CONTAINMENT & RECOVERY CHECKLIST]</span>
                              </div>
                              <div className="space-y-1.5">
                                {msg.structured.mitigationSteps.map((step, idx) => (
                                  <div key={idx} className="flex items-start space-x-2 text-xs text-slate-300 bg-slate-900/70 p-2 rounded border border-slate-800/80">
                                    <span className="px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 font-mono font-bold text-[10px] shrink-0">
                                      STEP {idx + 1}
                                    </span>
                                    <span className="leading-relaxed">{step}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* 6. VERIFICATION CURL */}
                          {msg.structured.verificationCurl && (
                            <div className="p-3.5 rounded-lg bg-black/80 border border-slate-800 space-y-2 font-mono">
                              <div className="flex items-center justify-between text-xs">
                                <span className="text-[11px] font-bold text-slate-400 flex items-center gap-1.5">
                                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                                  <span>[5. EXPLOIT TEST & VERIFICATION COMMAND]</span>
                                </span>
                                <button
                                  type="button"
                                  onClick={() => copyVerificationCurl(msg.structured!.verificationCurl!, msg.id)}
                                  className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                                >
                                  {copiedCurlId === msg.id ? (
                                    <>
                                      <Check className="w-3 h-3 text-emerald-400" />
                                      <span className="text-emerald-300">Copied!</span>
                                    </>
                                  ) : (
                                    <>
                                      <Copy className="w-3 h-3" />
                                      <span>Copy cURL</span>
                                    </>
                                  )}
                                </button>
                              </div>
                              <pre className="p-2.5 rounded bg-slate-950 text-emerald-400 text-[11px] overflow-x-auto select-all border border-slate-800">
                                {msg.structured.verificationCurl}
                              </pre>
                            </div>
                          )}
                        </>
                      ) : (
                        <div className="whitespace-pre-wrap leading-relaxed text-slate-200 text-xs sm:text-sm font-sans">
                          {msg.text}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {loading && (
            <div className="flex justify-start">
              <div className="bg-slate-900 border border-cyan-500/40 rounded-xl rounded-tl-none p-4 max-w-md flex items-center space-x-3 text-xs text-cyan-300 font-mono shadow-xl animate-pulse">
                <Bot className="w-5 h-5 animate-spin text-cyan-400" />
                <span>EXTREME ANALYST evaluating root cause & compiling next-level solution...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="pt-4 border-t border-slate-800/80 mt-2"
        >
          <div className="flex gap-2">
            <input
              type="text"
              placeholder={`Ask EXTREME ANALYST anything (e.g. "Solve active threat on ATC", "How to block bot attacks?", "Generate Next.js CSP headers")...`}
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              disabled={loading}
              className="flex-1 px-4 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-500 transition disabled:opacity-50 shadow-inner"
            />
            <button
              type="submit"
              disabled={!inputQuery.trim() || loading}
              className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs tracking-wider uppercase disabled:opacity-50 transition flex items-center space-x-1.5 shadow-md shadow-cyan-950 shrink-0 active:scale-95"
            >
              <Send className="w-3.5 h-3.5" />
              <span>SEND</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
