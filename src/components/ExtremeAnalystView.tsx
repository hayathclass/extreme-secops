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
  const [messages, setMessages] = useState<AnalystMessage[]>([
    {
      id: 'welcome',
      sender: 'analyst',
      text: `Hello Operator. I am EXTREME ANALYST. I provide expert cybersecurity intelligence. You can ask me ANYTHING related to security:
• Live target telemetry, incidents, and threat investigations for ${target.hostname}
• Core vulnerabilities & attack mechanics (SQLi, XSS, CSRF, SSRF, IDOR, DDoS)
• Defensive engineering, security headers (CSP, HSTS), rate limiting, and WAF rules
• OWASP standards, JWT & authentication architecture, and remediation code snippets.`,
      timestamp: new Date().toLocaleTimeString(),
      structured: {
        observed: [
          `Target: ${target.hostname} (${target.url})`,
          'Telemetry pipeline active & connected to knowledge engine',
        ],
        inferred: [
          'Ready to analyze active alerts or explain any cybersecurity concept and defense strategy.',
        ],
        recommended: [
          'Type any cybersecurity question below or click any of the suggestion chips.',
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

  const telemetryPrompts = [
    'What happened on this target?',
    'Why was this detected?',
    'Show the evidence logs',
    'What should I check?',
  ];

  const knowledgePrompts = [
    'What is SQL Injection and how to prevent it?',
    'How do I protect against Credential Stuffing & Brute Force?',
    'What is a DDoS attack and how do I mitigate it?',
    'Explain the OWASP Top 10 vulnerabilities',
    'What HTTP security headers should I configure?',
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

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Bot className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-base font-bold text-slate-100">EXTREME ANALYST</h1>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-700 text-cyan-300 font-bold">
                  Universal Security Intelligence
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Evaluates live target telemetry <span className="text-slate-200">AND</span> answers any question across
                the entire domain of cybersecurity, vulnerabilities, and defense.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Target:</span>
            <span className="text-slate-200 font-semibold">{target.hostname}</span>
          </div>
        </div>

        {/* Suggestion Chips */}
        <div className="pt-4 border-t border-slate-800/80 space-y-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] font-mono uppercase font-bold text-slate-400 mr-1">Target Queries:</span>
            {telemetryPrompts.map((prompt, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSend(prompt)}
                className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-cyan-500/40 hover:bg-slate-800/80 text-[11px] text-slate-300 font-medium transition"
              >
                "{prompt}"
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[10px] font-mono uppercase font-bold text-cyan-400/80 mr-1">Security Topics:</span>
            {knowledgePrompts.map((prompt, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSend(prompt)}
                className="px-2.5 py-1 rounded-md bg-cyan-950/40 border border-cyan-800/60 hover:border-cyan-400 hover:bg-cyan-900/40 text-[11px] text-cyan-200 font-medium transition"
              >
                {prompt}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Chat Messages Container */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5 min-h-[480px] max-h-[620px] flex flex-col justify-between shadow-xl">
        <div className="overflow-y-auto space-y-4 pr-1">
          {messages.map((msg) => {
            const isUser = msg.sender === 'user';
            return (
              <div key={msg.id} className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
                <div
                  className={`max-w-2xl rounded-xl p-4 space-y-3 ${
                    isUser
                      ? 'bg-cyan-600 text-white rounded-tr-none'
                      : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-tl-none'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] opacity-75">
                    <span className="font-bold">{isUser ? 'Security Operator' : 'EXTREME ANALYST'}</span>
                    <span>{msg.timestamp}</span>
                  </div>

                  {isUser ? (
                    <p className="text-xs leading-relaxed">{msg.text}</p>
                  ) : (
                    <div className="space-y-3 font-mono text-xs">
                      {msg.structured ? (
                        <>
                          {/* OBSERVED */}
                          {msg.structured.observed && msg.structured.observed.length > 0 && (
                            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                              <div className="flex items-center space-x-1.5 text-cyan-400 font-bold text-[11px]">
                                <Terminal className="w-3.5 h-3.5" />
                                <span>[OBSERVED / TECHNICAL OVERVIEW]</span>
                              </div>
                              <ul className="list-disc list-inside space-y-1 text-slate-300 text-xs pl-1">
                                {msg.structured.observed.map((item, idx) => (
                                  <li key={idx} className="leading-relaxed">
                                    {item}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* INFERRED */}
                          {msg.structured.inferred && msg.structured.inferred.length > 0 && (
                            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                              <div className="flex items-center space-x-1.5 text-amber-400 font-bold text-[11px]">
                                <AlertCircle className="w-3.5 h-3.5" />
                                <span>[INFERRED / RISK & IMPACT]</span>
                              </div>
                              <ul className="list-disc list-inside space-y-1 text-slate-300 text-xs pl-1">
                                {msg.structured.inferred.map((item, idx) => (
                                  <li key={idx} className="leading-relaxed">
                                    {item}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* RECOMMENDED */}
                          {msg.structured.recommended && msg.structured.recommended.length > 0 && (
                            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1">
                              <div className="flex items-center space-x-1.5 text-emerald-400 font-bold text-[11px]">
                                <CheckCircle className="w-3.5 h-3.5" />
                                <span>[RECOMMENDED / REMEDIATION]</span>
                              </div>
                              <ul className="list-disc list-inside space-y-1 text-slate-300 text-xs pl-1">
                                {msg.structured.recommended.map((item, idx) => (
                                  <li key={idx} className="leading-relaxed">
                                    {item}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </>
                      ) : (
                        <div className="whitespace-pre-wrap leading-relaxed text-slate-300">{msg.text}</div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {loading && (
            <div className="flex justify-start">
              <div className="bg-slate-900 border border-slate-800 rounded-xl rounded-tl-none p-4 max-w-sm flex items-center space-x-3 text-xs text-cyan-400 font-mono">
                <Bot className="w-4 h-4 animate-spin" />
                <span>Evaluating security intelligence & telemetry...</span>
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
          className="pt-4 border-t border-slate-800/80"
        >
          <div className="flex gap-2">
            <input
              type="text"
              placeholder="Ask anything about security (e.g. 'What happened on my site?', 'What is SQL Injection?', 'How to stop DDoS?')..."
              value={inputQuery}
              onChange={(e) => setInputQuery(e.target.value)}
              disabled={loading}
              className="flex-1 px-4 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 text-xs font-mono focus:outline-none focus:border-cyan-500 transition disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!inputQuery.trim() || loading}
              className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs tracking-wider uppercase disabled:opacity-50 transition flex items-center space-x-1.5 shadow-sm"
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
