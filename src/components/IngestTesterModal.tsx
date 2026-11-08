import React, { useState } from 'react';
import { Target } from '../types/security';
import { securityStore } from '../services/securityStore';
import { Code, X, Copy, Check, Send, CheckCircle2, AlertCircle } from 'lucide-react';

interface IngestTesterModalProps {
  isOpen: boolean;
  onClose: () => void;
  target: Target;
}

export const IngestTesterModal: React.FC<IngestTesterModalProps> = ({
  isOpen,
  onClose,
  target,
}) => {
  const [method, setMethod] = useState<'GET' | 'POST'>('POST');
  const [endpoint, setEndpoint] = useState('/api/v1/auth/login');
  const [status, setStatus] = useState(401);
  const [payloadSnippet, setPayloadSnippet] = useState(`{"username": "admin", "password": "123"}`);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [ingestSuccess, setIngestSuccess] = useState(false);

  if (!isOpen) return null;

  const realCollectorUrl = typeof window !== 'undefined' ? `${window.location.origin}/api/collector/ingest` : '/api/collector/ingest';

  const curlCommand = `curl -X POST ${realCollectorUrl} \\
  -H "Authorization: Bearer ${target.apiKey}" \\
  -H "X-Target-ID: ${target.id}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "endpoint": "${endpoint}",
    "method": "${method}",
    "status": ${status},
    "payloadSnippet": "${payloadSnippet.replace(/"/g, '\\"')}"
  }'`;

  const handleCopyKey = () => {
    navigator.clipboard.writeText(target.apiKey);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleCopyCurl = () => {
    navigator.clipboard.writeText(curlCommand);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  const handleSendTestLog = async () => {
    try {
      await securityStore.sendRealIngestEvent(target.id, {
        method,
        endpoint,
        status,
        eventType: status === 401 ? 'AUTHENTICATION' : 'API_REQUEST',
        severity: status >= 500 ? 'CRITICAL' : status === 401 ? 'SUSPICIOUS' : 'NORMAL',
        latencyMs: 19,
        payloadSnippet: payloadSnippet || undefined,
        flagReason: status === 401 ? 'Authentication failure event sent to live collector' : undefined,
      });
      setIngestSuccess(true);
      setTimeout(() => setIngestSuccess(false), 2500);
    } catch (err) {
      console.error('Failed sending real ingest event:', err);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-sans">
      <div className="bg-[#0f172a] border border-slate-700 w-full max-w-xl rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Code className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100">Collector API & Ingestion Token</h2>
              <p className="text-[11px] text-slate-400">Connect web applications using your secret ingestion key</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-5 text-xs">
          {/* Target API Key */}
          <div className="space-y-1.5">
            <label className="text-[10px] font-mono font-bold uppercase text-slate-400 block">
              INGESTION TOKEN FOR {target.hostname}
            </label>
            <div className="flex items-center justify-between bg-black/60 p-2.5 rounded-lg border border-slate-800 font-mono text-cyan-300">
              <span className="truncate mr-2">{target.apiKey}</span>
              <button
                type="button"
                onClick={handleCopyKey}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center space-x-1 transition font-sans text-xs font-semibold"
              >
                {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedKey ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>

          {/* Send Instant Ingestion Event */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-200 text-xs">Send Real Live Event to Pipeline</span>
              <span className="text-[10px] font-mono text-emerald-400 font-bold uppercase">LIVE HTTP INGEST</span>
            </div>

            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-[10px] uppercase font-mono text-slate-400 font-bold block mb-1">Method</label>
                <select
                  value={method}
                  onChange={(e) => setMethod(e.target.value as any)}
                  className="w-full px-2 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-200 font-mono text-xs"
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>
              <div className="col-span-2">
                <label className="text-[10px] uppercase font-mono text-slate-400 font-bold block mb-1">Endpoint</label>
                <input
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-200 font-mono text-xs"
                />
              </div>
            </div>

            <div className="grid grid-cols-3 gap-2">
              <div>
                <label className="text-[10px] uppercase font-mono text-slate-400 font-bold block mb-1">Status Code</label>
                <input
                  type="number"
                  value={status}
                  onChange={(e) => setStatus(Number(e.target.value))}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-200 font-mono text-xs"
                />
              </div>
              <div className="col-span-2">
                <label className="text-[10px] uppercase font-mono text-slate-400 font-bold block mb-1">Payload / Parameter</label>
                <input
                  type="text"
                  value={payloadSnippet}
                  onChange={(e) => setPayloadSnippet(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-700 text-slate-200 font-mono text-xs"
                />
              </div>
            </div>

            <div className="pt-1 flex items-center justify-between">
              {ingestSuccess ? (
                <div className="flex items-center space-x-1.5 text-emerald-400 text-xs font-semibold">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Event ingested into pipeline!</span>
                </div>
              ) : (
                <span className="text-[11px] text-slate-500">Pushes directly to live stream</span>
              )}
              <button
                type="button"
                onClick={handleSendTestLog}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center space-x-1.5 transition shadow-sm"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Send Event</span>
              </button>
            </div>
          </div>

          {/* cURL Example */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-[10px] font-mono font-bold uppercase text-slate-400">
                CURL INTEGRATION SNIPPET
              </label>
              <button
                type="button"
                onClick={handleCopyCurl}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold flex items-center space-x-1"
              >
                {copiedCurl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copiedCurl ? 'Copied' : 'Copy cURL'}</span>
              </button>
            </div>
            <pre className="p-3 rounded-lg bg-black/60 border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre">
              {curlCommand}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
