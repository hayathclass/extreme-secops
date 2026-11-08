import React, { useState } from 'react';
import { Target } from '../types/security';
import { securityStore } from '../services/securityStore';
import { liveUrlScanner, UrlAuditReport } from '../services/liveUrlScanner';
import {
  ShieldCheck,
  X,
  AlertCircle,
  Globe,
  Activity,
  CheckCircle,
  Copy,
  Check,
  Loader2,
  CheckCircle2,
} from 'lucide-react';

interface ConnectTargetModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTargetCreated: (target: Target) => void;
  defaultUrl?: string;
}

export const ConnectTargetModal: React.FC<ConnectTargetModalProps> = ({
  isOpen,
  onClose,
  onTargetCreated,
  defaultUrl = '',
}) => {
  const [url, setUrl] = useState(defaultUrl || '');
  const [targetName, setTargetName] = useState('');
  const [runLiveAudit, setRunLiveAudit] = useState(true);
  const [confirmedAuthorized, setConfirmedAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [createdTarget, setCreatedTarget] = useState<Target | null>(null);
  const [auditReport, setAuditReport] = useState<UrlAuditReport | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    let cleanUrl = url.trim();
    if (!cleanUrl) {
      setError('Please provide a valid website URL or domain name.');
      return;
    }

    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = `https://${cleanUrl}`;
    }

    try {
      new URL(cleanUrl);
    } catch {
      setError('Invalid URL format. Please enter a valid domain (e.g. https://mycompany.com).');
      return;
    }

    if (!confirmedAuthorized) {
      setError('You must certify authorization before connecting a target.');
      return;
    }

    try {
      setLoading(true);

      // Create Target
      setStatusMessage('Registering target in monitoring pipeline...');
      const newTarget = securityStore.createTarget(cleanUrl, targetName.trim() || undefined, 'REAL_PRODUCTION');

      // Optionally run live URL audit
      if (runLiveAudit) {
        setStatusMessage('Executing real SSL handshake, DNS resolution, and security header audit...');
        try {
          await securityStore.deepScanTarget(newTarget.id, cleanUrl);
          const audit = await liveUrlScanner.auditLiveWebsite(cleanUrl);
          setAuditReport(audit);
        } catch (auditErr) {
          console.warn('Live URL audit error:', auditErr);
        }
      }

      setCreatedTarget(newTarget);
      onTargetCreated(newTarget);
    } catch (err: any) {
      setError(err.message || 'Failed to connect target.');
    } finally {
      setLoading(false);
      setStatusMessage('');
    }
  };

  const handleCopyKey = () => {
    if (createdTarget?.apiKey) {
      navigator.clipboard.writeText(createdTarget.apiKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const handleReset = () => {
    setUrl('');
    setTargetName('');
    setRunLiveAudit(true);
    setConfirmedAuthorized(false);
    setError(null);
    setCreatedTarget(null);
    setAuditReport(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-sans">
      <div className="bg-[#0f172a] border border-slate-700 w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Globe className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-100">Connect & Audit Website</h2>
              <p className="text-[11px] text-slate-400">Register domain and probe live security posture</p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleReset}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-4 flex-1">
          {!createdTarget ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5">
                  Website URL / Hostname <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://your-app.vercel.app or https://mycompany.com"
                  className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 font-mono transition"
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Example: <span className="font-mono text-cyan-400">https://my-store.vercel.app</span> or <span className="font-mono text-cyan-400">https://api.mycompany.com</span>
                </p>
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5">
                  Display Label (Optional)
                </label>
                <input
                  type="text"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  placeholder="e.g. Production API Server"
                  className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 transition"
                />
              </div>

              {/* Live Security Audit Option Checkbox */}
              <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 flex items-start space-x-2.5">
                <input
                  id="live-audit-toggle"
                  type="checkbox"
                  checked={runLiveAudit}
                  onChange={(e) => setRunLiveAudit(e.target.checked)}
                  className="mt-0.5 w-4 h-4 rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-cyan-500"
                />
                <label htmlFor="live-audit-toggle" className="text-xs text-slate-300 cursor-pointer select-none">
                  <span className="font-bold text-cyan-300 block">Run live security probe on connect</span>
                  <span className="text-[11px] text-slate-400">
                    Probes HTTPS/TLS, Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), and sensitive file exposure.
                  </span>
                </label>
              </div>

              {/* Authorization Certification Checkbox */}
              <div className="flex items-start space-x-2.5 pt-1">
                <input
                  id="auth-cert-check"
                  type="checkbox"
                  checked={confirmedAuthorized}
                  onChange={(e) => setConfirmedAuthorized(e.target.checked)}
                  className="mt-0.5 w-4 h-4 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-cyan-500"
                />
                <label htmlFor="auth-cert-check" className="text-xs text-slate-300 leading-normal select-none">
                  <span className="font-bold text-slate-200">Authorized targets only.</span> I certify that I own,
                  operate, or have explicit authorization to monitor this target.
                </label>
              </div>

              {error && (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center space-x-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              {loading && (
                <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-500/40 text-cyan-300 text-xs flex items-center space-x-2 font-mono">
                  <Loader2 className="w-4 h-4 animate-spin shrink-0 text-cyan-400" />
                  <span>{statusMessage}</span>
                </div>
              )}

              {/* Buttons */}
              <div className="pt-2 flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={handleReset}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !confirmedAuthorized}
                  className="px-5 py-2.5 rounded-lg text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50 disabled:cursor-not-allowed transition shadow-md shadow-cyan-950"
                >
                  {loading ? 'CONNECTING...' : 'CONNECT & AUDIT'}
                </button>
              </div>
            </form>
          ) : (
            /* Result View */
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-emerald-300 text-xs space-y-2">
                <div className="flex items-center space-x-2 font-bold text-sm">
                  <CheckCircle className="w-4 h-4 text-emerald-400" />
                  <span>Website Connected Successfully</span>
                </div>
                <p className="text-slate-300 text-xs leading-relaxed">
                  Target <span className="font-mono text-emerald-400 font-bold">{createdTarget.hostname}</span> is now
                  registered in your EXTREME console in <span className="text-emerald-400 font-bold">Real Telemetry Mode</span>.
                  Synthetic fake logs are disabled for real targets.
                </p>
              </div>

              {/* Audit Grade summary if audited */}
              {auditReport && (
                <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between text-xs font-mono">
                  <div>
                    <span className="text-[10px] uppercase text-slate-400 block font-bold">LIVE SECURITY GRADE</span>
                    <span className="text-cyan-400 font-bold text-sm">
                      Grade: {auditReport.grade} ({auditReport.score}/100)
                    </span>
                  </div>
                  <span className="text-slate-400 text-[11px]">
                    {auditReport.checksPassed} Passed • {auditReport.checksFailed} Failed
                  </span>
                </div>
              )}

              {/* 24/7 Real Website Telemetry Installation for Vercel / Next.js / React */}
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-700/80 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="text-xs font-bold font-mono text-emerald-400 uppercase tracking-wider">
                      24/7 Real Visitor Log Collector
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/60 border border-slate-700 text-slate-300">
                    Target ID: {createdTarget.id}
                  </span>
                </div>

                <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                  To stream genuine user visits, API calls, and errors from your Vercel/Next.js/React app into this dashboard in real time with <strong>zero fake logs</strong>, copy your integration snippet below:
                </p>

                {/* Integration Option 1: 1-Line HTML / Layout Snippet */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>1. HTML / Next.js / React &lt;head&gt; (Instant Tracking):</span>
                    <button
                      type="button"
                      onClick={() => {
                        const snippet = `<script src="${window.location.origin}/api/collector/script.js" data-target-id="${createdTarget.id}" data-api-key="${createdTarget.apiKey}" async></script>`;
                        navigator.clipboard.writeText(snippet);
                        setCopiedKey(true);
                        setTimeout(() => setCopiedKey(false), 2000);
                      }}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                    >
                      {copiedKey ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedKey ? 'Copied Snippet' : 'Copy HTML Script Tag'}</span>
                    </button>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/70 border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto select-all break-all">
                    {`<script src="${typeof window !== 'undefined' ? window.location.origin : ''}/api/collector/script.js" data-target-id="${createdTarget.id}" data-api-key="${createdTarget.apiKey}" async></script>`}
                  </div>
                </div>

                {/* Integration Option 2: Next.js app/layout.tsx Script */}
                <div className="space-y-1.5 pt-1">
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>2. Next.js 13/14/15 App Router (app/layout.tsx):</span>
                    <button
                      type="button"
                      onClick={() => {
                        const nextSnippet = `import Script from 'next/script';\n\nexport default function RootLayout({ children }) {\n  return (\n    <html>\n      <head>\n        <Script src="${window.location.origin}/api/collector/script.js" data-target-id="${createdTarget.id}" data-api-key="${createdTarget.apiKey}" strategy="afterInteractive" />\n      </head>\n      <body>{children}</body>\n    </html>\n  );\n}`;
                        navigator.clipboard.writeText(nextSnippet);
                        setCopiedKey(true);
                        setTimeout(() => setCopiedKey(false), 2000);
                      }}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                    >
                      <Copy className="w-3 h-3" />
                      <span>Copy Next.js Snippet</span>
                    </button>
                  </div>
                  <div className="p-2.5 rounded-lg bg-black/70 border border-slate-800 font-mono text-[10px] text-slate-300 overflow-x-auto select-all">
                    {`<Script src="${typeof window !== 'undefined' ? window.location.origin : ''}/api/collector/script.js" data-target-id="${createdTarget.id}" data-api-key="${createdTarget.apiKey}" strategy="afterInteractive" />`}
                  </div>
                </div>

                {/* Integration Option 3: Immediate Mobile Phone / 2nd Person Test URL */}
                <div className="space-y-1.5 pt-1">
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span className="text-emerald-400 font-bold">3. Test From Phone / 2nd Person (Instant Real IP):</span>
                    <button
                      type="button"
                      onClick={() => {
                        const testUrl = `${window.location.origin}/api/collector/test-visit?targetId=${createdTarget.id}`;
                        navigator.clipboard.writeText(testUrl);
                        setCopiedKey(true);
                        setTimeout(() => setCopiedKey(false), 2000);
                      }}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
                    >
                      <Copy className="w-3 h-3" />
                      <span>Copy Phone Test URL</span>
                    </button>
                  </div>
                  <div className="p-2 rounded-lg bg-black/70 border border-emerald-500/30 font-mono text-[11px] text-emerald-300 overflow-x-auto select-all break-all">
                    {`${typeof window !== 'undefined' ? window.location.origin : ''}/api/collector/test-visit?targetId=${createdTarget.id}`}
                  </div>
                  <p className="text-[10px] text-slate-400 font-sans">
                    Open this URL on your phone or send it to a friend. Their true mobile public IP will appear on your console as Person 2 in real time!
                  </p>
                </div>

                {/* Ingestion Token Display */}
                <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400 text-[11px]">API Ingestion Key:</span>
                  <div className="flex items-center space-x-2">
                    <span className="text-cyan-300 font-bold bg-black/50 px-2 py-0.5 rounded border border-slate-800">
                      {createdTarget.apiKey}
                    </span>
                    <button
                      type="button"
                      onClick={handleCopyKey}
                      className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
                      title="Copy Key"
                    >
                      {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  type="button"
                  onClick={() => {
                    if (createdTarget) {
                      securityStore.setActiveTarget(createdTarget.id);
                      securityStore.toggleAutoStream(true);
                      onTargetCreated(createdTarget);
                    }
                    handleReset();
                  }}
                  className="px-5 py-2.5 rounded-xl text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-sm flex items-center space-x-1.5"
                >
                  <span>Open Real-Time Console</span>
                  <CheckCircle2 className="w-4 h-4 text-white" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
