import React, { useState, useEffect } from 'react';
import { LogEvent, Target, VisitorPerson } from '../types/security';
import { securityStore } from '../services/securityStore';
import {
  Terminal,
  Search,
  Play,
  Pause,
  Trash2,
  X,
  Copy,
  Check,
  Download,
  Plus,
  Radio,
  RefreshCw,
  Zap,
  Globe,
  ShieldCheck,
  Code2,
  Activity,
  Send,
  FileText,
  Users,
  Smartphone,
  Laptop,
  Tablet,
  Monitor,
  MapPin,
  ExternalLink,
  Sparkles,
  Clock,
  QrCode,
} from 'lucide-react';

interface LiveLogsViewProps {
  logs: LogEvent[];
  isStreaming: boolean;
  onToggleStreaming: () => void;
  onClearLogs?: () => void;
  onGenerateLogs?: (count?: number, scenario?: 'normal' | 'mixed' | 'auth_attack' | 'sqli' | 'suspicious') => void;
  target?: Target;
}

export const LiveLogsView: React.FC<LiveLogsViewProps> = ({
  logs,
  isStreaming,
  onToggleStreaming,
  onClearLogs,
  onGenerateLogs,
  target,
}) => {
  const [isProbing, setIsProbing] = useState(false);
  const [isSendingPing, setIsSendingPing] = useState(false);
  const [pingSuccess, setPingSuccess] = useState(false);
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const [copiedTestUrl, setCopiedTestUrl] = useState(false);
  const [showEmbedCode, setShowEmbedCode] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [methodFilter, setMethodFilter] = useState('ALL');
  // Default to REAL_ONLY for real authorized targets so synthetic fake logs are not shown
  const [sourceFilter, setSourceFilter] = useState<string>(
    target && !target.isLab ? 'REAL_ONLY' : 'ALL'
  );
  const [selectedLog, setSelectedLog] = useState<LogEvent | null>(null);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleManualRefresh = async () => {
    if (!target) return;
    setIsRefreshing(true);
    try {
      await securityStore.fetchRemoteCollectorEvents(target.id);
      await securityStore.probeLiveTarget(target.id);
    } catch (e) {
      console.error('Refresh error:', e);
    } finally {
      setTimeout(() => setIsRefreshing(false), 500);
    }
  };

  const filteredLogs = logs.filter((log) => {
    // Source filter: REAL_ONLY, REAL_LIVE_INGEST, REAL_SERVER_PROBE, SIMULATION, ALL
    if (sourceFilter === 'REAL_ONLY') {
      if (log.logSource === 'SIMULATION') return false;
    } else if (sourceFilter !== 'ALL') {
      if (log.logSource !== sourceFilter) return false;
    }

    if (severityFilter !== 'ALL' && log.severity !== severityFilter) return false;
    if (methodFilter !== 'ALL' && log.method !== methodFilter) return false;
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      return (
        log.endpoint.toLowerCase().includes(q) ||
        log.sourceIp.toLowerCase().includes(q) ||
        log.userAgent.toLowerCase().includes(q) ||
        (log.flagReason && log.flagReason.toLowerCase().includes(q)) ||
        (log.payloadSnippet && log.payloadSnippet.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const handleSendRealTestPing = async () => {
    if (!target) return;
    setIsSendingPing(true);
    try {
      const realIp = await securityStore.resolveCurrentClientIp();
      await securityStore.sendRealIngestEvent(target.id, {
        method: 'GET',
        endpoint: '/api/v1/visitor/session',
        status: 200,
        eventType: 'PAGEVIEW',
        latencyMs: 16,
        sourceIp: realIp,
        payloadSnippet: 'session_init: visitor_token_live',
        flagReason: `Real browser live event from ${realIp}`,
      });
      setPingSuccess(true);
      setTimeout(() => setPingSuccess(false), 2500);
    } finally {
      setIsSendingPing(false);
    }
  };

  const handleLiveProbe = async () => {
    if (!target) return;
    setIsProbing(true);
    try {
      await securityStore.probeLiveTarget(target.id);
    } finally {
      setIsProbing(false);
    }
  };

  const copyLogJson = (log: LogEvent) => {
    navigator.clipboard.writeText(JSON.stringify(log, null, 2));
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  const exportAsJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredLogs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `extreme-real-logs-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const realCount = logs.filter((l) => l.logSource === 'REAL_LIVE_INGEST').length;
  const probeCount = logs.filter((l) => l.logSource === 'REAL_SERVER_PROBE').length;

  // Local 1-second pulse so online/offline timeouts and relative timestamps update dynamically
  const [, setTick] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setTick((v) => v + 1), 1000);
    return () => clearInterval(timer);
  }, []);

  // Unique visitor persons based on distinct client IPs and device metadata
  const visitorPersons = target ? securityStore.getVisitorPersons(target.id) : [];
  const activeVisitors = visitorPersons.filter((p) => p.isOnline);
  const hostOrigin = typeof window !== 'undefined' ? window.location.origin : '';
  const mobileTestUrl = `${hostOrigin}/api/collector/test-visit?targetId=${target?.id || 'target-atc-simulator'}`;

  const copyIpAddress = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  const embedScriptSnippet = `<script src="${window.location.origin}/api/collector/script.js" data-target-id="${target?.id || 'target-id'}" data-api-key="${target?.apiKey || ''}" async></script>`;

  return (
    <div className="space-y-4 font-sans">
      {/* Real-Time Telemetry Pipeline Notice & Controller for Real Targets */}
      {target && !target.isLab && (
        <div className="bg-gradient-to-r from-emerald-950/40 via-cyan-950/20 to-slate-900 border border-emerald-500/30 rounded-xl p-4 sm:p-5 shadow-lg relative overflow-hidden">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-400">
                  REAL-TIME TELEMETRY PIPELINE ACTIVE
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 font-bold">
                  NO FAKE LOGS
                </span>
              </div>
              <h2 className="text-sm sm:text-base font-bold text-slate-100 font-mono">
                Monitoring Real Target: <span className="text-cyan-300">{target.hostname}</span>
              </h2>
              <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
                Fake synthetic log generation is disabled for real targets. Telemetry is collected directly from
                server health probes and live HTTP requests received at{' '}
                <code className="text-cyan-300 font-mono bg-black/40 px-1 py-0.5 rounded">/api/collector/ingest</code>.
              </p>
            </div>

            {/* Quick Live Actions */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleSendRealTestPing}
                disabled={isSendingPing}
                className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center space-x-1.5 shadow-md shadow-emerald-950 transition active:scale-95"
                title="Send a real live HTTP event directly to the collector"
              >
                <Send className={`w-3.5 h-3.5 ${isSendingPing ? 'animate-spin' : ''}`} />
                <span>{pingSuccess ? '✓ Real Event Ingested!' : isSendingPing ? 'Sending...' : 'Send Real Live Event'}</span>
              </button>

              <button
                type="button"
                onClick={handleLiveProbe}
                disabled={isProbing}
                className="px-3.5 py-2 rounded-lg bg-cyan-950/80 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/40 text-xs font-bold flex items-center space-x-1.5 transition"
                title="Execute real server-side HTTP request and inspect actual headers"
              >
                <Radio className={`w-3.5 h-3.5 text-cyan-400 ${isProbing ? 'animate-spin' : ''}`} />
                <span>{isProbing ? 'Probing...' : 'Probe Target Server'}</span>
              </button>

              <button
                type="button"
                onClick={() => setShowEmbedCode(!showEmbedCode)}
                className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center space-x-1.5 transition"
              >
                <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>Embed Code</span>
              </button>
            </div>
          </div>

          {/* Collapsible Embed Tracker Snippet */}
          {showEmbedCode && (
            <div className="mt-4 pt-4 border-t border-slate-800/80 space-y-3 animate-fade-in text-xs font-mono">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-[11px] font-bold text-slate-200 font-sans flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  24/7 Live Website Telemetry Integration (Vercel, Next.js, React, Node.js)
                </span>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(embedScriptSnippet);
                    setCopiedSnippet(true);
                    setTimeout(() => setCopiedSnippet(false), 2000);
                  }}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-sans flex items-center space-x-1"
                >
                  {copiedSnippet ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedSnippet ? 'Copied HTML Script' : 'Copy HTML Script Tag'}</span>
                </button>
              </div>

              {/* Snippet Option 1: Universal HTML / React / Static */}
              <div className="space-y-1">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold font-sans">
                  A. Universal HTML / React / Vercel Static Deployments (&lt;head&gt;):
                </span>
                <div className="p-3 rounded-lg bg-black/70 border border-slate-800 text-cyan-300 overflow-x-auto break-all select-all font-mono text-[11px]">
                  {embedScriptSnippet}
                </div>
              </div>

              {/* Snippet Option 2: Next.js 13/14/15 App Router (app/layout.tsx) */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold font-sans">
                    B. Next.js App on Vercel (app/layout.tsx):
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      const nextSnippet = `import Script from 'next/script';\n\n<Script src="${window.location.origin}/api/collector/script.js" data-target-id="${target?.id || 'target-id'}" data-api-key="${target?.apiKey || ''}" strategy="afterInteractive" />`;
                      navigator.clipboard.writeText(nextSnippet);
                      setCopiedSnippet(true);
                      setTimeout(() => setCopiedSnippet(false), 2000);
                    }}
                    className="text-cyan-400 hover:text-cyan-300 text-[10px] font-sans flex items-center space-x-1"
                  >
                    <Copy className="w-3 h-3" />
                    <span>Copy Next.js Code</span>
                  </button>
                </div>
                <div className="p-3 rounded-lg bg-black/70 border border-slate-800 text-slate-300 overflow-x-auto select-all font-mono text-[11px]">
                  {`import Script from 'next/script';\n\n<Script\n  src="${typeof window !== 'undefined' ? window.location.origin : ''}/api/collector/script.js"\n  data-target-id="${target?.id || 'target-id'}"\n  data-api-key="${target?.apiKey || ''}"\n  strategy="afterInteractive"\n/>`}
                </div>
              </div>

              {/* Snippet Option 3: Backend API / Serverless Log Forwarder */}
              <div className="space-y-1">
                <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold font-sans">
                  C. Serverless / Node.js API Middleware (Sends Real Backend HTTP Logs):
                </span>
                <div className="p-3 rounded-lg bg-black/70 border border-slate-800 text-slate-400 overflow-x-auto select-all font-mono text-[10px] leading-relaxed">
                  {`// Express / Node.js backend middleware on Vercel or cloud:\napp.use((req, res, next) => {\n  const t0 = Date.now();\n  res.on('finish', () => {\n    fetch('${typeof window !== 'undefined' ? window.location.origin : ''}/api/collector/ingest', {\n      method: 'POST',\n      headers: { 'Content-Type': 'application/json', 'X-Target-ID': '${target?.id || ''}', 'X-API-Key': '${target?.apiKey || ''}' },\n      body: JSON.stringify({\n        targetId: '${target?.id || ''}',\n        method: req.method,\n        endpoint: req.originalUrl || req.url,\n        status: res.statusCode,\n        latencyMs: Date.now() - t0,\n        userAgent: req.headers['user-agent']\n      })\n    }).catch(() => {});\n  });\n  next();\n});`}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Real-Time Active Visitors (Persons Online) Dedicated Panel */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 sm:p-5 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3.5">
          <div className="space-y-1">
            <div className="flex items-center space-x-2.5">
              <div className="w-8 h-8 rounded-lg bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                <Users className="w-4 h-4" />
              </div>
              <div className="flex items-center space-x-2">
                <h3 className="text-base font-bold text-slate-100 font-mono">
                  Active Real-Time Visitors
                </h3>
                {activeVisitors.length > 0 ? (
                  <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-950/90 text-emerald-300 border border-emerald-500/50 shadow-sm">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    <span>{activeVisitors.length} {activeVisitors.length === 1 ? 'Person' : 'Persons'} Online Now</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                    <span className="w-2 h-2 rounded-full bg-slate-500" />
                    <span>0 Online ({visitorPersons.length} Total Seen)</span>
                  </span>
                )}
              </div>
            </div>
            <p className="text-xs text-slate-400">
              Every distinct client device, mobile phone, and IP address accessing this target is identified and updated in real-time.
            </p>
          </div>

          {/* Quick Visitor Controls */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleManualRefresh}
              disabled={isRefreshing}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold flex items-center space-x-1.5 transition active:scale-95 shadow-sm"
              title="Refresh connected visitor devices"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : 'text-slate-400'}`} />
              <span>{isRefreshing ? 'Refreshing...' : 'Refresh Visitors'}</span>
            </button>

            <button
              type="button"
              onClick={() => {
                navigator.clipboard.writeText(mobileTestUrl);
                setCopiedTestUrl(true);
                setTimeout(() => setCopiedTestUrl(false), 2000);
              }}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center space-x-1.5 transition"
              title="Copy mobile test URL to open on your phone browser"
            >
              {copiedTestUrl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
              <span>{copiedTestUrl ? 'Copied Phone Test Link' : 'Copy Mobile Test Link'}</span>
            </button>

            {onClearLogs && (
              <button
                type="button"
                onClick={() => {
                  if (confirm('Clear all visitor persons and reset telemetry buffer to zero?')) {
                    onClearLogs();
                  }
                }}
                className="px-3 py-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-500/40 text-xs font-semibold flex items-center space-x-1.5 transition"
                title="Wipe previous visitor records so you can observe new visitors entering"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                <span>Clear All Persons</span>
              </button>
            )}
          </div>
        </div>

        {/* Visitor Cards List */}
        {visitorPersons.length === 0 ? (
          <div className="p-6 rounded-lg bg-slate-900/60 border border-dashed border-slate-800 text-center space-y-2">
            <div className="w-10 h-10 rounded-full bg-slate-800/80 mx-auto flex items-center justify-center text-slate-400">
              <Users className="w-5 h-5" />
            </div>
            <div className="text-xs font-bold text-slate-300">0 Persons Currently Tracked</div>
            <p className="text-[11px] text-slate-400 max-w-md mx-auto">
              No live persons or devices have entered yet. Click <span className="text-cyan-300 font-bold">"+ Add 2nd Device (Mobile IP)"</span> to simulate an instant visitor, or open the <span className="text-emerald-400 font-bold">Mobile Test Link</span> on your phone!
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3.5">
            {visitorPersons.map((person, idx) => (
              <div
                key={person.ip}
                className={`bg-slate-900/90 border rounded-xl p-3.5 space-y-2.5 transition shadow-md relative overflow-hidden ${
                  person.isOnline ? 'border-slate-800 hover:border-emerald-500/50 shadow-emerald-950/20' : 'border-slate-800/60 opacity-80 hover:opacity-100'
                }`}
              >
                {/* Person Header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="w-6 h-6 rounded-md bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center justify-center text-xs font-mono font-bold">
                      #{idx + 1}
                    </span>
                    <span className="text-xs font-bold text-slate-200">
                      Person {idx + 1}
                    </span>
                    {person.isSimulated && (
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800">
                        Test Device
                      </span>
                    )}
                  </div>
                  {person.isOnline ? (
                    <div className="flex items-center space-x-1 text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-500/30">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      <span>Online</span>
                    </div>
                  ) : (
                    <div className="flex items-center space-x-1 text-[11px] font-mono text-slate-400 bg-slate-800/90 px-2 py-0.5 rounded border border-slate-700">
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-400/80" />
                      <span>Left Website</span>
                    </div>
                  )}
                </div>

                {/* IP Address & Copy */}
                <div className="bg-black/50 border border-slate-800 rounded-lg p-2.5 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase font-mono block">Real Client IP</span>
                    <span className="text-sm font-mono font-bold text-cyan-300 tracking-wide select-all">
                      {person.ip}
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={() => copyIpAddress(person.ip)}
                    className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
                    title="Copy IP"
                  >
                    {copiedIp === person.ip ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>

                {/* Device & Location */}
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <div className="bg-slate-950/60 p-2 rounded border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 block">Device</span>
                    <span className="text-slate-200 font-bold flex items-center gap-1.5 truncate" title={person.device}>
                      {person.device.includes('iPad') || person.device.includes('Tablet') || person.device.includes('Tab') ? (
                        <Tablet className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                      ) : person.device.includes('iPhone') || person.device.includes('Android') || person.device.includes('Mobile') || person.device.includes('Pixel') || person.device.includes('Galaxy') ? (
                        <Smartphone className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      ) : person.device.includes('Laptop') || person.device.includes('MacBook') ? (
                        <Laptop className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      ) : (
                        <Monitor className="w-3.5 h-3.5 text-slate-300 shrink-0" />
                      )}
                      <span className="truncate">{person.device}</span>
                    </span>
                  </div>
                  <div className="bg-slate-950/60 p-2 rounded border border-slate-800/80">
                    <span className="text-[10px] text-slate-500 block">Location</span>
                    <span className="text-slate-200 font-bold flex items-center gap-1 truncate">
                      <MapPin className="w-3 h-3 text-emerald-400 shrink-0" />
                      <span>{person.city ? `${person.city}, ` : ''}{person.country || 'Global'}</span>
                    </span>
                  </div>
                </div>

                {/* Activity & Hits */}
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1 border-t border-slate-800/60">
                  <span className={person.isOnline ? "text-emerald-400 font-semibold" : "text-slate-400 font-semibold"}>
                    {person.isOnline ? `${person.totalHits} Total Hits (Active)` : `${person.totalHits} Hits (Left ${new Date(person.leftAt || person.lastSeen).toLocaleTimeString()})`}
                  </span>
                  <span className="text-slate-500 truncate max-w-[150px]" title={person.lastEndpoint}>
                    {person.lastEndpoint}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Control Bar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-4 sm:p-5 space-y-3 shadow-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Terminal className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-base font-bold text-slate-100">Live Security Log Stream</h1>
                <span className="text-xs font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-700">
                  {filteredLogs.length} / {logs.length} events
                </span>
              </div>
              <div className="flex items-center space-x-3 text-[11px] font-mono text-slate-400 mt-0.5">
                <span className="text-emerald-400 font-semibold">{realCount} Real Ingest</span>
                <span>•</span>
                <span className="text-cyan-400 font-semibold">{probeCount} Real Probes</span>
              </div>
            </div>
          </div>

          {/* Action Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Manual Refresh Button */}
            <button
              type="button"
              onClick={handleManualRefresh}
              disabled={isRefreshing}
              title="Manually fetch latest real logs from cloud collector"
              className="px-3 py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/50 text-xs font-bold flex items-center space-x-1.5 transition active:scale-95 shadow-sm"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
              <span>{isRefreshing ? 'Refreshing...' : 'Refresh Logs'}</span>
            </button>

            {/* Stream Active Toggle */}
            <button
              type="button"
              onClick={onToggleStreaming}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center space-x-1.5 border transition ${
                isStreaming
                  ? 'bg-emerald-950/40 text-emerald-400 border-emerald-500/40 hover:bg-emerald-950/60'
                  : 'bg-amber-950/40 text-amber-400 border-amber-500/40 hover:bg-amber-950/60'
              }`}
            >
              {isStreaming ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  <Pause className="w-3 h-3" />
                  <span>Real-Time Ingest ON</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3" />
                  <span>Stream Paused</span>
                </>
              )}
            </button>

            {/* Single Export Button */}
            <button
              type="button"
              onClick={exportAsJson}
              title="Export filtered logs as JSON"
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center space-x-1 transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export</span>
            </button>

            {onClearLogs && (
              <button
                type="button"
                onClick={() => {
                  if (confirm('Clear all visitor events and start fresh for this website?')) {
                    onClearLogs();
                  }
                }}
                title="Clear all recorded visitor IPs and events"
                className="px-2.5 py-1.5 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-500/40 text-xs font-semibold flex items-center space-x-1.5 transition"
              >
                <Trash2 className="w-3.5 h-3.5 text-rose-400" />
                <span>Clear Logs / Visitors</span>
              </button>
            )}
          </div>
        </div>

        {/* Filter Controls */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5 pt-1">
          {/* Search */}
          <div className="relative md:col-span-1">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search endpoint, IP, payload..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono transition"
            />
          </div>

          {/* Telemetry Source Filter */}
          <div className="flex items-center space-x-1 bg-slate-900 p-1 rounded-lg border border-slate-700 text-xs md:col-span-1 overflow-x-auto">
            <span className="text-[10px] text-slate-400 uppercase font-bold px-1.5 whitespace-nowrap">Source:</span>
            {[
              { id: 'REAL_ONLY', label: 'All Real' },
              { id: 'REAL_LIVE_INGEST', label: 'Live Ingest' },
              { id: 'REAL_SERVER_PROBE', label: 'Probes' },
              { id: 'REAL_LOG_FILE', label: 'Server Logs' },
              { id: 'ALL', label: 'Show All' },
            ].map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => setSourceFilter(s.id)}
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition whitespace-nowrap ${
                  sourceFilter === s.id
                    ? s.id === 'REAL_ONLY' || s.id === 'REAL_LIVE_INGEST'
                      ? 'bg-emerald-600 text-white'
                      : s.id === 'REAL_SERVER_PROBE'
                      ? 'bg-cyan-600 text-white'
                      : s.id === 'REAL_LOG_FILE'
                      ? 'bg-blue-600 text-white'
                      : 'bg-slate-700 text-cyan-400'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>

          {/* Severity Filter */}
          <div className="flex items-center space-x-1 bg-slate-900 p-1 rounded-lg border border-slate-700 text-xs">
            <span className="text-[10px] text-slate-400 uppercase font-bold px-1.5">Sev:</span>
            {['ALL', 'NORMAL', 'SUSPICIOUS', 'CRITICAL'].map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition ${
                  severityFilter === sev
                    ? sev === 'CRITICAL'
                      ? 'bg-rose-500 text-white'
                      : sev === 'SUSPICIOUS'
                      ? 'bg-amber-500 text-black'
                      : 'bg-cyan-600 text-white'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Method Filter */}
          <div className="flex items-center space-x-1 bg-slate-900 p-1 rounded-lg border border-slate-700 text-xs">
            <span className="text-[10px] text-slate-400 uppercase font-bold px-1.5">Method:</span>
            {['ALL', 'GET', 'POST'].map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMethodFilter(m)}
                className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold transition ${
                  methodFilter === m
                    ? 'bg-slate-700 text-cyan-400 font-bold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Real-Time Log Table */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/90 text-slate-400 text-[11px] uppercase tracking-wider">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Telemetry Source</th>
                <th className="py-2.5 px-3">Method</th>
                <th className="py-2.5 px-3">Endpoint</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Client / Source IP</th>
                <th className="py-2.5 px-3">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400 font-sans">
                    <div className="space-y-4 max-w-md mx-auto p-4">
                      <div className="w-12 h-12 rounded-full bg-emerald-950/80 border border-emerald-500/40 mx-auto flex items-center justify-center text-emerald-400">
                        <Radio className="w-6 h-6 animate-pulse" />
                      </div>
                      <div className="space-y-1">
                        <div className="font-bold text-slate-200 text-sm">
                          {target && !target.isLab
                            ? `Active Collector Listening for ${target.hostname}`
                            : 'No log events match current filters'}
                        </div>
                        <p className="text-xs text-slate-400">
                          {target && !target.isLab
                            ? 'Synthetic fake logs are disabled for real websites. Send an instant real test ping or probe the server to start recording genuine telemetry.'
                            : 'Adjust your search and severity filters above to view logs.'}
                        </p>
                      </div>

                      {target && !target.isLab && (
                        <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
                          <button
                            type="button"
                            onClick={handleSendRealTestPing}
                            disabled={isSendingPing}
                            className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs shadow-md transition inline-flex items-center space-x-1.5"
                          >
                            <Send className="w-3.5 h-3.5" />
                            <span>{isSendingPing ? 'Sending...' : 'Send Real Live Test Ping'}</span>
                          </button>
                          <button
                            type="button"
                            onClick={handleLiveProbe}
                            disabled={isProbing}
                            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs border border-slate-700 transition inline-flex items-center space-x-1.5"
                          >
                            <Radio className="w-3.5 h-3.5 text-cyan-400" />
                            <span>{isProbing ? 'Probing...' : 'Probe Live Server'}</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => {
                  const isRealIngest = log.logSource === 'REAL_LIVE_INGEST';
                  const isRealProbe = log.logSource === 'REAL_SERVER_PROBE';
                  const isSimulated = log.logSource === 'SIMULATION';

                  return (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedLog(log)}
                      className="hover:bg-slate-800/50 cursor-pointer transition select-none group"
                    >
                      <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{log.displayTime}</td>

                      {/* Source Badge */}
                      <td className="py-2 px-3 whitespace-nowrap">
                        {isRealIngest && (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-500/40">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                            <span>REAL INGEST</span>
                          </span>
                        )}
                        {isRealProbe && (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/40">
                            <Activity className="w-3 h-3 text-cyan-400" />
                            <span>REAL PROBE</span>
                          </span>
                        )}
                        {log.logSource === 'REAL_LOG_FILE' && (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950/80 text-blue-300 border border-blue-500/40">
                            <FileText className="w-3 h-3 text-blue-400" />
                            <span>SERVER LOG</span>
                          </span>
                        )}
                        {isSimulated && (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950/50 text-purple-300 border border-purple-500/30">
                            <span>SIMULATED</span>
                          </span>
                        )}
                        {!log.logSource && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400">
                            EVENT
                          </span>
                        )}
                      </td>

                      <td className="py-2 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            log.method === 'GET'
                              ? 'bg-cyan-950 text-cyan-400 border border-cyan-800'
                              : log.method === 'POST'
                              ? 'bg-indigo-950 text-indigo-400 border border-indigo-800'
                              : 'bg-slate-800 text-slate-300'
                          }`}
                        >
                          {log.method}
                        </span>
                      </td>

                      <td className="py-2 px-3 text-slate-200 max-w-xs truncate font-medium group-hover:text-cyan-300">
                        {log.endpoint}
                      </td>

                      <td className="py-2 px-3">
                        <span
                          className={`font-bold ${
                            log.status >= 500
                              ? 'text-rose-400'
                              : log.status === 401 || log.status === 403
                              ? 'text-amber-400'
                              : log.status === 404
                              ? 'text-slate-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {log.status}
                        </span>
                      </td>

                      <td className="py-2 px-3 whitespace-nowrap">
                        <div className="flex items-center space-x-1.5">
                          <span className="font-mono text-cyan-300 font-semibold">{log.sourceIp}</span>
                          {log.clientGeo?.device && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700 font-sans">
                              {log.clientGeo.device}
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="py-2 px-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            log.severity === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                              : log.severity === 'SUSPICIOUS'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                              : 'bg-slate-800/80 text-slate-400 border border-slate-700/60'
                          }`}
                        >
                          {log.severity}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Modal */}
      {selectedLog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in font-sans">
          <div className="bg-[#0f172a] border border-slate-700 w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span
                  className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase ${
                    selectedLog.severity === 'CRITICAL'
                      ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
                      : selectedLog.severity === 'SUSPICIOUS'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                      : 'bg-slate-800 text-slate-300'
                  }`}
                >
                  {selectedLog.severity}
                </span>

                {selectedLog.logSource && (
                  <span
                    className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase border ${
                      selectedLog.logSource === 'REAL_LIVE_INGEST'
                        ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40'
                        : selectedLog.logSource === 'REAL_SERVER_PROBE'
                        ? 'bg-cyan-950/80 text-cyan-300 border-cyan-500/40'
                        : 'bg-purple-950/50 text-purple-300 border-purple-500/30'
                    }`}
                  >
                    {selectedLog.logSource.replace(/_/g, ' ')}
                  </span>
                )}

                <h3 className="text-sm font-bold text-slate-100 font-mono">
                  {selectedLog.method} {selectedLog.endpoint}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-800 transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4 max-h-[80vh] overflow-y-auto font-mono text-xs">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 rounded-lg bg-slate-900 border border-slate-800">
                <div>
                  <span className="text-[10px] uppercase text-slate-400 font-bold block">TIMESTAMP</span>
                  <span className="text-slate-200">{selectedLog.displayTime}</span>
                </div>
                <div>
                  <span className="text-[10px] uppercase text-slate-400 font-bold block">HTTP STATUS</span>
                  <span
                    className={`font-bold ${
                      selectedLog.status >= 500
                        ? 'text-rose-400'
                        : selectedLog.status === 401 || selectedLog.status === 403
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {selectedLog.status}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] uppercase text-slate-400 font-bold block">SOURCE / CLIENT IP</span>
                  <div className="flex items-center space-x-1.5">
                    <span className="text-cyan-300 font-bold">{selectedLog.sourceIp}</span>
                    {selectedLog.clientGeo?.device && (
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {selectedLog.clientGeo.device}
                      </span>
                    )}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] uppercase text-slate-400 font-bold block">ROUNDTRIP</span>
                  <span className="text-slate-200">{selectedLog.latencyMs}ms</span>
                </div>
              </div>

              <div>
                <span className="text-[10px] uppercase text-slate-400 font-bold block mb-1">USER AGENT</span>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 break-all">
                  {selectedLog.userAgent}
                </div>
              </div>

              {selectedLog.flagReason && (
                <div>
                  <span className="text-[10px] uppercase text-amber-400 font-bold block mb-1">
                    VERIFICATION / FLAG REASON
                  </span>
                  <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-500/40 text-amber-300">
                    {selectedLog.flagReason}
                  </div>
                </div>
              )}

              {selectedLog.payloadSnippet && (
                <div>
                  <span className="text-[10px] uppercase text-slate-400 font-bold block mb-1">PAYLOAD SNIPPET</span>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-rose-300 break-all">
                    {selectedLog.payloadSnippet}
                  </div>
                </div>
              )}

              {selectedLog.headers && Object.keys(selectedLog.headers).length > 0 && (
                <div>
                  <span className="text-[10px] uppercase text-slate-400 font-bold block mb-1">
                    CAPTURED HTTP HEADERS
                  </span>
                  <div className="p-2.5 rounded-lg bg-black/60 border border-slate-800 text-slate-300 space-y-1">
                    {Object.entries(selectedLog.headers).map(([key, val]) => (
                      <div key={key} className="flex">
                        <span className="text-cyan-400 mr-2 font-semibold">{key}:</span>
                        <span className="text-slate-300 break-all">{val}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedLog.probeDetails && (
                <div>
                  <span className="text-[10px] uppercase text-cyan-400 font-bold block mb-1">
                    SERVER PROBE DETAILS
                  </span>
                  <div className="p-2.5 rounded-lg bg-cyan-950/20 border border-cyan-500/30 text-cyan-200 space-y-1">
                    {selectedLog.probeDetails.serverHeader && (
                      <div>Server: <span className="text-white font-bold">{selectedLog.probeDetails.serverHeader}</span></div>
                    )}
                    {selectedLog.probeDetails.title && (
                      <div>HTML Title: <span className="text-white font-bold">{selectedLog.probeDetails.title}</span></div>
                    )}
                    <div>Transport Protocol: <span className="text-white font-bold">{selectedLog.probeDetails.protocol || 'HTTPS'}</span></div>
                    <div>HSTS Active: <span className="text-white font-bold">{selectedLog.probeDetails.hsts ? 'Yes' : 'No'}</span></div>
                    <div>CSP Active: <span className="text-white font-bold">{selectedLog.probeDetails.csp ? 'Yes' : 'No'}</span></div>
                  </div>
                </div>
              )}

              <div className="pt-2 flex justify-between items-center">
                <span className="text-[11px] text-slate-400 font-sans">ID: {selectedLog.id}</span>
                <button
                  type="button"
                  onClick={() => copyLogJson(selectedLog)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold flex items-center space-x-1.5 transition"
                >
                  {copiedPayload ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedPayload ? 'JSON Copied' : 'Copy Event JSON'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
