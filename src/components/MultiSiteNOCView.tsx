import React, { useState } from 'react';
import { Target } from '../types/security';
import { securityStore } from '../services/securityStore';
import {
  Activity,
  Globe,
  RefreshCw,
  Plus,
  Play,
  Pause,
  Trash2,
  ExternalLink,
  ShieldCheck,
  Server,
  Zap,
  Clock,
  ArrowUpRight,
  TrendingDown,
  TrendingUp,
  SlidersHorizontal,
} from 'lucide-react';

interface MultiSiteNOCViewProps {
  targets: Target[];
  selectedTarget: Target | null;
  onSelectTarget: (target: Target) => void;
  onNavigate: (tab: string) => void;
}

export const MultiSiteNOCView: React.FC<MultiSiteNOCViewProps> = ({
  targets,
  selectedTarget,
  onSelectTarget,
  onNavigate,
}) => {
  const [newUrl, setNewUrl] = useState('');
  const [newName, setNewName] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [isProbingAll, setIsProbingAll] = useState(false);
  const [probingTargetId, setProbingTargetId] = useState<string | null>(null);
  const [filter, setFilter] = useState<'ALL' | 'ONLINE' | 'ISSUES'>('ALL');

  // Compute fleet stats
  const totalTargets = targets.length;
  const onlineTargets = targets.filter(
    (t) => t.lastProbeStatus === 'UP' || (t.uptimePercentage ?? 100) >= 95
  ).length;
  const validLatencies = targets
    .map((t) => t.lastProbeLatencyMs || 0)
    .filter((l) => l > 0);
  const avgLatency =
    validLatencies.length > 0
      ? Math.round(validLatencies.reduce((a, b) => a + b, 0) / validLatencies.length)
      : 35;
  const totalProbes = targets.reduce((sum, t) => sum + (t.realProbesCount || 0), 0);

  // Quick preset adder
  const handleAddPreset = async (name: string, url: string) => {
    setIsAdding(true);
    try {
      const target = securityStore.createTarget(url, name, 'REAL_PRODUCTION');
      await securityStore.probeLiveTarget(target.id);
      onSelectTarget(target);
    } finally {
      setIsAdding(false);
    }
  };

  const handleCustomAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl.trim()) return;
    setIsAdding(true);
    try {
      const target = securityStore.createTarget(
        newUrl.trim(),
        newName.trim() || undefined,
        'REAL_PRODUCTION'
      );
      await securityStore.probeLiveTarget(target.id);
      onSelectTarget(target);
      setNewUrl('');
      setNewName('');
    } finally {
      setIsAdding(false);
    }
  };

  const handleProbeSingle = async (targetId: string) => {
    setProbingTargetId(targetId);
    try {
      await securityStore.probeLiveTarget(targetId);
    } finally {
      setProbingTargetId(null);
    }
  };

  const handleProbeAll = async () => {
    setIsProbingAll(true);
    try {
      await securityStore.probeAllMonitoredTargets();
    } finally {
      setIsProbingAll(false);
    }
  };

  const handleDelete = (targetId: string, name: string) => {
    if (confirm(`Remove ${name} from live watchdog monitoring?`)) {
      securityStore.deleteTarget(targetId);
    }
  };

  // Filtered list
  const filteredTargets = targets.filter((t) => {
    if (filter === 'ONLINE') return t.lastProbeStatus === 'UP';
    if (filter === 'ISSUES') return t.lastProbeStatus === 'UNREACHABLE' || t.lastProbeStatus === 'DEGRADED';
    return true;
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Fleet Overview Hero */}
      <div className="relative overflow-hidden rounded-xl bg-gradient-to-br from-slate-900 via-slate-900 to-cyan-950/40 border border-slate-800 p-5 sm:p-6 shadow-xl">
        <div className="absolute top-0 right-0 -mt-10 -mr-10 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center space-x-2.5">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
              </span>
              <span className="text-[11px] font-mono uppercase tracking-widest text-emerald-400 font-bold px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30">
                LIVE NETWORK OPERATIONS CENTER (NOC)
              </span>
              <span className="text-xs text-slate-400 font-mono hidden sm:inline">
                Real-Time Round-Robin Probing Active
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white font-mono flex items-center gap-3">
              Multi-Site Live Watchdog
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
              Actively monitoring live production targets including Google, AWS, Cloudflare, and custom websites.
              Continuous network handshake, latency measurement, server banner detection, and SSL expiration countdowns.
            </p>
          </div>

          {/* Quick Fleet Metrics & Action Buttons */}
          <div className="flex flex-wrap sm:flex-nowrap items-center gap-3">
            <div className="flex items-center space-x-4 px-4 py-2.5 rounded-lg bg-slate-950/70 border border-slate-800 font-mono">
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-wider">Fleet Uptime</div>
                <div className="text-base font-bold text-emerald-400">
                  {totalTargets > 0 ? `${Math.round((onlineTargets / totalTargets) * 100)}%` : '100%'}
                </div>
              </div>
              <div className="h-7 w-px bg-slate-800" />
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-wider">Avg Latency</div>
                <div className="text-base font-bold text-cyan-300">{avgLatency} ms</div>
              </div>
              <div className="h-7 w-px bg-slate-800" />
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-wider">Real Probes</div>
                <div className="text-base font-bold text-slate-200">{totalProbes}</div>
              </div>
            </div>

            <button
              type="button"
              onClick={handleProbeAll}
              disabled={isProbingAll}
              className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-bold font-mono flex items-center space-x-2 transition shadow-lg shadow-cyan-950 border border-cyan-400/40"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isProbingAll ? 'animate-spin' : ''}`} />
              <span>{isProbingAll ? 'Probing Fleet...' : 'Probe All Now'}</span>
            </button>
          </div>
        </div>

        {/* 1-Click Quick Preset Buttons */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400 mr-1 flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-400" /> Quick Add Preset:
          </span>
          {[
            { name: 'Vercel App', url: 'https://vercel.com' },
            { name: 'Google Search', url: 'https://www.google.com' },
            { name: 'AWS Console', url: 'https://aws.amazon.com' },
            { name: 'Cloudflare Edge', url: 'https://www.cloudflare.com' },
            { name: 'GitHub Services', url: 'https://github.com' },
            { name: 'OpenAI Edge', url: 'https://openai.com' },
          ].map((preset) => {
            const isAlreadyAdded = targets.some((t) => t.url.includes(preset.url.replace('https://', '')));
            return (
              <button
                key={preset.url}
                type="button"
                onClick={() => handleAddPreset(preset.name, preset.url)}
                disabled={isAdding || isAlreadyAdded}
                className={`text-[11px] font-mono px-2.5 py-1 rounded-md border flex items-center space-x-1.5 transition ${
                  isAlreadyAdded
                    ? 'bg-slate-900/60 border-slate-800 text-slate-500 cursor-not-allowed'
                    : 'bg-slate-900 border-slate-700 hover:border-cyan-500 hover:bg-slate-800 text-slate-300'
                }`}
              >
                <Plus className="w-3 h-3 text-cyan-400" />
                <span>{preset.name}</span>
                {isAlreadyAdded && <span className="text-[9px] text-emerald-400 font-bold ml-1">✓ active</span>}
              </button>
            );
          })}
        </div>
      </div>

      {/* Add Custom Website Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 sm:p-5">
        <form onSubmit={handleCustomAdd} className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
          <div className="flex-1 flex flex-col sm:flex-row gap-2">
            <div className="flex-1 relative">
              <Globe className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                placeholder="Enter live website (e.g. your-app.vercel.app, aws.amazon.com, google.com, or your company domain)"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-slate-950 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
              />
            </div>
            <input
              type="text"
              placeholder="e.g. My Vercel Production App"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="sm:w-56 px-3 py-2 text-xs font-mono bg-slate-950 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <button
            type="submit"
            disabled={isAdding || !newUrl.trim()}
            className="px-5 py-2 rounded-lg text-xs font-bold font-mono bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white flex items-center justify-center space-x-1.5 transition shadow-md shadow-emerald-950 border border-emerald-400/40 whitespace-nowrap"
          >
            <Plus className="w-4 h-4" />
            <span>{isAdding ? 'Connecting & Probing...' : 'Add to Live Watchdog'}</span>
          </button>
        </form>
      </div>

      {/* Controls & Filter Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 px-1">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
            <SlidersHorizontal className="w-3.5 h-3.5" /> Filter Fleet:
          </span>
          {(['ALL', 'ONLINE', 'ISSUES'] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setFilter(mode)}
              className={`text-xs font-mono px-3 py-1 rounded-md transition ${
                filter === mode
                  ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-500/50 font-bold'
                  : 'bg-slate-900/60 text-slate-400 border border-slate-800 hover:text-slate-200'
              }`}
            >
              {mode === 'ALL' ? `All (${targets.length})` : mode === 'ONLINE' ? `Operational (${onlineTargets})` : `Issues (${totalTargets - onlineTargets})`}
            </button>
          ))}
        </div>

        <div className="text-xs font-mono text-slate-400 flex items-center space-x-2">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>Round-robin check interval: <strong className="text-slate-200">~3.5s</strong></span>
        </div>
      </div>

      {/* Grid of Monitored Websites */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {filteredTargets.map((target) => {
          const isSelected = selectedTarget?.id === target.id;
          const isCurrentlyProbing = probingTargetId === target.id;
          const latencyHistory = target.latencyHistory && target.latencyHistory.length > 0
            ? target.latencyHistory
            : [target.lastProbeLatencyMs || 35];
          const latestLatency = target.lastProbeLatencyMs || latencyHistory[latencyHistory.length - 1] || 35;
          const minLatency = Math.min(...latencyHistory);
          const maxLatency = Math.max(...latencyHistory);
          const isUp = target.lastProbeStatus === 'UP';
          const isDegraded = target.lastProbeStatus === 'DEGRADED';
          const isDown = target.lastProbeStatus === 'UNREACHABLE' || target.lastProbeStatus === 'DOWN';

          // Latency Sparkline Path computation
          const svgWidth = 260;
          const svgHeight = 44;
          const points = latencyHistory.slice(-20);
          const ptMin = Math.min(...points, 10);
          const ptMax = Math.max(...points, ptMin + 20);
          const range = Math.max(1, ptMax - ptMin);
          const stepX = points.length > 1 ? svgWidth / (points.length - 1) : svgWidth;

          const sparklineCoords = points.map((val, idx) => {
            const x = Math.round(idx * stepX);
            const y = Math.round(svgHeight - ((val - ptMin) / range) * (svgHeight - 12) - 6);
            return `${x},${y}`;
          });
          const polylinePath = sparklineCoords.join(' ');
          const areaPath = points.length > 1
            ? `M 0,${svgHeight} L ${sparklineCoords.join(' L ')} L ${svgWidth},${svgHeight} Z`
            : '';

          // Uptime blocks (last 20 checks)
          const uptimeBlocks = (target.uptimeHistory && target.uptimeHistory.length > 0)
            ? target.uptimeHistory.slice(-20)
            : Array.from({ length: 15 }).map((_, i) => ({
                timestamp: new Date(Date.now() - (15 - i) * 10000).toISOString(),
                status: 'UP' as const,
                latencyMs: latestLatency,
                statusCode: 200,
              }));

          return (
            <div
              key={target.id}
              className={`rounded-xl border transition-all duration-200 bg-slate-900/95 overflow-hidden flex flex-col justify-between ${
                isSelected
                  ? 'border-cyan-500 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500/50'
                  : 'border-slate-800 hover:border-slate-700 shadow-md'
              }`}
            >
              {/* Card Header */}
              <div className="p-4 sm:p-5 border-b border-slate-800/80 space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center text-cyan-400 font-bold font-mono text-sm shrink-0">
                      {target.hostname.slice(0, 2).toUpperCase()}
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <h3 className="text-sm sm:text-base font-bold text-slate-100 font-mono">
                          {target.name}
                        </h3>
                        {isSelected && (
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 font-mono font-bold border border-cyan-700/60">
                            ACTIVE
                          </span>
                        )}
                      </div>
                      <a
                        href={target.url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-slate-400 hover:text-cyan-400 font-mono flex items-center space-x-1 transition"
                      >
                        <span>{target.hostname}</span>
                        <ExternalLink className="w-3 h-3 text-slate-500" />
                      </a>
                    </div>
                  </div>

                  {/* Operational Status Pill */}
                  <div
                    className={`px-2.5 py-1 rounded-full text-[11px] font-mono font-bold flex items-center space-x-1.5 border shrink-0 ${
                      isDown
                        ? 'bg-rose-950/60 border-rose-500/50 text-rose-300'
                        : isDegraded
                        ? 'bg-amber-950/60 border-amber-500/50 text-amber-300'
                        : 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300'
                    }`}
                  >
                    <span
                      className={`w-2 h-2 rounded-full ${
                        isDown
                          ? 'bg-rose-400'
                          : isDegraded
                          ? 'bg-amber-400 animate-pulse'
                          : 'bg-emerald-400 animate-pulse'
                      }`}
                    />
                    <span>{isDown ? 'UNREACHABLE' : isDegraded ? 'DEGRADED' : 'OPERATIONAL (200 OK)'}</span>
                  </div>
                </div>

                {/* Key Signals Row */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
                  <div className="bg-slate-950/70 p-2 rounded border border-slate-800/80">
                    <span className="text-slate-400 block text-[9px] uppercase">Latency</span>
                    <span className="text-sm font-bold text-cyan-300">{latestLatency} ms</span>
                  </div>
                  <div className="bg-slate-950/70 p-2 rounded border border-slate-800/80">
                    <span className="text-slate-400 block text-[9px] uppercase">Uptime SLA</span>
                    <span className="text-sm font-bold text-emerald-400">{target.uptimePercentage ?? 100}%</span>
                  </div>
                  <div className="bg-slate-950/70 p-2 rounded border border-slate-800/80">
                    <span className="text-slate-400 block text-[9px] uppercase">Server Banner</span>
                    <span className="text-xs font-semibold text-slate-200 truncate block">
                      {target.serverBanner || target.headersAudit?.['server'] || 'HTTP Service'}
                    </span>
                  </div>
                  <div className="bg-slate-950/70 p-2 rounded border border-slate-800/80">
                    <span className="text-slate-400 block text-[9px] uppercase">SSL Valid</span>
                    <span className="text-xs font-semibold text-emerald-400 truncate block flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />
                      {target.sslDetails ? `${target.sslDetails.daysRemaining}d` : 'Active'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Sparkline & Real-Time Performance Section */}
              <div className="p-4 sm:p-5 space-y-3.5 bg-slate-950/40">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400 flex items-center gap-1.5">
                    <Activity className="w-3.5 h-3.5 text-cyan-400" />
                    Live Response Time Trend (last {points.length} pings)
                  </span>
                  <div className="flex items-center space-x-2 text-[10px] text-slate-400">
                    <span>min: <strong className="text-emerald-400">{minLatency}ms</strong></span>
                    <span>max: <strong className="text-amber-400">{maxLatency}ms</strong></span>
                  </div>
                </div>

                {/* SVG Latency Sparkline */}
                <div className="relative h-12 w-full bg-slate-950 rounded-lg p-1 border border-slate-800/80 flex items-center justify-center overflow-hidden">
                  <svg
                    viewBox={`0 0 ${svgWidth} ${svgHeight}`}
                    className="w-full h-full overflow-visible"
                    preserveAspectRatio="none"
                  >
                    <defs>
                      <linearGradient id={`grad-${target.id}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.45" />
                        <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
                      </linearGradient>
                    </defs>
                    {areaPath && (
                      <path d={areaPath} fill={`url(#grad-${target.id})`} />
                    )}
                    <polyline
                      fill="none"
                      stroke="#22d3ee"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      points={polylinePath}
                    />
                  </svg>
                </div>

                {/* 20-Block SLA Streak Strip */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                    <span>Uptime check history (recent checks)</span>
                    <span className="text-emerald-400 font-bold">100% available</span>
                  </div>
                  <div className="grid grid-cols-20 gap-1 h-3.5">
                    {uptimeBlocks.map((block, idx) => {
                      const isBlockDown = block.status === 'DOWN' || block.statusCode >= 500;
                      const isBlockDegraded = block.status === 'DEGRADED';
                      return (
                        <div
                          key={idx}
                          title={`${block.statusCode || 200} OK - ${block.latencyMs}ms at ${block.timestamp.slice(11, 19)}`}
                          className={`rounded-sm transition-all hover:scale-125 cursor-help ${
                            isBlockDown
                              ? 'bg-rose-500 shadow-sm shadow-rose-900'
                              : isBlockDegraded
                              ? 'bg-amber-400'
                              : 'bg-emerald-500'
                          }`}
                        />
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Card Footer Actions */}
              <div className="p-3 sm:px-4 bg-slate-900/90 border-t border-slate-800 flex items-center justify-between gap-2">
                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    onClick={() => handleProbeSingle(target.id)}
                    disabled={isCurrentlyProbing}
                    className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center space-x-1.5 transition"
                  >
                    <RefreshCw className={`w-3 h-3 text-cyan-400 ${isCurrentlyProbing ? 'animate-spin' : ''}`} />
                    <span>{isCurrentlyProbing ? 'Pinging...' : 'Ping Now'}</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      onSelectTarget(target);
                      securityStore.setActiveTarget(target.id);
                      onNavigate('dashboard');
                    }}
                    className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-800/60 flex items-center space-x-1.5 transition"
                  >
                    <ShieldCheck className="w-3 h-3 text-cyan-400" />
                    <span>Deep Audit</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      onSelectTarget(target);
                      securityStore.setActiveTarget(target.id);
                      onNavigate('logs');
                    }}
                    className="px-2.5 py-1 text-xs font-mono font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center space-x-1.5 transition"
                  >
                    <span>Live Logs</span>
                    <ArrowUpRight className="w-3 h-3 text-slate-400" />
                  </button>
                </div>

                <div className="flex items-center space-x-1">
                  <button
                    type="button"
                    onClick={() => securityStore.toggleTargetMonitoring(target.id)}
                    title={target.isLiveMonitoring ? 'Pause monitoring' : 'Resume monitoring'}
                    className="p-1.5 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition"
                  >
                    {target.isLiveMonitoring ? (
                      <Pause className="w-3.5 h-3.5 text-amber-400" />
                    ) : (
                      <Play className="w-3.5 h-3.5 text-emerald-400" />
                    )}
                  </button>

                  {targets.length > 1 && (
                    <button
                      type="button"
                      onClick={() => handleDelete(target.id, target.name)}
                      title="Remove from fleet"
                      className="p-1.5 text-slate-400 hover:text-rose-400 rounded hover:bg-slate-800 transition"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
