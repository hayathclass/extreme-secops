import React, { useState } from 'react';
import { Target } from '../types/security';
import {
  ShieldAlert,
  Activity,
  Terminal,
  AlertTriangle,
  FolderGit2,
  Bot,
  FileText,
  ChevronDown,
  Globe,
  Radio,
  Cpu,
} from 'lucide-react';

interface HeaderProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  targets: Target[];
  selectedTarget: Target | null;
  onSelectTarget: (target: Target) => void;
  onOpenConnectModal: () => void;
  logCount?: number;
  threatCount?: number;
  incidentCount?: number;
  isStreaming?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  setCurrentTab,
  targets,
  selectedTarget,
  onSelectTarget,
  onOpenConnectModal,
  logCount = 0,
  threatCount = 0,
  incidentCount = 0,
  isStreaming = true,
}) => {
  const [dropdownOpen, setDropdownOpen] = useState(false);

  return (
    <header className="sticky top-0 z-40 bg-[#06090e]/85 backdrop-blur-xl border-b border-white/[0.08] shadow-2xl shadow-black/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Name */}
          <div className="flex items-center space-x-3 sm:space-x-5">
            <div
              className="flex items-center space-x-2.5 cursor-pointer group"
              onClick={() => setCurrentTab('dashboard')}
            >
              <div className="relative w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-950/80 to-slate-900 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-900/40 group-hover:border-cyan-400 group-hover:shadow-cyan-500/20 transition">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
                <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400 animate-ping opacity-75" />
                <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-400" />
              </div>
              <div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-base sm:text-lg font-black tracking-widest text-slate-100 font-mono">
                    EXTREME
                  </span>
                  <span className="text-[9px] uppercase tracking-widest px-1.5 py-0.5 rounded font-mono font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                    SEC-OPS
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 font-mono tracking-wider hidden sm:block">
                  TACTICAL THREAT SURVEILLANCE
                </p>
              </div>
            </div>

            {/* Target Selector Dropdown */}
            {selectedTarget && (
              <div className="relative pl-3 sm:pl-4 border-l border-white/[0.08]">
                <button
                  type="button"
                  onClick={() => setDropdownOpen(!dropdownOpen)}
                  className="flex items-center space-x-2 px-2.5 py-1.5 rounded-lg bg-slate-900/90 border border-white/[0.08] hover:border-cyan-500/40 transition text-left"
                >
                  <div className="flex flex-col">
                    <span className="text-[8px] uppercase font-bold text-slate-400 tracking-wider font-mono">
                      SURVEILLANCE NODE
                    </span>
                    <span className="text-xs font-mono font-medium text-slate-200 truncate max-w-[140px] sm:max-w-[200px]">
                      {selectedTarget.hostname}
                    </span>
                  </div>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 ml-1" />
                </button>

                {dropdownOpen && (
                  <div className="absolute left-3 sm:left-4 mt-1.5 w-80 rounded-xl bg-[#090e17] border border-white/[0.1] shadow-2xl shadow-black/90 py-1.5 z-50 animate-fade-in font-sans">
                    <div className="px-3 py-1.5 border-b border-white/[0.06] text-[10px] font-bold uppercase text-slate-400 font-mono tracking-wider flex items-center justify-between">
                      <span>Monitored Fleet</span>
                      <span className="text-cyan-400">{targets.length} Nodes</span>
                    </div>
                    {targets.map((t) => (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => {
                          onSelectTarget(t);
                          setDropdownOpen(false);
                        }}
                        className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-800/60 transition ${
                          t.id === selectedTarget.id
                            ? 'bg-cyan-950/40 text-cyan-300 font-semibold border-l-2 border-cyan-400'
                            : 'text-slate-300'
                        }`}
                      >
                        <div className="flex flex-col truncate pr-2">
                          <span className="font-mono text-xs truncate">{t.hostname}</span>
                          <span className="text-[10px] text-slate-500 truncate">{t.url}</span>
                        </div>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 shrink-0">
                          ONLINE
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Right Status Badges & Action Buttons */}
          <div className="flex items-center space-x-2 sm:space-x-3">
            {selectedTarget && (
              <>
                {/* Target Status indicator */}
                <div className="hidden md:flex items-center space-x-2 px-2.5 py-1 rounded-lg bg-black/40 border border-white/[0.08] text-xs font-mono">
                  <span
                    className={`inline-block w-2 h-2 rounded-full ${
                      isStreaming ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
                    }`}
                  />
                  <span className="text-[10px] uppercase tracking-wider text-slate-300">
                    {isStreaming ? 'STREAM: 24/7' : 'PAUSED'}
                  </span>
                  <span className="text-slate-600">|</span>
                  <span className="text-[10px] text-cyan-400">
                    {selectedTarget.lastProbeLatencyMs || 18}ms
                  </span>
                </div>

                {/* Real Data Badge */}
                <div className="px-2.5 py-1 rounded-lg text-xs font-mono font-bold tracking-wider flex items-center space-x-1.5 border bg-emerald-950/20 border-emerald-500/30 text-emerald-300">
                  <Radio className="w-3 h-3 text-emerald-400 animate-pulse" />
                  <span className="text-[10px]">LIVE RECON</span>
                </div>
              </>
            )}

            {/* Single Primary Action: Connect / Audit Website */}
            <button
              type="button"
              onClick={onOpenConnectModal}
              title="Connect an authorized website domain or probe live security headers"
              className="px-3.5 py-1.5 rounded-lg text-xs font-bold font-mono bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white flex items-center space-x-1.5 transition shadow-lg shadow-cyan-950/80 border border-cyan-400/30 active:scale-95"
            >
              <Globe className="w-3.5 h-3.5 text-white" />
              <span>+ Audit Target</span>
            </button>
          </div>
        </div>

        {/* Tactical Navigation Tabs */}
        <div className="flex space-x-1 overflow-x-auto py-1 scrollbar-none border-t border-white/[0.06]">
          {[
            { id: 'dashboard', label: '01 // OVERVIEW', icon: Activity, count: null },
            { id: 'logs', label: '02 // LIVE WIRE', icon: Terminal, count: logCount },
            {
              id: 'threats',
              label: '03 // THREAT RADAR',
              icon: AlertTriangle,
              count: threatCount,
              alert: threatCount > 0,
            },
            { id: 'incidents', label: '04 // INCIDENTS', icon: FolderGit2, count: incidentCount },
            { id: 'analyst', label: '05 // EXTREME ANALYST', icon: Bot, count: null },
            { id: 'report', label: '06 // INTEL REPORT', icon: FileText, count: null },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setCurrentTab(tab.id)}
                className={`flex items-center space-x-2 px-3 py-2 text-xs font-mono font-semibold rounded-t-md transition whitespace-nowrap border-b-2 ${
                  active
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/30'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${active ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
                {tab.count !== null && tab.count !== undefined && (
                  <span
                    className={`ml-1 text-[9px] px-1.5 py-0.2 rounded font-mono font-bold ${
                      tab.alert
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40 animate-pulse'
                        : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};

