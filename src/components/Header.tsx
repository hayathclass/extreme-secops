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
  PlusCircle,
  ChevronDown,
  Globe,
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
    <header className="sticky top-0 z-40 bg-[#090d14]/95 backdrop-blur-md border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Name */}
          <div className="flex items-center space-x-3 sm:space-x-5">
            <div
              className="flex items-center space-x-2.5 cursor-pointer group"
              onClick={() => setCurrentTab('dashboard')}
            >
              <div className="w-9 h-9 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-900/30 group-hover:border-cyan-400 transition">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
              </div>
              <div>
                <div className="flex items-baseline space-x-2">
                  <span className="text-lg font-extrabold tracking-wider text-slate-100 font-mono">
                    EXTREME
                  </span>
                  <span className="text-[10px] uppercase tracking-widest px-1.5 py-0.5 rounded bg-cyan-950/60 text-cyan-400 font-bold border border-cyan-700/50">
                    SEC-OPS
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-normal tracking-wide hidden sm:block">
                  Monitor. Detect. Understand. Respond.
                </p>
              </div>
            </div>

            {/* Target Selector Dropdown */}
            {selectedTarget && (
              <div className="relative pl-3 sm:pl-4 border-l border-slate-800">
                <button
                  type="button"
                  onClick={() => setDropdownOpen(!dropdownOpen)}
                  className="flex items-center space-x-2 px-2.5 py-1.5 rounded-md bg-slate-900/90 border border-slate-700/80 hover:border-slate-600 transition text-left"
                >
                  <div className="flex flex-col">
                    <span className="text-[9px] uppercase font-bold text-slate-400 tracking-wider">
                      TARGET
                    </span>
                    <span className="text-xs font-mono font-medium text-slate-200 truncate max-w-[140px] sm:max-w-[180px]">
                      {selectedTarget.hostname}
                    </span>
                  </div>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400 ml-1" />
                </button>

                {dropdownOpen && (
                  <div className="absolute left-3 sm:left-4 mt-1.5 w-72 rounded-lg bg-[#0f172a] border border-slate-700 shadow-2xl shadow-black/80 py-1.5 z-50 animate-fade-in font-sans">
                    <div className="px-3 py-1.5 border-b border-slate-800 text-[10px] font-bold uppercase text-slate-400 tracking-wider">
                      Select Monitored Website
                    </div>
                    {targets.map((t) => (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => {
                          onSelectTarget(t);
                          setDropdownOpen(false);
                        }}
                        className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-800/80 transition ${
                          t.id === selectedTarget.id
                            ? 'bg-cyan-950/50 text-cyan-300 font-medium'
                            : 'text-slate-300'
                        }`}
                      >
                        <span className="font-mono truncate">{t.hostname}</span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          REAL
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
                <div className="hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs">
                  <span
                    className={`inline-block w-2 h-2 rounded-full ${
                      isStreaming ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
                    }`}
                  />
                  <span className="text-[11px] font-mono uppercase tracking-wide text-slate-300">
                    {isStreaming ? 'MONITORING' : 'PAUSED'}
                  </span>
                </div>

                {/* Real Data Badge */}
                <div className="px-2.5 py-1 rounded text-xs font-mono font-bold tracking-wider flex items-center space-x-1.5 border bg-emerald-950/30 border-emerald-500/40 text-emerald-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  <span className="text-[11px]">REAL TELEMETRY</span>
                </div>
              </>
            )}

            {/* Single Primary Action: Connect / Audit Website */}
            <button
              type="button"
              onClick={onOpenConnectModal}
              title="Connect an authorized website domain or probe live security headers"
              className="px-3.5 py-1.5 rounded-lg text-xs font-bold bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white flex items-center space-x-1.5 transition shadow-md shadow-cyan-950/60 border border-cyan-400/40"
            >
              <Globe className="w-3.5 h-3.5 text-white" />
              <span>Connect / Audit Website</span>
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-1 overflow-x-auto py-1 scrollbar-none border-t border-slate-800/60">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: Activity, count: null },
            { id: 'logs', label: 'Live Logs', icon: Terminal, count: logCount },
            {
              id: 'threats',
              label: 'Threats & Alerts',
              icon: AlertTriangle,
              count: threatCount,
              alert: threatCount > 0,
            },
            { id: 'incidents', label: 'Incidents', icon: FolderGit2, count: incidentCount },
            { id: 'analyst', label: 'Extreme Analyst', icon: Bot, count: null },
            { id: 'report', label: 'Report', icon: FileText, count: null },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setCurrentTab(tab.id)}
                className={`flex items-center space-x-2 px-3 py-2 text-xs font-semibold rounded-t-md transition whitespace-nowrap border-b-2 ${
                  active
                    ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${active ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
                {tab.count !== null && tab.count !== undefined && (
                  <span
                    className={`ml-1 text-[10px] px-1.5 py-0.2 rounded font-mono font-bold ${
                      tab.alert
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40'
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
