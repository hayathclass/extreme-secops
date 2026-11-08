import React, { useState, useEffect } from 'react';
import { Target, LogEvent, ThreatDetection, Incident } from './types/security';
import { securityStore } from './services/securityStore';
import { Header } from './components/Header';
import { ConnectTargetModal } from './components/ConnectTargetModal';
import { IngestTesterModal } from './components/IngestTesterModal';
import { DashboardView } from './components/DashboardView';
import { LiveLogsView } from './components/LiveLogsView';
import { ThreatsAlertsView } from './components/ThreatsAlertsView';
import { IncidentsView } from './components/IncidentsView';
import { ExtremeAnalystView } from './components/ExtremeAnalystView';
import { ReportView } from './components/ReportView';

export default function App() {
  const [targets, setTargets] = useState<Target[]>(securityStore.getTargets());
  const [selectedTarget, setSelectedTarget] = useState<Target | null>(targets[0] || null);
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [isConnectModalOpen, setIsConnectModalOpen] = useState(false);
  const [isIngestModalOpen, setIsIngestModalOpen] = useState(false);
  const [isStreaming, setIsStreaming] = useState(securityStore.getAutoStreamActive());

  // Synchronize with store
  useEffect(() => {
    if (selectedTarget) {
      securityStore.setActiveTarget(selectedTarget.id);
    }
  }, [selectedTarget?.id]);

  useEffect(() => {
    const unsubscribe = securityStore.subscribe(() => {
      const allTargets = securityStore.getTargets();
      setTargets(allTargets);
      setIsStreaming(securityStore.getAutoStreamActive());
      const activeId = securityStore.getActiveTargetId();
      if (activeId) {
        const active = securityStore.getTarget(activeId);
        if (active) {
          setSelectedTarget(active);
          return;
        }
      }
      if (selectedTarget) {
        const updated = securityStore.getTarget(selectedTarget.id);
        if (updated) setSelectedTarget(updated);
      } else if (allTargets.length > 0) {
        setSelectedTarget(allTargets[0]);
      }
    });
    return unsubscribe;
  }, [selectedTarget?.id]);

  const logs = selectedTarget ? securityStore.getLogs(selectedTarget.id, { limit: 300 }) : [];
  const threats = selectedTarget ? securityStore.getThreats(selectedTarget.id) : [];
  const incidents = selectedTarget ? securityStore.getIncidents(selectedTarget.id) : [];

  const handleTargetCreated = (newTarget: Target) => {
    securityStore.setActiveTarget(newTarget.id);
    setSelectedTarget(newTarget);
    setCurrentTab('dashboard');
  };

  const handleUpdateIncidentStatus = (incidentId: string, status: Incident['status']) => {
    if (!selectedTarget) return;
    securityStore.updateIncidentStatus(selectedTarget.id, incidentId, status);
  };

  const handleTriggerRealLogSample = async () => {
    if (!selectedTarget) return;
    const sample = securityStore.getSampleNginxAccessLog();
    await securityStore.parseRealLogFile(selectedTarget.id, sample);
  };

  const handleSendRealLiveHit = async () => {
    if (!selectedTarget) return;
    const realIp = await securityStore.resolveCurrentClientIp();
    await securityStore.sendRealIngestEvent(selectedTarget.id, {
      method: 'GET',
      endpoint: '/api/v1/health',
      status: 200,
      eventType: 'API_REQUEST',
      latencyMs: 16,
      sourceIp: realIp,
      payloadSnippet: 'telemetry_probe: client_verification_ok',
      flagReason: `Verified live HTTP request from ${realIp}`,
    });
  };

  const handleDeleteThreat = (threatId: string) => {
    if (!selectedTarget) return;
    securityStore.deleteThreat(selectedTarget.id, threatId);
  };

  const handleClearAllThreats = () => {
    if (!selectedTarget) return;
    securityStore.clearAllThreats(selectedTarget.id);
  };

  const handleToggleStreaming = () => {
    const newState = securityStore.toggleAutoStream();
    setIsStreaming(newState);
  };

  return (
    <div className="min-h-screen bg-[#090d14] text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header & Navigation */}
      <Header
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        targets={targets}
        selectedTarget={selectedTarget}
        onSelectTarget={(t) => setSelectedTarget(t)}
        onOpenConnectModal={() => setIsConnectModalOpen(true)}
        logCount={logs.length}
        threatCount={threats.length}
        incidentCount={incidents.filter((i) => i.status !== 'RESOLVED').length}
        isStreaming={isStreaming}
      />

      {/* Main Content Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* View Routing */}
        {selectedTarget ? (
          <>
            {currentTab === 'dashboard' && (
              <DashboardView
                target={selectedTarget}
                logs={logs}
                threats={threats}
                incidents={incidents}
                onNavigate={(tab) => setCurrentTab(tab)}
                onOpenIngestModal={() => setIsIngestModalOpen(true)}
                onSelectTarget={(t) => {
                  setSelectedTarget(t);
                  securityStore.setActiveTarget(t.id);
                }}
              />
            )}

            {currentTab === 'logs' && (
              <LiveLogsView
                logs={logs}
                isStreaming={isStreaming}
                onToggleStreaming={handleToggleStreaming}
                onClearLogs={() => securityStore.clearLogBuffer(selectedTarget.id)}
                target={selectedTarget}
              />
            )}

            {currentTab === 'threats' && (
              <ThreatsAlertsView
                threats={threats}
                target={selectedTarget}
                onNavigateToIncident={(threatId) => setCurrentTab('incidents')}
                onDeleteThreat={handleDeleteThreat}
                onClearAllThreats={handleClearAllThreats}
              />
            )}

            {currentTab === 'incidents' && (
              <IncidentsView
                incidents={incidents}
                onUpdateStatus={handleUpdateIncidentStatus}
              />
            )}

            {currentTab === 'analyst' && (
              <ExtremeAnalystView
                target={selectedTarget}
                logs={logs}
                threats={threats}
                incidents={incidents}
              />
            )}

            {currentTab === 'report' && <ReportView target={selectedTarget} />}
          </>
        ) : (
          <div className="py-20 text-center text-slate-400 font-mono text-xs">
            Loading EXTREME target environment...
          </div>
        )}
      </main>

      {/* Target Connection & Live Audit Modal */}
      <ConnectTargetModal
        isOpen={isConnectModalOpen}
        onClose={() => setIsConnectModalOpen(false)}
        onTargetCreated={handleTargetCreated}
        defaultUrl={selectedTarget?.url}
      />

      {/* Ingestion Tester Modal */}
      {selectedTarget && (
        <IngestTesterModal
          isOpen={isIngestModalOpen}
          onClose={() => setIsIngestModalOpen(false)}
          target={selectedTarget}
        />
      )}
    </div>
  );
}
