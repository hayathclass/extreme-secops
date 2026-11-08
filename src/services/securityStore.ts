import {
  LogEvent,
  Target,
  ThreatDetection,
  Incident,
  Remediation,
  SecurityReport,
  HttpMethod,
  EventType,
  EventSeverity,
  IncidentTimelineStep,
  LogSource,
  TelemetryMode,
  VisitorPerson,
} from '../types/security';

class SecurityStore {
  private targets: Target[] = [];
  private logs: Map<string, LogEvent[]> = new Map();
  private threats: Map<string, ThreatDetection[]> = new Map();
  private incidents: Map<string, Incident[]> = new Map();
  private listeners: Set<() => void> = new Set();
  private isAutoStreamActive = true;
  private streamInterval: any = null;
  private activeTargetId: string | null = null;
  private streamTick = 0;
  private lastFetchedEventTime: string = new Date(Date.now() - 3600000).toISOString();
  private isPollingCollector = false;

  constructor() {
    this.initDefaultData();
    this.startAutoStream();
  }

  private notify() {
    this.listeners.forEach((cb) => cb());
  }

  public subscribe(cb: () => void) {
    this.listeners.add(cb);
    return () => {
      this.listeners.delete(cb);
    };
  }

  private initDefaultData() {
    const defaultSites = [
      {
        id: 'target-atc-simulator',
        name: 'ATC Online Simulator',
        url: 'https://atc-onlinesimulator.onrender.com',
        hostname: 'atc-onlinesimulator.onrender.com',
        serverBanner: 'Render / Cloudflare',
        lastProbeLatencyMs: 42,
      },
    ];

    const initialTargets: Target[] = defaultSites.map((site) => ({
      id: site.id,
      name: site.name,
      url: site.url,
      hostname: site.hostname,
      isLab: false,
      connectedAt: new Date().toISOString(),
      status: 'MONITORING',
      apiKey: `ext_live_${Math.random().toString(36).substring(2, 10)}_${Date.now().toString(36)}`,
      totalRequests: 1,
      securityEventsCount: 0,
      threatsCount: 0,
      openIncidentsCount: 0,
      sourceType: 'REAL_PRODUCTION',
      telemetryMode: 'REAL_ONLY',
      realEventsCount: 1,
      realProbesCount: 1,
      customEndpoints: [
        '/',
        '/robots.txt',
        '/.well-known/security.txt',
        '/api/health',
      ],
      lastProbeStatus: 'UP',
      lastProbeLatencyMs: site.lastProbeLatencyMs,
      serverBanner: site.serverBanner,
      isLiveMonitoring: true,
      monitoringIntervalSeconds: 10,
      uptimePercentage: 100,
      latencyHistory: [site.lastProbeLatencyMs],
      uptimeHistory: [
        {
          timestamp: new Date().toISOString(),
          status: 'UP',
          latencyMs: site.lastProbeLatencyMs,
          statusCode: 200,
        },
      ],
    }));

    this.targets = initialTargets;
    this.activeTargetId = initialTargets[0].id;
    initialTargets.forEach((t) => {
      this.logs.set(t.id, []);
      this.threats.set(t.id, []);
      this.incidents.set(t.id, []);
    });

    // Probe first target immediately and schedule initial probes for others
    setTimeout(() => {
      this.probeAllMonitoredTargets().catch(() => {});
      this.deepScanTarget(initialTargets[0].id, initialTargets[0].url).catch(() => {});
    }, 1000);
  }

  public setActiveTarget(id: string): void {
    if (this.activeTargetId !== id) {
      this.activeTargetId = id;
      this.notify();
    }
  }

  public getActiveTargetId(): string | null {
    return this.activeTargetId;
  }

  public setTargetTelemetryMode(targetId: string, mode: TelemetryMode): void {
    const target = this.getTarget(targetId);
    if (target) {
      target.telemetryMode = mode;
      this.notify();
    }
  }

  public toggleTargetMonitoring(targetId: string): void {
    const target = this.getTarget(targetId);
    if (target) {
      target.isLiveMonitoring = !(target.isLiveMonitoring ?? true);
      target.status = target.isLiveMonitoring ? 'MONITORING' : 'IDLE';
      this.notify();
    }
  }

  public deleteTarget(targetId: string): boolean {
    const idx = this.targets.findIndex((t) => t.id === targetId);
    if (idx === -1) return false;
    this.targets.splice(idx, 1);
    this.logs.delete(targetId);
    this.threats.delete(targetId);
    this.incidents.delete(targetId);

    if (this.activeTargetId === targetId) {
      this.activeTargetId = this.targets[0]?.id || null;
    }
    this.notify();
    return true;
  }

  public async probeAllMonitoredTargets(): Promise<void> {
    const monitored = this.targets.filter(
      (t) => t.isLiveMonitoring !== false && t.status !== 'DISCONNECTED'
    );
    await Promise.allSettled(monitored.map((t) => this.probeLiveTarget(t.id)));
    this.notify();
  }

  private startAutoStream() {
    if (this.streamInterval) clearInterval(this.streamInterval);

    // 1. Establish immediate Server-Sent Events (SSE) stream for instant real-time pushes
    try {
      if (typeof window !== 'undefined' && window.EventSource) {
        const sseUrls = ['/api/collector/stream'];
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
          sseUrls.push('https://extreme-secops.onrender.com/api/collector/stream');
        }

        sseUrls.forEach((streamUrl) => {
          try {
            const sse = new EventSource(streamUrl);
            sse.onmessage = (e) => {
              try {
                const data = JSON.parse(e.data);
                if (data && data.type === 'CLEARED') {
                  const clearedTargetId = data.targetId || this.activeTargetId;
                  if (clearedTargetId) {
                    this.logs.set(clearedTargetId, []);
                    const target = this.getTarget(clearedTargetId);
                    if (target) {
                      target.realEventsCount = 0;
                      target.totalRequests = 0;
                      target.securityEventsCount = 0;
                    }
                    this.notify();
                  }
                  return;
                }
                if (data && data.id && data.sourceIp) {
                  const activeId = this.activeTargetId || (this.targets[0] ? this.targets[0].id : null);
                  const targetId = (data.targetId && this.getTarget(data.targetId)) ? data.targetId : activeId;
                  if (targetId) {
                    this.ingestLogs(targetId, [data]);
                    const target = this.getTarget(targetId);
                    if (target) {
                      target.realEventsCount = (target.realEventsCount || 0) + 1;
                      target.totalRequests = (target.totalRequests || 0) + 1;
                    }
                  }
                }
              } catch {}
            };
          } catch {}
        });
      }
    } catch {}

    // 2. Fast background polling loop every 1.5 seconds as a reliable backup
    this.streamInterval = setInterval(async () => {
      if (!this.isAutoStreamActive) return;
      this.streamTick++;

      // Pulse UI updates periodically so active/left timeouts update dynamically in real time
      this.notify();

      // Fetch remote collector events for active target
      const activeId = this.activeTargetId || (this.targets[0] ? this.targets[0].id : null);
      if (activeId) {
        await this.fetchRemoteCollectorEvents(activeId).catch(() => {});
      }

      // Periodic health check against live target fleet every 5 ticks (~7.5s)
      if (this.streamTick % 5 === 0) {
        const monitored = this.targets.filter(
          (t) => t.isLiveMonitoring !== false && t.status !== 'DISCONNECTED'
        );
        if (monitored.length > 0) {
          const targetToProbe = monitored[(this.streamTick / 5) % monitored.length];
          if (targetToProbe?.url) {
            await this.probeLiveTarget(targetToProbe.id).catch(() => {});
          }
        }
      }
    }, 1500);
  }

  public async fetchRemoteCollectorEvents(targetId: string): Promise<void> {
    if (this.isPollingCollector) return;
    this.isPollingCollector = true;
    try {
      const endpoints = [`/api/collector/events?targetId=${encodeURIComponent(targetId)}`];
      if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
        endpoints.push(`https://extreme-secops.onrender.com/api/collector/events?targetId=${encodeURIComponent(targetId)}`);
      }

      for (const endpoint of endpoints) {
        try {
          const res = await fetch(endpoint);
          if (res.ok) {
            const data = await res.json();
            if (data.events && Array.isArray(data.events) && data.events.length > 0) {
              const target = this.getTarget(targetId);
              const currentList = this.logs.get(targetId) || [];
              const currentIds = new Set(currentList.map((e) => e.id));
              const newEvents: LogEvent[] = data.events.filter((e: LogEvent) => !currentIds.has(e.id));
              if (newEvents.length > 0) {
                this.ingestLogs(targetId, newEvents);
                if (target) {
                  target.realEventsCount = (target.realEventsCount || 0) + newEvents.length;
                  target.totalRequests = (target.totalRequests || 0) + newEvents.length;
                }
              }
            }
          }
        } catch {}
      }
    } catch {
      // Ignore background network polling errors
    } finally {
      this.isPollingCollector = false;
    }
  }

  public getVisitorPersons(targetId: string): VisitorPerson[] {
    const list = (this.logs.get(targetId) || []).filter(
      (l) => l.logSource === 'REAL_LIVE_INGEST'
    );
    const now = Date.now();
    const ONLINE_TIMEOUT_MS = 25000;
    const map = new Map<string, VisitorPerson>();

    // Group events by client IP
    const eventsByIp = new Map<string, LogEvent[]>();
    list.forEach((event) => {
      const ip = (event.sourceIp || '127.0.0.1').trim();
      const group = eventsByIp.get(ip) || [];
      group.push(event);
      eventsByIp.set(ip, group);
    });

    eventsByIp.forEach((events, ip) => {
      // Sort newest to oldest for this IP
      events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      const latestEvent = events[0];
      const oldestEvent = events[events.length - 1];
      const isSim = events.some((e) => e.flagReason?.includes('Simulated') || e.payloadSnippet?.includes('simulator'));

      // Find the most recent SESSION_END event for this IP
      const sessionEndEvent = events.find((e) => e.eventType === 'SESSION_END');

      // Find the most recent active user interaction (pageview, heartbeat, click, authentication)
      const latestActiveEvent = events.find(
        (e) =>
          e.eventType === 'PAGEVIEW' ||
          e.eventType === 'HEARTBEAT' ||
          e.eventType === 'USER_INTERACTION' ||
          e.eventType === 'AUTHENTICATION' ||
          (e.eventType === 'API_REQUEST' && !e.endpoint.includes('firestore') && !e.endpoint.includes('firebase'))
      );

      const latestActiveTime = latestActiveEvent ? new Date(latestActiveEvent.timestamp).getTime() : 0;
      const sessionEndTime = sessionEndEvent ? new Date(sessionEndEvent.timestamp).getTime() : 0;

      let isOnline = false;
      let leftAt: string | undefined = undefined;

      // If user reported SESSION_END and no active pageview happened after it: OFFLINE!
      if (sessionEndTime > 0 && sessionEndTime >= (latestActiveTime - 3000)) {
        isOnline = false;
        leftAt = sessionEndEvent?.timestamp;
      } else if (latestActiveTime > 0 && (now - latestActiveTime) < ONLINE_TIMEOUT_MS) {
        // Active and within 25 seconds
        isOnline = true;
      } else {
        // Inactive / timed out
        isOnline = false;
        leftAt = sessionEndEvent?.timestamp || (latestActiveEvent ? latestActiveEvent.timestamp : latestEvent.timestamp);
      }

      map.set(ip, {
        ip,
        device: latestEvent.clientGeo?.device || (latestEvent.userAgent.includes('Mobile') ? 'Mobile Device' : 'Desktop'),
        country: latestEvent.clientGeo?.country,
        city: latestEvent.clientGeo?.city,
        firstSeen: oldestEvent.timestamp,
        lastSeen: latestActiveEvent ? latestActiveEvent.timestamp : latestEvent.timestamp,
        totalHits: events.length,
        lastEndpoint: latestActiveEvent ? `${latestActiveEvent.method} ${latestActiveEvent.endpoint}` : `${latestEvent.method} ${latestEvent.endpoint}`,
        lastStatus: latestEvent.status,
        userAgent: latestEvent.userAgent,
        isSimulated: isSim,
        isOnline,
        leftAt,
      });
    });

    return Array.from(map.values()).sort((a, b) => {
      if (a.isOnline && !b.isOnline) return -1;
      if (!a.isOnline && b.isOnline) return 1;
      return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime();
    });
  }

  public getActiveVisitorsCount(targetId: string): number {
    return this.getVisitorPersons(targetId).filter((p) => p.isOnline).length;
  }

  public async sendVisitorExitSimulation(targetId: string, ip?: string): Promise<LogEvent> {
    const list = this.getVisitorPersons(targetId);
    const targetIp = ip || (list.find((p) => p.isOnline)?.ip) || (list[0]?.ip) || '49.37.150.88';
    return await this.sendRealIngestEvent(targetId, {
      method: 'POST',
      endpoint: '/session/leave',
      status: 200,
      eventType: 'SESSION_END',
      sourceIp: targetIp,
      flagReason: `Visitor from ${targetIp} closed tab / left website (Simulated Exit)`,
    });
  }

  public async sendSecondDeviceSimulation(targetId: string, deviceType: 'mobile' | 'tablet' | 'remote_desktop' = 'mobile'): Promise<LogEvent> {
    const mobileIps = ['49.37.150.88', '182.72.10.45', '103.21.244.12', '152.58.42.19', '157.34.120.91'];
    const randomIp = mobileIps[Math.floor(Math.random() * mobileIps.length)];

    let ua = 'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36';
    let devLabel = 'Android Mobile';
    let path = '/products/featured';

    if (deviceType === 'tablet') {
      ua = 'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';
      devLabel = 'iPad (iPadOS)';
      path = '/dashboard/overview';
    } else if (deviceType === 'remote_desktop') {
      ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
      devLabel = 'Mac (macOS)';
      path = '/api/v1/auth/session';
    }

    return await this.sendRealIngestEvent(targetId, {
      method: 'GET',
      endpoint: path,
      status: 200,
      eventType: 'PAGEVIEW',
      latencyMs: 18,
      sourceIp: randomIp,
      userAgent: ua,
      clientGeo: {
        device: devLabel,
        country: 'IN',
        city: 'Mumbai',
      },
      flagReason: `Distinct 2nd device entry from public IP ${randomIp} (${devLabel})`,
    });
  }

  public async sendRealIngestEvent(targetId: string, eventData: Partial<LogEvent>): Promise<LogEvent> {
    const target = this.getTarget(targetId);
    const apiKey = target?.apiKey || '';

    try {
      const res = await fetch('/api/collector/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Target-ID': targetId,
          'X-API-Key': apiKey,
        },
        body: JSON.stringify({
          targetId,
          apiKey,
          ...eventData,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        const event = data.event as LogEvent;
        this.ingestLogs(targetId, [event]);
        if (target) {
          target.realEventsCount = (target.realEventsCount || 0) + 1;
        }
        return event;
      }
    } catch {
      // Direct local ingestion if server fetch fails
    }

    const fallbackEvent: LogEvent = {
      id: `real-log-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      targetId,
      timestamp: new Date().toISOString(),
      displayTime: new Date().toTimeString().slice(0, 8),
      method: eventData.method || 'POST',
      endpoint: eventData.endpoint || '/api/v1/auth/login',
      status: eventData.status || 200,
      sourceIp: '127.0.0.1 (Direct Client Ping)',
      userAgent: navigator.userAgent || 'Live Ingest Agent',
      eventType: eventData.eventType || 'API_REQUEST',
      severity: eventData.severity || 'NORMAL',
      latencyMs: eventData.latencyMs || 22,
      isLab: false,
      logSource: 'REAL_LIVE_INGEST',
      payloadSnippet: eventData.payloadSnippet,
      flagReason: eventData.flagReason,
    };
    this.ingestLogs(targetId, [fallbackEvent]);
    if (target) {
      target.realEventsCount = (target.realEventsCount || 0) + 1;
    }
    return fallbackEvent;
  }

  public async probeLiveTarget(targetId: string): Promise<LogEvent | null> {
    const target = this.getTarget(targetId);
    if (!target) return null;

    let probeResult: {
      isReachable: boolean;
      statusCode: number;
      latencyMs: number;
      server?: string;
      probeLog?: LogEvent;
    } | null = null;

    // 1. Perform genuine server-side probe via our Express backend
    try {
      const resp = await fetch('/api/probe/live', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target.url, targetId }),
      });

      if (resp.ok) {
        const data = await resp.json();
        probeResult = {
          isReachable: Boolean(data.isReachable),
          statusCode: data.status || 200,
          latencyMs: data.latencyMs || 28,
          server: data.server || data.headers?.['server'],
          probeLog: data.probeLog,
        };
      }
    } catch {
      // Fall through to browser probe fallback
    }

    // 2. Direct browser probe fallback if server route failed
    if (!probeResult) {
      const start = performance.now();
      let status = 200;
      let latency = 28;
      let isReachable = true;

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);
        await fetch(target.url, {
          method: 'HEAD',
          signal: controller.signal,
          mode: 'no-cors',
        });
        clearTimeout(timeoutId);
        latency = Math.max(12, Math.round(performance.now() - start));
      } catch {
        try {
          const controller2 = new AbortController();
          const timeoutId2 = setTimeout(() => controller2.abort(), 3500);
          await fetch(target.url, {
            method: 'GET',
            signal: controller2.signal,
            mode: 'no-cors',
          });
          clearTimeout(timeoutId2);
          latency = Math.max(18, Math.round(performance.now() - start));
        } catch {
          latency = Math.max(45, Math.round(performance.now() - start));
          status = 504;
          isReachable = false;
        }
      }

      probeResult = {
        isReachable,
        statusCode: status,
        latencyMs: latency,
      };
    }

    // Update target metrics
    const isUp = probeResult.isReachable && probeResult.statusCode < 500;
    const isDegraded = isUp && probeResult.latencyMs > 500;
    const probeStatus: 'UP' | 'DOWN' | 'DEGRADED' = !isUp ? 'DOWN' : isDegraded ? 'DEGRADED' : 'UP';

    target.lastProbeStatus = !isUp ? 'UNREACHABLE' : isDegraded ? 'DEGRADED' : 'UP';
    target.lastProbeLatencyMs = probeResult.latencyMs;
    target.realProbesCount = (target.realProbesCount || 0) + 1;
    if (probeResult.server) {
      target.serverBanner = probeResult.server;
    }

    // Accumulate latency history (last 30 samples)
    target.latencyHistory = [...(target.latencyHistory || []), probeResult.latencyMs].slice(-30);

    // Accumulate uptime history (last 30 checks)
    target.uptimeHistory = [
      ...(target.uptimeHistory || []),
      {
        timestamp: new Date().toISOString(),
        status: probeStatus,
        latencyMs: probeResult.latencyMs,
        statusCode: probeResult.statusCode,
      },
    ].slice(-30);

    if (target.uptimeHistory.length > 0) {
      const upCount = target.uptimeHistory.filter((u) => u.status !== 'DOWN').length;
      target.uptimePercentage = Math.round((upCount / target.uptimeHistory.length) * 1000) / 10;
    }

    let finalLog: LogEvent;
    if (probeResult.probeLog) {
      finalLog = {
        ...probeResult.probeLog,
        targetId,
        isLab: target.isLab,
        logSource: 'REAL_SERVER_PROBE',
      };
    } else {
      finalLog = {
        id: `probe-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        targetId,
        timestamp: new Date().toISOString(),
        displayTime: new Date().toTimeString().slice(0, 8),
        method: 'GET',
        endpoint: '/',
        status: probeResult.statusCode,
        sourceIp: `${target.hostname} (Server Host)`,
        userAgent: 'EXTREME-SecOps-Live-Monitor/3.0 (Active Health Checker)',
        eventType: 'PROBE',
        severity: isUp ? 'NORMAL' : 'SUSPICIOUS',
        latencyMs: probeResult.latencyMs,
        isLab: target.isLab,
        logSource: 'REAL_SERVER_PROBE',
        flagReason: isUp
          ? `Live Target Probed: ${target.hostname} responded in ${probeResult.latencyMs}ms`
          : `Live Target Probed: Connection timeout or error for ${target.hostname}`,
      };
    }

    // Target health & latency are updated, but automated probes do not generate user activity logs.
    this.notify();
    return finalLog;
  }

  public toggleAutoStream(forcedState?: boolean): boolean {
    if (typeof forcedState === 'boolean') {
      this.isAutoStreamActive = forcedState;
    } else {
      this.isAutoStreamActive = !this.isAutoStreamActive;
    }
    this.notify();
    return this.isAutoStreamActive;
  }

  public getAutoStreamActive(): boolean {
    return this.isAutoStreamActive;
  }

  public getTargets(): Target[] {
    return [...this.targets];
  }

  public getTarget(id: string): Target | undefined {
    return this.targets.find((t) => t.id === id);
  }

  public createTarget(
    url: string,
    name?: string,
    sourceType: 'UPLOADED_ZIP' | 'LIVE_URL' | 'REAL_PRODUCTION' = 'REAL_PRODUCTION'
  ): Target {
    let clean = url.trim();
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
      clean = `https://${clean}`;
    }

    let parsedHostname = 'authorized-site.com';
    let normalizedUrl = clean;
    try {
      const parsed = new URL(clean);
      parsedHostname = parsed.hostname;
      normalizedUrl = `${parsed.protocol}//${parsed.host}`;
    } catch {
      parsedHostname = clean.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
      normalizedUrl = `https://${parsedHostname}`;
    }

    // Check if target already exists for this domain
    const existing = this.targets.find(
      (t) => t.hostname.toLowerCase() === parsedHostname.toLowerCase()
    );
    if (existing) {
      existing.url = normalizedUrl;
      this.activeTargetId = existing.id;
      this.notify();
      return existing;
    }

    const id = `target-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const apiKey = `ext_live_${Math.random().toString(36).substring(2, 12)}_${Date.now().toString(36)}`;

    const defaultEndpoints = [
      '/',
      '/api/health',
      '/api/v1/auth',
      '/login',
      '/robots.txt',
      '/.well-known/security.txt',
    ];

    const target: Target = {
      id,
      name: name || parsedHostname,
      url: normalizedUrl,
      hostname: parsedHostname,
      isLab: false,
      connectedAt: new Date().toISOString(),
      status: 'MONITORING',
      apiKey,
      totalRequests: 1,
      securityEventsCount: 0,
      threatsCount: 0,
      openIncidentsCount: 0,
      sourceType,
      telemetryMode: 'REAL_ONLY',
      realEventsCount: 1,
      realProbesCount: 1,
      customEndpoints: defaultEndpoints,
      lastProbeStatus: 'UP',
      lastProbeLatencyMs: 25,
      isLiveMonitoring: true,
      monitoringIntervalSeconds: 10,
      uptimePercentage: 100,
      latencyHistory: [25],
      uptimeHistory: [
        {
          timestamp: new Date().toISOString(),
          status: 'UP',
          latencyMs: 25,
          statusCode: 200,
        },
      ],
    };

    this.targets = [target, ...this.targets];
    this.activeTargetId = id;
    this.logs.set(id, []);
    this.threats.set(id, []);
    this.incidents.set(id, []);

    // Perform immediate real health probe and deep network scan
    setTimeout(() => {
      this.probeLiveTarget(id).catch(() => {});
      this.deepScanTarget(id, normalizedUrl).catch(() => {});
    }, 200);

    this.notify();
    return target;
  }

  public getLogs(
    targetId: string,
    filters?: { severity?: string; method?: string; search?: string; source?: string; limit?: number }
  ): LogEvent[] {
    let list = this.logs.get(targetId) || [];
    const target = this.getTarget(targetId);

    // Filter by logSource: REAL_ONLY, REAL_LIVE_INGEST, REAL_SERVER_PROBE, SIMULATION, ALL
    if (filters?.source && filters.source !== 'ALL') {
      if (filters.source === 'REAL_ONLY') {
        list = list.filter((l) => l.logSource !== 'SIMULATION');
      } else {
        list = list.filter((l) => l.logSource === filters.source);
      }
    } else if (target && !target.isLab && target.telemetryMode === 'REAL_ONLY') {
      // For real websites, strictly exclude synthetic logs by default unless user explicitly chose otherwise
      list = list.filter((l) => l.logSource !== 'SIMULATION');
    }

    if (filters?.severity && filters.severity !== 'ALL') {
      list = list.filter((l) => l.severity === filters.severity);
    }
    if (filters?.method && filters.method !== 'ALL') {
      list = list.filter((l) => l.method === filters.method);
    }
    if (filters?.search && filters.search.trim()) {
      const q = filters.search.toLowerCase().trim();
      list = list.filter(
        (l) =>
          l.endpoint.toLowerCase().includes(q) ||
          l.sourceIp.toLowerCase().includes(q) ||
          l.userAgent.toLowerCase().includes(q) ||
          (l.flagReason && l.flagReason.toLowerCase().includes(q)) ||
          (l.payloadSnippet && l.payloadSnippet.toLowerCase().includes(q))
      );
    }
    const limit = filters?.limit || 300;
    return list.slice(0, limit);
  }

  public getThreats(targetId: string): ThreatDetection[] {
    return this.threats.get(targetId) || [];
  }

  public getIncidents(targetId: string): Incident[] {
    return this.incidents.get(targetId) || [];
  }

  public updateIncidentStatus(
    targetId: string,
    incidentId: string,
    status: Incident['status']
  ): Incident | undefined {
    const list = this.incidents.get(targetId) || [];
    const item = list.find((i) => i.id === incidentId);
    if (item) {
      item.status = status;
      const target = this.getTarget(targetId);
      if (target) {
        target.openIncidentsCount = list.filter((i) => i.status !== 'RESOLVED').length;
        if (target.openIncidentsCount === 0 && target.threatsCount === 0) {
          target.status = 'MONITORING';
        }
      }
      this.notify();
      return item;
    }
    return undefined;
  }

  public deleteThreat(targetId: string, threatId: string): boolean {
    const list = this.threats.get(targetId) || [];
    const idx = list.findIndex((t) => t.id === threatId);
    if (idx === -1) return false;
    const removedThreat = list[idx];
    list.splice(idx, 1);
    this.threats.set(targetId, list);

    // Also remove or update matching incident
    const incidents = this.incidents.get(targetId) || [];
    const updatedIncidents = incidents.filter(
      (i) => i.threatName !== removedThreat.threatName && i.id !== `inc-${threatId}`
    );
    this.incidents.set(targetId, updatedIncidents);

    const target = this.getTarget(targetId);
    if (target) {
      target.threatsCount = list.length;
      target.openIncidentsCount = updatedIncidents.filter((i) => i.status !== 'RESOLVED').length;
      if (target.threatsCount === 0 && target.openIncidentsCount === 0) {
        target.status = 'MONITORING';
      }
    }
    this.notify();
    return true;
  }

  public clearAllThreats(targetId: string): void {
    this.threats.set(targetId, []);
    this.incidents.set(targetId, []);
    const target = this.getTarget(targetId);
    if (target) {
      target.threatsCount = 0;
      target.openIncidentsCount = 0;
      target.status = 'MONITORING';
    }
    this.notify();
  }

  public clearLogBuffer(targetId: string): void {
    this.logs.set(targetId, []);
    const target = this.getTarget(targetId);
    if (target) {
      target.totalRequests = 0;
      target.realEventsCount = 0;
      target.securityEventsCount = 0;
    }
    fetch('/api/collector/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetId }),
    }).catch(() => {});
    this.notify();
  }

  public ingestLogs(targetId: string, newLogs: LogEvent[]): void {
    const currentList = this.logs.get(targetId) || [];
    currentList.unshift(...newLogs);
    if (currentList.length > 2500) {
      currentList.length = 2500;
    }
    this.logs.set(targetId, currentList);

    const target = this.getTarget(targetId);
    if (target && newLogs.length > 0) {
      target.totalRequests += newLogs.length;
      target.lastEventAt = newLogs[0].timestamp;
      const suspiciousBatch = newLogs.filter(
        (l) => l.severity === 'SUSPICIOUS' || l.severity === 'CRITICAL'
      );
      target.securityEventsCount += suspiciousBatch.length;
    }

    // Run threat detection engine on newly ingested logs
    this.runDetectionRules(targetId, newLogs);
    this.notify();
  }

  private runDetectionRules(targetId: string, recentBatch: LogEvent[]) {
    const buffer = this.logs.get(targetId) || [];
    const target = this.getTarget(targetId);
    const isLab = target ? target.isLab : false;

    // 1. SQL Injection Rule
    const sqliLogs = recentBatch.filter(
      (l) =>
        l.payloadSnippet?.includes("' OR '1'='1") ||
        l.payloadSnippet?.includes('UNION SELECT') ||
        l.payloadSnippet?.includes('SLEEP(') ||
        l.endpoint.includes("' OR '1'='1") ||
        l.endpoint.includes('UNION%20SELECT')
    );
    if (sqliLogs.length > 0) {
      this.createThreat(
        targetId,
        'RULE_SQLI_01',
        'SQL Injection Probe',
        'CRITICAL',
        96,
        sqliLogs[0].endpoint,
        [
          `Detected canonical SQL injection payload in parameter: ${sqliLogs[0].payloadSnippet || sqliLogs[0].endpoint}`,
          `Target endpoint received unescaped quote and boolean operator syntax (' OR '1'='1)`,
          `Source IP: ${sqliLogs[0].sourceIp}`,
        ],
        sqliLogs,
        'Suspicious database manipulation syntax was detected inside incoming request parameters.',
        'Incoming request contains SQL injection payloads designed to alter dynamic database queries (e.g. bypass authentication or extract table data).',
        {
          title: 'Mitigate SQL Injection Vulnerability',
          whatToCheck: [
            'Inspect backend database access layers servicing endpoint ' + sqliLogs[0].endpoint,
            'Review SQL statement generation for string concatenation or template literal usage',
            'Verify database account permissions to ensure principle of least privilege',
          ],
          configToReview: [
            'Database driver configuration (ensure prepared statements are enabled by default)',
            'Web Application Firewall (WAF) SQLi inspection rules',
            'ORM query builders (ensure parameterized queries are strictly enforced)',
          ],
          mitigationToApply: {
            summary:
              'Enforce parameterized queries or prepared statements across all database interactions. Reject raw SQL concatenation.',
            snippetLanguage: 'typescript',
            filename: 'db/query.ts',
            codeSnippet: `// VULNERABLE:
// const user = await db.query(\`SELECT * FROM users WHERE email = '\${email}'\`);

// SECURE - Parameterized Query:
const user = await db.query(
  'SELECT id, email, role FROM users WHERE email = $1 LIMIT 1',
  [email]
);`,
          },
          howToVerify: [
            "Send a safe test query with single-quote payload (' OR '1'='1) and confirm it returns HTTP 400 Bad Request or is treated as literal text",
            'Verify server database error logs do not output database schema or query tracebacks',
          ],
        }
      );
    }

    // 2. Directory Traversal Rule
    const traversalLogs = recentBatch.filter(
      (l) =>
        l.endpoint.includes('../') ||
        l.endpoint.includes('..%2f') ||
        l.endpoint.includes('/etc/passwd') ||
        l.payloadSnippet?.includes('../')
    );
    if (traversalLogs.length > 0) {
      this.createThreat(
        targetId,
        'RULE_TRAVERSAL_01',
        'Directory Traversal Attempt',
        'HIGH',
        93,
        traversalLogs[0].endpoint,
        [
          `Observed directory traversal sequence (../) targeting endpoint ${traversalLogs[0].endpoint}`,
          `Attempted escape from public web directory toward operating system paths`,
          `Source IP: ${traversalLogs[0].sourceIp}`,
        ],
        traversalLogs,
        'Directory path traversal sequences were detected attempting to escape the application root.',
        'Parent directory reference sequence (../) or operating system credential file path (/etc/passwd) was supplied in URI parameter.',
        {
          title: 'Prevent Directory Traversal and File Inclusion',
          whatToCheck: [
            'Review file downloading or dynamic template loading logic for endpoint ' +
              traversalLogs[0].endpoint,
            'Ensure user-supplied filenames or document IDs are never passed directly to file system APIs (e.g. fs.readFile)',
          ],
          configToReview: [
            'Web server root configuration and symlink traversal restrictions',
            'Storage mount permissions (mount static upload folders as read-only / noexec)',
          ],
          mitigationToApply: {
            summary:
              'Sanitize file paths using path.basename and enforce whitelist of permitted extensions or resolve canonical root.',
            snippetLanguage: 'typescript',
            filename: 'utils/fileServer.ts',
            codeSnippet: `import path from 'path';

export function getSafeFilePath(baseDir: string, userFilename: string): string {
  // Strip out directory traversal tokens
  const safeName = path.basename(userFilename);
  const targetPath = path.resolve(baseDir, safeName);

  if (!targetPath.startsWith(path.resolve(baseDir))) {
    throw new Error('Access denied: Illegal file path traversal attempt');
  }
  return targetPath;
}`,
          },
          howToVerify: [
            "Run curl -i 'https://yourwebsite.com/api/download?file=../../etc/passwd' and verify 400 Bad Request is returned",
            'Confirm target directory cannot traverse outside designated upload root',
          ],
        }
      );
    }

    // 3. Brute Force & Credential Stuffing Rule
    const recentAuthFails = buffer
      .slice(0, 30)
      .filter(
        (l) =>
          (l.endpoint.includes('/login') ||
            l.endpoint.includes('/auth') ||
            l.endpoint.includes('/signin') ||
            l.endpoint.includes('/token')) &&
          (l.status === 401 || l.status === 403)
      );
    if (recentAuthFails.length >= 3) {
      this.createThreat(
        targetId,
        'RULE_AUTH_BURST_01',
        'Suspicious Authentication Activity',
        'HIGH',
        94,
        recentAuthFails[0].endpoint,
        [
          `Observed ${recentAuthFails.length} failed authentication requests (HTTP 401) in rapid succession`,
          `Affected endpoint: ${recentAuthFails[0].endpoint}`,
          `Targeted credentials: multiple login attempts from source ${recentAuthFails[0].sourceIp}`,
          `Time window: within 20 seconds`,
        ],
        recentAuthFails.slice(0, 5),
        'Repeated failed authentication attempts detected within a condensed timeframe. Multiple consecutive 401 Unauthorized responses were returned.',
        'Observed rapid failed credential submissions from source IP exceeding normal human interaction latency thresholds, characteristic of automated credential stuffing or dictionary testing.',
        {
          title: 'Implement Authentication Rate Limiting & Account Protection',
          whatToCheck: [
            'Identity provider access logs for targeted usernames and accounts',
            'Credential stuffing indicators (distributed IPs or single IP burst)',
            'Account lockout states and password reset alerts',
          ],
          configToReview: [
            'Rate limiting middleware configuration on POST /login and POST /auth',
            'Account lockout thresholds (recommended: 5 failed attempts per 15 minutes)',
            'Generic error messaging (avoid disclosing whether email exists)',
          ],
          mitigationToApply: {
            summary:
              'Enable strict IP and username rate limiting on authentication endpoints with exponential backoff and CAPTCHA.',
            snippetLanguage: 'typescript',
            filename: 'middleware/authRateLimiter.ts',
            codeSnippet: `import rateLimit from 'express-rate-limit';

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 failed login attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    error: 'Too many authentication attempts. Please retry in 15 minutes.',
  },
});
// Apply to login route:
// app.post('/api/auth/login', loginLimiter, handleLogin);`,
          },
          howToVerify: [
            'Execute 6 consecutive failed authentication requests using curl or automated script',
            'Verify the 6th request immediately receives HTTP 429 Too Many Requests response with Retry-After header',
          ],
        }
      );
    }

    // 4. Dotfile & Sensitive Path Recon
    const probeLogs = buffer
      .slice(0, 25)
      .filter(
        (l) =>
          l.endpoint.includes('/.env') ||
          l.endpoint.includes('/.git') ||
          l.endpoint.includes('/wp-admin') ||
          l.endpoint.includes('/phpmyadmin') ||
          l.endpoint.includes('/actuator')
      );
    if (probeLogs.length >= 2) {
      this.createThreat(
        targetId,
        'RULE_PROBE_01',
        'Sensitive Path Reconnaissance',
        'MEDIUM',
        91,
        probeLogs[0].endpoint,
        [
          `Multiple requests probing known configuration files: ${probeLogs.map((p) => p.endpoint).slice(0, 3).join(', ')}`,
          `Source IP: ${probeLogs[0].sourceIp}`,
          `Status codes returned: ${probeLogs.map((p) => p.status).slice(0, 3).join(', ')}`,
        ],
        probeLogs.slice(0, 4),
        'Automated reconnaissance activity detected targeting sensitive configuration paths and administrative endpoints.',
        'Observed requests for common credential and environment exposure vectors (.env, .git) that are not part of legitimate application navigation.',
        {
          title: 'Restrict Access to Dotfiles and Administrative Endpoints',
          whatToCheck: [
            'Web server public root directory permissions',
            'Verify .env and .git directories are strictly excluded from web server document root',
            'Review server access logs for wider vulnerability scanner fingerprints',
          ],
          configToReview: [
            'Nginx/Apache server configuration blocks for dotfiles',
            'Reverse proxy route whitelists',
          ],
          mitigationToApply: {
            summary:
              'Configure web server or reverse proxy to unconditionally deny requests to hidden files and dotfiles.',
            snippetLanguage: 'nginx',
            filename: 'nginx.conf',
            codeSnippet: `# Deny all attempts to access hidden files such as .env, .git, .htaccess
location ~ /\\.(?!well-known).* {
    deny all;
    access_log off;
    log_not_found off;
    return 404;
}`,
          },
          howToVerify: [
            "Send curl -i 'https://yourwebsite.com/.env' and confirm HTTP 404 or 403 is returned immediately without application execution",
            'Verify .git/config returns 404/403',
          ],
        }
      );
    }

    // 5. Malicious Scanner Toolchains
    const scannerLogs = recentBatch.filter(
      (l) =>
        l.userAgent.toLowerCase().includes('nikto') ||
        l.userAgent.toLowerCase().includes('sqlmap') ||
        l.userAgent.toLowerCase().includes('masscan') ||
        l.userAgent.toLowerCase().includes('gobuster')
    );
    if (scannerLogs.length > 0) {
      this.createThreat(
        targetId,
        'RULE_SCANNER_UA_01',
        'Automated Vulnerability Scanner Identified',
        'HIGH',
        98,
        scannerLogs[0].endpoint,
        [
          `Request User-Agent explicitly matched known automated security scanner tool: ${scannerLogs[0].userAgent}`,
          `Source IP: ${scannerLogs[0].sourceIp}`,
          `Target endpoint: ${scannerLogs[0].endpoint}`,
        ],
        scannerLogs,
        'Traffic was identified as originating from an automated vulnerability testing tool.',
        'User-Agent header explicitly matched known vulnerability scanner signatures (e.g. sqlmap, nikto, masscan).',
        {
          title: 'Block Malicious Scanner Toolchains at Edge WAF',
          whatToCheck: [
            'All traffic records associated with IP ' + scannerLogs[0].sourceIp + ' across past 24 hours',
            'Check if scanner probed authentication or API endpoints',
          ],
          configToReview: ['WAF bot management rule sets', 'Cloud Armor / Cloudflare security policies'],
          mitigationToApply: {
            summary: 'Drop or challenge automated scanner user-agents at reverse proxy or edge CDN.',
            snippetLanguage: 'nginx',
            filename: 'nginx-bad-bots.conf',
            codeSnippet: `if ($http_user_agent ~* (sqlmap|nikto|masscan|nmap|gobuster|hydra)) {
    return 403 "Forbidden";
}`,
          },
          howToVerify: [
            'Run curl -A "nikto" -i https://yourwebsite.com/ and verify immediate 403 Forbidden',
          ],
        }
      );
    }
  }

  private createThreat(
    targetId: string,
    ruleId: string,
    threatName: string,
    severity: ThreatDetection['severity'],
    confidence: number,
    affectedEndpoint: string,
    evidence: string[],
    triggerLogs: LogEvent[],
    whatHappened: string,
    whyFlagged: string,
    remediationData: {
      title: string;
      whatToCheck: string[];
      configToReview: string[];
      mitigationToApply: Remediation['mitigationToApply'];
      howToVerify: string[];
    }
  ) {
    const list = this.threats.get(targetId) || [];
    // Prevent duplicate threat of same rule & endpoint within 25 seconds
    const existing = list.find((t) => t.ruleId === ruleId && t.affectedEndpoint === affectedEndpoint);
    if (existing) return;

    const nowIso = new Date().toISOString();
    const displayTime = new Date().toTimeString().slice(0, 8);
    const threatId = `threat-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const incidentId = `inc-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const target = this.getTarget(targetId);
    const isLab = target ? target.isLab : false;

    const threat: ThreatDetection = {
      id: threatId,
      targetId,
      threatName,
      severity,
      confidence,
      timestamp: nowIso,
      displayTime,
      affectedEndpoint,
      evidence,
      triggerLogIds: triggerLogs.map((l) => l.id),
      triggerLogs,
      whatHappened,
      whyFlagged,
      isLab,
      ruleId,
    };

    list.unshift(threat);
    this.threats.set(targetId, list);

    if (target) {
      target.threatsCount = list.length;
      target.status = 'ALERTING';
    }

    const remediation: Remediation = {
      id: `rem-${threatId}`,
      threatId,
      threatName,
      severity,
      affectedEndpoint,
      title: remediationData.title,
      whatToCheck: remediationData.whatToCheck,
      configToReview: remediationData.configToReview,
      mitigationToApply: remediationData.mitigationToApply,
      howToVerify: remediationData.howToVerify,
    };

    const timeline: IncidentTimelineStep[] = [];
    if (triggerLogs.length > 0) {
      timeline.push({
        step: 'Event Observed',
        timestamp: triggerLogs[0].timestamp,
        displayTime: triggerLogs[0].displayTime,
        description: `Incoming ${triggerLogs[0].method} ${triggerLogs[0].endpoint} (${triggerLogs[0].status}) recorded from ${triggerLogs[0].sourceIp}`,
        type: 'EVENT',
      });
    }
    timeline.push({
      step: 'Detection Rule Triggered',
      timestamp: nowIso,
      displayTime,
      description: `Rule ${ruleId} matched: ${threatName} with ${confidence}% confidence`,
      type: 'DETECTION',
    });
    timeline.push({
      step: 'Security Alert Raised',
      timestamp: nowIso,
      displayTime,
      description: `Raised ${severity} severity alert on target ${target?.hostname || 'target'}`,
      type: 'ALERT',
    });
    timeline.push({
      step: 'Investigation Queued',
      timestamp: nowIso,
      displayTime,
      description: 'Correlated evidence logs attached; operator remediation playbook generated',
      type: 'INVESTIGATION',
    });

    const incident: Incident = {
      id: incidentId,
      targetId,
      title: threatName,
      threatName,
      severity,
      target: target ? target.hostname : 'target',
      time: nowIso,
      displayTime,
      status: 'OPEN',
      affectedEndpoint,
      confidence,
      timeline,
      evidenceLogIds: triggerLogs.map((l) => l.id),
      evidenceLogs: triggerLogs,
      whatHappened,
      whyFlagged,
      remediation,
      isLab,
    };

    const incList = this.incidents.get(targetId) || [];
    incList.unshift(incident);
    this.incidents.set(targetId, incList);

    if (target) {
      target.openIncidentsCount = incList.filter((i) => i.status !== 'RESOLVED').length;
    }
  }

  // Generators for realistic logs
  public createNormalLogs(targetId: string, count: number = 5): LogEvent[] {
    const target = this.getTarget(targetId);
    let endpoints = [
      { method: 'GET' as HttpMethod, endpoint: '/', type: 'STATIC_RESOURCE' as EventType, status: 200 },
      { method: 'GET' as HttpMethod, endpoint: '/api/v1/products', type: 'API_REQUEST' as EventType, status: 200 },
      { method: 'GET' as HttpMethod, endpoint: '/assets/app.css', type: 'STATIC_RESOURCE' as EventType, status: 200 },
      { method: 'POST' as HttpMethod, endpoint: '/api/v1/cart', type: 'API_REQUEST' as EventType, status: 200 },
      { method: 'GET' as HttpMethod, endpoint: '/checkout', type: 'API_REQUEST' as EventType, status: 200 },
      { method: 'GET' as HttpMethod, endpoint: '/api/v1/user/profile', type: 'API_REQUEST' as EventType, status: 200 },
      { method: 'GET' as HttpMethod, endpoint: '/favicon.ico', type: 'STATIC_RESOURCE' as EventType, status: 200 },
      { method: 'GET' as HttpMethod, endpoint: '/api/v1/search?q=security', type: 'API_REQUEST' as EventType, status: 200 },
    ];

    if (target?.customEndpoints && target.customEndpoints.length > 0) {
      endpoints = target.customEndpoints.map((ep) => {
        const isPost =
          ep.includes('login') ||
          ep.includes('auth') ||
          ep.includes('cart') ||
          ep.includes('create') ||
          ep.includes('order');
        const isStatic =
          ep.endsWith('.css') ||
          ep.endsWith('.js') ||
          ep.endsWith('.ico') ||
          ep.endsWith('.html') ||
          ep === '/';
        return {
          method: (isPost ? 'POST' : 'GET') as HttpMethod,
          endpoint: ep,
          type: (isStatic ? 'STATIC_RESOURCE' : 'API_REQUEST') as EventType,
          status: 200,
        };
      });
    }

    const normalIps = ['198.51.100.42', '198.51.100.89', '203.0.113.15', '192.0.2.77', '198.51.100.12'];
    const logs: LogEvent[] = [];

    for (let i = 0; i < count; i++) {
      const ep = endpoints[Math.floor(Math.random() * endpoints.length)];
      const now = new Date(Date.now() - (count - i) * 600);
      const ip = normalIps[Math.floor(Math.random() * normalIps.length)];
      logs.push({
        id: `log-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        targetId,
        timestamp: now.toISOString(),
        displayTime: now.toTimeString().slice(0, 8),
        method: ep.method,
        endpoint: ep.endpoint,
        status: ep.status,
        sourceIp: ip,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0',
        eventType: ep.type,
        severity: 'NORMAL',
        latencyMs: Math.floor(Math.random() * 25) + 12,
        isLab: target ? target.isLab : false,
        logSource: 'SIMULATION',
      });
    }
    return logs;
  }

  public createSuspiciousLogs(targetId: string, count: number = 3): LogEvent[] {
    const target = this.getTarget(targetId);
    let probePaths = [
      { endpoint: '/.env', status: 404, reason: 'Attempted access to environment secrets' },
      { endpoint: '/.git/config', status: 404, reason: 'Attempted access to Git version repository' },
      { endpoint: '/wp-admin/', status: 403, reason: 'Probed unmapped WordPress admin login' },
      { endpoint: '/api/v1/debug', status: 404, reason: 'Reconnaissance on hidden debug interface' },
    ];

    if (target?.customEndpoints && target.customEndpoints.length > 0) {
      const customProbes = target.customEndpoints
        .filter((ep) => ep !== '/' && !ep.endsWith('.css') && !ep.endsWith('.ico'))
        .map((ep) => ({
          endpoint: ep.includes('?') ? `${ep}&debug=true` : `${ep}?test_param=recon`,
          status: 403,
          reason: `Automated reconnaissance probe targeting detected endpoint ${ep}`,
        }));
      if (customProbes.length > 0) {
        probePaths = [...probePaths, ...customProbes];
      }
    }

    const logs: LogEvent[] = [];

    for (let i = 0; i < count; i++) {
      const probe = probePaths[i % probePaths.length];
      const now = new Date(Date.now() - (count - i) * 600);
      logs.push({
        id: `log-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        targetId,
        timestamp: now.toISOString(),
        displayTime: now.toTimeString().slice(0, 8),
        method: 'GET',
        endpoint: probe.endpoint,
        status: probe.status,
        sourceIp: '198.51.100.199',
        userAgent: 'curl/8.4.0 (Automated Recon / Script)',
        eventType: 'PROBE',
        severity: 'SUSPICIOUS',
        latencyMs: 14,
        isLab: target ? target.isLab : false,
        logSource: 'SIMULATION',
        flagReason: probe.reason,
      });
    }
    return logs;
  }

  public createAuthAttackLogs(targetId: string): LogEvent[] {
    const target = this.getTarget(targetId);
    let authEndpoint = '/api/v1/auth/login';
    if (target?.customEndpoints) {
      const found = target.customEndpoints.find(
        (ep) => ep.includes('login') || ep.includes('auth') || ep.includes('signin')
      );
      if (found) authEndpoint = found;
    }

    const usernames = ['admin', 'root', 'administrator', 'operator', 'dev'];
    const logs: LogEvent[] = [];

    usernames.forEach((username, idx) => {
      const now = new Date(Date.now() - (usernames.length - idx) * 450);
      logs.push({
        id: `log-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        targetId,
        timestamp: now.toISOString(),
        displayTime: now.toTimeString().slice(0, 8),
        method: 'POST',
        endpoint: authEndpoint,
        status: 401,
        sourceIp: '198.51.100.199',
        userAgent: 'Python-requests/2.31.0 (Credential Brute-Force Bot)',
        eventType: 'AUTHENTICATION',
        severity: 'SUSPICIOUS',
        latencyMs: 38,
        isLab: target ? target.isLab : false,
        logSource: 'SIMULATION',
        payloadSnippet: `{"username": "${username}", "password": "••••••••"}`,
        flagReason: `Failed credential authentication burst on ${authEndpoint} for identifier: ${username}`,
      });
    });
    return logs;
  }

  public createSqlInjectionLogs(targetId: string): LogEvent[] {
    const target = this.getTarget(targetId);
    let targetEndpoint = '/api/v1/catalog';
    if (target?.customEndpoints && target.customEndpoints.length > 0) {
      const match =
        target.customEndpoints.find(
          (ep) =>
            ep.includes('catalog') ||
            ep.includes('user') ||
            ep.includes('search') ||
            ep.includes('product') ||
            ep.includes('item') ||
            ep.includes('db')
        ) ||
        target.customEndpoints[1] ||
        target.customEndpoints[0];
      if (match && match !== '/') targetEndpoint = match;
    }

    const payloads = [
      {
        endpoint: `${targetEndpoint}?id=' OR '1'='1`,
        payload: "' OR '1'='1",
        method: 'GET' as HttpMethod,
        status: 500,
      },
      {
        endpoint: `${targetEndpoint}/lookup`,
        payload: "admin' UNION SELECT null, username, password_hash FROM credentials --",
        method: 'POST' as HttpMethod,
        status: 500,
      },
    ];
    const logs: LogEvent[] = [];

    payloads.forEach((item, idx) => {
      const now = new Date(Date.now() - (payloads.length - idx) * 700);
      logs.push({
        id: `log-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        targetId,
        timestamp: now.toISOString(),
        displayTime: now.toTimeString().slice(0, 8),
        method: item.method,
        endpoint: item.endpoint,
        status: item.status,
        sourceIp: '198.51.100.199',
        userAgent: 'sqlmap/1.7.11#stable (https://sqlmap.org)',
        eventType: 'INJECTION_ATTEMPT',
        severity: 'CRITICAL',
        latencyMs: 82,
        isLab: target ? target.isLab : false,
        logSource: 'SIMULATION',
        payloadSnippet: item.payload,
        flagReason: 'Pattern matched SQL injection operator sequence: boolean tautology / union probe',
      });
    });
    return logs;
  }

  public createScannerSweepLogs(targetId: string): LogEvent[] {
    const paths = ['/login.php', '/config.php', '/phpinfo.php', '/server-status', '/backup.zip'];
    const logs: LogEvent[] = [];
    const target = this.getTarget(targetId);

    paths.forEach((p, idx) => {
      const now = new Date(Date.now() - (paths.length - idx) * 400);
      logs.push({
        id: `log-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        targetId,
        timestamp: now.toISOString(),
        displayTime: now.toTimeString().slice(0, 8),
        method: 'GET',
        endpoint: p,
        status: 404,
        sourceIp: '198.51.100.210',
        userAgent: 'Mozilla/5.0 (Nikto/2.1.6; Security Assessment Scanner)',
        eventType: 'PROBE',
        severity: 'SUSPICIOUS',
        latencyMs: 18,
        isLab: target ? target.isLab : false,
        logSource: 'SIMULATION',
        flagReason: 'Known vulnerability scanner User-Agent header (Nikto 2.1.6)',
      });
    });
    return logs;
  }

  private generateInitialSeededLogs(targetId: string): LogEvent[] {
    const normal = this.createNormalLogs(targetId, 18);
    const authAttack = this.createAuthAttackLogs(targetId);
    const recon = this.createSuspiciousLogs(targetId, 3);
    const sqli = this.createSqlInjectionLogs(targetId);

    const all = [...normal, ...authAttack, ...recon, ...sqli];
    all.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    return all;
  }

  public generateReport(targetId: string): SecurityReport {
    const target = this.getTarget(targetId) || {
      id: targetId,
      name: 'Unknown Target',
      url: 'https://unknown.target',
      hostname: 'unknown.target',
      isLab: false,
      connectedAt: new Date().toISOString(),
      status: 'MONITORING',
      apiKey: '',
      totalRequests: 0,
      securityEventsCount: 0,
      threatsCount: 0,
      openIncidentsCount: 0,
    };
    const threats = this.getThreats(targetId);
    const incidents = this.getIncidents(targetId);
    const allLogs = this.logs.get(targetId) || [];
    const remediations = incidents.map((i) => i.remediation).filter(Boolean);

    let healthStatus: SecurityReport['summary']['healthStatus'] = 'HEALTHY';
    if (threats.some((t) => t.severity === 'CRITICAL')) {
      healthStatus = 'CRITICAL_THREAT';
    } else if (threats.some((t) => t.severity === 'HIGH')) {
      healthStatus = 'ELEVATED_RISK';
    } else if (threats.length > 0 || target.securityEventsCount > 0) {
      healthStatus = 'ATTENTION_NEEDED';
    }

    const openCount = incidents.filter((i) => i.status !== 'RESOLVED').length;
    const resolvedCount = incidents.filter((i) => i.status === 'RESOLVED').length;

    return {
      generatedAt: new Date().toISOString(),
      target,
      isLab: target.isLab,
      summary: {
        totalMonitoredRequests: target.totalRequests,
        securityEvents: target.securityEventsCount,
        threatsDetected: threats.length,
        openIncidents: openCount,
        resolvedIncidents: resolvedCount,
        healthStatus,
      },
      threats,
      incidents,
      remediations,
      recentEvidenceLogs: allLogs.slice(0, 25),
    };
  }

  public applyScanResult(scanResult: any): Target {
    let hostname = scanResult.targetName.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
    if (!hostname) hostname = 'uploaded-website.com';

    let target = this.targets.find((t) => t.hostname === hostname && !t.isLab);
    if (!target) {
      target = this.createTarget(`https://${hostname}`, `Real Website (${hostname})`, 'UPLOADED_ZIP');
    } else {
      target.sourceType = 'UPLOADED_ZIP';
      target.telemetryMode = 'REAL_ONLY';
    }

    if (scanResult.discoveredEndpoints && scanResult.discoveredEndpoints.length > 0) {
      target.customEndpoints = scanResult.discoveredEndpoints;
    }
    target.vulnerabilitiesDetected = (scanResult.findings || []).map((f: any) => f.title);

    // Make this target immediately active
    this.activeTargetId = target.id;
    this.isAutoStreamActive = true;

    // Ingest actual parsed server logs if provided in the ZIP archive
    if (scanResult.parsedLogs && scanResult.parsedLogs.length > 0) {
      const taggedLogs: LogEvent[] = scanResult.parsedLogs.map((l: LogEvent) => ({
        ...l,
        logSource: 'REAL_LIVE_INGEST',
      }));
      this.ingestLogs(target.id, taggedLogs);
      target.realEventsCount = (target.realEventsCount || 0) + taggedLogs.length;
    }

    // Register genuine static SAST findings as threats with remediation steps
    for (const finding of scanResult.findings || []) {
      this.createThreat(
        target.id,
        `SAST_${finding.category}_${Date.now().toString(36)}`,
        finding.title,
        finding.severity,
        97,
        finding.file + (finding.line ? `:${finding.line}` : ''),
        [
          `File location: ${finding.file}` + (finding.line ? ` (line ${finding.line})` : ''),
          `Vulnerability Category: ${finding.category}`,
          finding.snippet ? `Observed Code: ${finding.snippet}` : finding.description,
        ],
        [],
        finding.description,
        `Static analysis identified critical security risk in uploaded website source: ${finding.title}`,
        {
          title: finding.title,
          whatToCheck: [
            `Inspect ${finding.file} around line ${finding.line || 1}`,
            `Check if variables or secrets have leaked into revision history or client bundles`,
            `Review defensive controls at ${finding.file}`,
          ],
          configToReview: [
            `Build configuration and environment file isolation`,
            `Input validation & output encoding libraries`,
            `Secret management vault / cloud provider keys`,
          ],
          mitigationToApply: {
            summary: finding.recommendation,
            filename: finding.remediationCode?.filename || finding.file,
            codeSnippet: finding.remediationCode?.snippet || `// Recommended mitigation:\n${finding.recommendation}`,
          },
          howToVerify: [
            `Verify that ${finding.file} no longer contains insecure patterns or exposed keys`,
            `Run automated tests or linter to ensure no regression`,
          ],
        }
      );
    }

    this.notify();
    return target;
  }

  public applyUrlAudit(audit: any): Target {
    let target = this.targets.find((t) => t.hostname === audit.hostname && !t.isLab);
    if (!target) {
      target = this.createTarget(audit.url, `Audited Target (${audit.hostname})`, 'LIVE_URL');
    } else {
      target.sourceType = 'LIVE_URL';
      target.telemetryMode = 'REAL_ONLY';
    }

    if (audit.detectedEndpoints && audit.detectedEndpoints.length > 0) {
      target.customEndpoints = audit.detectedEndpoints;
    }
    target.lastProbeStatus = audit.isReachable ? 'UP' : 'UNREACHABLE';
    target.lastProbeLatencyMs = audit.latencyMs || 28;
    target.realProbesCount = (target.realProbesCount || 0) + 1;

    this.activeTargetId = target.id;
    this.isAutoStreamActive = true;

    // Ingest immediate live probe handshake event with REAL_SERVER_PROBE tag
    const nowIso = new Date().toISOString();
    const probeLog: LogEvent = {
      id: `probe-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      targetId: target.id,
      timestamp: nowIso,
      displayTime: new Date().toTimeString().slice(0, 8),
      method: 'GET',
      endpoint: '/',
      status: audit.isReachable ? 200 : 504,
      sourceIp: '127.0.0.1 (Health Probe Agent)',
      userAgent: 'EXTREME-SecOps-Live-Monitor/3.0',
      eventType: 'PROBE',
      severity: audit.isReachable ? 'NORMAL' : 'SUSPICIOUS',
      latencyMs: audit.latencyMs || 28,
      isLab: false,
      logSource: 'REAL_SERVER_PROBE',
      flagReason: audit.isReachable
        ? `Live Target Audit: Successfully connected to ${audit.hostname} (${audit.latencyMs || 28}ms)`
        : `Live Target Audit: Host unreachable or timeout for ${audit.hostname}`,
    };
    this.ingestLogs(target.id, [probeLog]);

    const failedFindings = (audit.findings || []).filter((f: any) => !f.passed);
    for (const f of failedFindings) {
      const sev = f.severity === 'INFO' ? 'LOW' : f.severity;
      this.createThreat(
        target.id,
        `LIVE_AUDIT_${f.category}`,
        f.title,
        sev,
        92,
        `https://${audit.hostname}/`,
        [
          `Host: ${audit.hostname}`,
          `Category: ${f.category}`,
          f.description,
        ],
        [],
        f.description,
        `Live security probe failed verification on live target: ${f.title}`,
        {
          title: `Remediate ${f.title}`,
          whatToCheck: [
            `Inspect server response headers for ${audit.hostname}`,
            `Check reverse proxy or edge CDN configuration (Cloudflare, Nginx, CloudFront)`,
          ],
          configToReview: [
            `Web server configuration (nginx.conf, Apache httpd.conf, or Express security middleware)`,
          ],
          mitigationToApply: {
            summary: f.recommendation,
            filename: 'security-headers.conf',
            codeSnippet: f.codeSnippet || `# Enforce defensive configuration\n${f.recommendation}`,
          },
          howToVerify: [
            `Send test request: curl -I ${audit.url}`,
            `Confirm security header or defensive response is returned`,
          ],
        }
      );
    }

    this.notify();
    return target;
  }

  // Real Deep Network Security Audit of any website URL
  public async deepScanTarget(targetId: string, customUrl?: string): Promise<any> {
    const target = this.getTarget(targetId);
    if (!target) return null;
    const scanUrl = customUrl || target.url;

    try {
      const res = await fetch('/api/probe/deep-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl, targetId }),
      });

      if (!res.ok) {
        throw new Error(`Audit returned HTTP status ${res.status}`);
      }

      const data = await res.json();
      target.securityScore = data.score;
      target.securityGrade = data.grade;
      target.sslDetails = data.ssl;
      target.dnsDetails = data.dns;
      target.sensitiveFindings = data.sensitivePaths;
      target.headersAudit = data.headers;
      target.lastProbeStatus = data.isReachable ? 'UP' : 'UNREACHABLE';
      target.lastProbeLatencyMs = data.latencyMs;
      target.realProbesCount = (target.realProbesCount || 0) + 1;

      if (data.probeLog) {
        this.ingestLogs(targetId, [data.probeLog]);
      }

      // Generate remediations for any failed findings
      if (Array.isArray(data.findings)) {
        const failedFindings = data.findings.filter((f: any) => !f.passed);
        for (const f of failedFindings) {
          const sev = f.severity === 'INFO' ? 'LOW' : f.severity;
          this.createThreat(
            target.id,
            `DEEP_AUDIT_${f.category}_${f.title.replace(/\s+/g, '_').slice(0, 20)}`,
            f.title,
            sev,
            95,
            target.url,
            [
              `Category: ${f.category}`,
              `Severity: ${f.severity}`,
              f.description,
            ],
            data.probeLog ? [data.probeLog] : [],
            f.description,
            `Real deep network scanner flagged: ${f.title}`,
            {
              title: `Remediate ${f.title}`,
              whatToCheck: [
                `Verify server response headers on ${target.hostname}`,
                `Inspect TLS certificate and edge DNS records (SPF, DMARC)`,
              ],
              configToReview: [
                'Web server configuration (Nginx, Apache, or Caddy)',
                'DNS provider settings (Cloudflare, Route53, Google Domains)',
              ],
              mitigationToApply: {
                summary: f.recommendation,
                filename: f.category === 'SSL' ? 'ssl.conf' : 'security-headers.conf',
                codeSnippet: f.codeSnippet || `# Defensive Configuration\n${f.recommendation}`,
              },
              howToVerify: [
                `Test configuration: curl -sI ${target.url}`,
                `Verify expected defensive headers and certificates are in place`,
              ],
            }
          );
        }
      }

      this.notify();
      return data;
    } catch (err: any) {
      console.warn('Deep scan failed:', err);
      return null;
    }
  }

  // Ingest & Parse Real Server Log File (.log, .txt, JSON)
  public async parseRealLogFile(targetId: string, logContent: string): Promise<any> {
    const target = this.getTarget(targetId);
    if (!target) return null;

    try {
      const res = await fetch('/api/logs/parse-real', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ logContent, targetId }),
      });

      if (!res.ok) {
        throw new Error(`Log parser returned status ${res.status}`);
      }

      const data = await res.json();
      if (data.events && Array.isArray(data.events)) {
        this.ingestLogs(targetId, data.events);
        target.realEventsCount = (target.realEventsCount || 0) + data.events.length;
      }

      if (data.threats && Array.isArray(data.threats)) {
        for (const t of data.threats) {
          const matchingLogs = (data.events || []).filter((e: LogEvent) => t.logIds?.includes(e.id));
          this.createThreat(
            targetId,
            `LOG_THREAT_${t.threatName.replace(/\s+/g, '_')}`,
            t.threatName,
            t.severity,
            t.confidence || 90,
            t.affectedEndpoint || '/',
            t.evidence || [],
            matchingLogs,
            t.whatHappened,
            t.whyFlagged,
            {
              title: `Remediate ${t.threatName}`,
              whatToCheck: [
                `Check application logs and endpoint ${t.affectedEndpoint}`,
                `Verify WAF or reverse-proxy blocking rules`,
              ],
              configToReview: [
                'Nginx rate limiting & bad bot blocking rules',
                'Application input validation and SQL parameterization',
              ],
              mitigationToApply: {
                summary: 'Block malicious query patterns and suspicious clients at the edge reverse proxy.',
                filename: 'waf-rules.conf',
                codeSnippet: `# Nginx Block Scanner / Attack Payloads\nlocation ~* (union.*select|benchmark\\(|waitfor.*delay|/etc/passwd) {\n    deny all;\n    return 403;\n}`,
              },
              howToVerify: [
                'Verify 403 Forbidden is returned for injection probes',
                'Confirm threat counts reduce and incidents resolve',
              ],
            }
          );
        }
      }

      this.notify();
      return data;
    } catch (err: any) {
      console.error('Real log parsing failed:', err);
      throw err;
    }
  }

  // Pre-configured real-world server log samples for instant testing
  public getSampleNginxAccessLog(): string {
    const now = new Date();
    const dateStr = now.toUTCString();
    return `93.184.216.34 - - [${dateStr}] "GET / HTTP/1.1" 200 4523 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
198.51.100.12 - - [${dateStr}] "GET /api/v1/health HTTP/1.1" 200 128 "-" "Uptime-Robot/2.0"
203.0.113.88 - - [${dateStr}] "POST /login HTTP/1.1" 401 54 "https://example.com/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
203.0.113.88 - - [${dateStr}] "POST /login HTTP/1.1" 401 54 "https://example.com/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
141.98.10.45 - - [${dateStr}] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; ReconBot/1.0)"
141.98.10.45 - - [${dateStr}] "GET /.git/HEAD HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; ReconBot/1.0)"
185.220.101.5 - - [${dateStr}] "GET /products?category=1'%20OR%20'1'='1 HTTP/1.1" 200 8120 "-" "sqlmap/1.6.4#stable"
185.220.101.5 - - [${dateStr}] "GET /products?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 500 240 "-" "sqlmap/1.6.4#stable"
77.88.55.66 - - [${dateStr}] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 98 "-" "Nikto/2.1.6"
93.184.216.34 - - [${dateStr}] "GET /assets/style.css HTTP/1.1" 200 1240 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`;
  }
}

export const securityStore = new SecurityStore();

