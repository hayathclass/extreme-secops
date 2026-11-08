export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';

export type EventSeverity = 'NORMAL' | 'LOW' | 'SUSPICIOUS' | 'CRITICAL';

export type EventType =
  | 'AUTHENTICATION'
  | 'API_REQUEST'
  | 'STATIC_RESOURCE'
  | 'PROBE'
  | 'PAGEVIEW'
  | 'CLIENT_ERROR'
  | 'INJECTION_ATTEMPT'
  | 'RATE_SPIKE'
  | 'CONFIG_ACCESS'
  | 'ADMIN_ACCESS'
  | 'HEARTBEAT'
  | 'USER_INTERACTION'
  | 'SESSION_END';

export type LogSource = 'REAL_LIVE_INGEST' | 'REAL_SERVER_PROBE' | 'REAL_LOG_FILE' | 'SIMULATION';

export type TelemetryMode = 'REAL_ONLY' | 'SIMULATION' | 'ALL';

export interface LogEvent {
  id: string;
  targetId: string;
  timestamp: string; // ISO 8601
  displayTime: string; // HH:mm:ss
  method: HttpMethod;
  endpoint: string;
  status: number;
  sourceIp: string;
  userAgent: string;
  eventType: EventType;
  severity: EventSeverity;
  latencyMs: number;
  isLab: boolean;
  logSource?: LogSource;
  headers?: Record<string, string>;
  payloadSnippet?: string;
  flagReason?: string;
  matchedRuleId?: string;
  clientGeo?: {
    country?: string;
    city?: string;
    device?: string;
    visitorId?: string;
  };
  probeDetails?: {
    protocol?: string;
    serverHeader?: string;
    hsts?: boolean;
    csp?: boolean;
    xFrameOptions?: string;
    contentType?: string;
    title?: string;
    ssl?: {
      valid: boolean;
      issuer: string;
      validTo: string;
      daysRemaining: number;
      protocol: string;
      cipher: string;
    };
    dns?: {
      ipAddresses: string[];
      mxRecords: string[];
      hasSpf: boolean;
      hasDmarc: boolean;
    };
    sensitivePaths?: Array<{
      path: string;
      status: number;
      exposed: boolean;
      detail: string;
    }>;
  };
}

export interface Target {
  id: string;
  name: string;
  url: string;
  hostname: string;
  isLab: boolean;
  connectedAt: string;
  status: 'MONITORING' | 'IDLE' | 'ALERTING' | 'DISCONNECTED';
  apiKey: string;
  totalRequests: number;
  securityEventsCount: number;
  threatsCount: number;
  openIncidentsCount: number;
  lastEventAt?: string;
  customEndpoints?: string[];
  lastProbeStatus?: 'UP' | 'DOWN' | 'UNREACHABLE' | 'DEGRADED';
  lastProbeLatencyMs?: number;
  sourceType?: 'UPLOADED_ZIP' | 'LIVE_URL' | 'REAL_PRODUCTION';
  vulnerabilitiesDetected?: string[];
  telemetryMode?: TelemetryMode;
  realEventsCount?: number;
  realProbesCount?: number;
  securityScore?: number;
  securityGrade?: string;
  sslDetails?: {
    valid: boolean;
    issuer: string;
    validTo: string;
    daysRemaining: number;
    protocol: string;
    cipher: string;
  };
  dnsDetails?: {
    ipAddresses: string[];
    mxRecords: string[];
    hasSpf: boolean;
    hasDmarc: boolean;
    spfRecord?: string;
    dmarcRecord?: string;
  };
  sensitiveFindings?: Array<{
    path: string;
    status: number;
    exposed: boolean;
    detail: string;
  }>;
  headersAudit?: Record<string, string>;
  latencyHistory?: number[];
  uptimeHistory?: Array<{
    timestamp: string;
    status: 'UP' | 'DOWN' | 'DEGRADED';
    latencyMs: number;
    statusCode: number;
  }>;
  uptimePercentage?: number;
  monitoringIntervalSeconds?: number;
  isLiveMonitoring?: boolean;
  serverBanner?: string;
}

export interface VisitorPerson {
  id?: string;
  ip: string;
  device: string;
  country?: string;
  city?: string;
  firstSeen: string;
  lastSeen: string;
  totalHits: number;
  lastEndpoint: string;
  lastStatus: number;
  userAgent: string;
  isSimulated?: boolean;
  isOnline?: boolean;
  leftAt?: string;
}

export interface ThreatDetection {
  id: string;
  targetId: string;
  threatName: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number; // 0 - 100
  timestamp: string;
  displayTime: string;
  affectedEndpoint: string;
  evidence: string[]; // High-level evidence statements
  triggerLogIds: string[]; // Related log event IDs
  triggerLogs: LogEvent[]; // Correlated logs
  whatHappened: string;
  whyFlagged: string;
  isLab: boolean;
  ruleId: string;
}

export interface Remediation {
  id: string;
  threatId: string;
  threatName: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  affectedEndpoint: string;
  title: string;
  whatToCheck: string[];
  configToReview: string[];
  mitigationToApply: {
    summary: string;
    codeSnippet?: string;
    snippetLanguage?: string;
    filename?: string;
  };
  howToVerify: string[];
}

export interface IncidentTimelineStep {
  step: string;
  timestamp: string;
  displayTime: string;
  description: string;
  type: 'EVENT' | 'DETECTION' | 'ALERT' | 'INVESTIGATION' | 'MITIGATION';
}

export interface Incident {
  id: string;
  targetId: string;
  title: string;
  threatName: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  target: string;
  time: string;
  displayTime: string;
  status: 'OPEN' | 'INVESTIGATING' | 'MITIGATED' | 'RESOLVED';
  affectedEndpoint: string;
  confidence: number;
  timeline: IncidentTimelineStep[];
  evidenceLogIds: string[];
  evidenceLogs: LogEvent[];
  whatHappened: string;
  whyFlagged: string;
  remediation: Remediation;
  isLab: boolean;
}

export interface SecurityReport {
  generatedAt: string;
  target: Target;
  isLab: boolean;
  summary: {
    totalMonitoredRequests: number;
    securityEvents: number;
    threatsDetected: number;
    openIncidents: number;
    resolvedIncidents: number;
    healthStatus: 'HEALTHY' | 'ATTENTION_NEEDED' | 'ELEVATED_RISK' | 'CRITICAL_THREAT';
  };
  threats: ThreatDetection[];
  incidents: Incident[];
  remediations: Remediation[];
  recentEvidenceLogs: LogEvent[];
}

export interface AnalystCodePatch {
  filename: string;
  language: string;
  code: string;
  description: string;
}

export interface AnalystMessage {
  id: string;
  sender: 'user' | 'analyst';
  text: string;
  timestamp: string;
  structured?: {
    observed: string[];
    inferred: string[];
    recommended: string[];
    codePatch?: AnalystCodePatch;
    mitigationSteps?: string[];
    verificationCurl?: string;
  };
  insufficientEvidence?: boolean;
}
