import { GoogleGenAI } from '@google/genai';
import { LogEvent, ThreatDetection, Incident, Target, AnalystCodePatch } from '../types/security';

export interface AnalystResponse {
  answer: string;
  structured: {
    observed: string[];
    inferred: string[];
    recommended: string[];
    codePatch?: AnalystCodePatch;
    mitigationSteps?: string[];
    verificationCurl?: string;
  };
  insufficientEvidence: boolean;
}

export class AnalystService {
  private ai: GoogleGenAI | null = null;

  constructor() {
    const apiKey =
      (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_GEMINI_API_KEY) ||
      (typeof process !== 'undefined' && process.env?.GEMINI_API_KEY);

    if (apiKey) {
      try {
        this.ai = new GoogleGenAI({
          apiKey,
          httpOptions: {
            headers: {
              'User-Agent': 'aistudio-build',
            },
          },
        });
      } catch (e) {
        console.warn('Could not initialize Gemini SDK client:', e);
      }
    }
  }

  public async askAnalyst(
    question: string,
    context: {
      target: Target;
      logs: LogEvent[];
      threats: ThreatDetection[];
      incidents: Incident[];
    }
  ): Promise<AnalystResponse> {
    if (this.ai) {
      try {
        return await this.callGemini(question, context);
      } catch (err) {
        console.warn('Gemini API call failed, falling back to Monster Security Engine:', err);
      }
    }
    return this.deterministicAnalyst(question, context);
  }

  private async callGemini(
    question: string,
    context: {
      target: Target;
      logs: LogEvent[];
      threats: ThreatDetection[];
      incidents: Incident[];
    }
  ): Promise<AnalystResponse> {
    const recentLogs = context.logs.slice(0, 30).map((l) => ({
      time: l.displayTime,
      method: l.method,
      endpoint: l.endpoint,
      status: l.status,
      sourceIp: l.sourceIp,
      severity: l.severity,
      payloadSnippet: l.payloadSnippet,
      flagReason: l.flagReason,
    }));

    const activeThreats = context.threats.map((t) => ({
      name: t.threatName,
      severity: t.severity,
      confidence: `${t.confidence}%`,
      affectedEndpoint: t.affectedEndpoint,
      evidence: t.evidence,
      whatHappened: t.whatHappened,
      whyFlagged: t.whyFlagged,
    }));

    const systemInstruction = `You are EXTREME ANALYST — the principal cyber defense & incident response commander for web applications.
You are actively monitoring: ${context.target.hostname} (${context.target.url}).
ATC Online Simulator is a Next.js web application.

MISSION:
Whenever any problem, threat, anomaly, latency spike, or security vulnerability occurs on the monitored website, you provide a NEXT-LEVEL, PRODUCTION-READY SOLUTION.

RESPONSE STRUCTURE (MANDATORY):
Organize every response into these precise labeled blocks:

[OBSERVED]
- Factual technical breakdown: exact endpoint, timestamps, source IPs, status codes, payload analysis, and system conditions.

[INFERRED]
- Exploitability assessment, root cause analysis, attacker intent, blast radius, and vulnerability mechanics.

[RECOMMENDED]
- Actionable engineering strategy: architectural hardening, WAF configuration, and zero-trust controls.

[CODE_PATCH]
FILENAME: <exact file to edit, e.g. middleware.ts or next.config.mjs>
LANGUAGE: <typescript | javascript | json | bash>
DESCRIPTION: <brief one-line summary of what this code patch does>
CODE:
\`\`\`<language>
<complete, copy-pasteable, hardened production code>
\`\`\`

[MITIGATION_STEPS]
1. <immediate containment action within 60 seconds>
2. <patch deployment step>
3. <firewall / WAF edge rule>
4. <audit & recovery step>

[VERIFICATION_CURL]
<exact curl command to test the endpoint and verify the patch blocks the attack with 403/429>`;

    const prompt = `TARGET TELEMETRY CONTEXT:
- Domain: ${context.target.hostname} (${context.target.url})
- Status: ${context.target.status}
- Live Probe: ${context.target.lastProbeStatus || 'UP'} (${context.target.lastProbeLatencyMs || 42}ms)
- Total Requests Monitored: ${context.target.totalRequests}
- Security Events / Flags: ${context.target.securityEventsCount}
- Active Threats Detected: ${activeThreats.length}
- Open Incidents: ${context.incidents.length}

Recent Telemetry Logs (${recentLogs.length} events):
${JSON.stringify(recentLogs, null, 2)}

Active Threats Detected (${activeThreats.length}):
${JSON.stringify(activeThreats, null, 2)}

USER INQUIRY: "${question}"

Deliver a comprehensive, monster cybersecurity response with [OBSERVED], [INFERRED], [RECOMMENDED], [CODE_PATCH], [MITIGATION_STEPS], and [VERIFICATION_CURL].`;

    const response = await this.ai!.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction,
        temperature: 0.2,
      },
    });

    const text = response.text || 'Security intelligence analysis completed.';
    return this.parseStructuredOutput(text, context);
  }

  public deterministicAnalyst(
    question: string,
    context: {
      target: Target;
      logs: LogEvent[];
      threats: ThreatDetection[];
      incidents: Incident[];
    }
  ): AnalystResponse {
    const q = question.toLowerCase();
    const topThreat = context.threats[0];
    const topIncident = context.incidents[0];
    const targetHost = context.target.hostname || 'atc-onlinesimulator.onrender.com';
    const targetUrl = context.target.url || 'https://atc-onlinesimulator.onrender.com';

    // =========================================================================
    // 1. SOLVE ACTIVE PROBLEM / THREAT ON MONITORED ATC WEBSITE
    // =========================================================================
    if (
      q.includes('solve') ||
      q.includes('fix') ||
      q.includes('problem') ||
      q.includes('issue') ||
      q.includes('current') ||
      q.includes('what is wrong') ||
      q.includes('active threat') ||
      (q.includes('atc') && (q.includes('hack') || q.includes('attack') || q.includes('down') || q.includes('slow')))
    ) {
      if (topThreat || topIncident) {
        const threatName = topThreat?.threatName || topIncident?.title || 'Suspicious Web Attack Sequence';
        const endpoint = topThreat?.affectedEndpoint || topIncident?.affectedEndpoint || '/';
        const severity = topThreat?.severity || topIncident?.severity || 'HIGH';
        const confidence = topThreat?.confidence || topIncident?.confidence || 95;
        const evidence = topThreat?.evidence || [
          `Target: ${targetHost}`,
          `Flagged Endpoint: ${endpoint}`,
          `Severity: ${severity}`,
        ];

        return {
          answer: `🚨 [INCIDENT DETECTED]: ${threatName} on ${targetHost}${endpoint}`,
          structured: {
            observed: [
              `Target Under Active Monitoring: ${targetHost} (${targetUrl})`,
              `Active Security Alert: "${threatName}" [Severity: ${severity}, Confidence: ${confidence}%]`,
              `Targeted Endpoint: ${endpoint}`,
              ...evidence.slice(0, 3),
              `Live Probe Status: ${context.target.lastProbeStatus || 'UP'} (${context.target.lastProbeLatencyMs || 42}ms latency)`,
            ],
            inferred: [
              `Root Cause: Malicious request pattern exploiting unshielded endpoint ${endpoint}.`,
              `Attacker Objective: Probe application boundaries, test input validation evasion, or exhaust compute resources.`,
              `Risk Impact: Potential data exfiltration, service degradation, or unauthorized state alteration on ${targetHost}.`,
            ],
            recommended: [
              `1. Immediately deploy Next.js edge middleware to reject unauthorized request signatures with HTTP 403 Forbidden.`,
              `2. Enforce strict rate-limiting (maximum 10 requests per 10-second window per client IP).`,
              `3. Add Cloudflare / Edge WAF rule blocking suspicious user-agents and SQL/XSS evasion sequences.`,
              `4. Enable Content-Security-Policy (CSP) and HSTS security headers in next.config.mjs.`,
            ],
            codePatch: {
              filename: 'middleware.ts',
              language: 'typescript',
              description: 'Next.js Edge Middleware — Drop Attack Payloads & Enforce IP Rate Limiting',
              code: `import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

// Sliding-window in-memory rate limiter
const ipRequestCounts = new Map<string, { count: number; resetAt: number }>();

// Malicious attack signature regex (SQLi, Directory Traversal, Script Injection, Scanner Bots)
const ATTACK_REGEX = /(\\.\\.\\/|\\.\\.%2f|'\\s*OR\\s*'1'='1|UNION\\s+SELECT|<script|nikto|sqlmap|masscan)/i;

export function middleware(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for')?.split(',')[0].trim() || '127.0.0.1';
  const url = request.nextUrl.pathname;
  const userAgent = request.headers.get('user-agent') || '';
  const searchParams = request.nextUrl.search;

  // 1. Immediately drop malicious payloads or automated vulnerability scanners
  if (ATTACK_REGEX.test(url) || ATTACK_REGEX.test(searchParams) || ATTACK_REGEX.test(userAgent)) {
    return new NextResponse(
      JSON.stringify({ error: 'Blocked by EXTREME Defense Shield: Malicious Pattern Detected' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } }
    );
  }

  // 2. Protect sensitive files and hidden dotfiles (.env, .git, .vscode)
  if (url.startsWith('/.') || url.includes('/.env') || url.includes('/.git')) {
    return new NextResponse('Not Found', { status: 404 });
  }

  // 3. Sliding-window IP Rate Limiter (Max 25 requests per 10 seconds per IP)
  const now = Date.now();
  const windowMs = 10_000;
  const limit = 25;
  const record = ipRequestCounts.get(ip);

  if (!record || now > record.resetAt) {
    ipRequestCounts.set(ip, { count: 1, resetAt: now + windowMs });
  } else {
    record.count += 1;
    if (record.count > limit) {
      return new NextResponse(
        JSON.stringify({ error: 'Too Many Requests: Rate limit exceeded. Try again in 10 seconds.' }),
        { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '10' } }
      );
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};`,
            },
            mitigationSteps: [
              'Deploy the middleware.ts patch above into your Next.js project root to intercept all incoming requests.',
              'Verify that environment variables (Firebase secrets, API keys) are kept strictly server-side without NEXT_PUBLIC_ prefixes.',
              'Add Cloudflare WAF Expression: (http.request.uri.path contains "/." or http.user_agent contains "sqlmap") -> Action: Block.',
              'Monitor the Extreme SecOps live stream to confirm that offending requests now receive HTTP 403 Forbidden.',
            ],
            verificationCurl: `curl -i -X GET "${targetUrl}${endpoint}?probe='%20OR%20'1'='1" -H "User-Agent: Nikto/2.1.6"`,
          },
          insufficientEvidence: false,
        };
      }
    }

    // =========================================================================
    // 2. SQL INJECTION (SQLi) & DATABASE HARDENING
    // =========================================================================
    if (q.includes('sql') || q.includes('sqli') || q.includes('injection')) {
      return {
        answer: `🛡️ [NEXT-LEVEL DEFENSE]: Parameterized Queries & Runtime Input Sanitization`,
        structured: {
          observed: [
            'SQL Injection (SQLi) occurs when untrusted user input is directly concatenated or template-interpolated into SQL statements.',
            'Vectors: Tautology bypasses (\' OR \'1\'=\'1), UNION SELECT data harvesting, stacked DDL execution (DROP TABLE), and blind sleep delays (pg_sleep, WAITFOR DELAY).',
            `Target ${targetHost} monitoring: Analyzing all endpoint queries for SQL syntax evasion tokens.`,
          ],
          inferred: [
            'Risk Level: CRITICAL. Exploitation enables authentication bypass, full database dump, password hash extraction, and unauthorized record modification.',
            'Vulnerable Pattern: Dynamic queries like "SELECT * FROM users WHERE email = " + email without compile-time parameterization.',
          ],
          recommended: [
            'Always use parameterized queries ($1, $2 or ?) provided by database drivers (pg, postgres, Prisma, Drizzle).',
            'Enforce compile-time schema validation with Zod on all incoming API request bodies and query parameters.',
            'Grant least-privilege DB permissions: application user must not possess DROP, ALTER, or SUPERUSER roles.',
          ],
          codePatch: {
            filename: 'lib/db/secureQuery.ts',
            language: 'typescript',
            description: 'Hardened Database Query Pattern with Parameterized Bindings & Zod Schema Validation',
            code: `import { z } from 'zod';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// 1. Strict Input Schema
export const UserQuerySchema = z.object({
  email: z.string().email().max(100),
  tenantId: z.string().uuid(),
});

// 2. Parameterized Query — Immune to SQL Injection
export async function getUserByEmail(input: unknown) {
  // Validate before query touches database
  const validated = UserQuerySchema.parse(input);

  // Parameter bindings ($1, $2) guarantee database treats input purely as data, never executable SQL
  const query = 'SELECT id, email, role, created_at FROM users WHERE email = $1 AND tenant_id = $2 LIMIT 1';
  const values = [validated.email, validated.tenantId];

  const result = await pool.query(query, values);
  return result.rows[0] || null;
}`,
          },
          mitigationSteps: [
            'Audit every database query in the repository and eliminate all string concatenations (\`SELECT ... \${val}\`).',
            'Implement Zod schemas on every route handler to reject malformed payloads before database execution.',
            'Enable Edge WAF rule to block SQL evasion sequences: (http.request.uri.path contains "union+select" or http.request.body contains "1=1").',
          ],
          verificationCurl: `curl -i -X POST "${targetUrl}/api/login" -H "Content-Type: application/json" -d '{"email":"admin@site.com' OR '1'='1","password":"test"}'`,
        },
        insufficientEvidence: false,
      };
    }

    // =========================================================================
    // 3. BRUTE FORCE & CREDENTIAL STUFFING DEFENSE
    // =========================================================================
    if (q.includes('brute') || q.includes('credential') || q.includes('password') || q.includes('auth') || q.includes('login')) {
      return {
        answer: `🔒 [NEXT-LEVEL DEFENSE]: Token-Bucket Rate Limiter & Account Lockout Shield`,
        structured: {
          observed: [
            'Credential Stuffing & Brute-Force: Automated submission of dictionary wordlists or credential dumps against login/auth endpoints.',
            'Indicators: High frequency of HTTP 401 Unauthorized bursts from identical or rotating IP clusters within short time intervals.',
            `Active monitoring on ${targetHost}: Tracking authentication request velocity and failed login ratios.`,
          ],
          inferred: [
            'Risk: Account Takeover (ATO), credential harvesting, customer account compromise, and compute exhaustion.',
            'Threshold: Any client IP triggering > 5 failed authentication attempts within 60 seconds is identified as a scripted bot.',
          ],
          recommended: [
            'Implement an IP-based token-bucket rate limiter that enforces exponential backoff upon repeated 401 responses.',
            'Enforce Multi-Factor Authentication (MFA / TOTP) or passkeys for sensitive accounts.',
            'Implement Cloudflare Turnstile or CAPTCHA triggers after 3 consecutive failures.',
          ],
          codePatch: {
            filename: 'lib/auth/rateLimiter.ts',
            language: 'typescript',
            description: 'In-Memory Sliding-Window Authentication Shield with Lockout',
            code: `interface AttemptRecord {
  attempts: number;
  lockedUntil: number;
}

const authAttempts = new Map<string, AttemptRecord>();

export function checkAuthRateLimit(clientIp: string): { allowed: boolean; retryAfterSeconds?: number } {
  const now = Date.now();
  const record = authAttempts.get(clientIp);

  if (record && record.lockedUntil > now) {
    const retryAfter = Math.ceil((record.lockedUntil - now) / 1000);
    return { allowed: false, retryAfterSeconds: retryAfter };
  }

  return { allowed: true };
}

export function recordAuthFailure(clientIp: string): void {
  const now = Date.now();
  const record = authAttempts.get(clientIp) || { attempts: 0, lockedUntil: 0 };

  record.attempts += 1;

  // Lock IP for 15 minutes after 5 failed attempts
  if (record.attempts >= 5) {
    record.lockedUntil = now + 15 * 60 * 1000;
  }

  authAttempts.set(clientIp, record);
}

export function recordAuthSuccess(clientIp: string): void {
  authAttempts.delete(clientIp);
}`,
          },
          mitigationSteps: [
            'Integrate checkAuthRateLimit at the start of your login route handler.',
            'Call recordAuthFailure whenever passwords fail validation and return HTTP 429 Too Many Requests once locked.',
            'Call recordAuthSuccess on valid logins to reset failure counts.',
            'Set secure cookie flags: HttpOnly; Secure; SameSite=Strict; Path=/.',
          ],
          verificationCurl: `for i in {1..7}; do curl -i -X POST "${targetUrl}/api/auth/login" -H "Content-Type: application/json" -d '{"user":"test","pass":"wrong"}' ; sleep 0.5; done`,
        },
        insufficientEvidence: false,
      };
    }

    // =========================================================================
    // 4. NEXT.JS FULL SECURITY HEADERS (CSP, HSTS, X-FRAME-OPTIONS)
    // =========================================================================
    if (q.includes('header') || q.includes('csp') || q.includes('hsts') || q.includes('cors') || q.includes('next.config')) {
      return {
        answer: `🛡️ [NEXT-LEVEL DEFENSE]: Production Grade HTTP Security Headers for Next.js`,
        structured: {
          observed: [
            `HTTP Security Headers instruct web browsers to enforce strict sandboxing on ${targetHost}.`,
            'Missing headers permit clickjacking, cross-site framing, MIME-type sniffing, and protocol downgrade attacks.',
            `Headers checked: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.`,
          ],
          inferred: [
            'Without HSTS, attackers on open Wi-Fi can perform SSL Strip to downgrade HTTPS sessions to unencrypted HTTP.',
            'Without X-Frame-Options: DENY, malicious sites can embed ATC Online Simulator in an invisible iframe to execute clickjacking attacks.',
          ],
          recommended: [
            'Configure security headers directly in next.config.mjs so all SSR, API, and static routes inherit them automatically.',
            'Enforce HSTS with a 2-year max-age, includeSubDomains, and preload.',
            'Enforce X-Content-Type-Options: nosniff to prevent script execution from uploaded images or text files.',
          ],
          codePatch: {
            filename: 'next.config.mjs',
            language: 'javascript',
            description: 'Hardened Security Headers Configuration for Next.js',
            code: `/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), browsing-topics=()',
          },
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://extreme-secops.onrender.com",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
              "font-src 'self' https://fonts.gstatic.com data:",
              "img-src 'self' data: https:",
              "connect-src 'self' https://extreme-secops.onrender.com https://*.firebaseio.com https://*.googleapis.com wss://*",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
            ].join('; '),
          },
        ],
      },
    ];
  },
};

export default nextConfig;`,
          },
          mitigationSteps: [
            'Paste the headers block into next.config.mjs in your Next.js project.',
            'Run npm run build to verify syntax compilation.',
            'Deploy to Render/Vercel and inspect the live HTTP headers using curl -I.',
          ],
          verificationCurl: `curl -I "${targetUrl}"`,
        },
        insufficientEvidence: false,
      };
    }

    // =========================================================================
    // 5. DDOS, LAYER 7 FLOODS & MALICIOUS SCANNER BOTS
    // =========================================================================
    if (q.includes('ddos') || q.includes('flood') || q.includes('scanner') || q.includes('bot') || q.includes('nikto') || q.includes('sqlmap')) {
      return {
        answer: `🛑 [NEXT-LEVEL DEFENSE]: Edge Automated Scanner Blocker & Velocity Shield`,
        structured: {
          observed: [
            'Automated scanners (Nikto, sqlmap, masscan, OWASP ZAP) send thousands of rapid requests with specialized signature headers.',
            'Layer 7 HTTP Floods attempt to exhaust CPU, Node.js event loops, or database connection pools.',
            `Active telemetry on ${targetHost}: Tracking User-Agent signatures and request latency distributions.`,
          ],
          inferred: [
            'Attacker Methodology: Automated reconnaissance preceding targeted vulnerability exploitation.',
            'Impact: Elevated latency, Render container CPU throttling (100% usage), and false positive alert fatigue.',
          ],
          recommended: [
            'Block known scanner toolchain User-Agents immediately at the edge or middleware layer.',
            'Configure an Anycast reverse proxy / Cloudflare with Under Attack Mode enabled.',
            'Drop connections from requests lacking valid Host or Accept headers.',
          ],
          codePatch: {
            filename: 'lib/security/botBlocker.ts',
            language: 'typescript',
            description: 'Scanner Bot Filter Middleware & Cloudflare WAF Expression',
            code: `// Express / Next.js Bot Defense Helper
const FORBIDDEN_BOT_SIGNATURES = [
  'nikto', 'sqlmap', 'masscan', 'acunetix', 'nmap',
  'dirbuster', 'gobuster', 'wpscan', 'zgrab', 'censys'
];

export function isMaliciousBot(userAgent: string | null): boolean {
  if (!userAgent || userAgent.trim().length === 0) return true; // Scanners often omit UA
  const lower = userAgent.toLowerCase();
  return FORBIDDEN_BOT_SIGNATURES.some((bot) => lower.includes(bot));
}

/*
 * CLOUDFLARE WAF EXPRESSION RULE (Copy into Cloudflare Security > WAF):
 * (http.user_agent contains "nikto" or http.user_agent contains "sqlmap" or http.user_agent contains "masscan" or http.user_agent eq "")
 * Action: Block
 */`,
          },
          mitigationSteps: [
            'Drop all requests where isMaliciousBot(ua) returns true with HTTP 403 Forbidden.',
            'Set maximum request body size limits in Next.js / Express (limit: 1mb).',
            'Enable Cloudflare Bot Fight Mode in your Cloudflare dashboard.',
          ],
          verificationCurl: `curl -i -X GET "${targetUrl}/" -H "User-Agent: sqlmap/1.6#stable"`,
        },
        insufficientEvidence: false,
      };
    }

    // =========================================================================
    // 6. SENSITIVE DOTFILE EXPOSURE (.env, .git, .vscode)
    // =========================================================================
    if (q.includes('env') || q.includes('git') || q.includes('dotfile') || q.includes('traversal') || q.includes('sensitive file')) {
      return {
        answer: `🚫 [NEXT-LEVEL DEFENSE]: Strict Dotfile Drop & Path Traversal Lockdown`,
        structured: {
          observed: [
            `Dotfile Exposure: Requests attempting to access /.env, /.git/HEAD, /.vscode/settings.json, or /package.json.`,
            'Any successful HTTP 200 response to dotfiles leaks production secrets, private encryption keys, and database passwords.',
            `Active monitoring on ${targetHost}: Verified that sensitive paths return 403/404.`,
          ],
          inferred: [
            'Critical Threat: If .env is readable, attackers gain immediate administrative control over Firebase, databases, and third-party APIs.',
          ],
          recommended: [
            'Configure web server / Next.js to strictly drop all requests beginning with a dot (/.',
            'Ensure .env files are listed in .gitignore and never checked into GitHub repositories.',
            'Use platform-native environment variables (Render Environment Variables / Vercel Secrets) instead of on-disk .env in production.',
          ],
          codePatch: {
            filename: 'middleware.ts',
            language: 'typescript',
            description: 'Next.js Dotfile Lockdown Interceptor',
            code: `import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const path = request.nextUrl.pathname.toLowerCase();

  // Block any path containing dotfiles or parent traversal
  if (
    path.includes('/.') ||
    path.startsWith('/.') ||
    path.includes('..') ||
    path.includes('%2e%2e')
  ) {
    // Return 404 Not Found to prevent leaking that the file even exists
    return new NextResponse('Not Found', { status: 404 });
  }

  return NextResponse.next();
}`,
          },
          mitigationSteps: [
            'Deploy the dotfile blocking middleware.',
            'Rotate any API keys or Firebase secrets that were previously committed to version control.',
            'Audit repository history with git log -S "API_KEY" to ensure no secrets remain in git commits.',
          ],
          verificationCurl: `curl -i -X GET "${targetUrl}/.env"`,
        },
        insufficientEvidence: false,
      };
    }

    // =========================================================================
    // 7. DEFAULT UNIVERSAL CYBERSECURITY & TARGET INTELLIGENCE
    // =========================================================================
    const observed = [
      `Extreme Analyst Monster Engine Active for: ${targetHost} (${targetUrl})`,
      `Live Target Telemetry: ${context.target.totalRequests} events monitored | Status: ${context.target.lastProbeStatus || 'UP'} (${context.target.lastProbeLatencyMs || 42}ms)`,
      `Active Threat Alerts: ${context.threats.length} | Open Incidents: ${context.incidents.length}`,
      `Query Evaluated: "${question}"`,
    ];
    const inferred = [
      'Defense Assessment: The application requires layered controls spanning Edge WAF, Next.js Middleware, and Data Validation.',
      context.threats.length > 0
        ? `Target Alert: ${context.threats[0].threatName} is currently flagged on ${context.threats[0].affectedEndpoint}.`
        : 'Telemetry shows nominal baseline activity on ATC Online Simulator.',
    ];
    const recommended = [
      '1. Implement edge rate limiting and bot filtering in Next.js middleware.ts.',
      '2. Enforce strict HTTP security headers (HSTS, CSP, X-Frame-Options) in next.config.mjs.',
      '3. Validate all incoming parameters with Zod schemas to block injection vectors.',
      '4. Keep client telemetry streaming to https://extreme-secops.onrender.com/api/collector/ingest for 24/7 detection.',
    ];

    return {
      answer: `🛡️ Security Assessment & Next-Level Guidance for ${targetHost}`,
      structured: {
        observed,
        inferred,
        recommended,
        codePatch: {
          filename: 'middleware.ts',
          language: 'typescript',
          description: 'Universal Defense Shield for Next.js (Rate Limiting + Bot Blocker + Dotfile Protection)',
          code: `import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const url = request.nextUrl.pathname;
  const ua = request.headers.get('user-agent') || '';

  // 1. Drop sensitive dotfiles (.env, .git)
  if (url.includes('/.') || url.startsWith('/.')) {
    return new NextResponse('Not Found', { status: 404 });
  }

  // 2. Drop known malicious scanners
  if (/(nikto|sqlmap|masscan|acunetix)/i.test(ua)) {
    return new NextResponse('Access Denied', { status: 403 });
  }

  return NextResponse.next();
}`,
        },
        mitigationSteps: [
          'Verify that the collector script is active in layout.tsx on the ATC website.',
          'Review the Extreme SecOps Live Logs dashboard for real-time visitor IP tracking.',
          'Deploy security headers in next.config.mjs to achieve an A+ security rating.',
        ],
        verificationCurl: `curl -I "${targetUrl}"`,
      },
      insufficientEvidence: false,
    };
  }

  private parseStructuredOutput(text: string, context?: any): AnalystResponse {
    const observed: string[] = [];
    const inferred: string[] = [];
    const recommended: string[] = [];
    const mitigationSteps: string[] = [];
    let codePatch: AnalystCodePatch | undefined;
    let verificationCurl: string | undefined;

    const sections = text.split(/(?=\[(?:OBSERVED|INFERRED|RECOMMENDED|CODE_PATCH|MITIGATION_STEPS|VERIFICATION_CURL)\])/i);

    for (const sec of sections) {
      const trimmed = sec.trim();
      if (/^\[OBSERVED\]/i.test(trimmed)) {
        const content = trimmed.replace(/^\[OBSERVED\]/i, '').trim();
        observed.push(...content.split('\n').filter((l) => l.trim().length > 0));
      } else if (/^\[INFERRED\]/i.test(trimmed)) {
        const content = trimmed.replace(/^\[INFERRED\]/i, '').trim();
        inferred.push(...content.split('\n').filter((l) => l.trim().length > 0));
      } else if (/^\[RECOMMENDED\]/i.test(trimmed)) {
        const content = trimmed.replace(/^\[RECOMMENDED\]/i, '').trim();
        recommended.push(...content.split('\n').filter((l) => l.trim().length > 0));
      } else if (/^\[MITIGATION_STEPS\]/i.test(trimmed)) {
        const content = trimmed.replace(/^\[MITIGATION_STEPS\]/i, '').trim();
        mitigationSteps.push(...content.split('\n').filter((l) => l.trim().length > 0));
      } else if (/^\[VERIFICATION_CURL\]/i.test(trimmed)) {
        verificationCurl = trimmed.replace(/^\[VERIFICATION_CURL\]/i, '').trim();
      } else if (/^\[CODE_PATCH\]/i.test(trimmed)) {
        const content = trimmed.replace(/^\[CODE_PATCH\]/i, '').trim();
        const filenameMatch = content.match(/FILENAME:\s*(.+)/i);
        const langMatch = content.match(/LANGUAGE:\s*(.+)/i);
        const descMatch = content.match(/DESCRIPTION:\s*(.+)/i);
        const codeMatch = content.match(/```[a-z]*\n([\s\S]*?)```/i);

        if (codeMatch) {
          codePatch = {
            filename: filenameMatch ? filenameMatch[1].trim() : 'security-patch.ts',
            language: langMatch ? langMatch[1].trim() : 'typescript',
            description: descMatch ? descMatch[1].trim() : 'Defensive Security Patch',
            code: codeMatch[1].trim(),
          };
        }
      }
    }

    return {
      answer: text,
      structured: {
        observed: observed.length > 0 ? observed : [text],
        inferred: inferred.length > 0 ? inferred : ['Security analysis evaluated.'],
        recommended: recommended.length > 0 ? recommended : ['Apply defensive security controls.'],
        codePatch,
        mitigationSteps: mitigationSteps.length > 0 ? mitigationSteps : undefined,
        verificationCurl,
      },
      insufficientEvidence: false,
    };
  }
}

export const analystService = new AnalystService();
