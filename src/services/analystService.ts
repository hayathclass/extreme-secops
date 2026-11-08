import { GoogleGenAI } from '@google/genai';
import { LogEvent, ThreatDetection, Incident, Target } from '../types/security';

export interface AnalystResponse {
  answer: string;
  structured: {
    observed: string[];
    inferred: string[];
    recommended: string[];
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
        console.warn('Gemini API call failed, falling back to deterministic security engine:', err);
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
    const recentLogs = context.logs.slice(0, 25).map((l) => ({
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

    const systemInstruction = `You are EXTREME ANALYST, an elite principal cybersecurity engineer and threat investigation analyst.
YOUR EXPERTISE:
You answer ANY question related to cybersecurity, application security, cloud security, defensive engineering, attack mechanics, threat intelligence, and compliance.
DUAL CAPABILITIES:
1. TARGET TELEMETRY & INVESTIGATION:
   - When the user asks about the monitored target (${context.target.hostname}), recent logs, alerts, threats, or incidents, evaluate the factual context provided. State verified facts accurately without hallucinating unobserved log events.
2. UNIVERSAL CYBERSECURITY EXPERT:
   - When the user asks about ANY cybersecurity topic, vulnerability, attack type, protocol, tool, framework, or best practice (such as SQL Injection, XSS, CSRF, SSRF, IDOR, DDoS, Ransomware, Zero Trust, JWT/OAuth security, Password Hashing, WAF rules, Content Security Policy, OWASP Top 10, Port Scanning, Honeypots, Cryptography, Incident Response, etc.):
     Provide a thorough, highly technical, and practical answer with defensive configuration examples and code snippets.
RESPONSE FORMAT (MANDATORY):
Always organize your response into three clear sections:
[OBSERVED]
Factual observations from the target's telemetry (if answering about the target), OR the fundamental technical anatomy, attack signatures, and threat mechanisms of the security topic asked about.
[INFERRED]
Risk assessment, exploitability analysis, attacker motivation/methodology, systemic security implications, or detection confidence.
[RECOMMENDED]
Concrete, actionable defense guidance: configuration reviews, implementation code snippets, and verification procedures.
Tone: Authoritative, objective, engineering-focused, and practical.`;

    const prompt = `Target Information:
- Domain: ${context.target.hostname} (${context.target.url})
- Mode: ${context.target.isLab ? 'SIMULATED DEMO DATA' : 'REAL CONNECTED DATA'}
- Status: ${context.target.status}
- Monitored Requests: ${context.target.totalRequests}
- Security Events: ${context.target.securityEventsCount}
- Open Incidents: ${context.target.openIncidentsCount}

Available Security Logs (latest ${recentLogs.length}):
${JSON.stringify(recentLogs, null, 2)}

Active Threats Detected (${activeThreats.length}):
${JSON.stringify(activeThreats, null, 2)}

User Question: "${question}"

Provide your structured answer with [OBSERVED], [INFERRED], and [RECOMMENDED].`;

    const response = await this.ai!.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        systemInstruction,
        temperature: 0.25,
      },
    });

    const text = response.text || 'Security analysis completed.';
    return this.parseStructuredOutput(text);
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
    const hasThreats = context.threats.length > 0;
    const hasIncidents = context.incidents.length > 0;

    // 1. SQL Injection (SQLi)
    if (q.includes('sql') || q.includes('sqli') || q.includes('injection')) {
      const sqliThreat = context.threats.find((t) => t.threatName.toLowerCase().includes('sql'));
      const observed = [
        'SQL Injection occurs when untrusted user input is directly concatenated or interpolated into database queries without compile-time parameterization.',
        'Common vectors: tautology bypasses (\' OR \'1\'=\'1), UNION-based schema/data extraction, blind time delays (pg_sleep, WAITFOR DELAY), and stacked queries.',
        sqliThreat
          ? `Target Finding: Active SQL Injection probe detected on ${context.target.hostname} targeting endpoint ${sqliThreat.affectedEndpoint} (${sqliThreat.confidence}% confidence).`
          : `Target Telemetry: Currently monitoring ${context.target.hostname} for SQL syntax evasion patterns.`,
      ];
      const inferred = [
        'Exploitability: Critical. Attackers can bypass authentication gates, exfiltrate table contents (usernames, hashed passwords, PII), modify records, or execute OS commands via DB extensions.',
        'Root Cause: Dynamic query construction utilizing string formatting or template literals instead of parameterized bindings.',
      ];
      const recommended = [
        'Mandate parameterized queries or prepared statements across all database interaction layers (e.g., db.query("SELECT * FROM users WHERE email = $1", [email])).',
        'Employ hardened ORMs with strict type checking and avoid raw SQL concatenation helpers.',
        'Enforce database principle of least privilege: web app database role should not possess DROP, ALTER, or administrative superuser privileges.',
      ];
      return {
        answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
        structured: { observed, inferred, recommended },
        insufficientEvidence: false,
      };
    }

    // 2. Cross-Site Scripting (XSS)
    if (q.includes('xss') || q.includes('cross-site scripting') || q.includes('script injection')) {
      const observed = [
        'Cross-Site Scripting (XSS) occurs when malicious JavaScript is injected into trusted web applications and executed in the victim\'s browser.',
        'Variants: Reflected XSS (immediate reflection in query params), Stored XSS (persisted in DB and served to all users), and DOM-based XSS (client-side script writes unsafe data to DOM sinks).',
      ];
      const inferred = [
        'Impact: Session hijacking via document.cookie theft, credential phishing, unauthorized actions performed in victim context, and keylogging.',
        'Vulnerability condition: Inadequate output encoding, unsafe DOM sinks (innerHTML, eval, document.write), and lack of strict Content Security Policy.',
      ];
      const recommended = [
        'Set strict HTTP-only and Secure flags on authentication cookies: "Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Strict".',
        'Implement a strict Content Security Policy (CSP): "Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\'".',
        'Rely on framework auto-escaping (React JSX automatically escapes variables) and forbid dangerouslySetInnerHTML.',
      ];
      return {
        answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
        structured: { observed, inferred, recommended },
        insufficientEvidence: false,
      };
    }

    // 3. Cross-Site Request Forgery (CSRF)
    if (q.includes('csrf') || q.includes('cross-site request forgery')) {
      const observed = [
        'Cross-Site Request Forgery (CSRF) tricks an authenticated browser into transmitting unauthorized state-changing requests to a vulnerable application.',
        'Leverages the browser\'s default behavior of automatically including ambient session cookies with cross-origin requests.',
      ];
      const inferred = [
        'Impact: Unauthorized password changes, email address alterations, funds transfer, and account modification without victim consent.',
        'Condition: State-changing operations permitted via GET requests, or POST endpoints lacking anti-CSRF tokens or SameSite cookie protection.',
      ];
      const recommended = [
        'Set SameSite=Lax (default) or SameSite=Strict on all authentication and session cookies.',
        'Implement Synchronizer Token Pattern (anti-CSRF tokens in custom request headers like X-CSRF-Token or hidden form fields).',
        'Verify Origin and Referer HTTP headers on state-changing API endpoints.',
      ];
      return {
        answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
        structured: { observed, inferred, recommended },
        insufficientEvidence: false,
      };
    }

    // 4. DDoS / DoS / Rate Limiting
    if (q.includes('ddos') || q.includes('denial of service') || q.includes('dos') || q.includes('flood') || q.includes('rate limit')) {
      const observed = [
        'Denial of Service (DoS/DDoS) exhausts application or network resources to render services unavailable to legitimate users.',
        'Common vectors: Layer 7 HTTP floods (intensive API queries, login spam), Slowloris (slow headers holding socket connections), and Layer 3/4 volumetric floods.',
        `Target Monitoring: Tracking telemetry velocity and latency on ${context.target.hostname}.`,
      ];
      const inferred = [
        'Impact: Service outage, database connection pool starvation, elevated cloud infrastructure bills, and degraded user trust.',
        'Risk factor: Unprotected CPU-intensive endpoints (bcrypt hashing, PDF generation, unindexed database search).',
      ];
      const recommended = [
        'Implement edge rate-limiting middleware (express-rate-limit, Cloudflare WAF, or Nginx limit_req_zone).',
        'Deploy an Anycast CDN / reverse proxy with automated DDoS mitigation (Cloudflare, AWS Shield, Google Cloud Armor).',
        'Enforce connection timeouts and maximum body size restrictions (e.g. limit request body to 1MB).',
      ];
      return {
        answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
        structured: { observed, inferred, recommended },
        insufficientEvidence: false,
      };
    }

    // 5. Brute Force & Credential Stuffing
    if (q.includes('brute') || q.includes('credential') || q.includes('password') || q.includes('auth')) {
      const authThreat = context.threats.find((t) => t.threatName.toLowerCase().includes('auth'));
      const observed = [
        'Credential Stuffing & Brute Force: Automated submission of stolen credential pairs or dictionary wordlists against authentication endpoints.',
        'Indicators: High velocity of HTTP 401 Unauthorized responses, repeated requests from single or botnet source IPs, and scripted User-Agents.',
        authThreat
          ? `Active Finding: ${authThreat.threatName} flagged on ${authThreat.affectedEndpoint} with ${authThreat.confidence}% confidence.`
          : `Target telemetry: ${context.target.hostname} authentication endpoints are being actively monitored.`,
      ];
      const inferred = [
        'Impact: Account Takeover (ATO), unauthorized access to confidential customer data, and brand damage.',
        'High probability of automated tooling when failed authentication attempts exceed 5 requests within 30 seconds.',
      ];
      const recommended = [
        'Deploy IP and username-based rate limits with exponential backoff (e.g. 5 failed attempts locks IP for 15 minutes).',
        'Enforce Multi-Factor Authentication (MFA / TOTP or WebAuthn / Passkeys).',
        'Implement invisible CAPTCHA (Cloudflare Turnstile or reCAPTCHA v3) when suspicious velocity is detected.',
      ];
      return {
        answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
        structured: { observed, inferred, recommended },
        insufficientEvidence: false,
      };
    }

    // 6. Path Traversal & Dotfile Exposure (.env, .git)
    if (q.includes('path') || q.includes('traversal') || q.includes('env') || q.includes('dotfile') || q.includes('git')) {
      const observed = [
        'Path Traversal & Dotfile Reconnaissance: Requests attempting to access sensitive files outside the web root (e.g. ../../etc/passwd) or hidden files (.env, .git/config, .aws/credentials).',
        'Automated scanners frequently probe common paths: /.env, /.git/HEAD, /wp-config.php, /docker-compose.yml.',
      ];
      const inferred = [
        'Impact: Immediate exposure of database credentials, API secret keys, encryption salts, and application source code.',
        'Any HTTP 200 response to dotfiles constitutes a critical severity exposure.',
      ];
      const recommended = [
        'Deny all access to dotfiles at the web server layer (Nginx: location ~ /\\. { deny all; return 404; }).',
        'Sanitize file download paths using path.basename and path.resolve, ensuring resolved paths remain inside authorized root.',
        'Never store .env or version control directories in publicly accessible web document roots.',
      ];
      return {
        answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
        structured: { observed, inferred, recommended },
        insufficientEvidence: false,
      };
    }

    // 7. Security Headers (CSP, HSTS, CORS)
    if (q.includes('header') || q.includes('cors') || q.includes('csp') || q.includes('hsts')) {
      const observed = [
        'HTTP Security Headers instruct web browsers to enforce defensive behaviors against cross-site scripting, clickjacking, protocol downgrade, and unauthorized embedding.',
        'Essential headers: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options, X-Frame-Options, and Referrer-Policy.',
      ];
      const inferred = [
        'Absence of security headers leaves modern browsers unable to protect users against client-side exploitation even when application backend logic is sound.',
      ];
      const recommended = [
        'Use Helmet.js middleware for Node.js / Express applications: app.use(helmet()).',
        'Configure HSTS: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".',
        'Configure X-Frame-Options: "DENY" to prevent Clickjacking.',
        'Configure CORS with explicit allowed origins, avoiding wildcard ("*") with credentials enabled.',
      ];
      return {
        answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
        structured: { observed, inferred, recommended },
        insufficientEvidence: false,
      };
    }

    // 8. OWASP Top 10
    if (q.includes('owasp')) {
      const observed = [
        'OWASP Top 10 represents the most critical web application security risks defined by the Open Web Application Security Project.',
        'Key categories include: A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security Misconfiguration, A07 Identification & Auth Failures.',
      ];
      const inferred = [
        'Broken Access Control (BOLA/IDOR) is currently ranked #1, causing widespread unauthorized data exposure in modern APIs.',
      ];
      const recommended = [
        'Incorporate automated security testing (SAST/DAST) in CI/CD pipelines.',
        'Enforce server-side role and ownership validation on every data access query (never trust client-supplied user IDs).',
        'Conduct regular vulnerability assessments and dependency scanning (npm audit / Snyk).',
      ];
      return {
        answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
        structured: { observed, inferred, recommended },
        insufficientEvidence: false,
      };
    }

    // 9. Target Telemetry Specific Query ("What happened", "incident", "threats")
    if (q.includes('what happened') || q.includes('summarize') || q.includes('incident') || q.includes('threat') || q.includes('evidence')) {
      if (hasIncidents) {
        const topInc = context.incidents[0];
        const observed = [
          `Incident: "${topInc.title}" recorded on endpoint ${topInc.affectedEndpoint}`,
          `Evidence: ${topInc.evidenceLogs.length} correlated events logged with ${topInc.severity} severity.`,
          `Detection confidence: ${topInc.confidence}% | Current Status: ${topInc.status}`,
        ];
        const inferred = [
          topInc.whyFlagged,
          `Threat classification: ${topInc.threatName} on target ${context.target.hostname}.`,
        ];
        const recommended = topInc.remediation?.whatToCheck || [
          'Review endpoint access controls and authorization layers.',
          'Deploy rate limiting or IP-level firewall blocks.',
        ];
        return {
          answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
          structured: { observed, inferred, recommended },
          insufficientEvidence: false,
        };
      }
    }

    // 10. Default Universal Cybersecurity Inquiry Handler
    const observed = [
      `Security Analysis for Query: "${question}"`,
      `Monitored Target: ${context.target.hostname} (${context.target.isLab ? 'DEMO SIMULATION' : 'LIVE PRODUCTION'})`,
      `Active buffer contains ${context.logs.length} telemetry events, ${context.threats.length} threats, and ${context.incidents.length} incidents.`,
    ];
    const inferred = [
      'Evaluation: Security controls must follow Defense-in-Depth across transport, identity, input validation, and storage layers.',
      hasThreats
        ? `Note: Target currently has ${context.threats.length} active alerts requiring defensive attention.`
        : 'Target telemetry indicates baseline nominal activity; ensure continuous monitoring is maintained.',
    ];
    const recommended = [
      'Audit API endpoints against the OWASP Top 10 and OWASP API Security Top 10.',
      'Enforce strict input validation, parameterized queries, and output encoding across all application boundaries.',
      'Configure automated security alerting and review incident response playbooks regularly.',
    ];
    return {
      answer: `[OBSERVED]\n${observed.join('\n')}\n\n[INFERRED]\n${inferred.join('\n')}\n\n[RECOMMENDED]\n${recommended.join('\n')}`,
      structured: { observed, inferred, recommended },
      insufficientEvidence: false,
    };
  }

  private parseStructuredOutput(text: string): AnalystResponse {
    const observed: string[] = [];
    const inferred: string[] = [];
    const recommended: string[] = [];
    const sections = text.split(/(?=\[(?:OBSERVED|INFERRED|RECOMMENDED)\])/i);

    for (const sec of sections) {
      if (/^\[OBSERVED\]/i.test(sec.trim())) {
        const content = sec.replace(/^\[OBSERVED\]/i, '').trim();
        observed.push(...content.split('\n').filter((l) => l.trim().length > 0));
      } else if (/^\[INFERRED\]/i.test(sec.trim())) {
        const content = sec.replace(/^\[INFERRED\]/i, '').trim();
        inferred.push(...content.split('\n').filter((l) => l.trim().length > 0));
      } else if (/^\[RECOMMENDED\]/i.test(sec.trim())) {
        const content = sec.replace(/^\[RECOMMENDED\]/i, '').trim();
        recommended.push(...content.split('\n').filter((l) => l.trim().length > 0));
      }
    }

    const insufficientEvidence =
      text.toLowerCase().includes('insufficient evidence') &&
      observed.length === 0 &&
      inferred.length === 0 &&
      recommended.length === 0;

    return {
      answer: text,
      structured: {
        observed: observed.length > 0 ? observed : [text],
        inferred: inferred.length > 0 ? inferred : ['Expert analysis evaluated.'],
        recommended: recommended.length > 0 ? recommended : ['Apply standard security hardening.'],
      },
      insufficientEvidence,
    };
  }
}

export const analystService = new AnalystService();
