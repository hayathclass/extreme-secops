import JSZip from 'jszip';
import { LogEvent, ThreatDetection, Incident, Remediation, HttpMethod, EventType, EventSeverity } from '../types/security';

export interface ScanFinding {
  id: string;
  category: 'SECRET_LEAK' | 'SQLI_VULN' | 'XSS_VULN' | 'PATH_TRAVERSAL' | 'CONFIG_MISCONFIG' | 'LOG_ATTACK';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  file: string;
  line?: number;
  snippet?: string;
  description: string;
  recommendation: string;
  remediationCode?: {
    filename: string;
    snippet: string;
    summary: string;
  };
}

export interface UploadScanResult {
  targetName: string;
  totalFilesScanned: number;
  totalLinesScanned: number;
  scannedFileNames: string[];
  findings: ScanFinding[];
  parsedLogs: LogEvent[];
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  securityScore: number; // 0 - 100
  securityGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  discoveredEndpoints: string[];
}

export class WebsiteUploadScanner {
  // Regex rules for static analysis (SAST)
  private secretPatterns = [
    {
      name: 'Exposed AWS Access Key',
      regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
      severity: 'CRITICAL' as const,
      desc: 'Found AWS Access Key ID hardcoded in source code.',
      fix: 'Remove key immediately and load credentials via environment variables or AWS Secrets Manager.',
    },
    {
      name: 'Exposed OpenAI / Gemini API Key',
      regex: /(?:sk-[a-zA-Z0-9]{32,}|AIza[0-9A-Za-z-_]{35})/g,
      severity: 'CRITICAL' as const,
      desc: 'Found hardcoded AI provider API key (OpenAI / Google Gemini).',
      fix: 'Store API keys strictly in server-side environment variables (.env) and never bundle into client code.',
    },
    {
      name: 'Exposed Private Cryptographic Key',
      regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
      severity: 'CRITICAL' as const,
      desc: 'Discovered private RSA/SSH cryptographic key in source repository.',
      fix: 'Revoke and rotate private key immediately. Store keys in dedicated KMS / Secret Vaults.',
    },
    {
      name: 'Hardcoded Database Connection String with Credentials',
      regex: /(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+/gi,
      severity: 'CRITICAL' as const,
      desc: 'Database connection URI contains plain-text credentials.',
      fix: 'Use environment variables (DATABASE_URL) and configure identity-based or IAM database auth.',
    },
    {
      name: 'Exposed GitHub Personal Access Token',
      regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
      severity: 'CRITICAL' as const,
      desc: 'Discovered active GitHub Personal Access Token.',
      fix: 'Revoke the token on GitHub immediately and review audit logs for unauthorized access.',
    },
    {
      name: 'Exposed Stripe API Secret Key',
      regex: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
      severity: 'CRITICAL' as const,
      desc: 'Hardcoded Stripe Secret Key detected.',
      fix: 'Move secret key to backend environment variables. Only publishable keys (pk_...) may be on client.',
    },
    {
      name: 'Hardcoded Plaintext Password or JWT Secret',
      regex: /(?:password|jwt_secret|jwtSecret|api_secret)\s*[:=]\s*["']([^"']{5,})["']/gi,
      severity: 'HIGH' as const,
      desc: 'Plaintext password or JWT signing secret assigned directly in code.',
      fix: 'Load secrets from environment variables; use at least 256-bit cryptographically random JWT secrets.',
    },
  ];

  private vulnPatterns = [
    {
      name: 'SQL Injection via String Concatenation',
      category: 'SQLI_VULN' as const,
      regex: /(?:db\.query|connection\.query|execute|executeQuery)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'][^"']*\s*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*\s*["']\s*\+\s*[a-zA-Z0-9_]+)/gi,
      severity: 'CRITICAL' as const,
      desc: 'Database query dynamically concatenates untrusted user variables into raw SQL.',
      fix: 'Refactor query to use parameterized bindings (e.g. $1, ? or ORM prepared statements).',
      codeSnippet: `// VULNERABLE:
// const res = await db.query(\`SELECT * FROM users WHERE email = '\${email}'\`);

// SECURE:
const res = await db.query('SELECT * FROM users WHERE email = $1', [email]);`,
    },
    {
      name: 'Cross-Site Scripting (XSS) via Unsafe DOM Sink',
      category: 'XSS_VULN' as const,
      regex: /(?:\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|eval\s*\()/gi,
      severity: 'HIGH' as const,
      desc: 'Direct assignment to innerHTML or dangerouslySetInnerHTML without HTML sanitization.',
      fix: 'Use textContent, React JSX bindings, or DOMPurify.sanitize() before DOM insertion.',
      codeSnippet: `// VULNERABLE:
// element.innerHTML = userProvidedInput;

// SECURE:
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userProvidedInput);
// OR: element.textContent = userProvidedInput;`,
    },
    {
      name: 'Insecure Path Traversal in File Operations',
      category: 'PATH_TRAVERSAL' as const,
      regex: /(?:fs\.readFile|fs\.readFileSync|fs\.createReadStream|res\.sendFile)\s*\(\s*(?:path\.join\([^)]*req\.|req\.(?:query|params|body))/gi,
      severity: 'HIGH' as const,
      desc: 'File system API directly consumes user-controlled path parameter without canonicalization.',
      fix: 'Sanitize path with path.basename() and verify target path starts with base directory.',
      codeSnippet: `import path from 'path';
const safeFilename = path.basename(req.query.file);
const fullPath = path.resolve(SAFE_DIR, safeFilename);
if (!fullPath.startsWith(path.resolve(SAFE_DIR))) {
  return res.status(403).send('Forbidden');
}`,
    },
    {
      name: 'Permissive Wildcard CORS Configuration',
      category: 'CONFIG_MISCONFIG' as const,
      regex: /(?:Access-Control-Allow-Origin\s*[:=]\s*["']\*["']|cors\(\s*\{\s*origin\s*:\s*(?:true|["']\*["'])\s*,\s*credentials\s*:\s*true)/gi,
      severity: 'MEDIUM' as const,
      desc: 'CORS policy configured with wildcard origin (*) or credentials allowed with open origin.',
      fix: 'Explicitly specify trusted origin whitelists rather than wildcard.',
      codeSnippet: `app.use(cors({
  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],
  credentials: true
}));`,
    },
    {
      name: 'Disabled Helmet / Missing Security Headers',
      category: 'CONFIG_MISCONFIG' as const,
      regex: /app\.disable\s*\(\s*["']x-powered-by["']\s*\)/gi,
      severity: 'LOW' as const,
      desc: 'Basic express configuration without comprehensive HTTP security headers.',
      fix: 'Install and mount helmet middleware to automatically set HSTS, CSP, and X-Content-Type-Options.',
      codeSnippet: `import helmet from 'helmet';
app.use(helmet());`,
    },
  ];

  /**
   * Scans a list of uploaded files (from <input type="file" multiple /> or folder drag & drop)
   */
  public async scanUploadedFiles(
    files: { name: string; content: string; size?: number }[],
    targetDomain: string = 'uploaded-website.com'
  ): Promise<UploadScanResult> {
    const findings: ScanFinding[] = [];
    const parsedLogs: LogEvent[] = [];
    const endpointSet = new Set<string>();
    endpointSet.add('/');
    let totalLines = 0;
    const scannedNames: string[] = [];

    for (const file of files) {
      scannedNames.push(file.name);
      const isLog =
        file.name.endsWith('.log') ||
        file.name.endsWith('.txt') ||
        file.name.includes('access') ||
        file.name.endsWith('.csv') ||
        file.name.endsWith('.json');

      if (isLog) {
        // Try parsing as server access logs
        const logResults = this.parseAccessLog(file.content, targetDomain);
        if (logResults.length > 0) {
          parsedLogs.push(...logResults);
        }
      }

      // Check for committed sensitive dotfiles
      if (file.name.endsWith('.env') || file.name.endsWith('.env.local') || file.name.endsWith('.env.production')) {
        findings.push({
          id: `finding-dotfile-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          category: 'SECRET_LEAK',
          severity: 'CRITICAL',
          title: 'Unencrypted Environment Secrets File Included in Upload',
          file: file.name,
          description: `The file '${file.name}' was detected in website assets. If published to a public document root, attackers can download application secrets.`,
          recommendation: 'Add .env to .gitignore and configure environment variables in cloud hosting provider.',
          remediationCode: {
            filename: '.gitignore',
            summary: 'Ensure dotfiles containing secrets are excluded from public deployments',
            snippet: `# Exclude environment files\n.env\n.env.local\n.env.*.local`,
          },
        });
      }

      // Static code analysis across source files (.js, .ts, .jsx, .tsx, .php, .py, .html, .env, .json, .yml, .sql)
      const lines = file.content.split('\n');
      totalLines += lines.length;

      // Scan for secrets
      for (const secretRule of this.secretPatterns) {
        let match;
        const regex = new RegExp(secretRule.regex.source, secretRule.regex.flags);
        while ((match = regex.exec(file.content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = file.content.substring(0, matchIndex).split('\n').length;
          const snippet = lines[lineNumber - 1]?.trim().slice(0, 100);

          findings.push({
            id: `finding-sec-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            category: 'SECRET_LEAK',
            severity: secretRule.severity,
            title: secretRule.name,
            file: file.name,
            line: lineNumber,
            snippet: snippet || match[0].slice(0, 40) + '...',
            description: `${secretRule.desc} Match on line ${lineNumber}.`,
            recommendation: secretRule.fix,
          });
        }
      }

      // Scan for code vulnerabilities (SQLi, XSS, Path Traversal, Misconfigurations)
      for (const vulnRule of this.vulnPatterns) {
        let match;
        const regex = new RegExp(vulnRule.regex.source, vulnRule.regex.flags);
        while ((match = regex.exec(file.content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = file.content.substring(0, matchIndex).split('\n').length;
          const snippet = lines[lineNumber - 1]?.trim().slice(0, 120);

          findings.push({
            id: `finding-vuln-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            category: vulnRule.category,
            severity: vulnRule.severity,
            title: vulnRule.name,
            file: file.name,
            line: lineNumber,
            snippet,
            description: `${vulnRule.desc} Detected on line ${lineNumber}.`,
            recommendation: vulnRule.fix,
            remediationCode: vulnRule.codeSnippet
              ? {
                  filename: file.name,
                  summary: vulnRule.fix,
                  snippet: vulnRule.codeSnippet,
                }
              : undefined,
          });
        }
      }

      // Extract realistic endpoints from routes, API calls, and filenames
      const routeRegex = /(?:app|router)\.(?:get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]/gi;
      let routeMatch;
      while ((routeMatch = routeRegex.exec(file.content)) !== null) {
        if (routeMatch[1] && routeMatch[1].startsWith('/')) {
          endpointSet.add(routeMatch[1]);
        }
      }

      const fetchRegex = /(?:fetch|axios\.(?:get|post|put|delete))\(\s*['"](\/[a-zA-Z0-9_\-\/\.\?=&]+)['"]/gi;
      let fetchMatch;
      while ((fetchMatch = fetchRegex.exec(file.content)) !== null) {
        if (fetchMatch[1] && fetchMatch[1].startsWith('/')) {
          endpointSet.add(fetchMatch[1]);
        }
      }

      // Extract based on file paths
      if (file.name.includes('api/') || file.name.includes('routes/')) {
        const cleanName = file.name
          .replace(/.*(?:api|routes)\//, '/api/')
          .replace(/\.(ts|js|jsx|tsx|php|py)$/, '');
        endpointSet.add(cleanName);
      } else if (file.name.endsWith('.html')) {
        const htmlName = file.name.replace(/.*[\\/]/, '').replace(/\.html$/, '');
        endpointSet.add(htmlName === 'index' ? '/' : `/${htmlName}`);
      }
    }

    // Add endpoints from parsed logs
    parsedLogs.forEach((l) => {
      if (l.endpoint) endpointSet.add(l.endpoint.split('?')[0]);
    });

    // Ensure sensible baseline endpoints if few detected
    if (endpointSet.size < 4) {
      endpointSet.add('/');
      endpointSet.add('/api/health');
      endpointSet.add('/api/v1/auth/login');
      endpointSet.add('/dashboard');
      endpointSet.add('/assets/main.js');
    }

    const discoveredEndpoints = Array.from(endpointSet).slice(0, 16);

    // Calculate security metrics
    const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
    const highCount = findings.filter((f) => f.severity === 'HIGH').length;
    const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
    const lowCount = findings.filter((f) => f.severity === 'LOW').length;

    let score = 100;
    score -= criticalCount * 25;
    score -= highCount * 15;
    score -= mediumCount * 8;
    score -= lowCount * 3;
    if (score < 10) score = 10;

    let grade: UploadScanResult['securityGrade'] = 'A+';
    if (score >= 95) grade = 'A+';
    else if (score >= 85) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 50) grade = 'C';
    else if (score >= 30) grade = 'D';
    else grade = 'F';

    return {
      targetName: targetDomain,
      totalFilesScanned: files.length,
      totalLinesScanned: totalLines,
      scannedFileNames: scannedNames,
      findings,
      parsedLogs,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      securityScore: score,
      securityGrade: grade,
      discoveredEndpoints,
    };
  }

  /**
   * Unpacks a ZIP file in-memory and scans all contained text files
   */
  public async scanZipFile(file: File, targetDomain: string = 'uploaded-website.com'): Promise<UploadScanResult> {
    const zip = new JSZip();
    const loadedZip = await zip.loadAsync(file);
    const extractedFiles: { name: string; content: string; size: number }[] = [];

    const textExtensions = [
      '.html',
      '.htm',
      '.js',
      '.mjs',
      '.ts',
      '.tsx',
      '.jsx',
      '.json',
      '.php',
      '.py',
      '.rb',
      '.go',
      '.env',
      '.conf',
      '.config',
      '.yaml',
      '.yml',
      '.sql',
      '.txt',
      '.log',
      '.csv',
      '.xml',
      '.htaccess',
    ];

    const entries = Object.keys(loadedZip.files);
    for (const filename of entries) {
      const zipEntry = loadedZip.files[filename];
      if (zipEntry.dir) continue;

      const lowerName = filename.toLowerCase();
      const isText =
        textExtensions.some((ext) => lowerName.endsWith(ext)) ||
        lowerName.includes('.env') ||
        lowerName.endsWith('dockerfile') ||
        lowerName.endsWith('makefile');

      if (isText) {
        try {
          const content = await zipEntry.async('string');
          extractedFiles.push({
            name: filename,
            content,
            size: content.length,
          });
        } catch (e) {
          console.warn(`Could not read file ${filename} as text:`, e);
        }
      }
    }

    return this.scanUploadedFiles(extractedFiles, targetDomain || file.name.replace(/\.zip$/i, ''));
  }

  /**
   * Parses common web server access logs (Nginx / Apache / JSON)
   */
  public parseAccessLog(logContent: string, targetId: string): LogEvent[] {
    const lines = logContent.split('\n');
    const events: LogEvent[] = [];

    // Apache / Nginx Combined Log Format regex:
    // 127.0.0.1 - - [10/Oct/2026:13:55:36 -0700] "GET /api/v1/users HTTP/1.1" 200 2326 "referer" "User-Agent"
    const combinedRegex = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?/;

    for (let i = 0; i < lines.length && events.length < 500; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      // Try JSON line first
      if (line.startsWith('{') && line.endsWith('}')) {
        try {
          const parsed = JSON.parse(line);
          const endpoint = parsed.endpoint || parsed.url || parsed.path || '/';
          const method = (parsed.method?.toUpperCase() || 'GET') as HttpMethod;
          const status = Number(parsed.status) || 200;
          const ip = parsed.sourceIp || parsed.ip || parsed.client_ip || '198.51.100.1';
          const ua = parsed.userAgent || parsed.user_agent || 'Mozilla/5.0';

          events.push({
            id: `log-parsed-${Date.now().toString(36)}-${i}`,
            targetId,
            timestamp: parsed.timestamp || new Date().toISOString(),
            displayTime: new Date().toTimeString().slice(0, 8),
            method,
            endpoint,
            status,
            sourceIp: ip,
            userAgent: ua,
            eventType: status === 401 ? 'AUTHENTICATION' : 'API_REQUEST',
            severity: status >= 500 ? 'SUSPICIOUS' : status === 401 ? 'SUSPICIOUS' : 'NORMAL',
            latencyMs: Number(parsed.latencyMs) || 16,
            isLab: false,
          });
          continue;
        } catch {
          // not JSON, fallback to standard regex
        }
      }

      // Match Combined/Common log format
      const match = line.match(combinedRegex);
      if (match) {
        const [, ip, , methodStr, endpoint, statusStr, , , userAgent] = match;
        const status = Number(statusStr) || 200;
        const method = (methodStr.toUpperCase() || 'GET') as HttpMethod;

        let severity: EventSeverity = 'NORMAL';
        let flagReason: string | undefined;

        if (endpoint.includes("' OR '1'='1") || endpoint.includes('UNION%20SELECT')) {
          severity = 'CRITICAL';
          flagReason = 'SQL Injection query signature detected in access log URI';
        } else if (endpoint.includes('../') || endpoint.includes('/etc/passwd')) {
          severity = 'CRITICAL';
          flagReason = 'Path traversal escape pattern in access log';
        } else if (status === 401 || status === 403) {
          severity = 'SUSPICIOUS';
          flagReason = `Access denied (${status}) in server log`;
        } else if (status >= 500) {
          severity = 'SUSPICIOUS';
          flagReason = `Server error code ${status} recorded in log`;
        }

        events.push({
          id: `log-parsed-${Date.now().toString(36)}-${i}`,
          targetId,
          timestamp: new Date().toISOString(),
          displayTime: new Date().toTimeString().slice(0, 8),
          method,
          endpoint,
          status,
          sourceIp: ip,
          userAgent: userAgent || 'Web Client',
          eventType: status === 401 ? 'AUTHENTICATION' : 'API_REQUEST',
          severity,
          latencyMs: Math.floor(Math.random() * 25) + 10,
          isLab: false,
          flagReason,
        });
      }
    }

    return events;
  }
}

export const websiteUploadScanner = new WebsiteUploadScanner();
