import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns/promises';
import tls from 'tls';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface RealEvent {
  id: string;
  targetId: string;
  timestamp: string;
  displayTime: string;
  method: string;
  endpoint: string;
  status: number;
  sourceIp: string;
  userAgent: string;
  eventType: string;
  severity: string;
  latencyMs: number;
  isLab: boolean;
  logSource: 'REAL_LIVE_INGEST' | 'REAL_SERVER_PROBE' | 'REAL_LOG_FILE';
  payloadSnippet?: string;
  flagReason?: string;
  clientGeo?: {
    country?: string;
    city?: string;
    device?: string;
    visitorId?: string;
  };
  headers?: Record<string, string>;
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

const realEventsBuffer: RealEvent[] = [];
let sseClients: { id: string; targetId?: string; res: express.Response }[] = [];

export interface BlockedEntity {
  id: string;
  ip?: string;
  visitorId?: string;
  targetId: string;
  blockedAt: string;
  reason?: string;
}

const blockedEntities: BlockedEntity[] = [];

function checkIsBlocked(targetId: string = '', ip: string = '', visitorId?: string): { blocked: boolean; reason?: string } {
  const cleanIp = (ip || '').replace(/^::ffff:/, '').trim();
  const cleanVid = (visitorId || '').trim();
  const match = blockedEntities.find((b) => {
    if (b.targetId && targetId && b.targetId !== targetId && b.targetId !== 'all') return false;
    if (cleanVid && b.visitorId && b.visitorId === cleanVid) return true;
    if (cleanIp && b.ip && b.ip === cleanIp) return true;
    return false;
  });
  return { blocked: Boolean(match), reason: match?.reason };
}

// Helper: Timeout wrapper
function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

// Helper: Real TLS Certificate Inspector
async function inspectTlsCertificate(hostname: string, port = 443): Promise<{
  valid: boolean;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  protocol: string;
  cipher: string;
  error?: string;
}> {
  return new Promise((resolve) => {
    let resolved = false;
    const finish = (result: any) => {
      if (!resolved) {
        resolved = true;
        resolve(result);
      }
    };

    try {
      const socket = tls.connect(
        {
          host: hostname,
          port,
          servername: hostname,
          rejectUnauthorized: false,
          timeout: 3500,
        },
        () => {
          try {
            const cert = socket.getPeerCertificate();
            const protocol = socket.getProtocol() || 'TLS';
            const cipher = socket.getCipher()?.name || 'Unknown';

            if (!cert || !cert.valid_to) {
              socket.destroy();
              return finish({
                valid: false,
                issuer: 'Unknown',
                subject: hostname,
                validFrom: '',
                validTo: '',
                daysRemaining: 0,
                protocol,
                cipher,
                error: 'No peer certificate returned',
              });
            }

            const validToDate = new Date(cert.valid_to);
            const validFromDate = new Date(cert.valid_from);
            const now = Date.now();
            const daysRemaining = Math.max(0, Math.floor((validToDate.getTime() - now) / (1000 * 60 * 60 * 24)));
            const isValid = validToDate.getTime() > now && validFromDate.getTime() <= now;

            const issuer = cert.issuer ? (cert.issuer.O || cert.issuer.CN || 'Certificate Authority') : 'Unknown';
            const subject = cert.subject ? (cert.subject.CN || hostname) : hostname;

            socket.destroy();
            finish({
              valid: isValid,
              issuer: Array.isArray(issuer) ? issuer.join(', ') : issuer,
              subject: Array.isArray(subject) ? subject.join(', ') : subject,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              daysRemaining,
              protocol,
              cipher,
            });
          } catch (e: any) {
            socket.destroy();
            finish({
              valid: false,
              issuer: 'Unknown',
              subject: hostname,
              validFrom: '',
              validTo: '',
              daysRemaining: 0,
              protocol: 'TLS',
              cipher: 'Unknown',
              error: e.message || 'Certificate extraction error',
            });
          }
        }
      );

      socket.on('error', (err) => {
        socket.destroy();
        finish({
          valid: false,
          issuer: 'Unknown',
          subject: hostname,
          validFrom: '',
          validTo: '',
          daysRemaining: 0,
          protocol: 'TLS',
          cipher: 'Unknown',
          error: err.message,
        });
      });

      socket.on('timeout', () => {
        socket.destroy();
        finish({
          valid: false,
          issuer: 'Unknown',
          subject: hostname,
          validFrom: '',
          validTo: '',
          daysRemaining: 0,
          protocol: 'TLS',
          cipher: 'Unknown',
          error: 'TLS handshake timed out',
        });
      });

      // Guard timer
      setTimeout(() => {
        try { socket.destroy(); } catch {}
        finish({
          valid: false,
          issuer: 'Unknown',
          subject: hostname,
          validFrom: '',
          validTo: '',
          daysRemaining: 0,
          protocol: 'TLS',
          cipher: 'Unknown',
          error: 'TLS probe timed out',
        });
      }, 4000);
    } catch (err: any) {
      finish({
        valid: false,
        issuer: 'Unknown',
        subject: hostname,
        validFrom: '',
        validTo: '',
        daysRemaining: 0,
        protocol: 'TLS',
        cipher: 'Unknown',
        error: err.message,
      });
    }
  });
}

// Helper: Real DNS Records & Mail Security Check
async function inspectDnsSecurity(hostname: string): Promise<{
  ipAddresses: string[];
  mxRecords: string[];
  hasSpf: boolean;
  hasDmarc: boolean;
  spfRecord?: string;
  dmarcRecord?: string;
}> {
  let ipAddresses: string[] = [];
  let mxRecords: string[] = [];
  let hasSpf = false;
  let hasDmarc = false;
  let spfRecord: string | undefined;
  let dmarcRecord: string | undefined;

  await Promise.allSettled([
    withTimeout(dns.resolve4(hostname), 2500, [] as string[]).then((a) => {
      ipAddresses = a.slice(0, 4);
    }),
    withTimeout(dns.resolveMx(hostname), 2500, [] as Array<{ exchange: string; priority: number }>).then((mx) => {
      mxRecords = mx.map((m) => `${m.exchange} (prio ${m.priority})`).slice(0, 3);
    }),
    withTimeout(dns.resolveTxt(hostname), 2500, [] as string[][]).then((txts) => {
      for (const chunk of txts) {
        const line = chunk.join('');
        if (line.toLowerCase().startsWith('v=spf1')) {
          hasSpf = true;
          spfRecord = line;
        }
      }
    }),
    withTimeout(dns.resolveTxt(`_dmarc.${hostname}`), 2500, [] as string[][]).then((dmarcTxts) => {
      for (const chunk of dmarcTxts) {
        const line = chunk.join('');
        if (line.toLowerCase().startsWith('v=dmarc1')) {
          hasDmarc = true;
          dmarcRecord = line;
        }
      }
    }),
  ]);

  return {
    ipAddresses,
    mxRecords,
    hasSpf,
    hasDmarc,
    spfRecord,
    dmarcRecord,
  };
}

// Helper: Sensitive path check against real site
async function probePath(baseUrl: string, testPath: string): Promise<{
  path: string;
  status: number;
  exposed: boolean;
  detail: string;
}> {
  try {
    const targetUrl = new URL(testPath, baseUrl).toString();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);

    const res = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) EXTREME-SecOps-Audit/3.0',
      },
      signal: controller.signal,
      redirect: 'manual',
    });
    clearTimeout(timer);

    let exposed = false;
    let detail = `Status ${res.status}`;

    if (res.status === 200) {
      const text = await res.text().catch(() => '');
      if (testPath === '/.env' && (text.includes('DB_') || text.includes('SECRET') || text.includes('KEY='))) {
        exposed = true;
        detail = 'Exposed .env configuration with sensitive environment keys!';
      } else if (testPath === '/.git/HEAD' && text.includes('ref: refs/')) {
        exposed = true;
        detail = 'Exposed git repository HEAD reference!';
      } else if (testPath === '/robots.txt') {
        exposed = false;
        detail = `Active robots.txt (${text.length} bytes)`;
      } else if (testPath.includes('security.txt')) {
        exposed = false;
        detail = 'RFC 9116 security.txt disclosure present';
      } else {
        exposed = res.status === 200;
        detail = `HTTP 200 response returned on sensitive path ${testPath}`;
      }
    } else if (res.status === 403 || res.status === 404 || res.status === 401) {
      exposed = false;
      detail = `Securely blocked (${res.status})`;
    }

    return { path: testPath, status: res.status, exposed, detail };
  } catch (err: any) {
    return {
      path: testPath,
      status: 0,
      exposed: false,
      detail: err.name === 'AbortError' ? 'Probe timed out' : 'Connection failed',
    };
  }
}

// Helper: Granular Client & Server Device Detection
export function parseDeviceDetails(
  ua: string = '',
  clientHints?: {
    device?: string;
    clientDevice?: string;
    isMobile?: boolean;
    screenWidth?: number;
    screenHeight?: number;
    maxTouchPoints?: number;
    hasBattery?: boolean;
  }
): string {
  if (clientHints?.clientDevice && clientHints.clientDevice !== 'Desktop' && clientHints.clientDevice !== 'Desktop PC') {
    return clientHints.clientDevice;
  }
  if (clientHints?.device && clientHints.device !== 'Desktop' && clientHints.device !== 'Desktop PC') {
    return clientHints.device;
  }

  const uaLower = (ua || '').toLowerCase();
  const maxTouch = clientHints?.maxTouchPoints ?? 0;
  const sw = clientHints?.screenWidth ?? 0;
  const sh = clientHints?.screenHeight ?? 0;
  const isTouch = maxTouch > 0 || Boolean(clientHints?.isMobile);
  const hasBattery = Boolean(clientHints?.hasBattery);

  // 1. Apple iPad (iPadOS)
  const isIpad =
    uaLower.includes('ipad') ||
    (maxTouch > 1 && (uaLower.includes('macintosh') || uaLower.includes('macintel')));
  if (isIpad) {
    return 'Apple iPad (iPadOS)';
  }

  // 2. Apple iPhone (iOS)
  if (uaLower.includes('iphone')) {
    const iosMatch = ua.match(/OS (\d+[_.]\d+)/);
    const iosVer = iosMatch ? ` (iOS ${iosMatch[1].replace('_', '.')})` : ' (iOS)';

    const w = Math.min(sw, sh);
    const h = Math.max(sw, sh);
    let model = 'Apple iPhone';
    if (w === 430 && h === 932) model = 'iPhone 15/14 Pro Max';
    else if (w === 393 && h === 852) model = 'iPhone 15/14 Pro';
    else if (w === 428 && h === 926) model = 'iPhone 14 Plus / 13 Pro Max';
    else if (w === 390 && h === 844) model = 'iPhone 14 / 13 / 12';
    else if (w === 375 && h === 812) model = 'iPhone 13 mini / 12 mini / X';
    else if (w === 414 && h === 896) model = 'iPhone 11 / XR / XS Max';
    else if (w === 375 && h === 667) model = 'iPhone SE / 8';

    return `${model}${iosVer}`;
  }

  // 3. Apple Mac (MacBook Laptop vs Mac Desktop)
  if (uaLower.includes('macintosh') || uaLower.includes('mac os x')) {
    const macMatch = ua.match(/Mac OS X ([\d_]+)/);
    const macVer = macMatch ? `macOS ${macMatch[1].replace(/_/g, '.')}` : 'macOS';
    const isMacBook = hasBattery || (sw >= 1280 && sw <= 1728) || isTouch;
    return isMacBook ? `MacBook (${macVer} Laptop)` : `Apple Mac (${macVer} Desktop)`;
  }

  // 4. Android Mobile & Tablet
  if (uaLower.includes('android')) {
    const isTablet = !uaLower.includes('mobile') || (sw >= 768 && sh >= 1024);
    const avMatch = ua.match(/Android\s+([\d.]+)/i);
    const androidVer = avMatch ? `Android ${avMatch[1]}` : 'Android';

    let brand = isTablet ? 'Android Tablet' : 'Android Mobile';
    if (uaLower.includes('samsung') || uaLower.includes('sm-')) {
      brand = isTablet ? 'Samsung Galaxy Tab' : 'Samsung Galaxy';
    } else if (uaLower.includes('pixel')) {
      const pxMatch = ua.match(/Pixel\s*([0-9a-zA-Z\s]+)/i);
      brand = pxMatch ? `Google Pixel ${pxMatch[1].trim()}` : 'Google Pixel';
    } else if (uaLower.includes('oneplus')) {
      brand = 'OnePlus Mobile';
    } else if (uaLower.includes('xiaomi') || uaLower.includes('redmi') || uaLower.includes('poco')) {
      brand = 'Xiaomi / Redmi Mobile';
    } else if (uaLower.includes('vivo')) {
      brand = 'Vivo Mobile';
    } else if (uaLower.includes('oppo')) {
      brand = 'Oppo Mobile';
    } else if (uaLower.includes('motorola') || uaLower.includes('moto')) {
      brand = 'Motorola Mobile';
    }
    return `${brand} (${androidVer})`;
  }

  // 5. Windows (Laptop vs Desktop PC)
  if (uaLower.includes('windows')) {
    let winVer = 'Windows 11/10';
    if (uaLower.includes('windows nt 6.3')) winVer = 'Windows 8.1';
    else if (uaLower.includes('windows nt 6.1')) winVer = 'Windows 7';

    const isLaptop = isTouch || hasBattery || (sw > 0 && sw <= 1600 && sh <= 900);
    return isLaptop ? `${winVer} Laptop` : `${winVer} PC`;
  }

  // 6. Linux
  if (uaLower.includes('linux')) {
    const isLinuxLaptop = isTouch || hasBattery || (sw > 0 && sw <= 1600);
    return isLinuxLaptop ? 'Linux Laptop' : 'Linux Desktop';
  }

  // 7. ChromeOS / Chromebook
  if (uaLower.includes('cros')) {
    return 'Chromebook Laptop';
  }

  return 'Desktop PC';
}

async function createServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const isProd = process.env.NODE_ENV === 'production';

  app.use(express.json({ limit: '20mb' }));
  app.use(express.urlencoded({ extended: true, limit: '20mb' }));
  app.use(express.text({ type: ['text/plain', 'text/*'], limit: '20mb' }));

  // CORS support so external websites can post telemetry to /api/collector/ingest
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Target-ID, X-API-Key');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }
    next();
  });

  // Health probe
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'EXTREME Real-Time Production Telemetry & Security Engine',
      timestamp: new Date().toISOString(),
      bufferedEvents: realEventsBuffer.length,
      activeClients: sseClients.length,
    });
  });

  // Real embeddable JavaScript collector snippet for external websites
  app.get('/api/collector/script.js', (req, res) => {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    const host = req.headers.host || `localhost:${PORT}`;
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const baseUrl = `${protocol}://${host}`;

    const script = `/**
 * EXTREME SecOps — 24/7 Production Real-Time Telemetry Collector
 * For Vercel, Netlify, Next.js, React, Node.js, and static websites.
 * Install: <script src="${baseUrl}/api/collector/script.js" data-target-id="YOUR_TARGET_ID" data-api-key="YOUR_KEY" async></script>
 */
(function() {
  var scriptTag = document.currentScript || document.querySelector('script[data-target-id]') || document.querySelector('script[src*="/api/collector/script.js"]');
  var targetId = (scriptTag && (scriptTag.getAttribute('data-target-id') || scriptTag.getAttribute('data-site-id'))) || 'target-atc-simulator';
  var apiKey = (scriptTag && scriptTag.getAttribute('data-api-key')) || '';
  var ingestUrl = '${baseUrl}/api/collector/ingest';
  var cachedClientIp = '';
  var initialSent = false;
  var leaveReported = false;

  function detectClientDevice() {
    try {
      var ua = navigator.userAgent || '';
      var uaLower = ua.toLowerCase();
      var platform = navigator.platform || '';
      var maxTouch = navigator.maxTouchPoints || 0;
      var sw = (window.screen && window.screen.width) || 0;
      var sh = (window.screen && window.screen.height) || 0;
      var isTouch = maxTouch > 0 || (window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
      var hasBattery = 'getBattery' in navigator;

      if (/ipad/i.test(uaLower) || (maxTouch > 1 && (/macintosh|mac os x/i.test(uaLower) || platform === 'MacIntel'))) {
        return 'Apple iPad (iPadOS)';
      }

      if (/iphone/i.test(uaLower) || platform === 'iPhone') {
        var iosMatch = ua.match(/OS (\\d+[_.]\\d+)/);
        var iosVer = iosMatch ? ' (iOS ' + iosMatch[1].replace('_', '.') + ')' : ' (iOS)';
        var w = Math.min(sw, sh);
        var h = Math.max(sw, sh);
        var model = 'Apple iPhone';
        if (w === 430 && h === 932) model = 'iPhone 15/14 Pro Max';
        else if (w === 393 && h === 852) model = 'iPhone 15/14 Pro';
        else if (w === 428 && h === 926) model = 'iPhone 14 Plus / 13 Pro Max';
        else if (w === 390 && h === 844) model = 'iPhone 14 / 13 / 12';
        else if (w === 375 && h === 812) model = 'iPhone 13 mini / 12 mini / X';
        else if (w === 414 && h === 896) model = 'iPhone 11 / XR / XS Max';
        else if (w === 375 && h === 667) model = 'iPhone SE / 8';
        return model + iosVer;
      }

      if (/android/i.test(uaLower)) {
        var isTablet = !/mobile/i.test(uaLower) || (sw >= 768 && sh >= 1024);
        var androidVer = '';
        var avMatch = ua.match(/Android\\s+([\\d.]+)/i);
        if (avMatch) androidVer = ' (Android ' + avMatch[1] + ')';
        var brand = isTablet ? 'Android Tablet' : 'Android Mobile';
        if (/samsung|sm-[a-z0-9]+/i.test(uaLower)) {
          brand = isTablet ? 'Samsung Galaxy Tab' : 'Samsung Galaxy';
        } else if (/pixel/i.test(uaLower)) {
          var pxMatch = ua.match(/Pixel\\s*([0-9a-zA-Z\\s]+)/i);
          brand = pxMatch ? 'Google Pixel ' + pxMatch[1].trim() : 'Google Pixel';
        } else if (/oneplus/i.test(uaLower)) {
          brand = 'OnePlus Mobile';
        } else if (/xiaomi|redmi|poco/i.test(uaLower)) {
          brand = 'Xiaomi / Redmi Mobile';
        } else if (/vivo/i.test(uaLower)) {
          brand = 'Vivo Mobile';
        } else if (/oppo/i.test(uaLower)) {
          brand = 'Oppo Mobile';
        } else if (/motorola|moto/i.test(uaLower)) {
          brand = 'Motorola Mobile';
        }
        return brand + androidVer;
      }

      if (/windows/i.test(uaLower)) {
        var winVer = 'Windows 11/10';
        if (/windows nt 6\\.3/i.test(uaLower)) winVer = 'Windows 8.1';
        else if (/windows nt 6\\.1/i.test(uaLower)) winVer = 'Windows 7';
        var isLaptop = isTouch || hasBattery || (sw > 0 && sw <= 1600 && sh <= 900);
        return isLaptop ? winVer + ' Laptop' : winVer + ' PC';
      }

      if (/macintosh|mac os x/i.test(uaLower)) {
        var macVer = 'macOS';
        var mvMatch = ua.match(/Mac OS X ([\\d_]+)/);
        if (mvMatch) macVer = 'macOS ' + mvMatch[1].replace(/_/g, '.');
        var isMacBook = hasBattery || (sw >= 1280 && sw <= 1728) || isTouch;
        return isMacBook ? 'MacBook (' + macVer + ' Laptop)' : 'Apple Mac (' + macVer + ' Desktop)';
      }

      if (/linux/i.test(uaLower)) {
        return (isTouch || hasBattery || (sw > 0 && sw <= 1600)) ? 'Linux Laptop' : 'Linux Desktop';
      }

      if (/cros/i.test(uaLower)) {
        return 'Chromebook Laptop';
      }
    } catch(e) {}
    return 'Desktop PC';
  }

  var clientDeviceCached = detectClientDevice();
  var visitorDeviceId = '';
  try {
    visitorDeviceId = localStorage.getItem('ext_sec_device_id') || '';
    if (!visitorDeviceId) {
      visitorDeviceId = 'dev-' + Math.random().toString(36).substring(2, 9);
      localStorage.setItem('ext_sec_device_id', visitorDeviceId);
    }
  } catch(e) {
    visitorDeviceId = 'dev-' + Math.random().toString(36).substring(2, 9);
  }

  var blockPollTimer = null;
  function displayBlockScreen(reason, ip) {
    if (document.getElementById('extreme-secops-block-wall')) return;
    var wall = document.createElement('div');
    wall.id = 'extreme-secops-block-wall';
    wall.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;background:#06090e;color:#e2e8f0;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:ui-monospace,Menlo,Consolas,monospace;padding:24px;box-sizing:border-box;text-align:center;';
    wall.innerHTML = '<div style="max-width:540px;background:rgba(15,23,42,0.95);border:1px solid #f43f5e;border-radius:16px;padding:32px;box-shadow:0 0 60px rgba(244,63,94,0.35);">'
      + '<div style="font-size:42px;margin-bottom:12px;">🚫</div>'
      + '<div style="color:#f43f5e;font-size:13px;font-weight:bold;letter-spacing:2px;margin-bottom:8px;">ACCESS DENIED // 403 FORBIDDEN</div>'
      + '<h1 style="color:#ffffff;font-size:22px;margin:0 0 16px 0;font-weight:800;">DEVICE ACCESS SUSPENDED</h1>'
      + '<p style="color:#94a3b8;font-size:13px;line-height:1.6;margin-bottom:18px;">Your device and network IP <span style="color:#00f0ff;font-weight:bold;">[' + (ip || cachedClientIp || 'Client') + ']</span> have been blocked from interacting with this website by the EXTREME SecOps Administrator.</p>'
      + '<div style="background:#090d16;border:1px solid #1e293b;border-radius:8px;padding:12px;font-size:12px;color:#f87171;margin-bottom:18px;">WAF Policy: ' + (reason || 'Manual Administrator Block') + '</div>'
      + '<div style="font-size:11px;color:#64748b;font-family:monospace;">EXTREME SEC-OPS WAF ENGINE • SHIELD ACTIVE</div>'
      + '</div>';
    document.body.appendChild(wall);
    document.body.style.overflow = 'hidden';

    // Start background poller so unblocking in dashboard automatically removes this screen!
    if (!blockPollTimer) {
      blockPollTimer = setInterval(function() {
        fetch('${baseUrl}/api/collector/my-ip?targetId=' + encodeURIComponent(targetId) + '&visitorId=' + encodeURIComponent(visitorDeviceId))
          .then(function(r) { return r.json(); })
          .then(function(d) {
            if (d && !d.isBlocked) {
              removeBlockScreen();
            }
          }).catch(function() {});
      }, 3000);
    }
  }

  function removeBlockScreen() {
    var wall = document.getElementById('extreme-secops-block-wall');
    if (wall && wall.parentNode) {
      wall.parentNode.removeChild(wall);
    }
    document.body.style.overflow = '';
    if (blockPollTimer) {
      clearInterval(blockPollTimer);
      blockPollTimer = null;
    }
  }

  // Connect to SSE stream for sub-second instant real-time block and unblock enforcement
  try {
    if (window.EventSource) {
      var sseBlockStream = new EventSource('${baseUrl}/api/collector/stream');
      sseBlockStream.onmessage = function(e) {
        try {
          var d = JSON.parse(e.data);
          if (d.type === 'BLOCKED') {
            var myCleanIp = (cachedClientIp || '').replace(/^::ffff:/, '').trim();
            if ((d.blockRecord?.ip && d.blockRecord.ip === myCleanIp) || (d.blockRecord?.visitorId && d.blockRecord.visitorId === visitorDeviceId)) {
              displayBlockScreen(d.blockRecord?.reason, cachedClientIp);
            }
          } else if (d.type === 'UNBLOCKED') {
            var myCleanIp = (cachedClientIp || '').replace(/^::ffff:/, '').trim();
            if ((d.ip && d.ip === myCleanIp) || (d.visitorId && d.visitorId === visitorDeviceId)) {
              removeBlockScreen();
            }
          }
        } catch(err) {}
      };
    }
  } catch(err) {}

  function transmit(data) {
    // If user has exited/closed tab, do not transmit trailing background fetches or stream packets
    if (leaveReported && data.eventType !== 'SESSION_END') {
      return;
    }
    try {
      var payload = Object.assign({
        targetId: targetId,
        apiKey: apiKey,
        timestamp: new Date().toISOString(),
        url: window.location.href,
        path: window.location.pathname || '/',
        referrer: document.referrer || '',
        userAgent: navigator.userAgent,
        clientDevice: clientDeviceCached,
        visitorId: visitorDeviceId,
        clientPublicIp: cachedClientIp || undefined
      }, data);

      var body = JSON.stringify(payload);
      if (window.fetch) {
        fetch(ingestUrl, {
          method: 'POST',
          mode: 'cors',
          headers: { 'Content-Type': 'application/json' },
          body: body,
          keepalive: true
        }).then(function(res) {
          if (res.status === 403) {
            return res.json().then(function(d) {
              if (d && d.blocked) {
                displayBlockScreen(d.reason, d.ip || cachedClientIp);
              }
            }).catch(function() {
              displayBlockScreen('Administrator WAF Block Policy', cachedClientIp);
            });
          }
        }).catch(function() {
          if (navigator.sendBeacon) {
            navigator.sendBeacon(ingestUrl, body);
          }
        });
      } else if (navigator.sendBeacon) {
        navigator.sendBeacon(ingestUrl, body);
      }
    } catch (e) {}
  }

  function sendInitialPageview() {
    if (initialSent) return;
    initialSent = true;
    var navTiming = (window.performance && window.performance.getEntriesByType) ? window.performance.getEntriesByType('navigation')[0] : null;
    var initialLatency = navTiming ? Math.max(12, Math.round(navTiming.responseEnd - navTiming.requestStart || 24)) : 22;

    transmit({
      method: 'GET',
      endpoint: window.location.pathname || '/',
      status: 200,
      eventType: 'PAGEVIEW',
      severity: 'NORMAL',
      latencyMs: initialLatency,
      flagReason: 'Genuine visitor pageview landed on ' + (window.location.pathname || '/')
    });
  }

  // Query visitor public IP so remote phones/laptops send their exact external IP address
  var ipResolved = false;
  var ipTimeout = setTimeout(function() {
    if (!ipResolved) {
      ipResolved = true;
      sendInitialPageview();
    }
  }, 2200);

  function applyResolvedIp(ip) {
    if (ip && !cachedClientIp && ip !== '127.0.0.1' && ip !== '::1') {
      cachedClientIp = String(ip).trim();
    }
    if (!ipResolved) {
      ipResolved = true;
      clearTimeout(ipTimeout);
      sendInitialPageview();
    }
  }

  // 1. Direct Extreme SecOps IP detection endpoint (works across all browsers, zero adblock blocks)
  try {
    fetch('${baseUrl}/api/collector/my-ip?targetId=' + encodeURIComponent(targetId) + '&visitorId=' + encodeURIComponent(visitorDeviceId))
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (d && d.isBlocked) {
          displayBlockScreen(d.blockedReason, d.ip || cachedClientIp);
        }
        if (d && d.ip && d.ip !== '127.0.0.1' && d.ip !== '::1') {
          applyResolvedIp(d.ip);
        } else {
          throw new Error('Local fallback');
        }
      })
      .catch(function() {
        // 2. Secondary redundant external IP resolution
        fetch('https://api.ipify.org?format=json')
          .then(function(r) { return r.json(); })
          .then(function(d) {
            if (d && d.ip) {
              applyResolvedIp(d.ip);
            } else {
              applyResolvedIp('');
            }
          })
          .catch(function() {
            applyResolvedIp('');
          });
      });
  } catch(e) {
    applyResolvedIp('');
  }

  // 2. Intercept Single-Page App (SPA) History Navigation (Next.js / React Router on Vercel)
  var origPushState = history.pushState;
  if (origPushState) {
    history.pushState = function() {
      origPushState.apply(this, arguments);
      transmit({
        method: 'GET',
        endpoint: window.location.pathname || '/',
        status: 200,
        eventType: 'PAGEVIEW',
        severity: 'NORMAL',
        latencyMs: 14,
        flagReason: 'SPA client-side navigation to ' + (window.location.pathname || '/')
      });
    };
  }

  // 3. Transparently Intercept Outgoing window.fetch to Log Real API Calls
  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function(input, init) {
      var fetchUrl = typeof input === 'string' ? input : (input && input.url ? input.url : '');
      // Do not self-log telemetry calls, or third-party background long-poll streams (Firestore, Firebase, Google APIs)
      if (!fetchUrl || fetchUrl.indexOf('/api/collector/ingest') !== -1 ||
          fetchUrl.indexOf('firestore') !== -1 ||
          fetchUrl.indexOf('firebase') !== -1 ||
          fetchUrl.indexOf('googleapis.com') !== -1 ||
          fetchUrl.indexOf('_next/static') !== -1) {
        return origFetch.apply(this, arguments);
      }
      var fetchMethod = (init && init.method ? init.method : 'GET').toUpperCase();
      var tStart = performance.now();
      return origFetch.apply(this, arguments).then(function(response) {
        var tDur = Math.max(10, Math.round(performance.now() - tStart));
        try {
          var cleanPath = fetchUrl.replace(/^https?:\\/\\/[^\\/]+/, '');
          var isSuspicious = response.status >= 500 || response.status === 401 || response.status === 403;
          transmit({
            method: fetchMethod,
            endpoint: cleanPath || fetchUrl,
            status: response.status,
            eventType: cleanPath.indexOf('/api') !== -1 ? 'API_REQUEST' : 'STATIC_RESOURCE',
            severity: isSuspicious ? 'SUSPICIOUS' : 'NORMAL',
            latencyMs: tDur,
            flagReason: isSuspicious ? 'User API response returned status ' + response.status : undefined
          });
        } catch(e) {}
        return response;
      }).catch(function(err) {
        var tDur = Math.max(10, Math.round(performance.now() - tStart));
        try {
          var cleanPath = fetchUrl.replace(/^https?:\\/\\/[^\\/]+/, '');
          transmit({
            method: fetchMethod,
            endpoint: cleanPath || fetchUrl,
            status: 504,
            eventType: 'CLIENT_ERROR',
            severity: 'SUSPICIOUS',
            latencyMs: tDur,
            payloadSnippet: err.message || 'Network Fetch Failed',
            flagReason: 'Outbound user fetch network failure on ' + (cleanPath || fetchUrl)
          });
        } catch(e) {}
        throw err;
      });
    };
  }

  // 4. Capture Real Runtime Script Errors & Exceptions
  window.addEventListener('error', function(err) {
    transmit({
      method: 'GET',
      endpoint: window.location.pathname || '/',
      status: 500,
      eventType: 'CLIENT_ERROR',
      severity: 'SUSPICIOUS',
      payloadSnippet: (err.message || 'JavaScript Error') + (err.filename ? ' at ' + err.filename + ':' + err.lineno : ''),
      flagReason: 'Real browser runtime exception: ' + (err.message || 'Unhandled error')
    });
  });

  window.addEventListener('unhandledrejection', function(event) {
    var reason = event.reason ? (event.reason.message || String(event.reason)) : 'Promise rejected';
    transmit({
      method: 'GET',
      endpoint: window.location.pathname || '/',
      status: 500,
      eventType: 'CLIENT_ERROR',
      severity: 'SUSPICIOUS',
      payloadSnippet: 'Unhandled Promise: ' + reason,
      flagReason: 'Uncaught Promise rejection in user browser session'
    });
  });

  // 5. Capture Real User Interactions & Activities (Buttons, Tools, State changes)
  var lastClickTs = 0;
  document.addEventListener('click', function(e) {
    try {
      var el = e.target;
      var interactive = el.closest ? el.closest('button, a, input, select, textarea, [role="button"], [tabindex]') : null;
      if (!interactive) return;

      var now = Date.now();
      if (now - lastClickTs < 500) return; // Debounce rapid spam
      lastClickTs = now;

      var label = (interactive.innerText || interactive.getAttribute('aria-label') || interactive.title || interactive.id || interactive.tagName || 'Action').trim();
      label = label.replace(/\\s+/g, ' ').slice(0, 60) || 'Simulator Action';

      transmit({
        method: 'POST',
        endpoint: window.location.pathname || '/',
        status: 200,
        eventType: 'USER_INTERACTION',
        severity: 'NORMAL',
        latencyMs: 14,
        payloadSnippet: 'Interaction: ' + label,
        flagReason: 'Active visitor performed: "' + label + '" on ' + (window.location.pathname || '/')
      });
    } catch(ign) {}
  }, true);

  // 6. Live Presence Heartbeat (pulsed every 10s while tab is open)
  var heartbeatTimer = setInterval(function() {
    if (!document.hidden) {
      transmit({
        method: 'GET',
        endpoint: window.location.pathname || '/',
        status: 200,
        eventType: 'HEARTBEAT',
        severity: 'NORMAL',
        latencyMs: 10,
        flagReason: 'Live visitor presence heartbeat'
      });
    }
  }, 10000);

  // 7. Instant Leave Detection: when user closes tab, navigates away, or leaves website
  var leaveReported = false;
  function reportExit() {
    if (leaveReported) return;
    leaveReported = true;
    try { clearInterval(heartbeatTimer); } catch(e) {}

    var exitPayload = JSON.stringify({
      targetId: targetId,
      apiKey: apiKey,
      timestamp: new Date().toISOString(),
      url: window.location.href,
      path: window.location.pathname || '/',
      userAgent: navigator.userAgent,
      clientPublicIp: cachedClientIp || undefined,
      method: 'POST',
      endpoint: '/session/leave',
      status: 200,
      eventType: 'SESSION_END',
      severity: 'NORMAL',
      flagReason: 'Visitor left website / closed tab'
    });

    var beaconSent = false;
    try {
      if (navigator.sendBeacon) {
        var blob = new Blob([exitPayload], { type: 'text/plain' });
        beaconSent = navigator.sendBeacon(ingestUrl, blob);
      }
    } catch(e) {}

    if (!beaconSent && window.fetch) {
      try {
        fetch(ingestUrl, {
          method: 'POST',
          mode: 'no-cors',
          headers: { 'Content-Type': 'text/plain' },
          body: exitPayload,
          keepalive: true
        });
      } catch(e) {}
    }
  }

  window.addEventListener('pagehide', reportExit);
  window.addEventListener('beforeunload', reportExit);
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'hidden') {
      reportExit();
    } else if (document.visibilityState === 'visible' && leaveReported) {
      leaveReported = false;
      heartbeatTimer = setInterval(function() {
        if (!document.hidden) {
          transmit({
            method: 'GET',
            endpoint: window.location.pathname || '/',
            status: 200,
            eventType: 'HEARTBEAT',
            severity: 'NORMAL',
            latencyMs: 10,
            flagReason: 'Live visitor presence heartbeat'
          });
        }
      }, 10000);
      sendInitialPageview();
    }
  });
})();`;

    res.send(script);
  });

  // DEEP REAL SECURITY AUDIT: SSL/TLS handshake, DNS resolution, SPF/DMARC, HTTP headers, sensitive file exposures
  app.post('/api/probe/deep-scan', async (req, res) => {
    let { url, targetId } = req.body;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Valid URL or hostname is required' });
    }

    url = url.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = `https://${url}`;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    const hostname = parsedUrl.hostname;
    let isHttps = parsedUrl.protocol === 'https:';
    const start = Date.now();

    // 1. Parallel execution: TLS Cert extraction and DNS records resolution
    const [sslCert, dnsInfo] = await Promise.all([
      isHttps ? inspectTlsCertificate(hostname) : Promise.resolve(null),
      inspectDnsSecurity(hostname),
    ]);

    // 2. HTTP Security Headers Probe (with automatic HTTP fallback if HTTPS connection refused)
    let isReachable = false;
    let statusCode = 0;
    let latencyMs = 0;
    const responseHeaders: Record<string, string> = {};
    let pageTitle = '';
    let errorMessage = '';

    const executeProbeFetch = async (targetFetchUrl: string) => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4500);

      const resp = await fetch(targetFetchUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 EXTREME-SecOps-Audit/3.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        signal: controller.signal,
        redirect: 'follow',
      });

      clearTimeout(timeout);
      return resp;
    };

    try {
      const resp = await executeProbeFetch(url);
      latencyMs = Math.max(12, Date.now() - start);
      statusCode = resp.status;
      isReachable = true;

      resp.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });

      const contentType = responseHeaders['content-type'] || '';
      if (contentType.includes('text/html')) {
        const text = await resp.text();
        const match = text.match(/<title[^>]*>([^<]+)<\/title>/i);
        if (match) {
          pageTitle = match[1].trim().slice(0, 120);
        }
      }
    } catch (err: any) {
      // Fallback: If https failed, attempt plain http
      if (isHttps) {
        try {
          const fallbackHttpUrl = `http://${hostname}${parsedUrl.pathname}${parsedUrl.search}`;
          const resp = await executeProbeFetch(fallbackHttpUrl);
          latencyMs = Math.max(15, Date.now() - start);
          statusCode = resp.status;
          isReachable = true;
          isHttps = false;

          resp.headers.forEach((value, key) => {
            responseHeaders[key.toLowerCase()] = value;
          });

          const contentType = responseHeaders['content-type'] || '';
          if (contentType.includes('text/html')) {
            const text = await resp.text();
            const match = text.match(/<title[^>]*>([^<]+)<\/title>/i);
            if (match) {
              pageTitle = match[1].trim().slice(0, 120);
            }
          }
        } catch (fallbackErr: any) {
          latencyMs = Math.max(45, Date.now() - start);
          isReachable = false;
          statusCode = 504;
          errorMessage = fallbackErr.message || 'Connection failed';
        }
      } else {
        latencyMs = Math.max(45, Date.now() - start);
        isReachable = false;
        statusCode = 504;
        errorMessage = err.name === 'AbortError' ? 'HTTP probe timed out' : (err.message || 'Connection failed');
      }
    }

    // 3. Sensitive Exposed Paths Recon (parallel with 2.5s timeout)
    const sensitivePathsToCheck = [
      '/.env',
      '/.git/HEAD',
      '/robots.txt',
      '/.well-known/security.txt',
    ];
    const sensitiveResults = await Promise.all(
      sensitivePathsToCheck.map((p) => probePath(url, p))
    );

    // 4. Header evaluation
    const hasHsts = Boolean(responseHeaders['strict-transport-security']);
    const hasCsp = Boolean(responseHeaders['content-security-policy']);
    const hasXfo = Boolean(responseHeaders['x-frame-options']);
    const hasXcto = Boolean(responseHeaders['x-content-type-options']);
    const serverHeader = responseHeaders['server'];
    const poweredByHeader = responseHeaders['x-powered-by'];

    // 5. Build Comprehensive Findings Matrix
    const findings: Array<{
      category: 'SSL' | 'HEADERS' | 'DNS' | 'SENSITIVE_FILES' | 'DISCLOSURE';
      title: string;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
      passed: boolean;
      description: string;
      recommendation: string;
      codeSnippet?: string;
    }> = [];

    // SSL Finding
    if (isHttps && sslCert) {
      const sslPassed = sslCert.valid && sslCert.daysRemaining > 14;
      findings.push({
        category: 'SSL',
        title: 'TLS / SSL Certificate Health',
        severity: sslPassed ? 'INFO' : sslCert.daysRemaining <= 0 ? 'CRITICAL' : 'HIGH',
        passed: sslPassed,
        description: sslCert.valid
          ? `Valid SSL Certificate issued by ${sslCert.issuer}. Expires in ${sslCert.daysRemaining} days (${sslCert.validTo.slice(0, 10)}). Protocol: ${sslCert.protocol}, Cipher: ${sslCert.cipher}.`
          : `SSL Certificate issue: ${sslCert.error || 'Expired or invalid certificate'}`,
        recommendation: sslCert.daysRemaining < 30
          ? 'Renew SSL certificate before expiration to avoid browser warnings.'
          : 'Enable automated Let\'s Encrypt / ACME certbot renewal.',
      });
    } else {
      findings.push({
        category: 'SSL',
        title: 'HTTPS Transport Encryption',
        severity: 'CRITICAL',
        passed: false,
        description: 'Host connects over unencrypted HTTP protocol. Credentials and session tokens transmitted in plaintext.',
        recommendation: 'Deploy TLS certificate and configure unconditional HTTP to HTTPS redirect.',
        codeSnippet: `server {\n    listen 80;\n    server_name ${hostname};\n    return 301 https://$host$request_uri;\n}`,
      });
    }

    // Headers Findings
    findings.push({
      category: 'HEADERS',
      title: 'HTTP Strict Transport Security (HSTS)',
      severity: 'HIGH',
      passed: hasHsts,
      description: hasHsts
        ? `HSTS active (${responseHeaders['strict-transport-security']}). Prevents SSL stripping.`
        : 'Missing Strict-Transport-Security header. Browsers may downgrade to unencrypted HTTP.',
      recommendation: 'Add HSTS with at least 1-year max-age, includeSubDomains, and preload.',
      codeSnippet: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    });

    findings.push({
      category: 'HEADERS',
      title: 'Content Security Policy (CSP)',
      severity: 'HIGH',
      passed: hasCsp,
      description: hasCsp
        ? 'Content-Security-Policy header detected. Mitigates XSS and unauthorized script injection.'
        : 'Missing Content-Security-Policy header. Site vulnerable to Cross-Site Scripting (XSS).',
      recommendation: 'Define a strict CSP restricting script-src, object-src, and default-src.',
      codeSnippet: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
    });

    findings.push({
      category: 'HEADERS',
      title: 'X-Frame-Options (Clickjacking Protection)',
      severity: 'MEDIUM',
      passed: hasXfo,
      description: hasXfo
        ? `Clickjacking protection active: ${responseHeaders['x-frame-options']}.`
        : 'Missing X-Frame-Options. Site can be embedded in malicious iframes (clickjacking).',
      recommendation: 'Set X-Frame-Options to DENY or SAMEORIGIN.',
      codeSnippet: 'X-Frame-Options: SAMEORIGIN',
    });

    findings.push({
      category: 'HEADERS',
      title: 'X-Content-Type-Options',
      severity: 'LOW',
      passed: hasXcto,
      description: hasXcto
        ? 'MIME-sniffing protection enabled (nosniff).'
        : 'Missing X-Content-Type-Options: nosniff header.',
      recommendation: 'Set X-Content-Type-Options: nosniff on all HTTP responses.',
      codeSnippet: 'X-Content-Type-Options: nosniff',
    });

    // Tech disclosure
    if (serverHeader || poweredByHeader) {
      findings.push({
        category: 'DISCLOSURE',
        title: 'Server Banner / Technology Disclosure',
        severity: 'LOW',
        passed: false,
        description: `Server leaks backend technology: ${[serverHeader ? `Server: ${serverHeader}` : '', poweredByHeader ? `X-Powered-By: ${poweredByHeader}` : ''].filter(Boolean).join(', ')}.`,
        recommendation: 'Disable server signature tokens in Nginx (server_tokens off) or Express (app.disable("x-powered-by")).',
        codeSnippet: 'server_tokens off;\n# or in Express.js:\napp.disable("x-powered-by");',
      });
    }

    // Sensitive Files
    sensitiveResults.forEach((resItem) => {
      if (resItem.exposed) {
        findings.push({
          category: 'SENSITIVE_FILES',
          title: `CRITICAL: Exposed ${resItem.path}`,
          severity: 'CRITICAL',
          passed: false,
          description: resItem.detail,
          recommendation: `Immediately restrict public access to ${resItem.path} via web server rules.`,
          codeSnippet: `location ~ /\\.git {\n    deny all;\n    return 404;\n}\nlocation ~ /\\.env {\n    deny all;\n    return 404;\n}`,
        });
      }
    });

    // DNS & Mail findings
    if (!dnsInfo.hasSpf) {
      findings.push({
        category: 'DNS',
        title: 'Missing SPF Record',
        severity: 'MEDIUM',
        passed: false,
        description: 'Domain lacks an SPF DNS record. Attackers can forge phishing emails appearing from this domain.',
        recommendation: 'Publish a TXT record with SPF definition for your authorized mail senders.',
        codeSnippet: `v=spf1 include:_spf.google.com ~all`,
      });
    }
    if (!dnsInfo.hasDmarc) {
      findings.push({
        category: 'DNS',
        title: 'Missing DMARC Policy Record',
        severity: 'MEDIUM',
        passed: false,
        description: 'Domain lacks a _dmarc TXT record. Email spoofing defense cannot be enforced.',
        recommendation: 'Configure a DMARC policy record at _dmarc.' + hostname,
        codeSnippet: `v=DMARC1; p=reject; rua=mailto:dmarc-reports@${hostname}`,
      });
    }

    // Calculate Real Security Score (0-100)
    let score = 100;
    findings.forEach((f) => {
      if (!f.passed) {
        if (f.severity === 'CRITICAL') score -= 30;
        else if (f.severity === 'HIGH') score -= 15;
        else if (f.severity === 'MEDIUM') score -= 10;
        else if (f.severity === 'LOW') score -= 5;
      }
    });
    score = Math.max(10, Math.min(100, score));

    const grade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : score >= 35 ? 'D' : 'F';

    // Log the real scan event
    const probeLog: RealEvent = {
      id: `audit-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      targetId: targetId || `target-${hostname}`,
      timestamp: new Date().toISOString(),
      displayTime: new Date().toTimeString().slice(0, 8),
      method: 'GET',
      endpoint: parsedUrl.pathname || '/',
      status: statusCode,
      sourceIp: '127.0.0.1 (Real SecOps Probe Engine)',
      userAgent: 'EXTREME-SecOps-Audit/3.0 (Real Network Scanner)',
      eventType: 'PROBE',
      severity: score < 60 ? 'SUSPICIOUS' : 'NORMAL',
      latencyMs,
      isLab: false,
      logSource: 'REAL_SERVER_PROBE',
      flagReason: `Real Deep Audit of ${hostname}: Score ${score}/100 (${grade}). ${findings.filter((f) => !f.passed).length} security issues identified.`,
      headers: responseHeaders,
      probeDetails: {
        protocol: isHttps ? 'https:' : 'http:',
        serverHeader: responseHeaders['server'],
        hsts: hasHsts,
        csp: hasCsp,
        xFrameOptions: responseHeaders['x-frame-options'],
        contentType: responseHeaders['content-type'],
        title: pageTitle || undefined,
        ssl: sslCert ? {
          valid: sslCert.valid,
          issuer: sslCert.issuer,
          validTo: sslCert.validTo,
          daysRemaining: sslCert.daysRemaining,
          protocol: sslCert.protocol,
          cipher: sslCert.cipher,
        } : undefined,
        dns: {
          ipAddresses: dnsInfo.ipAddresses,
          mxRecords: dnsInfo.mxRecords,
          hasSpf: dnsInfo.hasSpf,
          hasDmarc: dnsInfo.hasDmarc,
        },
        sensitivePaths: sensitiveResults,
      },
    };

    // Probes update health metrics only; they do not pollute visitor activity logs

    res.json({
      success: true,
      url,
      hostname,
      isReachable,
      status: statusCode,
      latencyMs,
      pageTitle,
      score,
      grade,
      headers: responseHeaders,
      ssl: sslCert,
      dns: dnsInfo,
      sensitivePaths: sensitiveResults,
      findings,
      probeLog,
    });
  });

  // REAL LOG PARSER & ANOMALY DETECTOR
  app.post('/api/logs/parse-real', (req, res) => {
    const { logContent, targetId } = req.body;
    if (!logContent || typeof logContent !== 'string') {
      return res.status(400).json({ error: 'Log content string is required' });
    }

    const lines = logContent.split('\n').filter((l) => l.trim().length > 0);
    const parsedEvents: RealEvent[] = [];
    const threatDetections: Array<{
      threatName: string;
      severity: string;
      confidence: number;
      affectedEndpoint: string;
      whatHappened: string;
      whyFlagged: string;
      evidence: string[];
      logIds: string[];
    }> = [];

    const combinedLogRegex = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^ "]+)?\s+HTTP\/[0-9.]+"\s+([0-9]{3})\s+(\S+)(?:\s+"(.*?)"\s+"(.*?)"|.*)?$/;

    lines.slice(0, 1000).forEach((line, idx) => {
      const trimmed = line.trim();
      let ip = '127.0.0.1';
      let method = 'GET';
      let endpoint = '/';
      let status = 200;
      let userAgent = 'Web Client';
      let timestamp = new Date(Date.now() - (lines.length - idx) * 3000).toISOString();

      if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
        try {
          const jsonLog = JSON.parse(trimmed);
          ip = jsonLog.ip || jsonLog.client_ip || jsonLog.remote_addr || ip;
          method = (jsonLog.method || jsonLog.http_method || method).toUpperCase();
          endpoint = jsonLog.path || jsonLog.uri || jsonLog.endpoint || endpoint;
          status = parseInt(jsonLog.status || jsonLog.status_code || 200, 10);
          userAgent = jsonLog.user_agent || jsonLog.userAgent || userAgent;
          if (jsonLog.timestamp || jsonLog.time) {
            timestamp = new Date(jsonLog.timestamp || jsonLog.time).toISOString();
          }
        } catch {}
      } else {
        const match = combinedLogRegex.exec(trimmed);
        if (match) {
          ip = match[1];
          method = match[3];
          endpoint = match[4] || '/';
          status = parseInt(match[5], 10);
          userAgent = match[8] || userAgent;
        } else {
          const parts = trimmed.split(' ');
          if (parts.length >= 3) {
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parts[0])) ip = parts[0];
            const methodIdx = parts.findIndex((p) => ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'].includes(p.replace(/"/g, '')));
            if (methodIdx !== -1) {
              method = parts[methodIdx].replace(/"/g, '');
              endpoint = parts[methodIdx + 1] || '/';
            }
            const statusCandidate = parts.find((p) => /^[1-5][0-9]{2}$/.test(p));
            if (statusCandidate) status = parseInt(statusCandidate, 10);
          }
        }
      }

      let severity: 'NORMAL' | 'LOW' | 'SUSPICIOUS' | 'CRITICAL' = 'NORMAL';
      let eventType = 'PAGEVIEW';
      let flagReason: string | undefined;

      const lowerEndpoint = endpoint.toLowerCase();
      const lowerUa = userAgent.toLowerCase();

      if (
        lowerEndpoint.includes("' or '1'='1") ||
        lowerEndpoint.includes("union select") ||
        lowerEndpoint.includes("information_schema") ||
        lowerEndpoint.includes("waitfor delay") ||
        lowerEndpoint.includes("benchmark(")
      ) {
        severity = 'CRITICAL';
        eventType = 'INJECTION_ATTEMPT';
        flagReason = 'SQL Injection pattern detected in request URI query parameters';
      } else if (
        lowerEndpoint.includes('../..') ||
        lowerEndpoint.includes('..%2f') ||
        lowerEndpoint.includes('/etc/passwd') ||
        lowerEndpoint.includes('/win.ini')
      ) {
        severity = 'CRITICAL';
        eventType = 'INJECTION_ATTEMPT';
        flagReason = 'Path traversal attempt targeting sensitive operating system files';
      } else if (
        lowerUa.includes('nikto') ||
        lowerUa.includes('sqlmap') ||
        lowerUa.includes('acunetix') ||
        lowerUa.includes('dirbuster') ||
        lowerUa.includes('nmap') ||
        lowerUa.includes('masscan') ||
        lowerUa.includes('zgrab')
      ) {
        severity = 'HIGH' as any;
        eventType = 'PROBE';
        flagReason = `Automated vulnerability scanner identified via User-Agent: ${userAgent}`;
      } else if (
        lowerEndpoint.includes('.env') ||
        lowerEndpoint.includes('.git') ||
        lowerEndpoint.includes('phpmyadmin') ||
        lowerEndpoint.includes('wp-login.php') ||
        lowerEndpoint.includes('/aws/credentials')
      ) {
        severity = status === 200 ? 'CRITICAL' : 'SUSPICIOUS';
        eventType = 'CONFIG_ACCESS';
        flagReason = `Access probe to restricted path: ${endpoint} (Status: ${status})`;
      } else if (status === 401 || status === 403) {
        severity = 'SUSPICIOUS';
        eventType = 'AUTHENTICATION';
        flagReason = `Authentication/Authorization failure (HTTP ${status})`;
      } else if (status >= 500) {
        severity = 'SUSPICIOUS';
        eventType = 'CLIENT_ERROR';
        flagReason = `Internal server error response (HTTP ${status})`;
      } else if (endpoint.startsWith('/api/')) {
        eventType = 'API_REQUEST';
      }

      const event: RealEvent = {
        id: `log-${Date.now().toString(36)}-${idx}`,
        targetId: targetId || 'target-atc-simulator',
        timestamp,
        displayTime: new Date(timestamp).toTimeString().slice(0, 8),
        method,
        endpoint,
        status,
        sourceIp: ip,
        userAgent,
        eventType,
        severity,
        latencyMs: Math.floor(Math.random() * 35) + 12,
        isLab: false,
        logSource: 'REAL_LOG_FILE',
        payloadSnippet: trimmed.slice(0, 200),
        flagReason,
      };

      parsedEvents.push(event);
      realEventsBuffer.unshift(event);
    });

    if (realEventsBuffer.length > 3000) realEventsBuffer.length = 3000;

    const criticalLogs = parsedEvents.filter((e) => e.severity === 'CRITICAL' || e.severity === 'SUSPICIOUS');
    const sqliLogs = criticalLogs.filter((e) => e.eventType === 'INJECTION_ATTEMPT');
    if (sqliLogs.length > 0) {
      threatDetections.push({
        threatName: 'Web Application Injection Attack',
        severity: 'CRITICAL',
        confidence: 96,
        affectedEndpoint: sqliLogs[0].endpoint,
        whatHappened: `${sqliLogs.length} real attack requests containing SQL or path traversal payloads were logged against ${sqliLogs[0].endpoint}.`,
        whyFlagged: 'Payload contains SQL command structures or filesystem traversal characters directly within the URI query parameters.',
        evidence: sqliLogs.map((l) => `${l.sourceIp} -> ${l.method} ${l.endpoint} (${l.status})`).slice(0, 5),
        logIds: sqliLogs.map((l) => l.id),
      });
    }

    const scannerLogs = criticalLogs.filter((e) => e.eventType === 'PROBE' || e.eventType === 'CONFIG_ACCESS');
    if (scannerLogs.length > 0) {
      threatDetections.push({
        threatName: 'Automated Reconnaissance & Sensitive File Probing',
        severity: 'HIGH',
        confidence: 92,
        affectedEndpoint: scannerLogs[0].endpoint,
        whatHappened: `Automated reconnaissance probes targeting sensitive configuration files or using scanner User-Agents.`,
        whyFlagged: 'Access patterns match known vulnerability scanners probing for .git, .env, or administrative login consoles.',
        evidence: scannerLogs.map((l) => `${l.sourceIp} requested ${l.endpoint} with UA: ${l.userAgent.slice(0, 60)}`).slice(0, 5),
        logIds: scannerLogs.map((l) => l.id),
      });
    }

    parsedEvents.forEach((ev) => {
      sseClients.forEach((client) => {
        if (!client.targetId || client.targetId === ev.targetId) {
          client.res.write(`data: ${JSON.stringify(ev)}\n\n`);
        }
      });
    });

    res.json({
      success: true,
      totalLinesParsed: lines.length,
      eventsIngested: parsedEvents.length,
      threatsDetected: threatDetections.length,
      threats: threatDetections,
      events: parsedEvents,
    });
  });

  // Real HTTP Server Probe
  app.post('/api/probe/live', async (req, res) => {
    let { url, targetId } = req.body;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Valid URL is required' });
    }

    url = url.trim();
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = `https://${url}`;
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    const start = Date.now();
    let isReachable = false;
    let statusCode = 0;
    let latencyMs = 0;
    const responseHeaders: Record<string, string> = {};
    let pageTitle = '';
    let errorMessage = '';

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4500);

      const resp = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) EXTREME-SecOps-Probe/3.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
        signal: controller.signal,
        redirect: 'follow',
      });

      clearTimeout(timeout);
      latencyMs = Math.max(12, Date.now() - start);
      statusCode = resp.status;
      isReachable = true;

      resp.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });

      const contentType = responseHeaders['content-type'] || '';
      if (contentType.includes('text/html')) {
        const text = await resp.text();
        const match = text.match(/<title[^>]*>([^<]+)<\/title>/i);
        if (match) {
          pageTitle = match[1].trim().slice(0, 120);
        }
      }
    } catch (err: any) {
      latencyMs = Math.max(45, Date.now() - start);
      isReachable = false;
      statusCode = 504;
      errorMessage = err.name === 'AbortError' ? 'Probe timed out' : (err.message || 'Connection failed');
    }

    const hasHsts = Boolean(responseHeaders['strict-transport-security']);
    const hasCsp = Boolean(responseHeaders['content-security-policy']);

    // Resolve actual live server IP via DNS
    let resolvedServerIp = '';
    try {
      const ips = await withTimeout(dns.resolve4(parsedUrl.hostname), 1500, [] as string[]);
      if (ips.length > 0) resolvedServerIp = ips[0];
    } catch {}

    const probeLog: RealEvent = {
      id: `probe-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      targetId: targetId || `target-${parsedUrl.hostname}`,
      timestamp: new Date().toISOString(),
      displayTime: new Date().toTimeString().slice(0, 8),
      method: 'GET',
      endpoint: parsedUrl.pathname || '/',
      status: statusCode,
      sourceIp: resolvedServerIp ? `${resolvedServerIp} (Server Host IP)` : `${parsedUrl.hostname} (Resolved Host)`,
      userAgent: 'EXTREME-SecOps-Live-Monitor/3.0 (Server-Side Health Probe)',
      eventType: 'PROBE',
      severity: isReachable && statusCode < 400 ? 'NORMAL' : 'SUSPICIOUS',
      latencyMs,
      isLab: false,
      logSource: 'REAL_SERVER_PROBE',
      flagReason: isReachable
        ? `Real Probe: Connected to ${parsedUrl.hostname} (${statusCode} in ${latencyMs}ms). Host IP: ${resolvedServerIp || 'Active'}`
        : `Real Probe: Failed connecting to ${parsedUrl.hostname} - ${errorMessage}`,
      headers: responseHeaders,
      probeDetails: {
        protocol: parsedUrl.protocol,
        serverHeader: responseHeaders['server'],
        hsts: hasHsts,
        csp: hasCsp,
        xFrameOptions: responseHeaders['x-frame-options'],
        contentType: responseHeaders['content-type'],
        title: pageTitle || undefined,
      },
    };

    // Probes update health metrics only; do not add to visitor activity logs

    res.json({
      success: true,
      url,
      hostname: parsedUrl.hostname,
      isReachable,
      status: statusCode,
      latencyMs,
      server: responseHeaders['server'],
      headers: responseHeaders,
      pageTitle,
      probeLog,
    });
  });

  // Real Client IP discovery endpoint for mobile, tablet, and laptop visitors
  app.get('/api/collector/my-ip', (req, res) => {
    const cfIp = (req.headers['cf-connecting-ip'] as string)?.trim();
    const trueClientIp = (req.headers['true-client-ip'] as string)?.trim();
    const xRealIp = (req.headers['x-real-ip'] as string)?.trim();
    const xffRaw = (req.headers['x-forwarded-for'] as string);
    const xffList = xffRaw ? xffRaw.split(',').map((s) => s.trim()).filter(Boolean) : [];
    const directSocketIp = req.socket.remoteAddress?.replace(/^::ffff:/, '') || '';

    const isNonLocalIp = (ip: string) => {
      if (!ip || typeof ip !== 'string') return false;
      const c = ip.trim();
      return c !== '127.0.0.1' && c !== '::1' && c !== 'localhost';
    };

    let clientIp = cfIp || trueClientIp || xRealIp || xffList.find((ip) => isNonLocalIp(ip)) || directSocketIp || '127.0.0.1';
    clientIp = clientIp.replace(/^::ffff:/, '').trim();

    const country = (req.headers['cf-ipcountry'] as string) || undefined;
    const targetId = (req.query.targetId as string) || 'target-atc-simulator';
    const visitorId = (req.query.visitorId as string) || '';
    const blockCheck = checkIsBlocked(targetId, clientIp, visitorId);

    res.json({
      ip: clientIp,
      country,
      isBlocked: blockCheck.blocked,
      blockedReason: blockCheck.reason,
    });
  });

  // WAF: Query Blocked Entities
  app.get('/api/collector/blocked', (req, res) => {
    const targetId = (req.query.targetId as string) || '';
    const list = blockedEntities.filter((b) => !targetId || b.targetId === targetId || b.targetId === 'all');
    res.json({ success: true, blockedList: list });
  });

  // WAF: Block IP or Device
  app.post('/api/collector/block', (req, res) => {
    const { targetId = 'target-atc-simulator', ip, visitorId, reason = 'Blocked by SecOps Administrator' } = req.body || {};
    const cleanIp = (ip || '').replace(/^::ffff:/, '').trim();
    const cleanVid = (visitorId || '').trim();

    if (!cleanIp && !cleanVid) {
      return res.status(400).json({ error: 'Missing ip or visitorId to block' });
    }

    const entityId = cleanVid ? `${cleanIp || 'unknown'}::${cleanVid}` : cleanIp;
    const existingIndex = blockedEntities.findIndex((b) => b.id === entityId || (cleanIp && b.ip === cleanIp));
    const blockRecord: BlockedEntity = {
      id: entityId,
      ip: cleanIp || undefined,
      visitorId: cleanVid || undefined,
      targetId,
      blockedAt: new Date().toISOString(),
      reason,
    };

    if (existingIndex >= 0) {
      blockedEntities[existingIndex] = blockRecord;
    } else {
      blockedEntities.push(blockRecord);
    }

    // Inject critical alert in live log buffer
    const alertEvent: RealEvent = {
      id: `waf-block-rule-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      targetId,
      timestamp: new Date().toISOString(),
      displayTime: new Date().toTimeString().slice(0, 8),
      method: 'POST',
      endpoint: '/waf/block-rule',
      status: 403,
      sourceIp: cleanIp || 'Device',
      userAgent: 'EXTREME-SecOps-WAF/3.0',
      eventType: 'THREAT_ALERT',
      severity: 'CRITICAL',
      latencyMs: 8,
      isLab: false,
      logSource: 'REAL_LIVE_INGEST',
      flagReason: `🚫 WAF RULE ENFORCED: Administrator blocked access for ${cleanIp || cleanVid} (${reason})`,
      clientGeo: {
        device: 'WAF Firewall Rule',
        visitorId: cleanVid || undefined,
      },
    };
    realEventsBuffer.unshift(alertEvent);
    if (realEventsBuffer.length > 3000) realEventsBuffer.length = 3000;

    // Broadcast via SSE to all connected dashboards and client sessions
    sseClients.forEach((client) => {
      client.res.write(`data: ${JSON.stringify({ type: 'BLOCKED', blockRecord, alertEvent })}\n\n`);
    });

    res.json({ success: true, blocked: true, blockRecord });
  });

  // WAF: Unblock IP or Device
  app.post('/api/collector/unblock', (req, res) => {
    const { targetId = 'target-atc-simulator', ip, visitorId } = req.body || {};
    const cleanIp = (ip || '').replace(/^::ffff:/, '').trim();
    const cleanVid = (visitorId || '').trim();

    for (let i = blockedEntities.length - 1; i >= 0; i--) {
      const b = blockedEntities[i];
      const matchTarget = !targetId || b.targetId === targetId || b.targetId === 'all';
      const matchIp = cleanIp && b.ip === cleanIp;
      const matchVid = cleanVid && b.visitorId === cleanVid;
      if (matchTarget && (matchIp || matchVid)) {
        blockedEntities.splice(i, 1);
      }
    }

    // Broadcast UNBLOCKED via SSE
    sseClients.forEach((client) => {
      client.res.write(`data: ${JSON.stringify({ type: 'UNBLOCKED', ip: cleanIp, visitorId: cleanVid })}\n\n`);
    });

    res.json({ success: true, unblocked: true, remaining: blockedEntities.length });
  });

  // Real HTTP Event Ingestion endpoint with Robust Real Client IP Extraction
  app.post('/api/collector/ingest', (req, res) => {
    let body = req.body || {};
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch (e) {
        body = {};
      }
    }

    // 1. Extract Real Remote Client IP from proxy and edge headers
    const cfIp = (req.headers['cf-connecting-ip'] as string)?.trim();
    const trueClientIp = (req.headers['true-client-ip'] as string)?.trim();
    const xRealIp = (req.headers['x-real-ip'] as string)?.trim();
    const xffRaw = (req.headers['x-forwarded-for'] as string);
    const xffList = xffRaw ? xffRaw.split(',').map((s) => s.trim()).filter(Boolean) : [];
    const directSocketIp = req.socket.remoteAddress?.replace(/^::ffff:/, '') || '';

    // If body contains client-reported public IP from client browser resolution (e.g. ipify)
    const clientReportedIp = ((body.clientPublicIp || body.sourceIp || '') as string).replace(/^::ffff:/, '').trim();

    const isNonLocalIp = (ip: string) => {
      if (!ip || typeof ip !== 'string') return false;
      const c = ip.trim();
      if (c === '127.0.0.1' || c === '::1' || c === 'localhost') return false;
      if (c.toLowerCase().includes('client') || c.toLowerCase().includes('browser')) return false;
      return true;
    };

    let determinedIp = '127.0.0.1';
    // 1. If client device resolved their own public IP directly from the browser (e.g. on mobile/cell network)
    if (isNonLocalIp(clientReportedIp)) {
      determinedIp = clientReportedIp;
    } else if (cfIp && isNonLocalIp(cfIp)) {
      determinedIp = cfIp;
    } else if (trueClientIp && isNonLocalIp(trueClientIp)) {
      determinedIp = trueClientIp;
    } else if (xRealIp && isNonLocalIp(xRealIp)) {
      determinedIp = xRealIp;
    } else {
      // Find first non-local IP in X-Forwarded-For chain
      const firstValidXff = xffList.find((ip) => isNonLocalIp(ip));
      if (firstValidXff) {
        determinedIp = firstValidXff;
      } else if (isNonLocalIp(directSocketIp)) {
        determinedIp = directSocketIp;
      } else if (clientReportedIp) {
        determinedIp = clientReportedIp;
      } else {
        determinedIp = directSocketIp || '127.0.0.1';
      }
    }

    // Clean IPv6 mapped IPv4
    determinedIp = determinedIp.replace(/^::ffff:/, '');

    const userAgent = (body.userAgent || (req.headers['user-agent'] as string) || 'Live Visitor Browser');

    // Granular Device Type Parsing
    const deviceType = parseDeviceDetails(userAgent, body);

    const targetId = body.targetId || (req.headers['x-target-id'] as string) || 'target-atc-simulator';
    const method = (body.method || 'GET').toUpperCase();
    const endpoint = body.endpoint || body.path || '/';

    // WAF Access Enforcement Check: Blocked Devices & IPs are immediately rejected
    const blockCheck = checkIsBlocked(targetId, determinedIp, body.visitorId);
    if (blockCheck.blocked) {
      const blockEvent: RealEvent = {
        id: `waf-block-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
        targetId,
        timestamp: new Date().toISOString(),
        displayTime: new Date().toTimeString().slice(0, 8),
        method,
        endpoint,
        status: 403,
        sourceIp: determinedIp,
        userAgent,
        eventType: 'THREAT_ALERT',
        severity: 'CRITICAL',
        latencyMs: 8,
        isLab: false,
        logSource: 'REAL_LIVE_INGEST',
        flagReason: `🚫 WAF BLOCKED: Prohibited request attempt from ${determinedIp} (${deviceType})`,
        clientGeo: {
          device: deviceType,
          visitorId: (body.visitorId as string) || undefined,
          country: (req.headers['cf-ipcountry'] as string) || (body.country as string) || undefined,
        },
      };
      realEventsBuffer.unshift(blockEvent);
      if (realEventsBuffer.length > 3000) realEventsBuffer.length = 3000;
      sseClients.forEach((client) => {
        client.res.write(`data: ${JSON.stringify(blockEvent)}\n\n`);
      });

      return res.status(403).json({
        blocked: true,
        ip: determinedIp,
        error: 'Access Denied: Your IP or device has been blocked by EXTREME SecOps WAF',
        reason: blockCheck.reason || 'SecOps Administrator Manual Block',
        timestamp: new Date().toISOString(),
      });
    }

    const status = typeof body.status === 'number' ? body.status : 200;
    const latencyMs = typeof body.latencyMs === 'number' ? body.latencyMs : Math.floor(Math.random() * 20) + 14;
    const eventType = body.eventType || (status === 401 ? 'AUTHENTICATION' : endpoint.startsWith('/api') ? 'API_REQUEST' : 'PAGEVIEW');

    let severity = body.severity;
    if (!severity) {
      if (status >= 500 || status === 401 || status === 403 || body.payloadSnippet?.includes("' OR '1'='1")) {
        severity = 'SUSPICIOUS';
      } else {
        severity = 'NORMAL';
      }
    }

    const event: RealEvent = {
      id: `ingest-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      targetId,
      timestamp: new Date().toISOString(),
      displayTime: new Date().toTimeString().slice(0, 8),
      method,
      endpoint,
      status,
      sourceIp: determinedIp,
      userAgent,
      eventType,
      severity,
      latencyMs,
      isLab: false,
      logSource: 'REAL_LIVE_INGEST',
      payloadSnippet: body.payloadSnippet || undefined,
      flagReason: body.flagReason || (severity === 'SUSPICIOUS' ? `Real HTTP event flagged: ${method} ${endpoint} returned ${status}` : `Real user request from ${determinedIp}`),
      clientGeo: {
        device: deviceType,
        visitorId: (body.visitorId as string) || undefined,
        country: (req.headers['cf-ipcountry'] as string) || (body.country as string) || undefined,
      },
      headers: body.headers || {
        host: req.headers.host || '',
        'user-agent': userAgent,
        'content-type': req.headers['content-type'] || 'application/json',
      },
    };

    realEventsBuffer.unshift(event);
    if (realEventsBuffer.length > 3000) realEventsBuffer.length = 3000;

    // Broadcast to all active SSE dashboard streams
    sseClients.forEach((client) => {
      client.res.write(`data: ${JSON.stringify(event)}\n\n`);
    });

    res.json({
      success: true,
      eventId: event.id,
      receivedAt: event.timestamp,
      event,
    });
  });

  // Polling endpoint to retrieve real logs
  app.get('/api/collector/events', (req, res) => {
    const targetId = req.query.targetId as string;
    const since = req.query.since as string;
    const all = req.query.all === '1' || req.query.all === 'true';
    let list = realEventsBuffer;

    if (targetId && !all) {
      list = list.filter((e) => e.targetId === targetId || e.targetId === 'target-atc-simulator' || e.targetId === 'target-real-site' || e.targetId === 'target-prod-site');
    }
    if (since) {
      const sinceTime = new Date(since).getTime();
      list = list.filter((e) => new Date(e.timestamp).getTime() > sinceTime);
    }

    res.json({
      success: true,
      count: list.length,
      events: list.slice(0, 400),
    });
  });

  // Dedicated Distinct Active Visitor Persons API
  app.get('/api/collector/visitors', (req, res) => {
    const targetId = req.query.targetId as string;
    let list = realEventsBuffer.filter((e) => e.logSource === 'REAL_LIVE_INGEST');
    if (targetId) {
      list = list.filter((e) => e.targetId === targetId || e.targetId === 'target-atc-simulator' || e.targetId === 'target-real-site' || e.targetId === 'target-prod-site');
    }

    const now = Date.now();
    const ONLINE_TIMEOUT_MS = 25000;
    const visitorMap = new Map<string, any>();

    // Group events by distinct client device
    // Ensures multiple devices on the same WiFi router (which share one public IP)
    // each get their own separate active visitor card!
    const eventsByDevice = new Map<string, RealEvent[]>();
    list.forEach((event) => {
      const ip = (event.sourceIp || '127.0.0.1').trim();
      const dev = (event.clientGeo?.device || parseDeviceDetails(event.userAgent) || 'Device').trim();
      const vid = event.clientGeo?.visitorId || '';
      const deviceKey = vid ? `${ip}::${vid}` : `${ip}::${dev}`;
      const group = eventsByDevice.get(deviceKey) || [];
      group.push(event);
      eventsByDevice.set(deviceKey, group);
    });

    eventsByDevice.forEach((events, deviceKey) => {
      // Sort newest to oldest for this device
      events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      const latestEvent = events[0];
      const oldestEvent = events[events.length - 1];
      const ip = (latestEvent.sourceIp || '127.0.0.1').trim();

      // Find the most recent SESSION_END event for this device
      const sessionEndEvent = events.find((e) => e.eventType === 'SESSION_END');

      // Find the most recent active user interaction (pageview, heartbeat, click, interaction)
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

      const blockCheck = checkIsBlocked(targetId, ip, events[0]?.clientGeo?.visitorId);
      visitorMap.set(deviceKey, {
        id: deviceKey,
        visitorId: events[0]?.clientGeo?.visitorId,
        ip,
        device: latestEvent.clientGeo?.device || parseDeviceDetails(latestEvent.userAgent),
        country: latestEvent.clientGeo?.country,
        city: latestEvent.clientGeo?.city,
        firstSeen: oldestEvent.timestamp,
        lastSeen: latestActiveEvent ? latestActiveEvent.timestamp : latestEvent.timestamp,
        totalHits: events.length,
        lastEndpoint: latestActiveEvent ? `${latestActiveEvent.method} ${latestActiveEvent.endpoint}` : `${latestEvent.method} ${latestEvent.endpoint}`,
        lastStatus: latestEvent.status,
        userAgent: latestEvent.userAgent,
        isOnline,
        leftAt,
        isBlocked: blockCheck.blocked,
        blockedReason: blockCheck.reason,
      });
    });

    const visitors = Array.from(visitorMap.values()).sort((a, b) => {
      if (a.isOnline && !b.isOnline) return -1;
      if (!a.isOnline && b.isOnline) return 1;
      return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime();
    });

    const activeNowCount = visitors.filter((v) => v.isOnline).length;

    res.json({
      success: true,
      activeNowCount,
      totalUniquePersons: visitors.length,
      visitors,
    });
  });

  // Interactive Live Mobile Test Visit Page
  app.get('/api/collector/test-visit', (req, res) => {
    const targetId = (req.query.targetId as string) || 'target-atc-simulator';
    const host = req.headers.host || `localhost:${PORT}`;
    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const baseUrl = `${protocol}://${host}`;

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Live Visitor Device Verified — EXTREME SecOps</title>
  <style>
    body { background: #090d16; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 20px; display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; }
    .card { background: #0f172a; border: 1px solid #1e293b; border-radius: 16px; padding: 24px; max-width: 440px; width: 100%; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
    .badge-online { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; background: #064e3b; color: #34d399; font-size: 11px; font-weight: 700; border-radius: 9999px; font-family: monospace; border: 1px solid #059669; }
    .badge-offline { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; background: #451a1a; color: #f87171; font-size: 11px; font-weight: 700; border-radius: 9999px; font-family: monospace; border: 1px solid #b91c1c; }
    .pulse { width: 8px; height: 8px; background: #10b981; border-radius: 50%; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }
    h1 { font-size: 19px; font-weight: 800; margin: 14px 0 6px; color: #f8fafc; }
    p { font-size: 13px; color: #94a3b8; line-height: 1.5; margin: 0 0 14px; }
    .box { background: #020617; border: 1px solid #1e293b; border-radius: 10px; padding: 12px; margin-bottom: 14px; font-family: monospace; font-size: 12px; }
    .box div { margin-bottom: 6px; display: flex; justify-content: space-between; }
    .box div:last-child { margin-bottom: 0; }
    .val { color: #38bdf8; font-weight: 700; word-break: break-all; }
    .btn { display: block; width: 100%; padding: 11px; border-radius: 8px; border: none; font-weight: 700; font-size: 13px; cursor: pointer; transition: 0.15s; margin-bottom: 8px; text-align: center; }
    .btn:active { transform: scale(0.98); }
    .btn-primary { background: #10b981; color: #022c22; }
    .btn-secondary { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; }
    .btn-leave { background: #e11d48; color: #ffffff; }
    .status-msg { font-size: 12px; color: #34d399; text-align: center; font-weight: 600; min-height: 20px; margin-top: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <div id="statusBadge" class="badge-online"><div class="pulse"></div>REAL-TIME VISITOR CONNECTED</div>
    <h1 id="titleHeader">Live Telemetry Active</h1>
    <p id="descPara">Your device is streaming real telemetry to the SecOps dashboard. Heartbeat pulses every 10s.</p>
    <div class="box">
      <div><span>Device:</span><span class="val" id="devType">Detecting...</span></div>
      <div><span>Public IP:</span><span class="val" id="ipVal">Resolving...</span></div>
      <div><span>Target ID:</span><span class="val">${targetId}</span></div>
      <div><span>Hits Sent:</span><span class="val" id="hitCount">1</span></div>
      <div><span>Status:</span><span class="val" id="onlineStatus" style="color:#34d399">ONLINE</span></div>
    </div>

    <div id="activeControls">
      <button class="btn btn-primary" onclick="sendHit('/products', 200, 'PAGEVIEW')">Navigate /products (200 OK)</button>
      <button class="btn btn-secondary" onclick="sendHit('/api/user/checkout', 200, 'API_REQUEST')">POST /api/user/checkout</button>
      <button class="btn btn-secondary" onclick="sendHit('/admin/login', 401, 'AUTHENTICATION', 'Failed credentials from remote mobile device')">Trigger 401 Auth Flag</button>
      <button class="btn btn-leave" onclick="manualLeave()">🚪 Leave Website (Close Session)</button>
    </div>

    <div id="reconnectControls" style="display:none;">
      <button class="btn btn-primary" onclick="reconnect()">🔄 Re-enter Website (Go Back Online)</button>
    </div>

    <div class="status-msg" id="statusMsg">Event registered in dashboard</div>
  </div>

  <script>
    var hits = 0;
    var publicIp = '';
    var isConnected = true;
    function detectClientDev() {
      try {
        var ua = navigator.userAgent || '';
        var uaL = ua.toLowerCase();
        var maxT = navigator.maxTouchPoints || 0;
        var sw = (window.screen && window.screen.width) || 0;
        var sh = (window.screen && window.screen.height) || 0;
        var isTouch = maxT > 0 || (window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
        var hasBat = 'getBattery' in navigator;

        if (/ipad/i.test(uaL) || (maxT > 1 && (/macintosh|mac os x/i.test(uaL) || navigator.platform === 'MacIntel'))) {
          return 'Apple iPad (iPadOS)';
        }
        if (/iphone/i.test(uaL)) {
          var iosM = ua.match(/OS (\\d+[_.]\\d+)/);
          var iosV = iosM ? ' (iOS ' + iosM[1].replace('_', '.') + ')' : ' (iOS)';
          var w = Math.min(sw, sh);
          var h = Math.max(sw, sh);
          var m = 'Apple iPhone';
          if (w === 430 && h === 932) m = 'iPhone 15/14 Pro Max';
          else if (w === 393 && h === 852) m = 'iPhone 15/14 Pro';
          else if (w === 428 && h === 926) m = 'iPhone 14 Plus / 13 Pro Max';
          else if (w === 390 && h === 844) m = 'iPhone 14 / 13 / 12';
          else if (w === 375 && h === 812) m = 'iPhone 13 mini / 12 mini / X';
          else if (w === 414 && h === 896) m = 'iPhone 11 / XR';
          return m + iosV;
        }
        if (/android/i.test(uaL)) {
          var isTab = !/mobile/i.test(uaL) || (sw >= 768 && sh >= 1024);
          var brand = isTab ? 'Android Tablet' : 'Android Mobile';
          if (/samsung|sm-[a-z0-9]+/i.test(uaL)) brand = isTab ? 'Samsung Galaxy Tab' : 'Samsung Galaxy';
          else if (/pixel/i.test(uaL)) brand = 'Google Pixel';
          else if (/oneplus/i.test(uaL)) brand = 'OnePlus Mobile';
          else if (/xiaomi|redmi/i.test(uaL)) brand = 'Xiaomi / Redmi Mobile';
          var av = ua.match(/Android\\s+([\\d.]+)/i);
          return brand + (av ? ' (Android ' + av[1] + ')' : '');
        }
        if (/windows/i.test(uaL)) {
          return (isTouch || hasBat || (sw <= 1600 && sh <= 900)) ? 'Windows 11/10 Laptop' : 'Windows 11/10 PC';
        }
        if (/macintosh|mac os x/i.test(uaL)) {
          return (hasBat || (sw >= 1280 && sw <= 1728) || isTouch) ? 'MacBook (macOS Laptop)' : 'Apple Mac (macOS Desktop)';
        }
        if (/linux/i.test(uaL)) {
          return (isTouch || hasBat || sw <= 1600) ? 'Linux Laptop' : 'Linux Desktop';
        }
      } catch(e) {}
      return 'Desktop PC';
    }
    var dev = detectClientDev();
    document.getElementById('devType').textContent = dev;

    var visitorDeviceId = '';
    try {
      visitorDeviceId = localStorage.getItem('ext_sec_device_id') || '';
      if (!visitorDeviceId) {
        visitorDeviceId = 'dev-' + Math.random().toString(36).substring(2, 9) + '-' + Date.now().toString(36);
        localStorage.setItem('ext_sec_device_id', visitorDeviceId);
      }
    } catch(e) {
      visitorDeviceId = 'dev-' + Math.random().toString(36).substring(2, 9);
    }

    var blockPollTimer = null;
    function displayBlockScreen(reason, ip) {
      if (document.getElementById('extreme-secops-block-wall')) return;
      var wall = document.createElement('div');
      wall.id = 'extreme-secops-block-wall';
      wall.style.cssText = 'position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;background:#06090e;color:#e2e8f0;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:ui-monospace,Menlo,Consolas,monospace;padding:24px;box-sizing:border-box;text-align:center;';
      wall.innerHTML = '<div style="max-width:540px;background:rgba(15,23,42,0.95);border:1px solid #f43f5e;border-radius:16px;padding:32px;box-shadow:0 0 60px rgba(244,63,94,0.35);">'
        + '<div style="font-size:42px;margin-bottom:12px;">🚫</div>'
        + '<div style="color:#f43f5e;font-size:13px;font-weight:bold;letter-spacing:2px;margin-bottom:8px;">ACCESS DENIED // 403 FORBIDDEN</div>'
        + '<h1 style="color:#ffffff;font-size:22px;margin:0 0 16px 0;font-weight:800;">DEVICE ACCESS SUSPENDED</h1>'
        + '<p style="color:#94a3b8;font-size:13px;line-height:1.6;margin-bottom:18px;">Your device and network IP <span style="color:#00f0ff;font-weight:bold;">[' + (ip || publicIp || 'Client') + ']</span> have been blocked from interacting with this website by the EXTREME SecOps Administrator.</p>'
        + '<div style="background:#090d16;border:1px solid #1e293b;border-radius:8px;padding:12px;font-size:12px;color:#f87171;margin-bottom:18px;">WAF Policy: ' + (reason || 'Manual Administrator Block') + '</div>'
        + '<div style="font-size:11px;color:#64748b;font-family:monospace;">EXTREME SEC-OPS WAF ENGINE • SHIELD ACTIVE</div>'
        + '</div>';
      document.body.appendChild(wall);
      document.body.style.overflow = 'hidden';

      if (!blockPollTimer) {
        blockPollTimer = setInterval(function() {
          fetch('${baseUrl}/api/collector/my-ip?targetId=' + encodeURIComponent('${targetId}') + '&visitorId=' + encodeURIComponent(visitorDeviceId))
            .then(function(r) { return r.json(); })
            .then(function(d) {
              if (d && !d.isBlocked) {
                removeBlockScreen();
              }
            }).catch(function() {});
        }, 3000);
      }
    }

    function removeBlockScreen() {
      var wall = document.getElementById('extreme-secops-block-wall');
      if (wall && wall.parentNode) {
        wall.parentNode.removeChild(wall);
      }
      document.body.style.overflow = '';
      if (blockPollTimer) {
        clearInterval(blockPollTimer);
        blockPollTimer = null;
      }
    }

    try {
      if (window.EventSource) {
        var sse = new EventSource('${baseUrl}/api/collector/stream');
        sse.onmessage = function(e) {
          try {
            var d = JSON.parse(e.data);
            if (d.type === 'BLOCKED') {
              var cleanP = (publicIp || '').replace(/^::ffff:/, '').trim();
              if ((d.blockRecord?.ip && d.blockRecord.ip === cleanP) || (d.blockRecord?.visitorId && d.blockRecord.visitorId === visitorDeviceId)) {
                displayBlockScreen(d.blockRecord?.reason, cleanP);
              }
            } else if (d.type === 'UNBLOCKED') {
              var cleanP = (publicIp || '').replace(/^::ffff:/, '').trim();
              if ((d.ip && d.ip === cleanP) || (d.visitorId && d.visitorId === visitorDeviceId)) {
                removeBlockScreen();
              }
            }
          } catch(err) {}
        };
      }
    } catch(err) {}

    function sendHit(endpoint, status, eventType, flagReason) {
      if (!isConnected && eventType !== 'PAGEVIEW') return;
      hits++;
      document.getElementById('hitCount').textContent = hits;
      fetch('${baseUrl}/api/collector/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetId: '${targetId}',
          visitorId: visitorDeviceId,
          endpoint: endpoint,
          method: endpoint.startsWith('/api') ? 'POST' : 'GET',
          status: status || 200,
          eventType: eventType || 'PAGEVIEW',
          clientPublicIp: publicIp || undefined,
          clientDevice: dev,
          userAgent: navigator.userAgent,
          flagReason: flagReason || ('Real user navigated ' + endpoint)
        })
      }).then(function(res) {
        if (res.status === 403) {
          return res.json().then(function(d) {
            displayBlockScreen(d.reason || 'SecOps Administrator WAF Block Policy', publicIp);
          }).catch(function() {
            displayBlockScreen('SecOps Administrator WAF Block Policy', publicIp);
          });
        }
        document.getElementById('statusMsg').textContent = '✓ Live Event: ' + (eventType || 'PAGEVIEW') + ' (' + endpoint + ')';
        setTimeout(function() { document.getElementById('statusMsg').textContent = ''; }, 2500);
      });
    }

    // 10-Second Heartbeat while connected
    var heartbeatTimer = setInterval(function() {
      if (isConnected && !document.hidden) {
        sendHit(window.location.pathname, 200, 'HEARTBEAT', 'Mobile visitor presence heartbeat');
      }
    }, 10000);

    // Leave Website / Exit Detection
    function triggerLeave() {
      if (!isConnected) return;
      isConnected = false;
      try { clearInterval(heartbeatTimer); } catch(e) {}

      var exitPayload = JSON.stringify({
        targetId: '${targetId}',
        visitorId: visitorDeviceId,
        timestamp: new Date().toISOString(),
        url: window.location.href,
        path: window.location.pathname || '/',
        userAgent: navigator.userAgent,
        clientPublicIp: publicIp || undefined,
        method: 'POST',
        endpoint: '/session/leave',
        status: 200,
        eventType: 'SESSION_END',
        severity: 'NORMAL',
        flagReason: 'Visitor left website / closed tab'
      });

      var beaconSent = false;
      try {
        if (navigator.sendBeacon) {
          var blob = new Blob([exitPayload], { type: 'text/plain' });
          beaconSent = navigator.sendBeacon('${baseUrl}/api/collector/ingest', blob);
        }
      } catch(e) {}

      if (!beaconSent && window.fetch) {
        try {
          fetch('${baseUrl}/api/collector/ingest', {
            method: 'POST',
            mode: 'no-cors',
            headers: { 'Content-Type': 'text/plain' },
            body: exitPayload,
            keepalive: true
          });
        } catch(e) {}
      }
    }

    function manualLeave() {
      triggerLeave();
      document.getElementById('statusBadge').className = 'badge-offline';
      document.getElementById('statusBadge').innerHTML = '● VISITOR DISCONNECTED / LEFT';
      document.getElementById('titleHeader').textContent = 'Session Closed (Left Website)';
      document.getElementById('descPara').textContent = 'You left the website. Check your SecOps dashboard now: active visitor count immediately updated to 0!';
      document.getElementById('onlineStatus').textContent = 'OFFLINE (LEFT)';
      document.getElementById('onlineStatus').style.color = '#f87171';
      document.getElementById('activeControls').style.display = 'none';
      document.getElementById('reconnectControls').style.display = 'block';
      document.getElementById('statusMsg').textContent = '✓ Sent SESSION_END beacon to dashboard';
    }

    function reconnect() {
      isConnected = true;
      document.getElementById('statusBadge').className = 'badge-online';
      document.getElementById('statusBadge').innerHTML = '<div class="pulse"></div>REAL-TIME VISITOR CONNECTED';
      document.getElementById('titleHeader').textContent = 'Live Telemetry Active';
      document.getElementById('descPara').textContent = 'Your device is streaming real telemetry to the SecOps dashboard.';
      document.getElementById('onlineStatus').textContent = 'ONLINE';
      document.getElementById('onlineStatus').style.color = '#34d399';
      document.getElementById('activeControls').style.display = 'block';
      document.getElementById('reconnectControls').style.display = 'none';
      sendHit(window.location.pathname, 200, 'PAGEVIEW', 'Rejoined website session');
      heartbeatTimer = setInterval(function() {
        if (isConnected && !document.hidden) {
          sendHit(window.location.pathname, 200, 'HEARTBEAT', 'Mobile visitor presence heartbeat');
        }
      }, 10000);
    }

    window.addEventListener('pagehide', triggerLeave);
    window.addEventListener('beforeunload', triggerLeave);
    document.addEventListener('visibilitychange', function() {
      if (document.visibilityState === 'hidden') {
        triggerLeave();
      } else if (document.visibilityState === 'visible' && !isConnected) {
        reconnect();
      }
    });

    fetch('${baseUrl}/api/collector/my-ip?targetId=' + encodeURIComponent('${targetId}') + '&visitorId=' + encodeURIComponent(visitorDeviceId))
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (d && d.isBlocked) {
          displayBlockScreen(d.blockedReason, d.ip || publicIp);
        }
        if (d && d.ip && d.ip !== '127.0.0.1' && d.ip !== '::1') {
          publicIp = d.ip;
          document.getElementById('ipVal').textContent = d.ip;
          sendHit(window.location.pathname, 200, 'PAGEVIEW', 'Live verified visit from ' + d.ip);
        } else {
          throw new Error('Fallback external');
        }
      })
      .catch(function() {
        fetch('https://api.ipify.org?format=json')
          .then(function(r) { return r.json(); })
          .then(function(d) {
            if (d && d.ip) {
              publicIp = d.ip;
              document.getElementById('ipVal').textContent = d.ip;
              sendHit(window.location.pathname, 200, 'PAGEVIEW', 'Live verified visit from ' + d.ip);
            } else {
              document.getElementById('ipVal').textContent = 'Direct Network IP';
              sendHit(window.location.pathname, 200, 'PAGEVIEW', 'Live device visit');
            }
          })
          .catch(function() {
            document.getElementById('ipVal').textContent = 'Direct Network IP';
            sendHit(window.location.pathname, 200, 'PAGEVIEW', 'Live device visit');
          });
      });
  </script>
</body>
</html>`);
  });

  // Clear events endpoint for target
  app.post('/api/collector/clear', (req, res) => {
    const { targetId } = req.body || {};
    if (targetId) {
      for (let i = realEventsBuffer.length - 1; i >= 0; i--) {
        if (realEventsBuffer[i].targetId === targetId || realEventsBuffer[i].targetId === 'target-atc-simulator' || realEventsBuffer[i].targetId === 'target-real-site' || realEventsBuffer[i].targetId === 'target-prod-site') {
          realEventsBuffer.splice(i, 1);
        }
      }
    } else {
      realEventsBuffer.length = 0;
    }
    // Broadcast clear event to all active SSE dashboards
    sseClients.forEach((client) => {
      client.res.write(`data: ${JSON.stringify({ type: 'CLEARED', targetId })}\n\n`);
    });
    res.json({ success: true, remaining: realEventsBuffer.length });
  });

  // SSE Stream for real-time live events
  app.get('/api/collector/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const clientId = `client-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const targetId = req.query.targetId as string;
    const client = { id: clientId, targetId, res };
    sseClients.push(client);

    res.write(`data: ${JSON.stringify({ type: 'CONNECTED', message: 'Real-time telemetry pipeline established', time: new Date().toISOString() })}\n\n`);

    const keepAlive = setInterval(() => {
      res.write(': keepalive\n\n');
    }, 15000);

    req.on('close', () => {
      clearInterval(keepAlive);
      sseClients = sseClients.filter((c) => c.id !== clientId);
    });
  });

  // Frontend mounting
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`EXTREME SecOps Server running on http://0.0.0.0:${PORT}`);
  });
}

createServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
