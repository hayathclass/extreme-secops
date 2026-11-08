import React, { useState, useRef, useEffect } from 'react';
import { Target } from '../types/security';
import { websiteUploadScanner, UploadScanResult } from '../services/websiteUploadScanner';
import { securityStore } from '../services/securityStore';
import {
  UploadCloud,
  FileArchive,
  FileCode,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  X,
  ArrowRight,
  Loader2,
  FileText,
  Key,
  Flame,
  Sparkles,
} from 'lucide-react';

interface UploadWebsiteModalProps {
  isOpen: boolean;
  onClose: () => void;
  onUploadApplied: (target: Target) => void;
}

export const UploadWebsiteModal: React.FC<UploadWebsiteModalProps> = ({
  isOpen,
  onClose,
  onUploadApplied,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState<string>('');
  const [scanResult, setScanResult] = useState<UploadScanResult | null>(null);
  const [websiteDomain, setWebsiteDomain] = useState('my-production-app.com');
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setScanResult(null);
      setIsScanning(false);
      setScanStep('');
    }
  }, [isOpen]);

  const handleClose = () => {
    setScanResult(null);
    setIsScanning(false);
    onClose();
  };

  if (!isOpen) return null;

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const processFiles = async (files: FileList | File[]) => {
    if (!files || files.length === 0) return;
    setIsScanning(true);
    setScanResult(null);

    try {
      const file = files[0];
      // Check if it is a ZIP archive
      if (file.name.toLowerCase().endsWith('.zip')) {
        setScanStep(`Unpacking archive ${file.name}...`);
        await new Promise((r) => setTimeout(r, 600));
        setScanStep('Running Static Application Security Testing (SAST) & Secret Scanner...');
        const result = await websiteUploadScanner.scanZipFile(
          file,
          websiteDomain.trim() || file.name.replace(/\.zip$/i, '')
        );
        setScanResult(result);
      } else {
        // Multi-file reading
        setScanStep(`Reading ${files.length} uploaded files...`);
        const fileDataList: { name: string; content: string; size: number }[] = [];
        for (let i = 0; i < files.length; i++) {
          const f = files[i];
          const text = await f.text();
          fileDataList.push({
            name: f.name,
            content: text,
            size: f.size,
          });
        }
        setScanStep('Analyzing source code for secrets, vulnerabilities, and server logs...');
        await new Promise((r) => setTimeout(r, 500));
        const result = await websiteUploadScanner.scanUploadedFiles(
          fileDataList,
          websiteDomain.trim() || 'uploaded-website.com'
        );
        setScanResult(result);
      }
    } catch (err: any) {
      console.error('Scan failed:', err);
      alert('Failed to process uploaded website: ' + (err.message || String(err)));
    } finally {
      setIsScanning(false);
      setScanStep('');
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFiles(e.dataTransfer.files);
    }
  };

  // Instant Sample Upload Test (for quick demo of real website audit)
  const handleLoadSampleWebsite = async () => {
    setIsScanning(true);
    setScanStep('Analyzing real e-commerce & API production website package...');
    await new Promise((r) => setTimeout(r, 800));

    const sampleFiles = [
      {
        name: 'src/api/auth.ts',
        content: `import express from 'express';
// Vulnerable hardcoded JWT Secret
const JWT_SECRET = "super_secret_production_key_12345";
export async function login(req, res) {
  const { username, password } = req.body;
  // Hardcoded test backdoor
  if (username === "admin" && password === "pass123") {
    return res.json({ token: JWT_SECRET });
  }
}`,
      },
      {
        name: 'src/db/users.ts',
        content: `import { db } from './connection';
// CRITICAL: Raw SQL injection concatenation
export async function findUserByEmail(email: string) {
  const query = "SELECT id, email, password_hash, role FROM users WHERE email = '" + email + "' LIMIT 1";
  return await db.query(query);
}`,
      },
      {
        name: 'src/components/UserProfile.tsx',
        content: `export function UserBio({ bioHtml }: { bioHtml: string }) {
  // HIGH: Unsanitized DOM XSS
  return <div dangerouslySetInnerHTML={{ __html: bioHtml }} />;
}`,
      },
      {
        name: '.env',
        content: `PORT=3000
DATABASE_URL=postgres://app_user:db_password_8899@production-db.internal:5432/main_db
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
OPENAI_API_KEY=sk-demo1234567890abcdef1234567890abcdef12345678`,
      },
      {
        name: 'logs/production-access.log',
        content: `198.51.100.199 - - [22/Oct/2026:10:14:02 -0700] "POST /api/v1/auth/login HTTP/1.1" 401 84 "-" "Python-requests/2.31.0"
198.51.100.199 - - [22/Oct/2026:10:14:03 -0700] "POST /api/v1/auth/login HTTP/1.1" 401 84 "-" "Python-requests/2.31.0"
198.51.100.199 - - [22/Oct/2026:10:14:04 -0700] "POST /api/v1/auth/login HTTP/1.1" 401 84 "-" "Python-requests/2.31.0"
198.51.100.199 - - [22/Oct/2026:10:14:05 -0700] "GET /api/v1/catalog?category=' OR '1'='1 HTTP/1.1" 500 240 "-" "sqlmap/1.7"
198.51.100.199 - - [22/Oct/2026:10:14:06 -0700] "GET /api/v1/download?file=../../etc/passwd HTTP/1.1" 404 120 "-" "curl/8.4"`,
      },
    ];

    const result = await websiteUploadScanner.scanUploadedFiles(sampleFiles, websiteDomain);
    setScanResult(result);
    setIsScanning(false);
    setScanStep('');
  };

  const handleApplyToDashboard = () => {
    if (!scanResult) return;
    const target = securityStore.applyScanResult(scanResult);
    securityStore.setActiveTarget(target.id);
    securityStore.toggleAutoStream(true);
    onUploadApplied(target);
    setScanResult(null);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-fade-in font-sans">
      <div className="bg-[#0f172a] border border-slate-700 w-full max-w-3xl rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-md">
              <UploadCloud className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-bold text-slate-100">Upload Real-Time Website & Logs</h2>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 font-bold border border-cyan-800">
                  DEEP SECURITY SCAN
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Upload your website ZIP archive, source files, or server access logs to uncover real vulnerabilities and attacks
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {/* Target Hostname Input */}
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5">
              Website Domain / Name:
            </label>
            <input
              type="text"
              value={websiteDomain}
              onChange={(e) => setWebsiteDomain(e.target.value)}
              placeholder="e.g. my-production-website.com"
              className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 placeholder-slate-500 text-sm font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>

          {!scanResult && !isScanning && (
            <>
              {/* Drag and Drop Zone */}
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-2xl p-8 text-center cursor-pointer transition flex flex-col items-center justify-center space-y-3 ${
                  dragActive
                    ? 'border-cyan-400 bg-cyan-950/20 shadow-lg shadow-cyan-950/50'
                    : 'border-slate-700 bg-slate-900/60 hover:border-cyan-500/50 hover:bg-slate-900'
                }`}
              >
                <div className="w-14 h-14 rounded-2xl bg-cyan-950/80 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <FileArchive className="w-7 h-7" />
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-bold text-slate-200">
                    Drag and drop your website <span className="text-cyan-400">.ZIP</span> or files here
                  </div>
                  <p className="text-xs text-slate-400">
                    Supports <span className="font-mono text-slate-300">.zip</span>, source code (JS, TS, HTML, PHP,
                    Python, .env), and server access logs (<span className="font-mono text-slate-300">.log, .csv, .json</span>)
                  </p>
                </div>
                <div className="flex flex-wrap items-center justify-center gap-2.5 pt-1">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      fileInputRef.current?.click();
                    }}
                    className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition shadow-sm flex items-center space-x-1.5"
                  >
                    <UploadCloud className="w-4 h-4" />
                    <span>Upload ZIP File</span>
                  </button>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      fileInputRef.current?.click();
                    }}
                    className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold border border-slate-700 transition"
                  >
                    Browse Files from Computer
                  </button>
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  accept=".zip,.html,.htm,.js,.ts,.jsx,.tsx,.php,.py,.json,.env,.log,.txt,.csv"
                  onChange={(e) => {
                    if (e.target.files) processFiles(e.target.files);
                  }}
                  className="hidden"
                />
              </div>

              {/* Sample Quick Demo Card */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/40 to-slate-900 border border-cyan-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center space-x-3">
                  <Sparkles className="w-5 h-5 text-cyan-400 shrink-0" />
                  <div>
                    <span className="text-xs font-bold text-slate-200 block">Don't have a ZIP file ready?</span>
                    <span className="text-[11px] text-slate-400">
                      Load a realistic production website package (contains live code with SQLi, XSS, leaked keys, and real attack logs).
                    </span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleLoadSampleWebsite}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs whitespace-nowrap transition shadow-sm"
                >
                  Load Sample Website
                </button>
              </div>
            </>
          )}

          {/* Scanning Progress */}
          {isScanning && (
            <div className="py-12 text-center space-y-4">
              <Loader2 className="w-10 h-10 animate-spin text-cyan-400 mx-auto" />
              <div className="space-y-1">
                <h3 className="text-sm font-bold text-slate-100">Scanning Uploaded Website...</h3>
                <p className="text-xs font-mono text-cyan-400">{scanStep}</p>
              </div>
              <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
                Parsing files, checking for SQLi, XSS DOM sinks, path traversals, exposed cloud credentials, and attack log signatures.
              </p>
            </div>
          )}

          {/* Scan Results View */}
          {scanResult && (
            <div className="space-y-5 animate-fade-in font-sans">
              {/* Action Bar when results are showing */}
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <span className="text-xs font-bold text-slate-200 block">
                    Security Audit for <span className="font-mono text-cyan-400">{scanResult.targetName}</span>
                  </span>
                  <span className="text-[11px] text-slate-400">
                    Want to test your real production codebase or website archive instead?
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setScanResult(null);
                    setTimeout(() => fileInputRef.current?.click(), 100);
                  }}
                  className="px-4 py-2 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold flex items-center space-x-1.5 transition shrink-0"
                >
                  <UploadCloud className="w-4 h-4 text-cyan-400" />
                  <span>Upload ZIP File</span>
                </button>
              </div>

              {/* Scorecard Header */}
              <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-center space-x-4">
                  <div
                    className={`w-14 h-14 rounded-2xl flex items-center justify-center text-2xl font-extrabold font-mono border-2 shadow-lg ${
                      scanResult.securityGrade === 'A+' || scanResult.securityGrade === 'A'
                        ? 'bg-emerald-950/60 text-emerald-400 border-emerald-500'
                        : scanResult.securityGrade === 'B'
                        ? 'bg-cyan-950/60 text-cyan-400 border-cyan-500'
                        : scanResult.securityGrade === 'C'
                        ? 'bg-amber-950/60 text-amber-400 border-amber-500'
                        : 'bg-rose-950/60 text-rose-400 border-rose-500'
                    }`}
                  >
                    {scanResult.securityGrade}
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-slate-100">
                      Security Audit Score: <span className="font-mono text-cyan-400">{scanResult.securityScore}/100</span>
                    </h3>
                    <p className="text-xs text-slate-400 font-mono">
                      Scanned {scanResult.totalFilesScanned} files ({scanResult.totalLinesScanned} lines of code)
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3 text-xs font-mono">
                  <div className="px-3 py-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 font-bold">
                    {scanResult.criticalCount} Critical
                  </div>
                  <div className="px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 font-bold">
                    {scanResult.highCount} High
                  </div>
                  {scanResult.parsedLogs.length > 0 ? (
                    <div className="px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-bold">
                      {scanResult.parsedLogs.length} Real Logs Ingested
                    </div>
                  ) : (
                    <div className="px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-bold">
                      Real-Time Telemetry Ready
                    </div>
                  )}
                </div>
              </div>

              {/* Real Telemetry Assurance Notice */}
              <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex items-center space-x-2.5 text-xs text-emerald-300">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shrink-0" />
                <span>
                  <strong>Real Target Mode:</strong> Telemetry will only stream authentic requests from your live website visitors or server probes. Synthetic fake logs are disabled.
                </span>
              </div>

              {/* Findings List */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    Identified Vulnerabilities & Risks ({scanResult.findings.length})
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      setScanResult(null);
                      setTimeout(() => fileInputRef.current?.click(), 100);
                    }}
                    className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center space-x-1"
                  >
                    <UploadCloud className="w-3.5 h-3.5" />
                    <span>Upload ZIP File</span>
                  </button>
                </div>

                <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
                  {scanResult.findings.map((finding) => (
                    <div
                      key={finding.id}
                      className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5 text-xs font-mono"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              finding.severity === 'CRITICAL'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                : finding.severity === 'HIGH'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                            }`}
                          >
                            {finding.severity}
                          </span>
                          <span className="font-bold text-slate-200 font-sans">{finding.title}</span>
                        </div>
                        <span className="text-slate-400 text-[11px] truncate max-w-[200px]">{finding.file}</span>
                      </div>

                      <p className="text-slate-300 font-sans text-xs">{finding.description}</p>

                      {finding.snippet && (
                        <div className="p-2 rounded bg-black/60 border border-slate-800 text-[11px] text-rose-300 truncate">
                          Code: {finding.snippet}
                        </div>
                      )}

                      <div className="text-[11px] text-cyan-300 font-sans">
                        <span className="font-bold text-slate-400">Fix: </span>
                        {finding.recommendation}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-[#090d14] flex items-center justify-between">
          <button
            type="button"
            onClick={handleClose}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 transition"
          >
            Close
          </button>

          {scanResult && (
            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => {
                  setScanResult(null);
                  setTimeout(() => fileInputRef.current?.click(), 100);
                }}
                className="px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-bold flex items-center space-x-1.5 transition"
              >
                <UploadCloud className="w-4 h-4 text-cyan-400" />
                <span>Upload ZIP File</span>
              </button>

              <button
                type="button"
                onClick={handleApplyToDashboard}
                className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center space-x-2 transition shadow-lg shadow-cyan-950"
              >
                <span>Monitor Website on Dashboard</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
