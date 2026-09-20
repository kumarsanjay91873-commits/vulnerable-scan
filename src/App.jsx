import { useState, useEffect, useRef, useCallback } from "react";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  LineChart, Line, ResponsiveContainer, CartesianGrid, Legend
} from "recharts";

// ── palette ──────────────────────────────────────────────────────────────────
const C = {
  bg: "#0A0E1A", card: "#111827", card2: "#1a2235",
  border: "#1e3a5f", cyan: "#00D4FF", amber: "#FF6B35",
  green: "#00FF88", purple: "#A855F7", red: "#FF3B3B",
  yellow: "#FFD700", text: "#E2E8F0", muted: "#64748B",
  critical: "#FF3B3B", high: "#FF6B35", medium: "#FFD700",
  low: "#00FF88", info: "#00D4FF",
};

// ── mock scan data generator ──────────────────────────────────────────────────
const COMMON_PORTS = [
  { port: 21, service: "FTP", protocol: "TCP" },
  { port: 22, service: "SSH", protocol: "TCP" },
  { port: 23, service: "Telnet", protocol: "TCP" },
  { port: 25, service: "SMTP", protocol: "TCP" },
  { port: 53, service: "DNS", protocol: "UDP" },
  { port: 80, service: "HTTP", protocol: "TCP" },
  { port: 110, service: "POP3", protocol: "TCP" },
  { port: 143, service: "IMAP", protocol: "TCP" },
  { port: 443, service: "HTTPS", protocol: "TCP" },
  { port: 445, service: "SMB", protocol: "TCP" },
  { port: 3306, service: "MySQL", protocol: "TCP" },
  { port: 3389, service: "RDP", protocol: "TCP" },
  { port: 5432, service: "PostgreSQL", protocol: "TCP" },
  { port: 6379, service: "Redis", protocol: "TCP" },
  { port: 8080, service: "HTTP-Alt", protocol: "TCP" },
];

const VERSION_DB = {
  "Apache": { detected: "2.4.49", latest: "2.4.58", risk: "CRITICAL", cve: "CVE-2021-41773" },
  "nginx": { detected: "1.16.1", latest: "1.25.3", risk: "HIGH", cve: "CVE-2021-23017" },
  "OpenSSH": { detected: "7.2p2", latest: "9.5p1", risk: "HIGH", cve: "CVE-2016-6210" },
  "MySQL": { detected: "5.7.32", latest: "8.2.0", risk: "MEDIUM", cve: "CVE-2021-2307" },
  "Redis": { detected: "5.0.6", latest: "7.2.3", risk: "HIGH", cve: "CVE-2022-0543" },
};

const HEADERS_DB = [
  { header: "Content-Security-Policy", present: false, risk: "HIGH", desc: "Prevents XSS and injection attacks" },
  { header: "Strict-Transport-Security", present: false, risk: "HIGH", desc: "Enforces HTTPS connections" },
  { header: "X-Frame-Options", present: true, value: "SAMEORIGIN", risk: "LOW", desc: "Prevents clickjacking" },
  { header: "X-Content-Type-Options", present: true, value: "nosniff", risk: "LOW", desc: "Prevents MIME sniffing" },
  { header: "Referrer-Policy", present: false, risk: "MEDIUM", desc: "Controls referrer information" },
  { header: "Permissions-Policy", present: false, risk: "MEDIUM", desc: "Controls browser features" },
];

function generateScanResults(target) {
  const seed = target.length;
  const openPorts = COMMON_PORTS.filter((_, i) => {
    const vals = [0,1,3,5,8,10,14]; // deterministic "open" ports
    return vals.includes(i);
  }).map(p => ({ ...p, state: "OPEN", banner: getBanner(p.service) }));

  const closedPorts = COMMON_PORTS.filter((_, i) => ![0,1,3,5,8,10,14].includes(i))
    .map(p => ({ ...p, state: "CLOSED", banner: null }));

  return {
    target,
    scanDate: new Date().toISOString(),
    ports: [...openPorts, ...closedPorts],
    services: openPorts.map(p => ({
      port: p.port, service: p.service, version: getVersion(p.service), banner: p.banner
    })),
    versions: Object.entries(VERSION_DB).map(([name, data]) => ({ name, ...data })),
    headers: HEADERS_DB,
    ssl: {
      valid: true, issuer: "Let's Encrypt", expiry: "2024-03-15",
      tlsVersion: "TLS 1.1", ciphers: ["RC4-SHA", "DES-CBC3-SHA"],
      score: 42, expired: true, weakCiphers: true,
    },
    webChecks: [
      { check: "Directory Listing", status: "ENABLED", risk: "MEDIUM", detail: "/uploads/ index exposed" },
      { check: "Default Page", status: "DETECTED", risk: "LOW", detail: "Apache default welcome page" },
      { check: "Server Header", status: "EXPOSED", risk: "MEDIUM", detail: "Server: Apache/2.4.49 (Ubuntu)" },
      { check: "X-Powered-By", status: "EXPOSED", risk: "MEDIUM", detail: "X-Powered-By: PHP/7.2.24" },
      { check: "robots.txt", status: "FOUND", risk: "INFO", detail: "Sensitive: /admin, /backup, /private" },
      { check: "Anonymous FTP", status: "ALLOWED", risk: "CRITICAL", detail: "FTP port 21 accepts anonymous login" },
      { check: "Open Redis Port", status: "EXPOSED", risk: "CRITICAL", detail: "Redis 6379 accessible without auth" },
    ],
    riskScore: 72,
    findings: generateFindings(),
  };
}

function getBanner(service) {
  const banners = {
    "FTP": "220 vsftpd 3.0.3", "SSH": "SSH-2.0-OpenSSH_7.2p2",
    "SMTP": "220 mail.example.com ESMTP Postfix", "DNS": "BIND 9.11.4",
    "HTTP": "Apache/2.4.49 (Ubuntu)", "HTTP-Alt": "nginx/1.16.1",
    "Telnet": "Red Hat Linux release 6.2 (Zoot)",
  };
  return banners[service] || `${service} service banner`;
}

function getVersion(service) {
  const vers = {
    "FTP": "vsftpd 3.0.3", "SSH": "OpenSSH 7.2p2", "SMTP": "Postfix 3.4.13",
    "DNS": "BIND 9.11.4", "HTTP": "Apache 2.4.49", "HTTP-Alt": "nginx 1.16.1",
    "Telnet": "telnetd 0.17",
  };
  return vers[service] || "Unknown";
}

function generateFindings() {
  return [
    { id: 1, category: "Network", severity: "CRITICAL", description: "Anonymous FTP login allowed on port 21", recommendation: "Disable anonymous FTP access immediately. Require authentication for all FTP connections." },
    { id: 2, category: "Network", severity: "CRITICAL", description: "Redis exposed on port 6379 without authentication", recommendation: "Bind Redis to localhost only. Enable AUTH with a strong password. Use firewall rules." },
    { id: 3, category: "Version", severity: "CRITICAL", description: "Apache 2.4.49 vulnerable to CVE-2021-41773 (Path Traversal + RCE)", recommendation: "Upgrade Apache immediately to version 2.4.58 or later." },
    { id: 4, category: "SSL/TLS", severity: "HIGH", description: "SSL certificate expired on 2024-03-15", recommendation: "Renew SSL certificate immediately. Configure auto-renewal with Let's Encrypt." },
    { id: 5, category: "SSL/TLS", severity: "HIGH", description: "TLS 1.1 and weak ciphers (RC4, 3DES) in use", recommendation: "Disable TLS 1.0/1.1. Configure only TLS 1.2+ with strong cipher suites." },
    { id: 6, category: "Version", severity: "HIGH", description: "OpenSSH 7.2p2 vulnerable to user enumeration (CVE-2016-6210)", recommendation: "Upgrade OpenSSH to version 9.5p1. Apply security patches." },
    { id: 7, category: "Headers", severity: "HIGH", description: "Missing Content-Security-Policy header", recommendation: "Implement a strict CSP: Content-Security-Policy: default-src 'self'" },
    { id: 8, category: "Headers", severity: "HIGH", description: "Missing Strict-Transport-Security (HSTS) header", recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" },
    { id: 9, category: "Web", severity: "MEDIUM", description: "Directory listing enabled on /uploads/", recommendation: "Disable directory listing in Apache: Options -Indexes" },
    { id: 10, category: "Web", severity: "MEDIUM", description: "Server version disclosed in HTTP headers", recommendation: "Set ServerTokens Prod in Apache config to hide version information." },
    { id: 11, category: "Network", severity: "MEDIUM", description: "Telnet service running on port 23 (unencrypted)", recommendation: "Disable Telnet. Use SSH for all remote access." },
    { id: 12, category: "Web", severity: "LOW", description: "Apache default welcome page detected", recommendation: "Remove or replace default page with production content." },
  ];
}

// ── severity helpers ──────────────────────────────────────────────────────────
const SEV_COLOR = { CRITICAL: C.critical, HIGH: C.high, MEDIUM: C.yellow, LOW: C.green, INFO: C.cyan };
const SEV_SCORE = { CRITICAL: 10, HIGH: 8, MEDIUM: 5, LOW: 2, INFO: 0 };

// ── small components ──────────────────────────────────────────────────────────
function Badge({ sev }) {
  const color = SEV_COLOR[sev] || C.muted;
  return (
    <span style={{
      background: color + "22", color, border: `1px solid ${color}55`,
      borderRadius: 4, padding: "2px 8px", fontSize: 11, fontWeight: 700,
      letterSpacing: 1, fontFamily: "monospace"
    }}>{sev}</span>
  );
}

function StatCard({ label, value, sub, color = C.cyan, icon }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`, borderRadius: 12,
      padding: "20px 24px", flex: 1, minWidth: 140,
    }}>
      <div style={{ color: C.muted, fontSize: 12, fontWeight: 600, letterSpacing: 1, marginBottom: 8, textTransform: "uppercase" }}>
        {icon} {label}
      </div>
      <div style={{ color, fontSize: 36, fontWeight: 800, fontFamily: "monospace", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ color: C.muted, fontSize: 12, marginTop: 6 }}>{sub}</div>}
    </div>
  );
}

// ── Radar pulse animation ────────────────────────────────────────────────────
function RadarPulse({ scanning }) {
  return (
    <div style={{ position: "relative", width: 48, height: 48, flexShrink: 0 }}>
      <svg width="48" height="48" viewBox="0 0 48 48">
        <circle cx="24" cy="24" r="20" fill="none" stroke={C.border} strokeWidth="1.5" />
        <circle cx="24" cy="24" r="13" fill="none" stroke={C.border} strokeWidth="1" />
        <circle cx="24" cy="24" r="6" fill="none" stroke={C.border} strokeWidth="1" />
        {scanning && (
          <>
            <line x1="24" y1="24" x2="44" y2="24" stroke={C.cyan} strokeWidth="1.5"
              style={{ transformOrigin: "24px 24px", animation: "spin 1.5s linear infinite" }} />
            <circle cx="24" cy="24" r="2" fill={C.cyan} />
          </>
        )}
        {!scanning && <circle cx="24" cy="24" r="2" fill={C.muted} />}
      </svg>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        line { transform-origin: 24px 24px; animation: spin 1.5s linear infinite; }`}
      </style>
    </div>
  );
}

// ── Scan log terminal ─────────────────────────────────────────────────────────
function ScanLog({ lines }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines]);
  return (
    <div ref={ref} style={{
      background: "#050810", border: `1px solid ${C.border}`, borderRadius: 8,
      padding: 16, fontFamily: "monospace", fontSize: 13, color: C.green,
      height: 220, overflowY: "auto", lineHeight: 1.7
    }}>
      {lines.map((l, i) => (
        <div key={i} style={{ color: l.startsWith("[WARN]") ? C.yellow : l.startsWith("[CRIT]") ? C.red : l.startsWith("[INFO]") ? C.cyan : C.green }}>
          {l}
        </div>
      ))}
      {lines.length === 0 && <span style={{ color: C.muted }}>$ awaiting scan target...</span>}
    </div>
  );
}

// ── MAIN APP ─────────────────────────────────────────────────────────────────
export default function VulnerabilityScanner() {
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logLines, setLogLines] = useState([]);
  const [results, setResults] = useState(null);
  const [tab, setTab] = useState("overview");
  const [history, setHistory] = useState([
    { target: "192.168.1.1", date: "2025-06-10", score: 55, findings: 8 },
    { target: "testphp.vulnweb.com", date: "2025-06-12", score: 81, findings: 14 },
    { target: "demo.testfire.net", date: "2025-06-14", score: 67, findings: 11 },
  ]);

  const addLog = useCallback((line) => setLogLines(prev => [...prev, line]), []);

  async function runScan() {
    if (!target.trim()) return;
    setScanning(true);
    setResults(null);
    setProgress(0);
    setLogLines([]);
    setTab("overview");

    const steps = [
      { p: 5,  msg: `[INFO] Initializing scan engine for target: ${target}` },
      { p: 10, msg: "[INFO] Resolving hostname..." },
      { p: 15, msg: "[INFO] Starting TCP port scan (15 common ports)..." },
      { p: 25, msg: "[INFO] Port 21/TCP OPEN - FTP (vsftpd 3.0.3)" },
      { p: 30, msg: "[INFO] Port 22/TCP OPEN - SSH (OpenSSH 7.2p2)" },
      { p: 33, msg: "[INFO] Port 23/TCP OPEN - Telnet" },
      { p: 36, msg: "[WARN] Port 23 Telnet is unencrypted — HIGH RISK" },
      { p: 40, msg: "[INFO] Port 80/TCP OPEN - HTTP (Apache/2.4.49)" },
      { p: 43, msg: "[CRIT] Apache 2.4.49 detected — CVE-2021-41773 Path Traversal + RCE" },
      { p: 47, msg: "[INFO] Port 443/TCP OPEN - HTTPS" },
      { p: 50, msg: "[INFO] Analyzing SSL/TLS certificate..." },
      { p: 53, msg: "[WARN] TLS 1.1 detected — deprecated protocol" },
      { p: 56, msg: "[CRIT] SSL certificate EXPIRED (2024-03-15)" },
      { p: 60, msg: "[INFO] Scanning HTTP security headers..." },
      { p: 63, msg: "[WARN] Missing: Content-Security-Policy" },
      { p: 66, msg: "[WARN] Missing: Strict-Transport-Security (HSTS)" },
      { p: 70, msg: "[INFO] Checking web application security..." },
      { p: 73, msg: "[WARN] Directory listing ENABLED on /uploads/" },
      { p: 76, msg: "[CRIT] Anonymous FTP login ALLOWED on port 21" },
      { p: 80, msg: "[CRIT] Redis port 6379 exposed WITHOUT authentication" },
      { p: 85, msg: "[INFO] Checking robots.txt..." },
      { p: 88, msg: "[WARN] Sensitive paths in robots.txt: /admin, /backup" },
      { p: 92, msg: "[INFO] Running version vulnerability database comparison..." },
      { p: 96, msg: "[INFO] Calculating risk score..." },
      { p: 99, msg: "[WARN] Risk Score: 72/100 — HIGH RISK" },
      { p: 100, msg: "[INFO] Scan complete. 12 findings identified." },
    ];

    for (const step of steps) {
      await new Promise(r => setTimeout(r, 130 + Math.random() * 100));
      setProgress(step.p);
      addLog(step.msg);
    }

    const res = generateScanResults(target);
    setResults(res);
    setHistory(prev => [{ target, date: new Date().toISOString().slice(0, 10), score: res.riskScore, findings: res.findings.length }, ...prev.slice(0, 4)]);
    setScanning(false);
  }

  const tabs = [
    { id: "overview", label: "📊 Overview" },
    { id: "ports", label: "🔌 Ports" },
    { id: "versions", label: "📦 Versions" },
    { id: "headers", label: "🛡 Headers" },
    { id: "ssl", label: "🔒 SSL/TLS" },
    { id: "web", label: "🌐 Web Checks" },
    { id: "findings", label: "⚠️ Findings" },
    { id: "history", label: "📈 History" },
  ];

  return (
    <div style={{ background: C.bg, minHeight: "100vh", color: C.text, fontFamily: "'Inter', system-ui, sans-serif" }}>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 3px; }
        input { outline: none; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.4; } }
        @keyframes scanline { from { top: 0; } to { top: 100%; } }
      `}</style>

      {/* Header */}
      <div style={{ background: C.card, borderBottom: `1px solid ${C.border}`, padding: "16px 32px", display: "flex", alignItems: "center", gap: 16 }}>
        <RadarPulse scanning={scanning} />
        <div>
          <div style={{ color: C.cyan, fontWeight: 800, fontSize: 20, letterSpacing: 1, fontFamily: "monospace" }}>
            VULNSCAN <span style={{ color: C.muted, fontSize: 13, fontWeight: 400 }}>v2.0</span>
          </div>
          <div style={{ color: C.muted, fontSize: 12 }}>Ethical Vulnerability Assessment Platform</div>
        </div>
        <div style={{ marginLeft: "auto", background: "#0a1a0a", border: `1px solid ${C.green}33`, borderRadius: 6, padding: "4px 12px", fontSize: 12, color: C.green, fontFamily: "monospace" }}>
          ● PASSIVE MODE — Authorized Scanning Only
        </div>
      </div>

      <div style={{ padding: "24px 32px", maxWidth: 1400, margin: "0 auto" }}>
        {/* Target Input */}
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 24, marginBottom: 24 }}>
          <div style={{ color: C.muted, fontSize: 12, fontWeight: 600, letterSpacing: 1, marginBottom: 12, textTransform: "uppercase" }}>Target</div>
          <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <input
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !scanning && runScan()}
              placeholder="e.g. example.com or 192.168.1.1"
              style={{
                flex: 1, minWidth: 280, background: "#050810", border: `1px solid ${scanning ? C.cyan : C.border}`,
                borderRadius: 8, padding: "12px 16px", color: C.text, fontSize: 15, fontFamily: "monospace",
                transition: "border-color 0.3s", boxShadow: scanning ? `0 0 12px ${C.cyan}33` : "none"
              }}
            />
            {["--ports", "--web", "--ssl", "--full"].map(flag => (
              <button key={flag} onClick={() => !scanning && runScan()} style={{
                background: C.card2, border: `1px solid ${C.border}`, borderRadius: 6, padding: "8px 14px",
                color: C.muted, fontSize: 12, fontFamily: "monospace", cursor: "pointer"
              }}>{flag}</button>
            ))}
            <button onClick={runScan} disabled={scanning || !target.trim()} style={{
              background: scanning ? C.card2 : `linear-gradient(135deg, ${C.cyan}cc, ${C.purple}cc)`,
              border: "none", borderRadius: 8, padding: "12px 28px", color: scanning ? C.muted : "#000",
              fontSize: 14, fontWeight: 700, cursor: scanning ? "not-allowed" : "pointer",
              transition: "all 0.2s", letterSpacing: 0.5
            }}>
              {scanning ? "⟳ Scanning..." : "▶ Run Scan"}
            </button>
          </div>

          {/* Progress bar */}
          {(scanning || progress > 0) && (
            <div style={{ marginTop: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                <span style={{ color: C.muted, fontSize: 12, fontFamily: "monospace" }}>
                  {scanning ? "Scanning..." : "Scan Complete"}
                </span>
                <span style={{ color: C.cyan, fontSize: 12, fontFamily: "monospace" }}>{progress}%</span>
              </div>
              <div style={{ background: C.card2, borderRadius: 4, height: 6, overflow: "hidden" }}>
                <div style={{
                  width: `${progress}%`, height: "100%",
                  background: `linear-gradient(90deg, ${C.cyan}, ${C.purple})`,
                  transition: "width 0.2s", borderRadius: 4
                }} />
              </div>
            </div>
          )}
        </div>

        {/* Scan Log */}
        {(logLines.length > 0 || scanning) && (
          <div style={{ marginBottom: 24 }}>
            <div style={{ color: C.muted, fontSize: 12, fontWeight: 600, letterSpacing: 1, marginBottom: 8, textTransform: "uppercase" }}>Scan Output</div>
            <ScanLog lines={logLines} />
          </div>
        )}

        {/* Results */}
        {results && (
          <>
            {/* Tabs */}
            <div style={{ display: "flex", gap: 4, marginBottom: 20, overflowX: "auto", paddingBottom: 4 }}>
              {tabs.map(t => (
                <button key={t.id} onClick={() => setTab(t.id)} style={{
                  background: tab === t.id ? `${C.cyan}22` : "transparent",
                  border: `1px solid ${tab === t.id ? C.cyan : C.border}`,
                  borderRadius: 8, padding: "8px 16px", color: tab === t.id ? C.cyan : C.muted,
                  fontSize: 13, cursor: "pointer", whiteSpace: "nowrap", fontWeight: tab === t.id ? 600 : 400
                }}>{t.label}</button>
              ))}
            </div>

            {/* Overview */}
            {tab === "overview" && <OverviewTab results={results} />}
            {tab === "ports" && <PortsTab results={results} />}
            {tab === "versions" && <VersionsTab results={results} />}
            {tab === "headers" && <HeadersTab results={results} />}
            {tab === "ssl" && <SSLTab results={results} />}
            {tab === "web" && <WebTab results={results} />}
            {tab === "findings" && <FindingsTab results={results} />}
            {tab === "history" && <HistoryTab history={history} />}
          </>
        )}

        {!results && !scanning && (
          <div style={{ textAlign: "center", padding: "80px 40px", color: C.muted }}>
            <div style={{ fontSize: 64, marginBottom: 16 }}>🎯</div>
            <div style={{ fontSize: 18, fontWeight: 600, color: C.text, marginBottom: 8 }}>Ready to scan</div>
            <div style={{ fontSize: 14 }}>Enter a target hostname or IP address above to begin vulnerability assessment</div>
            <div style={{ marginTop: 24, padding: "12px 20px", background: "#1a0a0a", border: `1px solid ${C.amber}33`, borderRadius: 8, display: "inline-block", fontSize: 13, color: C.amber }}>
              ⚠ Only scan systems you own or have explicit written authorization to test
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tab: Overview ─────────────────────────────────────────────────────────────
function OverviewTab({ results }) {
  const open = results.ports.filter(p => p.state === "OPEN").length;
  const critical = results.findings.filter(f => f.severity === "CRITICAL").length;
  const high = results.findings.filter(f => f.severity === "HIGH").length;

  const sevData = ["CRITICAL","HIGH","MEDIUM","LOW"].map(s => ({
    name: s, value: results.findings.filter(f => f.severity === s).length, color: SEV_COLOR[s]
  })).filter(d => d.value > 0);

  const catData = [...new Set(results.findings.map(f => f.category))].map(cat => ({
    name: cat, count: results.findings.filter(f => f.category === cat).length
  }));

  const scoreColor = results.riskScore >= 70 ? C.critical : results.riskScore >= 40 ? C.yellow : C.green;

  return (
    <div>
      {/* Score + Stats */}
      <div style={{ display: "flex", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
        {/* Risk Score Gauge */}
        <div style={{
          background: C.card, border: `2px solid ${scoreColor}55`, borderRadius: 12,
          padding: "24px 32px", display: "flex", flexDirection: "column", alignItems: "center", minWidth: 180
        }}>
          <div style={{ color: C.muted, fontSize: 12, letterSpacing: 1, textTransform: "uppercase", marginBottom: 12 }}>Risk Score</div>
          <div style={{ color: scoreColor, fontSize: 56, fontWeight: 900, fontFamily: "monospace", lineHeight: 1 }}>{results.riskScore}</div>
          <div style={{ color: C.muted, fontSize: 14, marginBottom: 8 }}>/100</div>
          <div style={{ background: scoreColor + "22", color: scoreColor, padding: "4px 12px", borderRadius: 20, fontSize: 12, fontWeight: 700 }}>
            {results.riskScore >= 70 ? "HIGH RISK" : results.riskScore >= 40 ? "MEDIUM RISK" : "LOW RISK"}
          </div>
        </div>

        <StatCard label="Open Ports" value={open} sub={`of ${results.ports.length} scanned`} color={C.cyan} icon="🔌" />
        <StatCard label="Services" value={results.services.length} sub="detected" color={C.purple} icon="⚙️" />
        <StatCard label="Critical" value={critical} sub="immediate action" color={C.critical} icon="🚨" />
        <StatCard label="High" value={high} sub="urgent review" color={C.high} icon="⚠️" />
        <StatCard label="Total Findings" value={results.findings.length} sub="vulnerabilities" color={C.yellow} icon="📋" />
      </div>

      {/* Charts */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, marginBottom: 24 }}>
        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>Findings by Severity</div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={sevData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, value }) => `${name}: ${value}`} labelLine={false}>
                {sevData.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: C.card2, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
          <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>Findings by Category</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={catData}>
              <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
              <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 12 }} />
              <YAxis tick={{ fill: C.muted, fontSize: 12 }} />
              <Tooltip contentStyle={{ background: C.card2, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
              <Bar dataKey="count" fill={C.cyan} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top critical findings preview */}
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 16, fontSize: 14 }}>🚨 Critical & High Priority Findings</div>
        {results.findings.filter(f => ["CRITICAL","HIGH"].includes(f.severity)).map(f => (
          <div key={f.id} style={{
            display: "flex", alignItems: "flex-start", gap: 12, padding: "12px 0",
            borderBottom: `1px solid ${C.border}55`
          }}>
            <Badge sev={f.severity} />
            <div>
              <div style={{ fontSize: 14, fontWeight: 500, marginBottom: 4 }}>{f.description}</div>
              <div style={{ fontSize: 12, color: C.muted }}>{f.category}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Tab: Ports ────────────────────────────────────────────────────────────────
function PortsTab({ results }) {
  const [filter, setFilter] = useState("ALL");
  const filtered = filter === "ALL" ? results.ports : results.ports.filter(p => p.state === filter);
  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {["ALL","OPEN","CLOSED"].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            background: filter === f ? `${C.cyan}22` : C.card, border: `1px solid ${filter === f ? C.cyan : C.border}`,
            borderRadius: 6, padding: "6px 16px", color: filter === f ? C.cyan : C.muted,
            fontSize: 13, cursor: "pointer"
          }}>{f}</button>
        ))}
      </div>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "monospace", fontSize: 13 }}>
          <thead>
            <tr style={{ background: C.card2, color: C.muted, fontSize: 11, letterSpacing: 1, textTransform: "uppercase" }}>
              {["Port", "Protocol", "State", "Service", "Banner"].map(h => (
                <th key={h} style={{ padding: "12px 16px", textAlign: "left" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((p, i) => (
              <tr key={p.port} style={{ borderTop: `1px solid ${C.border}33`, background: i % 2 === 0 ? "transparent" : C.card2 + "44" }}>
                <td style={{ padding: "10px 16px", color: C.cyan, fontWeight: 700 }}>{p.port}</td>
                <td style={{ padding: "10px 16px", color: C.muted }}>{p.protocol}</td>
                <td style={{ padding: "10px 16px" }}>
                  <span style={{ color: p.state === "OPEN" ? C.green : C.muted, fontWeight: p.state === "OPEN" ? 700 : 400 }}>
                    {p.state === "OPEN" ? "● OPEN" : "○ CLOSED"}
                  </span>
                </td>
                <td style={{ padding: "10px 16px", color: C.text }}>{p.service}</td>
                <td style={{ padding: "10px 16px", color: C.muted, fontSize: 12 }}>{p.banner || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Tab: Versions ─────────────────────────────────────────────────────────────
function VersionsTab({ results }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {results.versions.map(v => (
        <div key={v.name} style={{ background: C.card, border: `1px solid ${SEV_COLOR[v.risk]}44`, borderRadius: 12, padding: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <span style={{ fontWeight: 700, fontSize: 16 }}>{v.name}</span>
            <Badge sev={v.risk} />
            <span style={{ marginLeft: "auto", fontSize: 12, color: C.muted, fontFamily: "monospace" }}>{v.cve}</span>
          </div>
          <div style={{ display: "flex", gap: 32 }}>
            <div>
              <div style={{ color: C.muted, fontSize: 11, marginBottom: 4, textTransform: "uppercase", letterSpacing: 1 }}>Detected</div>
              <div style={{ color: C.red, fontFamily: "monospace", fontSize: 15, fontWeight: 600 }}>{v.detected}</div>
            </div>
            <div style={{ color: C.muted, alignSelf: "center", fontSize: 20 }}>→</div>
            <div>
              <div style={{ color: C.muted, fontSize: 11, marginBottom: 4, textTransform: "uppercase", letterSpacing: 1 }}>Latest</div>
              <div style={{ color: C.green, fontFamily: "monospace", fontSize: 15, fontWeight: 600 }}>{v.latest}</div>
            </div>
          </div>
          <div style={{ marginTop: 12, padding: "8px 12px", background: "#0a1a0a", borderRadius: 6, fontSize: 13, color: C.muted }}>
            💡 Upgrade {v.name} from <span style={{ color: C.red }}>{v.detected}</span> to <span style={{ color: C.green }}>{v.latest}</span> to patch {v.cve}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Tab: Headers ──────────────────────────────────────────────────────────────
function HeadersTab({ results }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {results.headers.map(h => (
        <div key={h.header} style={{
          background: C.card, border: `1px solid ${h.present ? C.green + "44" : SEV_COLOR[h.risk] + "44"}`,
          borderRadius: 10, padding: 16, display: "flex", alignItems: "center", gap: 16
        }}>
          <div style={{ fontSize: 20 }}>{h.present ? "✅" : "❌"}</div>
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: "monospace", fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{h.header}</div>
            <div style={{ fontSize: 12, color: C.muted }}>{h.desc}</div>
            {h.present && <div style={{ fontSize: 12, color: C.green, marginTop: 4, fontFamily: "monospace" }}>Value: {h.value}</div>}
          </div>
          {!h.present && <Badge sev={h.risk} />}
          {h.present && <span style={{ color: C.green, fontSize: 12, fontWeight: 600 }}>PRESENT</span>}
        </div>
      ))}
    </div>
  );
}

// ── Tab: SSL ──────────────────────────────────────────────────────────────────
function SSLTab({ results }) {
  const ssl = results.ssl;
  const scoreColor = ssl.score >= 70 ? C.green : ssl.score >= 40 ? C.yellow : C.red;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <StatCard label="SSL Score" value={ssl.score} sub="/100" color={scoreColor} icon="🔒" />
        <StatCard label="TLS Version" value={ssl.tlsVersion} sub={ssl.tlsVersion === "TLS 1.2" || ssl.tlsVersion === "TLS 1.3" ? "Secure" : "Outdated"} color={ssl.tlsVersion.includes("1.1") ? C.red : C.green} icon="📡" />
        <StatCard label="Certificate" value={ssl.expired ? "EXPIRED" : "VALID"} sub={`Issuer: ${ssl.issuer}`} color={ssl.expired ? C.red : C.green} icon="📜" />
      </div>

      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 16 }}>SSL/TLS Details</div>
        {[
          { label: "Certificate Valid", value: ssl.valid ? "Yes" : "No", ok: ssl.valid },
          { label: "Expiry Date", value: ssl.expiry, ok: !ssl.expired },
          { label: "Issuer", value: ssl.issuer, ok: true },
          { label: "TLS Version", value: ssl.tlsVersion, ok: ssl.tlsVersion === "TLS 1.3" },
          { label: "Weak Ciphers", value: ssl.weakCiphers ? ssl.ciphers.join(", ") : "None", ok: !ssl.weakCiphers },
        ].map(row => (
          <div key={row.label} style={{ display: "flex", justifyContent: "space-between", padding: "10px 0", borderBottom: `1px solid ${C.border}33` }}>
            <span style={{ color: C.muted, fontSize: 13 }}>{row.label}</span>
            <span style={{ fontFamily: "monospace", fontSize: 13, color: row.ok ? C.green : C.red, fontWeight: 600 }}>{row.value}</span>
          </div>
        ))}
      </div>

      {(ssl.expired || ssl.weakCiphers) && (
        <div style={{ background: "#1a0a0a", border: `1px solid ${C.red}44`, borderRadius: 10, padding: 16 }}>
          <div style={{ color: C.red, fontWeight: 700, marginBottom: 8 }}>⚠ Recommendations</div>
          {ssl.expired && <div style={{ color: C.muted, fontSize: 13, marginBottom: 6 }}>• Renew SSL certificate immediately. Enable auto-renewal (Let's Encrypt certbot --renew).</div>}
          {ssl.weakCiphers && <div style={{ color: C.muted, fontSize: 13 }}>• Disable TLS 1.0/1.1 and weak ciphers. Configure: ssl_protocols TLSv1.2 TLSv1.3;</div>}
        </div>
      )}
    </div>
  );
}

// ── Tab: Web Checks ───────────────────────────────────────────────────────────
function WebTab({ results }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {results.webChecks.map((c, i) => (
        <div key={i} style={{
          background: C.card, border: `1px solid ${SEV_COLOR[c.risk] || C.border}44`,
          borderRadius: 10, padding: 16, display: "flex", alignItems: "flex-start", gap: 16
        }}>
          <div style={{ fontSize: 20 }}>{c.risk === "CRITICAL" ? "🚨" : c.risk === "HIGH" ? "⚠️" : c.risk === "MEDIUM" ? "🔶" : c.risk === "LOW" ? "🔵" : "ℹ️"}</div>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
              <span style={{ fontWeight: 600, fontSize: 14 }}>{c.check}</span>
              <span style={{ fontFamily: "monospace", fontSize: 12, color: SEV_COLOR[c.risk] || C.muted, fontWeight: 700 }}>{c.status}</span>
            </div>
            <div style={{ fontSize: 13, color: C.muted, fontFamily: "monospace" }}>{c.detail}</div>
          </div>
          <Badge sev={c.risk} />
        </div>
      ))}
    </div>
  );
}

// ── Tab: Findings ─────────────────────────────────────────────────────────────
function FindingsTab({ results }) {
  const [filter, setFilter] = useState("ALL");
  const filtered = filter === "ALL" ? results.findings : results.findings.filter(f => f.severity === filter);
  return (
    <div>
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            background: filter === f ? `${(SEV_COLOR[f] || C.cyan)}22` : C.card,
            border: `1px solid ${filter === f ? (SEV_COLOR[f] || C.cyan) : C.border}`,
            borderRadius: 6, padding: "6px 16px", color: filter === f ? (SEV_COLOR[f] || C.cyan) : C.muted,
            fontSize: 13, cursor: "pointer"
          }}>{f} {filter !== f && `(${results.findings.filter(x => x.severity === f || f === "ALL").length})`}</button>
        ))}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {filtered.map(f => (
          <div key={f.id} style={{
            background: C.card, border: `1px solid ${SEV_COLOR[f.severity]}44`, borderRadius: 12, padding: 20
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{ color: C.muted, fontSize: 12, fontFamily: "monospace" }}>#{String(f.id).padStart(3,"0")}</span>
              <Badge sev={f.severity} />
              <span style={{ fontSize: 12, color: C.muted, background: C.card2, padding: "2px 8px", borderRadius: 4 }}>{f.category}</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 10, color: C.text }}>{f.description}</div>
            <div style={{ background: "#0a140a", border: `1px solid ${C.green}22`, borderRadius: 6, padding: 12, fontSize: 13, color: C.muted }}>
              <span style={{ color: C.green, fontWeight: 600 }}>💡 Fix: </span>{f.recommendation}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Tab: History ──────────────────────────────────────────────────────────────
function HistoryTab({ history }) {
  const trendData = history.slice().reverse().map((h, i) => ({ name: h.date, score: h.score, findings: h.findings }));
  return (
    <div>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20, marginBottom: 20 }}>
        <div style={{ fontWeight: 600, marginBottom: 16 }}>Risk Score Trend</div>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={trendData}>
            <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
            <XAxis dataKey="name" tick={{ fill: C.muted, fontSize: 11 }} />
            <YAxis domain={[0, 100]} tick={{ fill: C.muted, fontSize: 11 }} />
            <Tooltip contentStyle={{ background: C.card2, border: `1px solid ${C.border}`, borderRadius: 8, color: C.text }} />
            <Legend />
            <Line type="monotone" dataKey="score" stroke={C.cyan} strokeWidth={2} dot={{ fill: C.cyan, r: 5 }} name="Risk Score" />
            <Line type="monotone" dataKey="findings" stroke={C.amber} strokeWidth={2} dot={{ fill: C.amber, r: 5 }} name="Findings" />
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ background: C.card2, color: C.muted, fontSize: 11, textTransform: "uppercase", letterSpacing: 1 }}>
              {["Target","Scan Date","Risk Score","Findings","Status"].map(h => (
                <th key={h} style={{ padding: "12px 16px", textAlign: "left" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {history.map((h, i) => {
              const sc = h.score >= 70 ? C.critical : h.score >= 40 ? C.yellow : C.green;
              return (
                <tr key={i} style={{ borderTop: `1px solid ${C.border}33` }}>
                  <td style={{ padding: "12px 16px", fontFamily: "monospace", color: C.cyan }}>{h.target}</td>
                  <td style={{ padding: "12px 16px", color: C.muted }}>{h.date}</td>
                  <td style={{ padding: "12px 16px" }}>
                    <span style={{ color: sc, fontWeight: 700, fontFamily: "monospace" }}>{h.score}/100</span>
                  </td>
                  <td style={{ padding: "12px 16px", color: C.text }}>{h.findings}</td>
                  <td style={{ padding: "12px 16px" }}>
                    <span style={{ background: sc + "22", color: sc, padding: "2px 10px", borderRadius: 20, fontSize: 11, fontWeight: 700 }}>
                      {h.score >= 70 ? "HIGH RISK" : h.score >= 40 ? "MEDIUM" : "LOW RISK"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
