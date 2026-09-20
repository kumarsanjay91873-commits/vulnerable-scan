# VULNSCAN v2.0 — Ethical Vulnerability Assessment Platform

A full-featured cybersecurity vulnerability scanner dashboard built with React + Recharts.

> ⚠️ **IMPORTANT:** This tool is for educational and authorized security testing only.
> Only scan systems you own or have explicit written permission to test.

## Features

| Module | Description |
|--------|-------------|
| 🔌 Port Scanner | TCP scan of 15 common ports with banner grabbing |
| 📦 Version Detection | Compares detected versions against CVE database |
| 🛡 HTTP Headers | Checks 6 security headers (CSP, HSTS, X-Frame-Options, etc.) |
| 🔒 SSL/TLS Analyzer | Certificate validity, TLS version, weak cipher detection |
| 🌐 Web Checks | Directory listing, info disclosure, robots.txt, default pages |
| ⚠️ Findings | All vulnerabilities with severity ratings + fix recommendations |
| 📊 Dashboard | Pie + bar charts, risk score gauge, scan history trend |
| 📈 History | Historical scan tracking with risk score trend line |

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm start
# → Opens at http://localhost:3000
```

## Usage

1. Enter a target hostname or IP (e.g. `example.com`, `192.168.1.1`)
2. Click **Run Scan** or press Enter
3. Watch the live terminal output as scanning progresses
4. Review findings across all 8 tabs

## Tabs

- **Overview** — Risk score (0–100), severity charts, top findings
- **Ports** — Full port table, filterable by state
- **Versions** — Outdated software detection with CVE references
- **Headers** — HTTP security header analysis
- **SSL/TLS** — Certificate + cipher suite checks
- **Web Checks** — Application-level security issues
- **Findings** — All vulnerabilities with remediation guidance
- **History** — Scan trend over time

## Tech Stack

- **React 18** + functional components + hooks
- **Recharts** — PieChart, BarChart, LineChart
- **CSS-in-JS** — no external CSS framework needed

## Project Structure

```
vulnscan/
├── public/
│   └── index.html
├── src/
│   ├── index.js       ← React entry point
│   └── App.jsx        ← Full scanner application
├── package.json
└── README.md
```

## Disclaimer

This is a **simulation tool** for educational purposes. The scan results are
generated from a realistic mock dataset. In a production implementation, the
backend scanning modules would use:

- `python-nmap` for port scanning
- `requests` / `ssl` for HTTP + TLS checks
- A real CVE database (NVD API or local SQLite)
- FastAPI backend with async scanning

## License

MIT — free for personal and educational use.
