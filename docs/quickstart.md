# ReconAI Quick Start Guide

## 1. Quick Verification

Before scanning, verify that your environment is ready:

```bash
# 1. Activate virtual environment
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\activate          # Windows

# 2. Check installed tools & Python status
reconai doctor
```

---

## 2. Choosing the Right Scan Mode

ReconAI adapts its module execution graph based on your engagement objectives:

| Mode | Modules & Capabilities | Interaction Level | Typical Duration |
| :--- | :--- | :--- | :--- |
| `passive` | crt.sh, WHOIS, DNS, Wayback/GAU, ASN/BGP, SaaS, OSINT Fusion | **Zero packets to target** | 30s – 2m |
| `light` | Passive + HTTP probes, Header audit, Tech detection | Minimal / Non-intrusive | 1m – 3m |
| `standard` | Light + Naabu port scan, Nmap, Web crawler, Dev artifacts, Screenshots | Standard assessment | 5m – 15m |
| `deep` | Standard + Katana, FFuF fuzzing, Nuclei CVEs, SQLMap, Dalfox, Arjun, Secrets, Cloud | Full offensive auditing | 15m – 45m |
| `cloud` | S3, Azure Blob, GCS buckets, CNAME takeovers, SSRF metadata, IAM policy audits | Cloud surface focus | 5m – 12m |
| `browser` | Standard + Headless Chrome CDP crawler for SPAs (React/Vue/Angular) | Real browser interaction | 8m – 20m |

### Running Scans:

```bash
# 1. Silent passive recon (Stealth engagement)
reconai scan target.com -m passive

# 2. General penetration testing baseline
reconai scan target.com -m standard

# 3. Comprehensive red team scan with AI synthesis
reconai scan target.com -m deep --ai --ai-model deepseek-r1:7b

# 4. Strict scope enforcement (blocks any out-of-scope third-party assets)
reconai scan target.com -m standard --strict-scope
```

---

## 3. Dedicated Focused Pipelines

When you do not need the full multi-phase pipeline, run dedicated single-purpose pipelines directly:

### 3.1 Subdomain Intelligence Pipeline (`subs`)
Aggregates passive DNS, certificate transparency logs, AlienVault OTX, Wayback archives, DNSx active validation, and SSL Subject Alternative Names (SANs):

```bash
reconai subs target.com
```

### 3.2 Port & Service Discovery Pipeline (`ports`)
Executes high-speed port scanning via Naabu, conducts Nmap service versioning, and performs CDN vs. true origin IP classification:

```bash
# Quick top 100 ports (fastest)
reconai ports target.com --profile quick

# Standard top 1000 ports
reconai ports target.com --profile standard

# Deep service detection with default NSE scripts
reconai ports target.com --profile service
```

### 3.3 Web Attack Surface Pipeline (`web`)
Executes deep crawling via Katana, technology fingerprinting, security header audits, WAF classification, directory brute-forcing, hidden parameter mining via Arjun, and visual website captures:

```bash
reconai web target.com
```

### 3.4 Vulnerability & Exploitation Pipeline (`vuln`)
Probes discovered surfaces for CVEs via Nuclei, reflected/stored XSS via Dalfox, SQL injection via SQLMap, hardcoded secrets via Gitleaks/TruffleHog, and dangling CNAME subdomain takeovers:

```bash
reconai vuln target.com
```

---

## 4. AI-Powered Offensive Analysis

### 4.1 Launching the Interactive Copilot

Start a live interactive session with any historical scan:

```bash
reconai copilot <scan_id>
```

**Example Copilot Prompts:**
- `What are the highest risk attack surfaces discovered on this target?`
- `Explain the SQL injection vulnerability found on the login endpoint and suggest manual verification steps.`
- `List all discovered subdomains that bypass Cloudflare CDN.`
- `/summary` (Instant executive brief)
- `/attack-paths` (Correlated kill chain paths)

### 4.2 Autonomous Red Team Operation Plan

Generate a comprehensive 5-phase red teaming plan from findings:

```bash
reconai ai-agent <scan_id>
```

### 4.3 Threat Actor Profiling

Correlate target technology stacks with known adversary campaigns and MITRE ATT&CK TTPs:

```bash
reconai profile-threat <scan_id>
```

### 4.4 Model Context Protocol (MCP) Server

Expose ReconAI to modern AI coding assistants (Antigravity, Cursor, Claude Desktop):

```bash
reconai mcp
```

---

## 5. Working with Results & Reports

After every scan, structured reports are automatically generated in `output/<target>/<scan_id>/`:

```
output/example_com/20261008_143000_a1b2c3/
├── reconai.db            # SQLite database with all raw and normalized findings
├── logs/                 # Timestamped execution logs with secret redaction
├── screenshots/          # Web page visual captures (PNG)
└── reports/
    ├── report.html       # Full interactive dashboard (open in any web browser)
    ├── report.md         # Markdown technical report (ideal for notes/Git)
    └── report.json       # Structured JSON document for CI/CD ingestion
```

### Useful Management Commands:

```bash
# List all historical scan sessions
reconai scans list

# Inspect findings from a specific scan
reconai scans show <scan_id>

# Compare two scans to detect attack surface changes or new subdomains
reconai compare <older_scan_id> <newer_scan_id>

# Regenerate report from an existing scan database
reconai report <scan_id> --format html
```

---

## 6. Authorized Practice Targets

To test ReconAI safely and ethically without impacting unauthorized assets:

```bash
# Authorized scan test targets:
reconai scan scanme.nmap.org -m standard
reconai scan testphp.vulnweb.com -m light
```
