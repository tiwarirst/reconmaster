<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ █████╗ ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
```

**AI-Augmented Autonomous Attack Surface Intelligence Platform**

*Where Human Expertise Meets Machine Cognition*

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Ubuntu%20%7C%20macOS-black?style=for-the-badge&logo=linux&logoColor=white)](https://www.kali.org/)
[![AI](https://img.shields.io/badge/AI-Ollama%20%7C%20Local%20LLM-blueviolet?style=for-the-badge)](https://ollama.ai/)
[![Async](https://img.shields.io/badge/Architecture-Async%20%7C%20Event--Driven-orange?style=for-the-badge)](https://docs.python.org/3/library/asyncio.html)

</div>

---

> **ReconAI** is not a scanner. It is a **cognitive reconnaissance platform** — a fusion of autonomous AI reasoning, the complete Kali Linux tool ecosystem, and enterprise-grade modular architecture. Built for professional red teamers, bug bounty hunters, and security engineers who demand precision at scale.

---

## Table of Contents

- [Philosophy](#philosophy)
- [Architecture Overview](#architecture-overview)
- [Feature Matrix](#feature-matrix)
- [NEXUS — The AI Operations Center](#nexus--the-ai-operations-center)
- [Scan Modes](#scan-modes)
- [Module Catalogue](#module-catalogue)
- [Intelligence Layer](#intelligence-layer)
- [AI Stack](#ai-stack)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [GPU / Remote LLM Setup](#gpu--remote-llm-setup)
- [Output & Reporting](#output--reporting)
- [Tool Integrations](#tool-integrations)
- [API Keys](#api-keys)
- [Architecture Deep Dive](#architecture-deep-dive)
- [Development](#development)
- [Legal & Ethics](#legal--ethics)

---

## Philosophy

Most security tools are **data collectors**. ReconAI is a **thinking system**.

The platform operates on three foundational principles:

| Principle | Implementation |
|-----------|---------------|
| **Fail-Safe** | Every external tool has a pure-Python offline fallback. No binary = no crash, just degraded speed |
| **Fail-Fast on Logic** | Type-safe configuration (Pydantic v2), validated scope enforcement, strict error propagation |
| **Modular by Design** | Each module is self-registering, independently testable, and composable |

ReconAI bridges the gap between **automated scanning** and **elite red team reasoning** through a three-tier AI integration: passive analysis, active agent collaboration, and an autonomous mission terminal.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         R E C O N A I   P L A T F O R M                │
├──────────────┬──────────────────────────────────┬───────────────────────┤
│   CLI Layer  │      Core Orchestration           │    AI / Intelligence  │
│              │                                   │                       │
│  reconai     │  ┌─────────────────────────────┐ │  ┌─────────────────┐  │
│  scan        │  │     Orchestrator             │ │  │  Ollama LLM     │  │
│  nexus       │  │  ┌───────────┐  ┌─────────┐ │ │  │  (local/remote) │  │
│  agent       │  │  │ Scope Mgr │  │ Event   │ │ │  └────────┬────────┘  │
│  ai          │  │  │ (strict / │  │ Bus     │ │ │           │           │
│  report      │  │  │ permissiv)│  │(asyncio)│ │ │  ┌────────▼────────┐  │
│  doctor      │  │  └─────┬─────┘  └────┬────┘ │ │  │  AI Adapter     │  │
│  mcp-server  │  │        │             │      │ │  │  (provider agn.)│  │
│              │  │  ┌─────▼─────────────▼────┐ │ │  └────────┬────────┘  │
│              │  │  │   Module Executor       │ │ │           │           │
│              │  │  │ (async, rate-limited,  │ │ │  ┌────────▼────────┐  │
│              │  │  │  concurrent, scoped)   │ │ │  │ Analyzer        │  │
│              │  │  └────────────┬───────────┘ │ │  │ RedTeamAgent    │  │
│              │  │               │             │ │  │ ThreatProfiler  │  │
│              │  │  ┌────────────▼───────────┐ │ │  │ DefensiveAdvisr │  │
│              │  │  │   SQLite Database      │ │ │  │ FuzzOptimizer   │  │
│              │  │  │ (aiosqlite, typed)     │ │ │  └────────┬────────┘  │
│              │  │  └────────────────────────┘ │ │           │           │
│              │  └─────────────────────────────┘ │  ┌────────▼────────┐  │
│              │                                   │  │ PoC Generator   │  │
│              │  ┌─────────────────────────────┐ │  │ CVE Lookup      │  │
│              │  │     Module Registry          │ │  │ Exploit Index   │  │
│              │  │  passive│active│web│vuln│cloud│ │  └─────────────────┘  │
│              │  └─────────────────────────────┘ │                       │
├──────────────┴──────────────────────────────────┴───────────────────────┤
│                     NEXUS Terminal  (nexus_shell.py)                    │
│        Three-pane TUI · Autopilot · Copilot · Manual+AI modes          │
│        Full Kali ecosystem · ReAct loop · Kill-chain synthesis          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Feature Matrix

### Core Reconnaissance Engine

| Capability | Description | Tools |
|---|---|---|
| **Subdomain Discovery** | Passive + active enumeration across 10+ OSINT sources | subfinder, amass, dnsx, cert transparency (crt.sh), archive mining |
| **DNS Intelligence** | Full record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA, DNSKEY) + zone transfer detection | dnsx, dnspython |
| **Port & Service Mapping** | SYN scan, full TCP, banner grabbing, service version detection | naabu, nmap, custom probe engine |
| **TLS / Certificate Analysis** | SAN extraction, JARM fingerprinting, expiry detection, weak cipher auditing | tlsx, built-in httpx |
| **HTTP Probing** | Status code, title, technology, WAF, redirect chain, CORS headers, security header audit | httpx, custom async engine |
| **Web Crawling** | Depth-controlled spider, form discovery, parameter mining, JS endpoint extraction | katana, playwright, custom async crawler |
| **Directory & Parameter Discovery** | Wordlist-based fuzzing, hidden parameter enumeration | ffuf, arjun |
| **Screenshot Capture** | Headless Chrome visual fingerprinting at scale | gowitness, playwright |
| **Technology Detection** | 1,500+ technology signatures, version inference, CDN / WAF classification | whatweb, wafw00f, wappalyzer heuristics |
| **JavaScript Analysis** | API endpoint extraction, hardcoded secret detection, DOM XSS sink mapping | custom JS parser |
| **Archive Mining** | Wayback Machine, AlienVault OTX, CommonCrawl URL harvesting | gau, waybackurls |

### Cloud Security Modules

| Capability | Description |
|---|---|
| **S3 / GCS / Azure Bucket Enumeration** | Permutation-based public bucket discovery across AWS, GCP, Azure |
| **Cloud SSRF → Metadata Exfiltration** | IMDSv1 endpoint probing (169.254.169.254, 100.100.100.200, fd00:ec2::254) |
| **IAM Policy Analysis** | Overly-permissive role detection, privilege escalation path identification |
| **Subdomain Takeover** | Dangling CNAME detection, service fingerprinting for 40+ providers | subzy |
| **Multi-Cloud OSINT** | Correlated asset discovery across cloud provider IP ranges | cloud_enum |

### Vulnerability Detection

| Capability | Tools |
|---|---|
| **Nuclei Template Engine** | 7,000+ community + custom templates across all severity levels |
| **XSS Detection & Exploitation** | Reflected, DOM, stored XSS with payload generation | dalfox |
| **SQL Injection** | Union, blind, time-based, error-based with DB fingerprinting | sqlmap |
| **Secret & Credential Scanning** | AWS keys, GCP tokens, JWT, private keys, API tokens in HTTP responses and JS | gitleaks, trufflehog |
| **SSRF Detection** | Cloud metadata, internal network, file:// scheme probing |
| **Security Header Audit** | CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy grading |
| **Email Security Posture** | SPF, DKIM, DMARC record validation and spoofing risk assessment |
| **Dev Artifact Detection** | Exposed `.git`, `.env`, `backup.zip`, `phpinfo`, `swagger.json` |

### OSINT & Threat Intelligence

| Capability | Data Sources |
|---|---|
| **WHOIS / RDAP** | Registration history, registrar, nameserver mapping |
| **ASN Enumeration** | BGP routing, IP block ownership, peer AS mapping |
| **SaaS Footprint** | Office 365, G Suite, Salesforce, Slack tenant detection |
| **CVE Correlation** | Real-time NVD lookup for detected technology versions |
| **Exploit Index** | ExploitDB / Metasploit module correlation for confirmed CVEs |

---

## NEXUS — The AI Operations Center

NEXUS is the flagship feature of ReconAI — a **cinematic terminal interface** that transforms the tool into an AI-driven security operations platform.

```bash
reconai nexus
```

### Three Operation Modes

```
┌──────────────────────────────────────────────────────────────┐
│  🤖 AUTOPILOT  │  AI drives everything. You define the       │
│                │  mission goal; NEXUS plans, executes,        │
│                │  interprets output, and delivers a full      │
│                │  intelligence report — autonomously.         │
├──────────────────────────────────────────────────────────────┤
│  🤝 COPILOT    │  Human + AI collaboration. AI proposes       │
│                │  each step with full rationale. You          │
│                │  approve, modify, or skip. Nothing runs      │
│                │  without your confirmation.                  │
├──────────────────────────────────────────────────────────────┤
│  🖥️  MANUAL+AI │  You run commands freely. AI watches         │
│                │  all output in real-time, auto-detects       │
│                │  findings, and provides live commentary.     │
└──────────────────────────────────────────────────────────────┘
```

### Mission Execution Lifecycle

```
MISSION GOAL (natural language)
        │
        ▼
  ┌─────────────────┐
  │  Mission Planner│  AI decomposes goal into MITRE ATT&CK-
  │  (NexusAgent)   │  aligned phases: Recon → Enum → Vuln →
  └────────┬────────┘  Exploit → Post-Exploit → Report
           │
           ▼
  ┌─────────────────────────────────────────────┐
  │           ReAct Execution Loop              │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
  │  │  Reason  │→ │   Act    │→ │ Observe  │  │
  │  │ (select  │  │ (execute │  │ (parse   │  │
  │  │  tool,   │  │  exact   │  │  output, │  │
  │  │  build   │  │  command)│  │  extract │  │
  │  │  command)│  │          │  │  findings│  │
  │  └──────────┘  └──────────┘  └──────────┘  │
  │                      ↑______________|        │
  └─────────────────────────────────────────────┘
           │
           ▼
  ┌─────────────────┐
  │  Kill-Chain     │  AI synthesizes all findings into a
  │  Synthesis      │  cohesive attack narrative with
  └────────┬────────┘  MITRE ATT&CK mapping
           │
           ▼
  ┌─────────────────┐
  │  Mission Report │  HTML + JSON + Markdown with PoCs
  └─────────────────┘
```

### Dynamic Kali Tool Discovery

NEXUS dynamically discovers **every tool installed on the system** — not a hardcoded list:

- Scans all `PATH` directories for executables
- Reads `/usr/share/kali-menu` category definitions
- Queries `dpkg -l` for installed security packages
- Maintains a semantic knowledge base of 300+ Kali tools with risk ratings and input type annotations

**The AI selects the right tool, generates the exact command with optimal flags, and interprets the output** — for any tool on the system.

---

## Scan Modes

```bash
reconai scan <target> --mode <mode>
```

| Mode | Scope | Use Case |
|---|---|---|
| `quick` | Top 1000 ports, passive recon, HTTP probe | Initial triage, time-constrained assessments |
| `standard` | Full subdomain enum, common web paths, nuclei | Bug bounty reconnaissance |
| `deep` | Full port range, deep crawling, all vuln modules | Comprehensive penetration test |
| `cloud` | Cloud-focused: S3/GCS/Azure, SSRF, IAM | Cloud-native application assessment |
| `stealth` | Rate-limited, passive-only, no active probing | Sensitive engagements requiring minimum noise |
| `api` | REST/GraphQL API surface, parameter mining, auth testing | API security assessment |

### Scan Profiles

```bash
reconai scan example.com --mode deep --profile thorough
```

| Profile | Rate Limiting | Concurrency | Notes |
|---|---|---|---|
| `quick` | Aggressive | High | CI/CD pipeline, fast feedback |
| `balanced` | Moderate | Medium | Default, suitable for most targets |
| `thorough` | Conservative | Low | Maximum coverage, stealth-compatible |

---

## Module Catalogue

### Passive Reconnaissance (`modules/passive/`)

| Module | Description |
|---|---|
| `dns_enum` | Full DNS record enumeration with zone transfer detection |
| `cert_transparency` | crt.sh / Censys certificate transparency log mining |
| `whois` | WHOIS + RDAP registration data with historical comparison |
| `archive` | Wayback Machine, CommonCrawl, AlienVault URL harvesting |
| `paramspider` | Hidden parameter mining from web archives |
| `dnsx` | High-speed DNS resolution and validation at scale |
| `email_security` | SPF, DKIM, DMARC record auditing and spoofing risk scoring |
| `saas_enum` | SaaS tenant detection (O365, GSuite, Salesforce, Slack, Zoom) |
| `asn_enum` | BGP ASN lookup, IP block ownership, peer AS discovery |
| `osint_fusion` | Multi-source OSINT correlation (Shodan, VirusTotal, Censys, SecurityTrails) |

### Active Reconnaissance (`modules/active/`)

| Module | Description |
|---|---|
| `subdomains` | Multi-source subdomain enumeration (subfinder + amass + dnsx brute-force) |
| `http_probe` | HTTP/HTTPS probing with tech detection, redirect chains, status codes |
| `port_scan` | Nmap-powered service version detection with NSE scripting |
| `naabu` | Ultra-fast SYN/CONNECT port scanning (100k ports/sec) |
| `tlsx_probe` | TLS certificate analysis, JARM fingerprinting, SAN extraction |
| `cdn_classifier` | CDN / WAF detection and origin IP leak analysis |

### Web Analysis (`modules/web/`)

| Module | Description |
|---|---|
| `crawler` | Async recursive web spider with depth/page/URL limits |
| `katana` | ProjectDiscovery Katana next-gen crawler with JS form filling |
| `directory` | Wordlist-based directory and file discovery |
| `ffuf` | Fast web fuzzer integration for directory and parameter brute-force |
| `technologies` | WhatWeb + Wappalyzer heuristics technology fingerprinting |
| `waf` | WAF/CDN detection and evasion advisory |
| `headers` | HTTP security header audit with grading (A–F) |
| `javascript` | JS endpoint extraction, secret detection, DOM sink analysis |
| `api_miner` | REST / GraphQL API surface discovery from JS and responses |
| `arjun_miner` | Hidden HTTP parameter discovery via differential response analysis |
| `dev_artifacts` | Exposed dev/CI artifacts: .git, .env, backup files, phpinfo, swagger |
| `browser` | Playwright headless browser for JavaScript-heavy SPA analysis |
| `host_browser` | Virtual host discovery via Host header manipulation |
| `screenshot` | Headless Chrome screenshot capture at scale |

### Vulnerability Assessment (`modules/vuln/`)

| Module | Description |
|---|---|
| `nuclei` | 7,000+ template vulnerability scanner with severity grading |
| `intelligence` | CVE correlation against detected technologies using NVD |
| `secrets` | Multi-engine secret detection in HTTP responses (gitleaks + trufflehog) |
| `dalfox` | Parameter analysis and XSS exploitation with payload verification |
| `sqlmap` | Automated SQL injection detection and exploitation |

### Cloud Security (`modules/cloud/`)

| Module | Description |
|---|---|
| `bucket_enum` | Public cloud storage bucket discovery (AWS S3, GCS, Azure Blob) |
| `cloud_enum` | Multi-cloud OSINT asset enumeration |
| `metadata_ssrf` | SSRF-via-cloud-metadata probing (IMDSv1, GCP, Azure endpoints) |
| `iam_analyzer` | Overly-permissive IAM role and policy detection |
| `subzy_takeover` | Subdomain takeover via dangling CNAME (40+ provider fingerprints) |

---

## Intelligence Layer

### PoC Generator (`intelligence/poc_generator.py`)

For every confirmed finding, ReconAI auto-generates a **unique, targeted Proof-of-Concept package**:

| PoC Component | Description |
|---|---|
| **Curl Verification** | Exact reproduction command with correct headers and payloads |
| **Python PoC Script** | Runnable Python verification script with full request/response handling |
| **Nuclei Template** | Ready-to-run YAML template for CI/CD pipeline integration |
| **Raw HTTP Request** | Burp Suite-importable raw request |
| **Verification Steps** | Numbered checklist for manual confirmation |
| **Impact Description** | Business impact and CVSS context |

Supported vulnerability classes with **word-boundary-safe dispatch**:

`XSS` · `SQL Injection` · `SSRF` · `SSTI` · `LFI` · `RCE / Command Injection` · `IDOR` · `Open Redirect` · `XXE` · `CRLF Injection` · `Exposed Endpoints` · `Secret / Credential Exposure` · `Subdomain Takeover`

### CVE & Exploit Correlation (`intelligence/cve_lookup.py`, `exploit_lookup.py`)

- Real-time NVD API lookup for detected `technology@version` pairs
- ExploitDB and Metasploit module correlation for confirmed CVEs
- CVSS v3 scoring integration with severity classification

### Attack Surface Correlation Engine (`core/correlation/engine.py`)

Builds a directed attack surface **graph** (nodes: subdomains, IPs, ports, findings; edges: DNS, network, vulnerability relationships) to:

- Identify the weakest-link assets for red team prioritisation
- Detect lateral movement paths across the infrastructure
- Generate MITRE ATT&CK-mapped kill chains

---

## AI Stack

### Provider Architecture

```
┌────────────────────────────────────────────────────┐
│                  AI Adapter Layer                  │
│          (provider-agnostic interface)             │
├────────────────────────────────────────────────────┤
│  Currently Supported: Ollama (local / remote GPU)  │
│  Extensible to: OpenAI, Anthropic, Gemini, Groq    │
└────────────────────────────────────────────────────┘
```

### AI Components

| Component | Role |
|---|---|
| `analyzer.py` | Post-scan AI report narration — converts raw findings into expert prose |
| `agent.py` (RedTeamAgent) | Autonomous attack surface reasoning → Red Team operation plan generation |
| `nexus_agent.py` (NexusAgent) | Mission planner with ReAct loop for NEXUS terminal |
| `shell_agent.py` (ShellAgent) | Natural-language-to-tool-execution pipeline |
| `threat_profiler.py` | Target threat profiling and attack surface prioritisation |
| `defensive_advisor.py` | WAF/CDN bypass advisory, origin IP leak analysis |
| `fuzz_optimizer.py` | AI-guided payload and wordlist selection |
| `verifier.py` | Finding confidence scoring and false-positive reduction |
| `copilot.py` | Interactive AI assistant for mid-scan guidance |

### Recommended Models

| Model | Best For |
|---|---|
| `llama3` | Fast general reasoning, report narration, correlation |
| `deepseek-r1:7b` | Deep chain-of-thought vulnerability reasoning, attack chain synthesis |
| `mistral` | Compact, high-precision technical analysis |
| `dolphin-llama3` | Uncensored offensive posture analysis, exploitation guidance |
| `qwen2.5-coder:7b` | Payload generation, script analysis, source code comprehension |

---

## Installation

### Prerequisites

- Python 3.11+
- `pip` / `pipx`
- [Ollama](https://ollama.ai) (for AI features — optional)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/reconai.git
cd reconai

# Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\Activate.ps1      # Windows PowerShell

# Install ReconAI
pip install -e .

# Verify installation
reconai --version
reconai doctor
```

### Install Script (Linux / Kali)

```bash
chmod +x install.sh
./install.sh
```

The install script handles:
- Python dependency installation
- Ollama setup and model pull
- Optional Kali tool installation (ProjectDiscovery suite: subfinder, httpx, nuclei, naabu, dnsx, katana, tlsx, naabu)
- PATH configuration

### Docker (Recommended for Isolated Environments)

```bash
docker build -t reconai .
docker run --rm -it \
  -v $(pwd)/output:/app/output \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 \
  reconai scan example.com --mode standard --ai
```

---

## Quick Start

### 1. Health Check

```bash
# Diagnose tool availability and AI connectivity
reconai doctor
```

```
✅ Python 3.11.9          — OK
✅ subfinder 2.6.6        — OK (passive subdomain discovery)
✅ httpx 1.3.7            — OK (HTTP probing)
✅ naabu 2.3.1            — OK (port scanning)
✅ nuclei 3.2.4           — OK (7,234 templates loaded)
✅ Ollama llama3          — OK (http://localhost:11434)
⚠️  sqlmap                — Not found (pure-Python fallback active)
⚠️  dalfox                — Not found (XSS module disabled)
```

### 2. Standard Scan

```bash
# Standard reconnaissance scan
reconai scan example.com

# Deep scan with all modules
reconai scan example.com --mode deep

# With AI analysis and report narration
reconai scan example.com --mode standard --ai

# Dry run (show what would execute without running)
reconai scan example.com --mode deep --dry-run
```

### 3. AI-Powered Scan

```bash
# Enable AI for this scan with a specific model
reconai scan example.com --mode deep --ai \
  --ai-model deepseek-r1:7b \
  --ai-url http://localhost:11434
```

### 4. NEXUS Terminal (AI Agent Interface)

```bash
# Launch the full AI security operations terminal
reconai nexus

# With a specific mode
reconai nexus --mode autopilot
reconai nexus --mode copilot
```

**Example NEXUS session:**

```
NEXUS> Perform a full reconnaissance on example.com and identify the highest
       risk attack vectors for a cloud-native application

[NEXUS] 🧠 Planning mission: Full Recon → Attack Vector Analysis
[NEXUS] 📋 Phase 1: Passive Reconnaissance
  → Running: subfinder -d example.com -all -o /tmp/subs.txt
  → Running: gau example.com --subs
[NEXUS] 📋 Phase 2: Active Enumeration
  → Running: naabu -l /tmp/subs.txt -top-ports 1000
  → Running: httpx -l /tmp/subs.txt -tech-detect -title
[NEXUS] 📋 Phase 3: Vulnerability Analysis
  → Running: nuclei -l /tmp/live_hosts.txt -severity high,critical
[NEXUS] 🔍 Synthesizing 847 data points across 12 tool outputs...
[NEXUS] 💀 CRITICAL: SSRF via cloud metadata at api.example.com → IAM credential theft
[NEXUS] 🔴 HIGH: SQL Injection in /api/v2/search (PostgreSQL confirmed)
[NEXUS] 🟡 MEDIUM: 3 S3 buckets with public list access (sensitive files exposed)
```

### 5. Natural Language Shell Agent

```bash
# Launch the conversational AI security agent
reconai agent
```

```
Agent> find all subdomains of target.com
Agent> scan for open ports on api.target.com
Agent> look for XSS on https://target.com/search?q=
Agent> check if target.com is behind a WAF
Agent> run full recon on target.corp
Agent> check for CVE-2023-44487 (HTTP/2 Rapid Reset) on 10.0.0.1
```

### 6. Generate Reports

```bash
# Generate all report formats from an existing scan
reconai report <scan-id> --format html
reconai report <scan-id> --format json
reconai report <scan-id> --format md

# List previous scans
reconai scans
```

### 7. MCP Server (Model Context Protocol)

```bash
# Start the MCP server for IDE / AI assistant integration
reconai mcp-server --port 8080
```

ReconAI exposes a full MCP server, enabling **Claude Desktop, Cursor, and other MCP-compatible tools** to invoke reconnaissance operations as native AI tool calls.

---

## Configuration

All configuration lives in [`config.yaml`](config.yaml). Every value has a safe default — the file is entirely optional for basic usage.

### Key Sections

```yaml
# ── Timeouts (seconds) ──────────────────────────────────────────────────────
timeouts:
  dns_query: 10
  http_probe: 30
  nmap_full: 600
  cloud_bucket_enum: 180

# ── Concurrency ──────────────────────────────────────────────────────────────
concurrency:
  dns: 20
  http: 20
  crawler: 10
  browser: 2           # Headless browser instances are resource-intensive

# ── Rate Limits (requests per second) ────────────────────────────────────────
rate_limits:
  http: 20
  dns: 50

# ── AI Configuration ─────────────────────────────────────────────────────────
ai:
  enabled: false        # Set true to enable AI on every scan without --ai flag
  provider: "ollama"
  url: "http://localhost:11434"
  model: "llama3"

# ── Tool Paths ───────────────────────────────────────────────────────────────
tools:
  nuclei:
    enabled: true
    path: ""            # Auto-detected; override: "/usr/local/bin/nuclei"
    rate_limit: 150
```

### CLI Priority Chain

```
CLI flag  >  Environment variable  >  config.yaml  >  built-in default
```

**Environment variables** supported:

| Variable | Purpose |
|---|---|
| `OLLAMA_BASE_URL` | Override Ollama server URL |
| `OLLAMA_HOST` | Alternative URL variable |
| `OLLAMA_MODEL` | Override model name |
| `RECONAI_CONFIG` | Path to custom config.yaml |

---

## GPU / Remote LLM Setup

ReconAI supports **100% local AI** with no external API calls. For larger models requiring GPU acceleration, point to a remote Ollama instance:

### Remote GPU Machine Setup

**On the GPU machine:**

```bash
# Allow external connections to Ollama
export OLLAMA_HOST=0.0.0.0:11434
ollama serve &

# Pull your model
ollama pull deepseek-r1:7b
ollama pull llama3
```

**In `config.yaml` on your attack machine:**

```yaml
ai:
  enabled: true
  url: "http://192.168.1.50:11434"   # Your GPU machine's IP
  model: "deepseek-r1:7b"
```

**Or via CLI flag:**

```bash
reconai scan example.com --ai \
  --ai-url http://192.168.1.50:11434 \
  --ai-model deepseek-r1:7b
```

### SSH Tunnel (Private Network GPU)

```bash
# Create a tunnel to a remote GPU (keeps it on a private network)
ssh -L 11434:localhost:11434 user@gpu-server-ip -N &

# Then use localhost in config — traffic goes through the tunnel
reconai scan example.com --ai --ai-url http://localhost:11434
```

---

## Output & Reporting

Every scan produces structured output in `output/<scan-id>/`:

```
output/
└── <scan-id>/
    ├── report.html          # Interactive HTML report with expandable PoC panels
    ├── report.json          # Machine-readable findings (CI/CD integration)
    ├── report.md            # Markdown report for Confluence / Notion / GitHub
    ├── raw/                 # Raw tool output (JSON / text per module)
    ├── normalized/          # Schema-normalized findings (Pydantic models)
    ├── pocs/                # Auto-generated Proof-of-Concept packages
    │   ├── poc_1_sqli_login.py       # Python verification script
    │   ├── poc_1_sqli_login.sh       # Curl reproduction command
    │   ├── poc_1_sqli_login.yaml     # Nuclei template
    │   ├── poc_2_xss_search.py
    │   └── ...
    └── scan.log             # Full execution log with timestamps
```

### HTML Report Features

- **Executive Summary** with risk score and finding distribution
- **Finding Detail Cards** with severity-coded badges
- **Per-Finding PoC Panel** (4 expandable sections per vulnerability):
  - 🔍 Curl Verification Command
  - 🐍 Python Exploit Script
  - ✅ Manual Verification Steps
  - 📡 Raw HTTP Request (Burp Suite compatible)
- **Technology Inventory** with CVE correlation
- **Asset Map** with subdomain → IP → port topology
- **MITRE ATT&CK** technique tagging

---

## Tool Integrations

ReconAI integrates with the following external tools. **All are optional** — missing tools activate pure-Python fallbacks automatically.

| Tool | Category | Install |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP Probe | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [naabu](https://github.com/projectdiscovery/naabu) | Port Scan | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vuln Scan | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| [katana](https://github.com/projectdiscovery/katana) | Crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [tlsx](https://github.com/projectdiscovery/tlsx) | TLS | `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest` |
| [amass](https://github.com/owasp-amass/amass) | Subdomain | `go install github.com/owasp-amass/amass/v4/...@latest` |
| [nmap](https://nmap.org/) | Port Scan | `apt install nmap` |
| [dalfox](https://github.com/hahwul/dalfox) | XSS | `go install github.com/hahwul/dalfox/v2@latest` |
| [sqlmap](https://sqlmap.org/) | SQLi | `apt install sqlmap` |
| [ffuf](https://github.com/ffuf/ffuf) | Fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| [gau](https://github.com/lc/gau) | Archive | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Archive | `go install github.com/tomnomnom/waybackurls@latest` |
| [arjun](https://github.com/s0md3v/Arjun) | Params | `pip install arjun` |
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | `go install github.com/gitleaks/gitleaks/v8@latest` |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Secrets | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| [subzy](https://github.com/PentestPad/subzy) | Takeover | `go install github.com/PentestPad/subzy@latest` |
| [cloud_enum](https://github.com/initstring/cloud_enum) | Cloud | `pip install cloud-enum` |
| [gowitness](https://github.com/sensepost/gowitness) | Screenshot | `go install github.com/sensepost/gowitness@latest` |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | Tech | `apt install whatweb` |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | WAF | `pip install wafw00f` |

> **Kali Linux users:** Most tools above are pre-installed. Run `reconai doctor` to see exactly what's available on your system.

---

## API Keys

All API keys are **optional**. ReconAI uses free public endpoints when keys are absent.

Configure in `config.yaml` under `api_keys:`, or set environment variables:

| Service | env var / config key | Free Tier | Unlocks |
|---|---|---|---|
| [Shodan](https://account.shodan.io) | `shodan` | 1 query/day | Port data, banners, CVEs for IPs |
| [VirusTotal](https://www.virustotal.com/gui/my-apikey) | `virustotal` | 500 req/day | Domain reputation, passive DNS |
| [Censys](https://search.censys.io/account/api) | `censys_id` + `censys_secret` | 250 req/month | Deep IP / cert intelligence |
| [SecurityTrails](https://securitytrails.com/app/account/credentials) | `securitytrails` | 50 req/month | Historical DNS, subdomain history |
| [GitHub PAT](https://github.com/settings/tokens) | `github` | Unlimited | Secret scanning in public repos |
| [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io) | `chaos` | Free | 1M+ indexed subdomains |
| [BinaryEdge](https://app.binaryedge.io/account/api-tokens) | `binaryedge` | 250 req/month | Real-time internet scanning data |
| [AlienVault OTX](https://otx.alienvault.com/api) | `alienvault` | Unlimited | Threat indicators, passive DNS |
| [Hunter.io](https://hunter.io/api-keys) | `hunter_io` | 25 req/month | Email address discovery |

---

## Architecture Deep Dive

### Event-Driven Module System

Modules communicate via an **asyncio event bus**. No module imports another module directly — they publish typed events that downstream consumers subscribe to:

```python
# A module publishes a discovery event
await bus.publish(SubdomainFoundEvent(subdomain="api.example.com", source="subfinder"))

# Downstream modules (port_scan, http_probe) auto-subscribe and react
# without tight coupling
```

This enables:
- **Parallel execution** — independent modules run concurrently
- **Live streaming** — results appear in the terminal as they're found
- **Selective execution** — any module can be disabled without breaking others

### Scope Enforcement

```python
# Strict mode — rejects any asset outside the registered scope
scope = ScopeManager.from_yaml(Path("scope.yaml"), strict=True)

# Permissive mode (default) — allows correlated assets for AI synthesis
scope = ScopeManager.for_target("example.com", strict=False)
```

The scope manager validates **every URL, IP, and hostname** before it's processed or stored, preventing accidental out-of-scope testing.

### Database Layer

All scan data is stored in a **per-scan SQLite database** (`aiosqlite`, fully async):

```
Tables: scans · subdomains · ips · ports · technologies · findings
        cloud_assets · urls · parameters · screenshots
```

This enables:
- Cross-module data sharing without race conditions
- Post-scan re-analysis and report regeneration
- Scan comparison and delta reporting
- Long-term asset tracking across multiple engagements

### Stealth Engine (`core/stealth/`)

- Configurable request timing and jitter
- Rotating User-Agent strings
- X-Forwarded-For / X-Real-IP header manipulation
- HTTP/2 support for header fingerprint evasion
- Rate-limit-aware adaptive throttling

---

## Development

### Project Structure

```
reconai/
├── ai/                     # AI components and agents
│   ├── adapter.py          # Provider-agnostic LLM interface
│   ├── agent.py            # Red Team autonomous agent (ReAct loop)
│   ├── nexus_agent.py      # NEXUS mission planner and executor
│   ├── nexus_shell.py      # NEXUS TUI terminal (Rich-powered)
│   ├── shell_agent.py      # Natural-language shell agent
│   ├── analyzer.py         # Post-scan AI report narration
│   ├── threat_profiler.py  # Threat model and risk prioritisation
│   ├── defensive_advisor.py# WAF bypass and origin IP analysis
│   ├── fuzz_optimizer.py   # AI-guided payload selection
│   ├── verifier.py         # False-positive reduction
│   └── tool_discovery.py   # Dynamic Kali tool catalogue
├── cli/
│   └── main.py             # Click CLI (scan, nexus, agent, report, doctor)
├── core/
│   ├── orchestrator.py     # Main scan orchestrator
│   ├── config/             # Pydantic v2 configuration management
│   ├── database/           # aiosqlite async database layer
│   ├── events/             # Asyncio event bus
│   ├── executor/           # Command runner (sandboxed subprocess)
│   ├── correlation/        # Attack surface graph engine
│   ├── normalizer/         # Multi-tool output normalization
│   ├── scope/              # Scope enforcement and validation
│   ├── stealth/            # Rate limiting and evasion
│   └── logging/            # Structured async logging
├── intelligence/
│   ├── poc_generator.py    # Per-vulnerability PoC package generator
│   ├── cve_lookup.py       # NVD CVE correlation
│   └── exploit_lookup.py   # ExploitDB / Metasploit module lookup
├── integrations/           # One file per external tool (30+ tools)
├── modules/
│   ├── passive/            # Zero-footprint OSINT modules
│   ├── active/             # Active probing modules
│   ├── web/                # Web analysis modules
│   ├── vuln/               # Vulnerability assessment modules
│   └── cloud/              # Cloud security modules
├── reports/
│   ├── generator.py        # Orchestrates all report formats
│   ├── html.py             # Interactive HTML report with PoC panels
│   ├── json_report.py      # Structured JSON output
│   └── markdown.py         # Markdown report
├── mcp/
│   └── server.py           # MCP server for IDE/AI assistant integration
└── ui/
    └── console.py          # Rich-powered terminal UI
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run full test suite
pytest

# Run with verbose output
pytest -v

# Run a specific test module
pytest tests/unit/test_events.py

# Type checking
mypy reconai/

# Lint
ruff check reconai/
```

### Adding a New Module

```python
# reconai/modules/passive/my_module.py
from reconai.core.events.bus import EventBus
from reconai.core.database.manager import DatabaseManager

class MyModule:
    NAME = "my_module"
    DESCRIPTION = "What this module does"

    def __init__(self, db: DatabaseManager, scan_id: str, config, bus: EventBus):
        self.db = db
        self.scan_id = scan_id
        self.config = config
        self.bus = bus

    async def run(self) -> None:
        # Discover something, publish events, store to DB
        ...
```

Then register it in `cli/main.py`:
```python
import reconai.modules.passive.my_module
```

---

## Legal & Ethics

> **⚠️ IMPORTANT — Read Before Use**

ReconAI is a professional security research tool intended for:

- **Authorized penetration testing** with explicit written permission
- **Bug bounty programs** within defined scope
- **Red team engagements** under a signed Rules of Engagement
- **Security research** on systems you own or have authorization to test

**Unauthorized use against systems you do not own or have explicit permission to test is illegal under computer fraud laws in most jurisdictions** (CFAA, Computer Misuse Act, and equivalents).

The authors and contributors of ReconAI accept no liability for misuse. Always obtain written authorization before testing any system.

---

## Contributing

Contributions are welcome. Please open an issue before submitting a PR for significant changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Write tests for your changes
4. Ensure `mypy` and `ruff` pass
5. Open a pull request with a clear description

---

<div align="center">

**Built for the red team. Engineered for reliability. Designed for the future.**

*ReconAI — Because intelligence wins engagements, not just scan counts.*

</div>
