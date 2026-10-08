<div align="center">

<br/>

# ⚡ ReconAI

### Enterprise-Grade, Asynchronous, AI-Powered Attack Surface Intelligence Platform

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img alt="License" src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge"/>
  <img alt="Architecture" src="https://img.shields.io/badge/Architecture-Event--Driven-f97316?style=for-the-badge"/>
  <img alt="AI Engine" src="https://img.shields.io/badge/AI-Ollama%20%2F%20MCP-8b5cf6?style=for-the-badge"/>
  <img alt="Type Safety" src="https://img.shields.io/badge/Type_Safety-Pydantic%20%26%20Mypy-2a6db5?style=for-the-badge"/>
  <img alt="Status" src="https://img.shields.io/badge/Tests-71%2F71%20Passing-22c55e?style=for-the-badge"/>
</p>

<p align="center">
  <em>Autonomous · Fail-Safe · Non-Blocking · Red Team Oriented · Cross-Platform</em>
</p>

<br/>

</div>

---

## 📋 Table of Contents

- [Executive Summary](#-executive-summary)
- [Core Engineering Principles](#-core-engineering-principles)
- [System Architecture](#-system-architecture)
- [Offensive Tools Ecosystem](#-offensive-tools-ecosystem)
- [Autonomous AI & Red Teaming Subsystem](#-autonomous-ai--red-teaming-subsystem)
  - [Interactive Security Copilot](#1-interactive-security-copilot-reconai-copilot)
  - [Autonomous Red Team Agent](#2-autonomous-red-team-agent-reconai-ai-agent)
  - [Threat Actor Profiler](#3-threat-actor-profiler-reconai-profile-threat)
  - [Model Context Protocol (MCP) Server](#4-model-context-protocol-mcp-server-reconai-mcp)
  - [Uncensored & Local GPU Integration](#5-uncensored--local-gpu-integration)
- [Pipeline Modes & Specialized Commands](#-pipeline-modes--specialized-commands)
- [Configuration Management](#-configuration-management)
- [Installation & Quick Start](#-installation--quick-start)
- [Command Line Reference](#-command-line-reference)
- [Documentation Index](#-documentation-index)
- [License](#-license)

---

## 🔍 Executive Summary

**ReconAI** is a high-performance attack surface intelligence and automated security reconnaissance platform engineered for penetration testers, red teams, and bug bounty researchers.

Traditional reconnaissance frameworks rely on brittle, sequential bash scripts that break whenever external binaries are missing or rate limits are reached. **ReconAI** replaces this legacy paradigm with an **asynchronous event-driven architecture**, orchestrating 24+ industry-standard offensive tools into an atomic, idempotent pipeline with pure-Python offline fallbacks.

```
                                  ┌────────────────────────┐
                                  │      Target Asset      │
                                  └───────────┬────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
          ┌───────────────────────┐                       ┌───────────────────────┐
          │  External Binaries    │                       │  Pure-Python Engines  │
          │  (httpx, nuclei, ...) │                       │  (DNS, HTTP, SSL, ...)│
          └───────────┬───────────┘                       └───────────┬───────────┘
                      └───────────────────────┬───────────────────────┘
                                              ▼
                                  ┌────────────────────────┐
                                  │   Async O(1) EventBus  │
                                  └───────────┬────────────┘
                                              │
                      ┌───────────────────────┼───────────────────────┐
                      ▼                       ▼                       ▼
          ┌───────────────────────┐┌────────────────────┐┌────────────────────────┐
          │ SQLite Storage Engine ││ Correlation Graph  ││ Autonomous AI Copilot  │
          │ (Atomic Upserts)      ││ (Attack Paths)     ││ (Uncensored Reasoning) │
          └───────────────────────┘└────────────────────┘└────────────────────────┘
```

---

## ⚡ Core Engineering Principles

ReconAI is architected around three foundational principles:

1. **High Concurrency & Asynchronous I/O**:
   - Zero synchronous blocking calls across networking, DNS queries, or process execution.
   - Built natively on Python 3.10+ `asyncio`, utilizing connection pooling, multiplexed HTTP/2, and semaphore-managed concurrency.

2. **Absolute Fail-Safe Guarantee**:
   - **Zero Mandatory External Dependencies**: If an external binary (e.g., `httpx`, `nuclei`, `subzy`, `arjun`) is missing, ReconAI automatically switches to built-in pure-Python differential probes, socket analyzers, or public OSINT APIs without failing the scan.
   - Process tree isolation terminates runaway or hanging subprocesses using platform-native process management, preventing zombie processes on Windows and Linux alike.
   - Robust transactional SQLite database persistence guarantees that interrupted scans can be resumed or inspected with zero data loss.

3. **Autonomous, Uncensored Red Team Assistance**:
   - Built-in local and remote LLM integration (Ollama) designed for penetration testing analysis.
   - Offers interactive terminal copilot capabilities with zero arbitrary refusal guardrails, allowing security professionals to evaluate deep exploitation vectors and attack chains against authorized targets.

---

## 🧩 System Architecture

ReconAI maintains a strictly layered codebase where every component communicates through typed models and asynchronous events:

```
reconai/
├── ai/                 # LLM copilot, autonomous red team agent, threat profiler, verifier
├── cli/                # Click-based CLI suite with Rich interactive terminal rendering
├── core/
│   ├── config/         # Pydantic schemas, YAML configuration loaders, operational defaults
│   ├── correlation/    # Attack surface graph builder and attack path synthesizer
│   ├── database/       # SQLite schema models, transactional session manager, atomic upserts
│   ├── events/         # Non-blocking async event bus with circular history buffer
│   ├── executor/       # Subprocess runner, shell-injection validators, process-tree reaper
│   ├── logging/        # Structured JSON/console logging with automatic secret redaction
│   └── scope/          # Strict & permissive CIDR, IP, and wildcard domain scope validators
├── integrations/       # 24+ stateless tool adapters (httpx, nuclei, arjun, subzy, tlsx, etc.)
├── intelligence/       # PoC generation, CVE matching, and threat advisory pipelines
├── mcp/                # Model Context Protocol (MCP) server for agentic IDE integration
├── modules/
│   ├── active/         # HTTP probe, Naabu ports, Nmap, TLS inspection, CDN classifier
│   ├── cloud/          # Bucket enumeration, CNAME takeover, IMDS SSRF, IAM validation
│   ├── passive/        # DNS enum, CT logs, Wayback/GAU archives, ASN/BGP, SaaS mapping
│   ├── vuln/           # Nuclei CVEs, Dalfox XSS, SQLMap, Gitleaks, TruffleHog secrets
│   └── web/            # Katana crawler, FFuF, Arjun params, API mining, screenshots
└── reports/            # Multi-format report generators (Interactive HTML, Markdown, JSON)
```

---

## 🛠️ Offensive Tools Ecosystem

ReconAI provides complete adapter wrappers and autonomous Python fallback engines for the modern offensive security toolchain:

| Tool | Category | Primary Functionality | Pure-Python Fallback Engine |
| :--- | :--- | :--- | :--- |
| **`httpx`** | HTTP Discovery | Multiplexed HTTP/2 probing, status codes, tech detection | Async HTTP client with redirect analysis |
| **`tlsx`** | TLS & SANs | Cryptographic auditing, SAN subdomain extraction, JARM | Socket + `ssl` context handshake & cert decoder |
| **`nuclei`** | Vulnerability | Template-driven CVE, misconfiguration, and exposure scan | Lightweight heuristics & known pattern matcher |
| **`arjun`** | Param Mining | Hidden HTTP parameter discovery | Differential response variance analysis |
| **`subzy`** | Subdomain Takeover | Dangling DNS & CNAME vulnerability scanning | 20+ cloud provider fingerprint signature engine |
| **`gitleaks`** | Secret Detection | Fast secret and credential pattern scanning | High-entropy regex pattern matching engine |
| **`gau`** | URL Archiving | Multi-source URL gathering (Wayback, OTX, CommonCrawl) | Direct HTTP queries to AlienVault OTX & CDX APIs |
| **`subfinder`** | Subdomain OSINT | Multi-source passive DNS asset enumeration | crt.sh + HackerTarget + AlienVault query engine |
| **`naabu`** | Port Scanning | Ultra-fast TCP port scanning | Async TCP connect port scanner |
| **`nmap`** | Service Discovery | Deep service versioning, NSE scripts, OS detection | Socket banner grabbing and service probe engine |
| **`katana`** | Web Crawler | Next-gen JS-rendered web crawler and link extractor | Async BeautifulSoup HTML/JS link extractor |
| **`ffuf`** | Directory Fuzzing | High-speed web endpoint and directory brute-forcing | Async HTTP directory brute-forcer |
| **`dalfox`** | XSS Analysis | Parameter-level reflected and DOM XSS verification | Context-aware reflection scanner |
| **`sqlmap`** | SQL Injection | Automated database vulnerability detection | Heuristic SQL error and anomaly detector |
| **`trufflehog`** | Secret Scanner | High-entropy secret and credential detector | Built-in regex and Shannon entropy analyzer |
| **`gowitness`** | Visual Recon | Headless browser website screenshot utility | System Chrome / Edge CDP automation |
| **`wafw00f`** | WAF Fingerprint | Web Application Firewall detection | Header and response block-page fingerprinting |
| **`cloud_enum`** | Cloud OSINT | AWS S3, Azure Blob, Google Cloud bucket scanner | Multi-cloud direct DNS & HTTP storage prober |
| **`dnsx`** | DNS Resolution | High-throughput multi-record DNS resolution | `dnspython` asynchronous resolver pool |

Run `reconai doctor` at any time to inspect real-time tool availability and one-line installation commands.

---

## 🤖 Autonomous AI & Red Teaming Subsystem

ReconAI is architected from the ground up to integrate AI models directly into offensive workflows.

### 1. Interactive Security Copilot (`reconai copilot`)

Launch an interactive, terminal-based AI copilot directly within any completed scan database:

```bash
reconai copilot <scan_id>
```

- **Natural Language Inquiry**: Query targets, open ports, technologies, exposed secrets, and findings using plain English.
- **Exploitation Depth Assessment**: Ask the copilot: *"How can I manually verify the SQL injection on `/api/search`? What is the maximum penetration depth?"*
- **Built-in Quick Commands**:
  - `/summary` — Comprehensive high-level executive briefing.
  - `/critical` — Deep breakdown of critical and high severity findings.
  - `/attack-paths` — Synthesized multi-stage attack scenarios.
  - `/targets` — Inventory of all alive discovered subdomains and services.
  - `/help` — Display interactive command menu.

### 2. Autonomous Red Team Agent (`reconai ai-agent`)

Generate structured, 5-phase red teaming operation plans:

```bash
reconai ai-agent <scan_id>
```

Produces structured operations plans containing:
1. **Reconnaissance & Initial Access Vectors**: Best entry points based on exposed services.
2. **Execution & Weaponization Paths**: Verified parameters, endpoints, and misconfigurations.
3. **Privilege Escalation & Lateral Movement**: Discovered cloud credentials, IMDS metadata, and internal subnets.
4. **Defense Evasion Strategies**: WAF evasion recommendations based on detected firewalls.
5. **Actionable Command Runbook**: Copy-paste terminal commands for authorized validation.

### 3. Threat Actor Profiler (`reconai profile-threat`)

Correlates discovered tech stacks and exposed assets against real-world threat actors, adversary campaigns, and known TTPs:

```bash
reconai profile-threat <scan_id>
```

### 4. Model Context Protocol (MCP) Server (`reconai mcp`)

ReconAI includes a native **Model Context Protocol (MCP)** server on standard I/O:

```bash
reconai mcp
```

Connect your favorite AI-powered development environments (Antigravity, Cursor, Claude Desktop) to ReconAI. This allows external LLMs to invoke tools like `scan_target`, `get_findings`, `get_attack_paths`, and `verify_finding` directly.

### 5. Uncensored & Local GPU Integration

ReconAI does not impose arbitrary ethical refusals or content filters at the application layer, allowing legitimate red team operators to analyze complex attack vectors.

**Recommended Models for Ollama:**
- `deepseek-r1:7b` / `deepseek-r1:14b` — Advanced chain-of-thought attack vector synthesis.
- `dolphin-llama3` — Uncensored offensive security reasoning and PoC generation.
- `qwen2.5-coder:7b` — Superior comprehension of disassembled source code and web APIs.
- `llama3:latest` — High-speed general summarization and triage.

**Remote GPU Setup:**
If your LLM is running on a dedicated GPU machine:
```bash
# On GPU machine:
export OLLAMA_HOST=0.0.0.0:11434
ollama serve

# Run ReconAI pointing to the GPU host:
reconai scan example.com --ai --ai-url http://192.168.1.50:11434 --ai-model deepseek-r1:7b
```

---

## 🎯 Pipeline Modes & Specialized Commands

### Full-Scope Scan Modes

```bash
# Passive OSINT only (Zero packet transmission to target)
reconai scan example.com -m passive

# Lightweight discovery (DNS, certs, HTTP banner grabbing)
reconai scan example.com -m light

# Standard assessment (Subdomains, ports, tech, web crawl, vulns)
reconai scan example.com -m standard

# Deep red team assessment (Fuzzing, parameter mining, secrets, cloud, CVEs)
reconai scan example.com -m deep

# Cloud attack surface audit (S3, Azure Blobs, CNAME takeovers, SSRF, IAM)
reconai scan example.com -m cloud
```

### Dedicated Focused Pipelines

For specialized workflows, ReconAI provides direct, high-speed single-focus pipelines:

```bash
# 1. Subdomain Intelligence (DNS, CT logs, Wayback, GAU, DNSx, TLS SANs)
reconai subs example.com

# 2. Port & Service Exposure (Naabu, Nmap, CDN classification, Origin IP detection)
reconai ports example.com --profile standard

# 3. Web Attack Surface (Katana crawler, FFuF, Arjun parameter mining, Screenshots)
reconai web example.com

# 4. Vulnerability & Exploit Pipeline (Nuclei, Dalfox XSS, SQLMap, Gitleaks, Subzy)
reconai vuln example.com
```

---

## ⚙️ Configuration Management

ReconAI loads configuration automatically from `config.yaml` in your working directory. You can customize timeouts, concurrency, external tool paths, and API keys:

```yaml
# config.yaml (Excerpt)
timeouts:
  http_probe: 30
  nmap_quick: 60
  nuclei: 180

concurrency:
  dns: 20
  http: 20
  crawler: 10

tools:
  httpx:
    enabled: true
    path: ""                  # Custom path e.g. "C:\\tools\\httpx.exe"
    threads: 30
    extra_args: ["-tech-detect", "-status-code"]

  nuclei:
    enabled: true
    rate_limit: 150
    extra_args: ["-severity", "info,low,medium,high,critical"]

  arjun:
    enabled: true
    threads: 5
    extra_args: ["--passive"]

api_keys:
  shodan: ""                  # Optional Shodan API key
  virustotal: ""              # Optional VirusTotal API key

ai:
  enabled: true
  url: "http://localhost:11434"
  model: "llama3"
```

---

## 🚀 Installation & Quick Start

### 1. System Requirements

- **Python**: 3.10 or higher.
- **Operating System**: Linux (Ubuntu, Debian, Kali), macOS, or Windows 10/11 (PowerShell / WSL).

### 2. Setup ReconAI

```bash
# Clone the repository
git clone https://github.com/tiwarirst/reconai.git
cd reconai

# Create virtual environment
python -m venv .venv
source .venv/bin/activate       # On Linux/macOS
.venv\Scripts\activate          # On Windows

# Install package dependencies
pip install -r requirements.txt
pip install -e .

# Audit environment and verify tools
reconai doctor
```

### 3. Verify System Health

Run the automated test suite to ensure all 71 unit and integration tests pass:

```bash
python -m pytest tests/ -v
# 71 passed in 6.25s (100% pass rate)
```

---

## 📖 Command Line Reference

```
Usage: reconai [OPTIONS] COMMAND [ARGS]...

  ReconAI — Modular Attack Surface Intelligence Platform

Commands:
  scan            Run an orchestrated reconnaissance scan against a target.
  subs            Dedicated Subdomain Intelligence Pipeline.
  ports           Dedicated Port & Service Pipeline.
  web             Dedicated Web Attack Surface Pipeline.
  vuln            Dedicated Vulnerability Pipeline.
  copilot         Interactive AI Security Copilot for scan analysis.
  ai-agent        Autonomous Red Team Attack Path Generator.
  profile-threat  Correlate assets against Threat Actor TTPs.
  mcp             Start the Model Context Protocol (MCP) server.
  doctor          Audit installed security tools and display fix commands.
  scans           Manage, inspect, and list historical scans.
  compare         Compare two scans for attack surface drift and new assets.
  report          Regenerate HTML, JSON, or Markdown reports from a scan.
```

---

## 📚 Documentation Index

For in-depth operational guides and developer references, see the `docs/` directory:

- [Architecture Guide](docs/architecture.md) — Comprehensive technical architecture, event bus, and data flow.
- [Installation Guide](docs/installation.md) — Multi-platform installation steps, package management, and Go tool setup.
- [Quick Start Guide](docs/quickstart.md) — Practical command walkthroughs and test targets.
- [AI Red Team Guide](docs/ai_redteam.md) — LLM configuration, Ollama GPU setup, Copilot usage, and attack chain modeling.
- [Tools & Fallbacks Reference](docs/tools_reference.md) — Complete breakdown of all 24+ integrated tools and their pure-Python fallbacks.

---

## 📄 License

ReconAI is released under the **MIT License**. See [LICENSE](LICENSE) for details.
