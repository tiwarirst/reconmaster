<div align="center">

<br/>

# ⚡ ReconAI

### Next-Generation, Asynchronous, AI-Powered Reconnaissance Framework

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img alt="License" src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge"/>
  <img alt="Code Style" src="https://img.shields.io/badge/Code_Style-Black-000000?style=for-the-badge&logo=python&logoColor=white"/>
  <img alt="Type Safety" src="https://img.shields.io/badge/Type_Safety-Mypy-2a6db5?style=for-the-badge"/>
  <img alt="Async" src="https://img.shields.io/badge/Runtime-Asyncio-f97316?style=for-the-badge"/>
  <img alt="Status" src="https://img.shields.io/badge/Status-Active-22c55e?style=for-the-badge"/>
</p>

<p align="center">
  <em>Automated · Idempotent · Stateless · Concurrent · Production-Grade</em>
</p>

<br/>

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Why ReconAI?](#-why-reconai)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Module Breakdown](#-module-breakdown)
- [Scan Modes](#-scan-modes)
- [Installation](#️-installation)
- [Usage](#-usage)
- [Engineering Standards](#️-engineering-standards)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**ReconAI** is a production-grade, fully asynchronous reconnaissance and vulnerability discovery framework built for security engineers and bug bounty hunters who demand accuracy, speed, and reliability at scale.

Built on a strict **event-driven architecture**, ReconAI eliminates the fragile, sequential approach of traditional shell-script wrappers. Instead, it orchestrates the world's most powerful open-source security tools — `Nmap`, `Nuclei`, `FFuF`, `SQLMap`, `Amass`, `Dalfox`, and more — into a **single, cohesive, idempotent pipeline** that can be paused, resumed, and audited at any point without losing a single data point.

> ReconAI is not a script. It is a **framework** — engineered with the same rigor as production backend systems: strict type safety, zero race conditions, atomic database operations, and a fully decoupled module graph.

---

## 💡 Why ReconAI?

Most reconnaissance tools are single-purpose, tightly coupled, or stateful — making them brittle, slow, and error-prone at scale.

| Capability | Traditional Tools | ReconAI |
|---|---|---|
| **Concurrency** | Sequential execution | Fully async, event-driven pipeline |
| **Data Integrity** | File-based, lossy | Idempotent SQLite with atomic upserts |
| **Tool Coupling** | Hard-coded pipelines | Decoupled via O(1) async event bus |
| **Race Conditions** | Common with temp files | Zero — stateless adapters, no shared state |
| **Resumability** | Must restart from scratch | Crash-safe; resume from any point |
| **False Positives** | Manual triage | AI/LLM-powered deduplication and PoC generation |
| **Type Safety** | None | Strict `mypy` — zero errors across 100+ files |
| **Cloud Coverage** | Limited | AWS S3, GCP Storage, Azure Blobs, IAM validation |

---

## 🚀 Key Features

### 🔄 Asynchronous Event Bus
True loose coupling via an **O(1) async event bus**. A subdomain discovered by `Subfinder` immediately publishes an event that triggers `DNSx` for resolution, which in turn triggers `Nmap` for port scanning — all concurrently, without any module waiting on another.

### 🛡️ Idempotent Database Persistence
All findings are persisted to a **robust SQLite schema** featuring strict `UNIQUE` constraints and `ON CONFLICT DO UPDATE` (upsert) semantics. You can pause, crash, or restart a scan mid-execution — data is never lost, duplicated, or corrupted.

### 🧩 Stateless Tool Adapters
Every tool integration (`Nuclei`, `Dalfox`, `SQLMap`, `FFuF`) is **strictly stateless**. Temporary file lifecycles are owned exclusively by the async orchestrator, eliminating race conditions during 100+ concurrent brute-force or fuzzing operations.

### 🧠 Intelligent Attack Surface Correlation
Findings are not left in isolation. ReconAI's **correlation engine** maps IPs, open ports, discovered directories, technologies, and vulnerabilities into a unified **attack surface graph** — giving you context, not just raw data.

### 🤖 AI-Powered Deduplication & PoC Generation
Integrates seamlessly with LLM modules to **filter false positives**, classify severity, and generate **dynamic, contextual Proof-of-Concepts** tailored to each finding.

### ☁️ Deep Cloud Reconnaissance
Full multi-cloud coverage: **AWS S3, GCP Storage, Azure Blob** bucket enumeration, 40+ CNAME service fingerprint checks for subdomain takeover, SSRF → cloud metadata (IMDS) bypasses, and live **IAM credential validation**.

### 🔒 Fail-Safe Execution Engine
All tool integrations run inside **memory-safe async subprocess wrappers** with configurable timeouts, zombie-process cleanup via process-tree termination, and deep crash isolation — the event loop never breaks.

---

## 🧩 Architecture

ReconAI is built on a **strictly layered, modular architecture** where every component has a single responsibility and communicates only through well-defined interfaces.

```
reconai/
├── core/
│   ├── database/       # Idempotent SQLite session managers & fully-typed ORM models
│   ├── events/         # O(1) async publish/subscribe event bus for module orchestration
│   ├── executor/       # Safe async subprocess runner with timeout & zombie-process cleanup
│   └── correlation/    # Attack surface graph builder — correlates all finding types
│
├── integrations/       # Stateless, single-responsibility tool wrappers
│   ├── nmap.py         # Port & service scanner
│   ├── nuclei.py       # Template-based vulnerability scanner
│   ├── ffuf.py         # High-speed web fuzzer
│   ├── sqlmap.py       # Automated SQL injection engine
│   ├── dalfox.py       # XSS parameter analysis & PoC generator
│   └── cloud_enum.py   # Multi-cloud asset enumerator
│
├── modules/
│   ├── passive/        # Zero-traffic recon: DNS, crt.sh, Whois, Wayback, SPF/DMARC, SaaS
│   ├── active/         # Subfinder, Nmap, HTTP Probing, CDN detection & origin IP resolution
│   ├── web/            # FFuF, WhatWeb, Katana crawling, API/GraphQL mining, Dev artifact detection
│   ├── vuln/           # Nuclei CVEs, SQLi, XSS, Secrets scanning (TruffleHog)
│   └── cloud/          # S3/GCS/Azure buckets, CNAME takeover, SSRF IMDS, IAM validation
│
├── ai/                 # LLM deduplication, severity classification & PoC generation
├── intelligence/       # Threat intelligence feeds & enrichment pipelines
├── mcp/                # Model Context Protocol server for agentic integration
├── reports/            # Structured report generator (JSON, Markdown, HTML)
├── ui/                 # Rich terminal UI components & live progress displays
└── cli/                # CLI entrypoint, argument parsing & scan orchestration
```

**Data Flow:**

```
Target Domain
     │
     ▼
┌─────────────────────────────────────────────────────┐
│                   CLI Orchestrator                   │
│              (Selects modules by scan mode)          │
└─────────────────────┬───────────────────────────────┘
                      │  Publishes events to:
                      ▼
┌─────────────────────────────────────────────────────┐
│               Async O(1) Event Bus                   │
│         (Decouples all module communication)         │
└──────┬──────────┬──────────┬──────────┬─────────────┘
       │          │          │          │
       ▼          ▼          ▼          ▼
  [Passive]   [Active]    [Web]     [Cloud]
  Modules     Modules    Modules    Modules
       │          │          │          │
       └──────────┴──────────┴──────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│           Idempotent SQLite Database                 │
│    (Atomic upserts · Crash-safe · Zero duplication) │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│         Correlation Engine + AI Deduplication        │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
              Structured Report
           (JSON / Markdown / HTML)
```

---

## 📦 Module Breakdown

### Passive Reconnaissance

| Module | Description |
|--------|-------------|
| DNS Enumeration | Brute-force & recursive DNS subdomain resolution |
| Certificate Transparency | crt.sh queries for historical subdomain discovery |
| WHOIS Lookup | Registrar, registrant & nameserver enumeration |
| Wayback Machine | Historical URL and endpoint extraction from Archive.org |
| Email Security | SPF, DKIM & DMARC policy analysis |
| SaaS Workspace Enum | Identifies linked Google Workspace, Office 365, Slack tenants |

### Active Reconnaissance

| Module | Description |
|--------|-------------|
| Subfinder | Multi-source subdomain discovery with live DNS validation |
| Port Scanning | Full TCP/UDP port scan via `Nmap` with service & version detection |
| HTTP Probing | Technology fingerprinting, status codes & redirect chain analysis |
| CDN & Origin IP | Identifies CDN providers and resolves true origin server IPs |

### Web Reconnaissance

| Module | Description |
|--------|-------------|
| Directory Fuzzing | High-speed fuzzing via `FFuF` with custom wordlists |
| Web Crawler | Deep-link crawling via `Katana` with JS-rendered page support |
| API & GraphQL Miner | Extracts undocumented REST endpoints and GraphQL introspection |
| Dev Artifact Detection | Discovers exposed `.git`, `.env`, Spring Actuator, and admin panels |
| Technology Detection | `WhatWeb` fingerprinting for frameworks, CMS, and server stacks |

### Vulnerability Scanning

| Module | Description |
|--------|-------------|
| Nuclei | Template-based CVE, misconfiguration & exposure scanning |
| SQL Injection | Automated injection via `SQLMap` across discovered endpoints |
| XSS Scanning | Parameter-level XSS detection and PoC generation via `Dalfox` |
| Secrets Detection | Source code & response scanning for leaked keys via `TruffleHog` |

### Cloud Reconnaissance

| Module | Description |
|--------|-------------|
| Bucket Enumeration | AWS S3, GCP Storage & Azure Blob public/private bucket discovery |
| Subdomain Takeover | 40+ CNAME service fingerprints for dangling DNS detection |
| SSRF → Cloud Metadata | SSRF payloads targeting IMDS endpoints (AWS, GCP, Azure) |
| IAM Validation | Live validation of discovered cloud credentials and IAM permissions |

---

## 🎯 Scan Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `passive` | Zero-traffic API queries (crt.sh, Archive.org, DNS) | Initial recon without alerting the target |
| `light` | Passive + fast, non-intrusive HTTP probing | Quick asset mapping |
| `standard` | Subdomains, ports, tech fingerprinting, crawling, vuln checks | General-purpose penetration tests |
| `deep` | Full active scan + fuzzing + heavy vuln checks + cloud | Comprehensive bug bounty or red team engagements |
| `cloud` | Multi-cloud bucket enum, CNAME takeover, SSRF IMDS, IAM | Cloud-focused attack surface assessments |
| `browser` | Real-browser crawling via Chrome CDP | Authenticated flows & SPA reconnaissance |

---

## 🛠️ Installation

### Prerequisites

ReconAI requires **Python 3.9+** and a set of external Go/Python/C security binaries on your system `$PATH`.

**Install external tool dependencies:**

```bash
# Go-based tools (requires Go 1.20+)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest

# Python-based tools
pip install trufflehog
pip install cloud-enum       # Optional, for cloud enumeration

# System packages (Debian/Ubuntu)
sudo apt-get install -y nmap sqlmap whatweb
```

**Verify all dependencies are accessible:**

```bash
python -m reconai doctor
```

### Install ReconAI

```bash
# 1. Clone the repository
git clone https://github.com/tiwarirst/reconai.git
cd reconai

# 2. (Recommended) Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate         # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Verify installation
python -m reconai --version
```

---

## 🎮 Usage

ReconAI exposes a clean, terminal-rich CLI powered by `Rich`.

### Core Scanning

```bash
# Passive scan — zero traffic sent to the target
python -m reconai scan example.com --mode passive

# Light scan — passive + HTTP probing
python -m reconai scan example.com --mode light

# Standard scan — subdomains, ports, tech, crawl, vulns
python -m reconai scan example.com --mode standard

# Deep scan — all modules, maximum coverage
python -m reconai scan example.com --mode deep

# Cloud-focused scan
python -m reconai scan example.com --mode cloud
```

### Advanced Options

```bash
# Set output format (json, markdown, html)
python -m reconai scan example.com --mode deep --output html

# Limit concurrency (default: 50)
python -m reconai scan example.com --mode deep --concurrency 25

# Set a global tool timeout in seconds
python -m reconai scan example.com --mode standard --timeout 60

# Resume an interrupted scan by ID
python -m reconai scan example.com --mode deep --resume <scan_id>

# Exclude specific modules
python -m reconai scan example.com --mode deep --exclude vuln,cloud
```

### Utility Commands

```bash
# Check health of all installed dependencies
python -m reconai doctor

# List all completed scan sessions
python -m reconai scans list

# View detailed findings from a past scan
python -m reconai scans show <scan_id>

# Delta analysis — compare two scans to detect new assets or regressions
python -m reconai compare <old_scan_id> <new_scan_id>

# Export findings in a structured format
python -m reconai export <scan_id> --format json --output ./report.json
```

---

## 🏗️ Engineering Standards

ReconAI is held to the same engineering standards as production backend systems.

### ✅ Zero Race Conditions
All tool adapter instances are **strictly stateless**. They share no mutable state between invocations. Temporary files created during execution are owned and lifecycle-managed exclusively by the async orchestrator, which guarantees cleanup even on hard crashes.

### ✅ Zero Data Loss
Every database write is wrapped in a transactional boundary. `ON CONFLICT DO UPDATE` upsert semantics ensure that no finding is ever lost or duplicated, regardless of when a scan is interrupted or restarted.

### ✅ Zero O(n) Queue Penalty
BFS crawlers and event history buffers use `collections.deque` with a strict `maxlen`, providing **O(1)** append and pop operations and preventing unbounded memory growth during large-scope scans.

### ✅ Zero Deadlocks
The subprocess execution engine guarantees **process-tree termination** on timeout using `SIGKILL` on the entire process group — never leaving orphaned `nmap`, `nuclei`, or `ffuf` processes on the host OS.

### ✅ Strict Type Safety
The entire codebase maintains **zero `mypy` errors** across 100+ files under strict mode. All public interfaces are fully annotated with no `Any` types in core logic.

### ✅ Code Quality Tools

| Tool | Purpose |
|------|---------|
| `black` | Auto-formatter (PEP 8, line-length 88) |
| `flake8` | Linter with security-focused plugins |
| `mypy` | Static type checker (strict mode) |
| `pytest` | Test runner with `pytest-asyncio` for async test support |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome.

### Development Setup

```bash
git clone https://github.com/tiwarirst/reconai.git
cd reconai
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # black, mypy, pytest, flake8
```

### Pre-Submission Checklist

Before submitting a pull request, ensure all of the following pass locally:

```bash
# 1. Format your code
python -m black reconai/

# 2. Run the type checker — zero errors required
python -m mypy reconai/

# 3. Run the linter
python -m flake8 reconai/

# 4. Run the full test suite
python -m pytest tests/ -v
```

> Pull requests that introduce `mypy` errors or fail the test suite will not be merged.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](./LICENSE) for full terms.

---

<div align="center">

**ReconAI** — Built with precision. Engineered for scale. Designed for the real world.

<br/>

*If ReconAI has been useful in your work, please consider giving it a ⭐ on GitHub.*

</div>
