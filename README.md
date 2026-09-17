<div align="center">
  <img src="https://raw.githubusercontent.com/reconai/reconai/main/assets/logo.png" alt="ReconAI Logo" width="200" onerror="this.style.display='none'"/>
  
  # ReconAI
  
  **Next-Generation, Asynchronous, AI-Powered Reconnaissance Framework**
  
  [![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
  [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
  [![Type Checker: mypy](https://img.shields.io/badge/type%20checker-mypy-blue)](http://mypy-lang.org/)
  
  *Automated. Idempotent. Stateless. Fast.*
</div>

---

## ⚡ Overview

**ReconAI** is an advanced, fully asynchronous reconnaissance and vulnerability discovery framework. Built on top of an event-driven architecture, ReconAI seamlessly orchestrates the world's most powerful open-source security tools (Nmap, Nuclei, FFuF, SQLMap, Amass, etc.) into a single, cohesive, idempotent pipeline.

Unlike traditional shell-script wrappers, ReconAI guarantees data integrity, features strict type safety (zero `mypy` errors across 100+ files), and runs on a fully stateless adapter pattern to ensure massive concurrency without race conditions or temp file leaks.

## 🚀 Key Features

- **Asynchronous Event Bus:** True loose coupling. A subdomain discovered by `Subfinder` immediately triggers a DNS resolution by `DNSx`, which in turn triggers a port scan by `Nmap`. Modules don't wait for each other.
- **Idempotent Database Persistence:** Powered by a robust SQLite schema with strict `UNIQUE` constraints and `ON CONFLICT DO UPDATE` (upserts). You can pause, crash, or restart a scan, and data will never be duplicated.
- **Stateless Tool Adapters:** Tool integrations (Nuclei, Dalfox, SQLMap, FFuF) are strictly stateless. Temp file lifecycles are owned by the async orchestrator, eliminating race conditions when running 100+ concurrent brute-force attacks.
- **Intelligent Correlation:** Correlates findings (IPs, open ports, directories, vulnerabilities) into a unified attack surface graph.
- **Smart AI Deduplication:** Integrates seamlessly with AI/LLM modules to filter out false positives and generate dynamic, contextual proof-of-concepts.
- **Fail-Safe & Graceful:** All integrations run in memory-safe execution wrappers with configurable timeouts, zombie-process cleanup, and deep crash isolation.

## 🧩 Architecture

ReconAI is built on a highly modular core:

```text
reconai/
├── core/
│   ├── database/     # Idempotent SQLite managers & typed models
│   ├── events/       # Fast O(1) async event bus for module triggering
│   ├── executor/     # Safe async subprocess runner & timeout managers
│   └── correlation/  # Attack surface graph builder
├── integrations/     # Stateless wrappers (Nmap, Nuclei, FFuF, SQLMap, Dalfox)
├── modules/
│   ├── passive/      # DNS Enum, crt.sh, Whois, Waybackurls
│   ├── active/       # Subfinder, Nmap Port Scanning, HTTP Probing
│   ├── web/          # FFuF Dir Brute, WhatWeb, Katana Crawler
│   └── vuln/         # Nuclei, SQLi (SQLMap), XSS (Dalfox), Secrets
└── cli/              # Rich console UI and orchestration logic
```

## 🛠️ Installation

### 1. Prerequisites
Ensure you have Python 3.9+ installed. ReconAI relies on several external Go/Python/C security binaries. Ensure the following tools are installed and available in your system `$PATH`:

* `subfinder`, `dnsx`, `naabu` / `nmap`
* `httpx`, `katana`, `waybackurls`
* `ffuf`, `whatweb`, `sqlmap`, `dalfox`, `nuclei`, `trufflehog`

### 2. Install ReconAI
```bash
git clone https://github.com/tiwarirst/reconai.git
cd reconai
python -m pip install -r requirements.txt
```

## 🎯 Usage

ReconAI provides a beautiful, terminal-rich CLI. 

```bash
# Basic passive reconnaissance
python -m reconai --target example.com --mode passive

# Comprehensive web + vulnerability scan
python -m reconai --target example.com --mode full --output report.html

# Run specific modules only
python -m reconai --target example.com --modules subdomains,dnsx,http_probe,nuclei
```

### Modes of Operation

1. **Passive**: Queries third-party APIs (crt.sh, Archive.org, DNS) without sending direct traffic to the target.
2. **Active**: Performs DNS resolution, port scanning, and basic HTTP probing.
3. **Web**: Actively crawls web applications, brute-forces directories, and fingerprints technology stacks.
4. **Vuln**: Launches heavy offensive payloads (SQLMap, Dalfox, Nuclei) against discovered attack surfaces.
5. **Full**: Chains all of the above continuously.

## 🧠 The "God-Level" Standards (Internal Audit)

ReconAI maintains an exceptionally high code quality standard. The architecture has been rigorously audited and hardened against standard framework pitfalls:
- **Zero Race Conditions:** Adapter instances share no state.
- **Zero Data Loss:** `try/except` boundaries protect the event loop. Database interactions are atomic.
- **Zero O(n) Queues:** BFS crawlers and Event Histories use `collections.deque` for O(1) pops and strict max-length eviction.
- **Zero Deadlocks:** The subprocess runner guarantees process-tree termination on timeouts, never leaving zombie `nmap` or `nuclei` instances on the OS.

## 🤝 Contributing

Contributions are welcome! Please ensure that your pull requests pass the strict type-checker before submitting:

```bash
python -m mypy reconai
```

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.
