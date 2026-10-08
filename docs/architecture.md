# ReconAI Architecture Specification

## 1. Architectural Philosophy

ReconAI is architected as an asynchronous, event-driven attack surface intelligence platform. It is engineered with the rigor of distributed production systems:

- **Asynchronous & Non-Blocking**: All I/O operations (HTTP probes, DNS queries, network sockets, external subprocesses) run asynchronously via Python 3.10+ `asyncio`. The central event loop is never blocked.
- **Fail-Safe & Self-Healing**: External tool binaries are treated as optional performance accelerators. If a binary is missing or fails, the platform autonomously invokes its pure-Python fallback engine without interrupting the scan.
- **Stateless & Idempotent**: Tool adapters do not maintain internal mutable state between target invocations. Database writes use atomic `ON CONFLICT DO UPDATE` (upsert) queries.
- **Decoupled via Async Event Bus**: Modules do not import or call one another directly. They publish and subscribe to typed events through an $O(1)$ async event bus.

---

## 2. System Component Topology

```
┌────────────────────────────────────────────────────────────────────────┐
│                              CLI Layer                                 │
│  reconai scan | subs | ports | web | vuln | copilot | ai-agent | mcp   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Pipeline Orchestrator                           │
│  - Target normalization & ScopeManager boundary validation             │
│  - ConfigManager resolution (CLI overrides > config.yaml > defaults)   │
│  - Scan session lifecycle management & process tree registration       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Asynchronous O(1) EventBus                         │
│  - Broadcasts discoveries (Subdomains, IPs, Ports, URLs, Findings)     │
│  - Decouples producer modules from consumer modules                    │
│  - Fixed-size circular event history buffer via collections.deque      │
└──────────────┬────────────────────┬────────────────────┬───────────────┘
               │                    │                    │
               ▼                    ▼                    ▼
┌───────────────────────┐┌───────────────────────┐┌──────────────────────┐
│    Active Modules     ││    Passive Modules    ││  Web & Vuln Modules  │
│ (HTTP, Naabu, Nmap,   ││ (DNS, CT, Wayback,    ││ (Katana, FFuF,       │
│  TLS, CDN Classifier) ││  GAU, ASN, SaaS Enum) ││  Nuclei, Arjun, etc) │
└──────────────┬────────┘└──────────┬────────────┘└──────────┬───────────┘
               │                    │                        │
               └────────────────────┼────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      CommandRunner & Fallbacks                         │
│  - Subprocess tree lifecycle management & timeout enforcement          │
│  - Shell-injection validation & dangerous character neutralization     │
│  - Autonomous pure-Python fallback invocation when tool is absent      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Idempotent Database Layer                          │
│  - Thread-safe SQLite management via aiosqlite and WAL journaling      │
│  - Transactional batch insertions & conflict-safe upsert queries       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│              Correlation Engine, AI Subsystem & Reporting              │
│  - Attack surface graph synthesis & multi-hop kill chain modeling      │
│  - Offline heuristic / LLM false-positive filtering                    │
│  - Interactive AI Copilot, Red Team Agent & Model Context Protocol     │
│  - Multi-format report generation (Interactive HTML, Markdown, JSON)   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Subsystem Deep Dive

### 3.1 Event-Driven Bus (`reconai.core.events.bus`)
The event bus decouples discovery from exploitation:
1. When a subdomain discovery module (e.g. `cert_transparency` or `subfinder`) discovers a new hostname, it emits a `SUBDOMAIN_DISCOVERED` event.
2. The DNS resolution module (`dnsx`) is subscribed to `SUBDOMAIN_DISCOVERED` and resolves the A/AAAA/CNAME records.
3. Upon IP resolution, `IP_DISCOVERED` events trigger port scanners (`naabu` / `ports`).
4. Discovered open web ports trigger `HTTP_PROBED` events, driving crawlers, TLS inspectors, and technology detectors simultaneously.

All handler invocations are wrapped in isolation blocks: a failure or timeout in one subscriber never stops other subscribers from processing the event.

### 3.2 Process Execution & Zombie Management (`reconai.core.executor`)
External processes are managed with stringent execution controls:
- **Argument Sanitization**: Arguments are passed as explicit `list[str]` vectors to `asyncio.create_subprocess_exec` without invoking a shell (`shell=False`).
- **Dangerous Character Guard**: The `CommandRunner.is_safe()` validator rejects command-chaining and shell-injection tokens (`;&|`$<>!\n\r`) before execution.
- **Process-Tree Termination**: On timeout, `ProcessManager.terminate_tree(pid)` recursively walks child processes using `psutil` or platform-native signals (`SIGTERM` followed by `SIGKILL`), preventing orphaned child processes.

### 3.3 Autonomous Pure-Python Fallback Layer
Every module that interfaces with an external binary is built with a non-blocking pure-Python fallback:
- **`http_probe`**: Uses `httpx.AsyncClient` with HTTP/2 and follow-redirect logic if `httpx` CLI is unavailable.
- **`tls_probe`**: Uses native Python `socket` + `ssl` context handshake to extract SANs, expiration dates, and cipher suites if `tlsx` is missing.
- **`archive_urls`**: Directly queries the AlienVault OTX API and Wayback Machine CDX API if `gau` or `waybackurls` is absent.
- **`arjun_params`**: Performs differential parameter probing comparing response lengths and status variations if `arjun` CLI is absent.
- **`subzy_takeover`**: Inspects CNAME chains against a built-in library of 20+ dangling service signatures if `subzy` is absent.
- **`secrets`**: Employs Shannon entropy analysis and regex signatures (AWS, Slack, JWT, GCP, Stripe) if `gitleaks` or `trufflehog` is absent.

### 3.4 Data Integrity & SQLite Schema
ReconAI persists all state in a normalized SQLite schema:
- **Atomic Upserts**: Subdomains, ports, URLs, endpoints, and findings use composite unique keys with `ON CONFLICT DO UPDATE`. Rescanning a target enriches existing records with new metadata (timestamps, response codes, evidence) rather than duplicating rows.
- **Batch Processing**: High-throughput crawlers buffer records and flush them in atomic database transactions, sustaining 10,000+ records per minute.

---

## 4. AI & Red Team Engine Architecture

The AI subsystem operates across three modular components:

1. **Local & Remote LLM Client (`reconai.ai.local`)**:
   - Interfaces with any standard OpenAI-compatible or Ollama endpoint over HTTP.
   - Configurable timeout, temperature, and streaming response handlers.
   - Zero application-level moralizing or guardrail blocking, granting full analytical flexibility for penetration tests.

2. **Attack Surface Correlation Engine (`reconai.core.correlation.engine`)**:
   - Synthesizes findings into unified attack paths (e.g., *Discovered Subdomain -> Cloud Bucket -> Leaked Credentials -> IAM Admin Privilege*).
   - Generates contextual, reproducible Proof-of-Concepts (PoCs) customized to target parameters and endpoints.

3. **Model Context Protocol (MCP) Interface (`reconai.mcp.server`)**:
   - Exposes ReconAI as an agentic toolserver over stdio.
   - Implements JSON-RPC 2.0 endpoints for listing available recon tools, querying scan databases, and dispatching targeted security verifications from modern AI environments.
