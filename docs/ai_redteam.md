# ReconAI AI & Red Team Subsystem Guide

## 1. Design Philosophy: Red Team Independence & Uncensored Analysis

During red team operations and authorized penetration tests, security engineers must analyze real attack paths, examine functional vulnerability payloads, evaluate defense evasion, and assess the true depth of potential exploitation.

Traditional commercial AI wrappers frequently impose arbitrary refusal filters (e.g. refusing to explain an SQL injection finding or declining to correlate an IAM credential leak), rendering them ineffective during critical security assessments.

**ReconAI enforces complete operational independence**:
- The application layer applies zero moralizing filters or refusal guardrails on model interactions.
- All guardrails and safety bounds are deferred directly to the user's operational engagement scope (`ScopeManager`).
- Operates natively with local, private, open-weights models running via Ollama on your own hardware or dedicated remote GPU servers, ensuring 100% confidentiality of client reconnaissance data.

---

## 2. Recommended Open-Weights Models

When running Ollama with ReconAI, select a model tailored to your operational requirements:

| Model | Size / Quant | Strengths & Operational Focus | Command |
| :--- | :--- | :--- | :--- |
| **`deepseek-r1:7b` / `14b`** | 4.7 GB / 9.0 GB | Chain-of-thought attack vector synthesis, kill chain correlation, multi-hop reasoning | `ollama pull deepseek-r1:7b` |
| **`dolphin-llama3:8b`** | 4.9 GB | Uncensored offensive security reasoning, payload analysis, adversarial simulation | `ollama pull dolphin-llama3` |
| **`qwen2.5-coder:7b`** | 4.7 GB | Deep code comprehension, decompiled JS analysis, API mining, regex exploit construction | `ollama pull qwen2.5-coder:7b` |
| **`llama3:8b`** | 4.7 GB | High-speed general summarization, triage, executive briefing generation | `ollama pull llama3` |
| **`mistral:7b`** | 4.1 GB | Compact footprint, low VRAM consumption, concise technical explanations | `ollama pull mistral` |

---

## 3. Remote GPU Host Configuration

If your primary scanning laptop lacks a dedicated GPU, you can host Ollama on an internal GPU server (e.g. RTX 3090, 4090, or cloud VM) and point ReconAI to it.

### Option A: Direct LAN Access
On the remote GPU machine:
```bash
# Allow connections on all network interfaces
export OLLAMA_HOST=0.0.0.0:11434
ollama serve
```

On your scanning host, specify the remote IP:
```bash
# In CLI:
reconai scan example.com --ai --ai-url http://192.168.1.50:11434 --ai-model deepseek-r1:7b

# Or in config.yaml:
ai:
  enabled: true
  url: "http://192.168.1.50:11434"
  model: "deepseek-r1:7b"
```

### Option B: Encrypted SSH Tunnel
If connecting over an untrusted network:
```bash
# Forward remote port 11434 to local port 11434:
ssh -L 11434:localhost:11434 user@gpu-machine-ip -N

# ReconAI connects to localhost transparently:
reconai scan example.com --ai --ai-url http://localhost:11434
```

---

## 4. Interactive Security Copilot (`reconai copilot`)

The Copilot is an interactive terminal interface that loads your scan database into memory and provides conversational analysis:

```bash
reconai copilot <scan_id>
```

### Copilot Capabilities:
1. **Target Surface Q&A**:
   ```
   copilot> What technologies were discovered on subdomains with port 8080 open?
   ```
2. **Exploitation & Depth Assessment**:
   ```
   copilot> Explain finding #3 (Reflected XSS on /search). How deep can this be leveraged in a real engagement?
   ```
3. **Defense Evasion Consultation**:
   ```
   copilot> Cloudflare WAF was detected. What encoding techniques are appropriate for probing the JSON API?
   ```
4. **Built-In Commands**:
   - `/summary`: Outputs an executive summary with overall risk posture and statistics.
   - `/critical`: Filters and presents only critical and high severity findings.
   - `/attack-paths`: Analyzes multi-hop attack paths synthesized across findings.
   - `/targets`: Lists discovered subdomains, web applications, and alive hosts.
   - `/help`: Displays help and available commands.
   - `/exit` or `exit`: Exits the copilot session.

---

## 5. Autonomous Red Team Agent (`reconai ai-agent`)

The Red Team Agent conducts automated scenario synthesis across findings:

```bash
reconai ai-agent <scan_id>
```

The agent executes a 5-phase evaluation:
- **Phase 1: Initial Foothold**: Identifies default credentials, unauthenticated endpoints, exposed admin panels, and dangling CNAME takeovers.
- **Phase 2: Execution & Validation**: Synthesizes verified parameters, vulnerable endpoints, and CVE exposures.
- **Phase 3: Privilege Escalation & Lateral Movement**: Correlates discovered internal IP ranges, active directory names, and cloud IAM credentials.
- **Phase 4: Evasion & Operational Security**: Recommends payload delivery rates, headers, and encoding based on detected WAFs and CDNs.
- **Phase 5: Automated Runbook**: Outputs formatted terminal commands for verification by human operators.

---

## 6. Threat Actor Profiler (`reconai profile-threat`)

```bash
reconai profile-threat <scan_id>
```

Analyzes target technologies (e.g. WordPress, Apache Struts, Jira, Fortinet VPN, AWS S3) against threat intelligence records to identify:
- Known threat actors actively targeting that stack (e.g., APT29, FIN7, Lazarus).
- Associated CVE campaigns and exploit kits.
- Recommended defensive mitigations and detection rules.

---

## 7. Model Context Protocol (MCP) Server

ReconAI implements the Model Context Protocol (MCP) standard, enabling modern AI development agents (Antigravity, Claude Desktop, Cursor) to directly query and interact with ReconAI scans:

```bash
reconai mcp
```

### Exposed MCP Tools:
- `scan_target(target, mode)`: Dispatches a new reconnaissance scan.
- `get_scan_summary(scan_id)`: Fetches high-level metrics and target metadata.
- `get_findings(scan_id, severity)`: Queries findings filtered by severity level.
- `get_attack_paths(scan_id)`: Queries correlated multi-stage attack paths.
- `verify_finding(scan_id, finding_id)`: Runs heuristic/closed-loop verification on a specific finding.
