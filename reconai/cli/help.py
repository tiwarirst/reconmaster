"""ReconAI — Comprehensive Help & Beginner Onboarding Module.

Provides:
  • ``reconai help``              — Full interactive command reference
  • ``reconai help <COMMAND>``    — Deep-dive into a specific command
  • ``reconai examples``          — Ready-to-run example recipes
  • ``reconai quickstart``        — Step-by-step beginner walkthrough

Design goals
------------
- Every real command is documented with real, copy-paste-ready examples.
- Placeholder / dummy target values clearly show beginners what to substitute.
- Sections are colour-coded so the reader's eye naturally groups Scan vs AI vs Utility.
- No external dependencies beyond Click and Rich (already in requirements).
"""
from __future__ import annotations

from typing import NamedTuple

import click
from rich.columns import Columns
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ─────────────────────────────────────────────────────────────────────────────
# Data model — every command lives here so it is the single source of truth
# ─────────────────────────────────────────────────────────────────────────────

class CommandDoc(NamedTuple):
    name: str
    group: str           # display group / category
    tagline: str         # one-line summary (shown in the overview table)
    description: str     # multi-line rich markup (shown in detail view)
    synopsis: str        # usage line(s)
    options: list[tuple[str, str]]   # (flag, description)
    examples: list[tuple[str, str]]  # (command, comment)
    beginner_tip: str    # 💡 tip block for newcomers


# ── colour palette used throughout ───────────────────────────────────────────
C_CMD   = "bold cyan"
C_OPT   = "bold yellow"
C_EX    = "green"
C_HEAD  = "bold white"
C_DIM   = "dim"
C_TIP   = "bold blue"
C_WARN  = "bold red"

# ─────────────────────────────────────────────────────────────────────────────
# Command catalogue (exhaustive — mirrors every @cli.command in main.py)
# ─────────────────────────────────────────────────────────────────────────────

COMMANDS: list[CommandDoc] = [

    # ── SCANNING ──────────────────────────────────────────────────────────────

    CommandDoc(
        name="scan",
        group="🔍 Scanning",
        tagline="Full orchestrated recon pipeline — the main command for most users",
        description=(
            "Runs the complete ReconAI reconnaissance pipeline against a target domain, IP, or CIDR.\n\n"
            "Internally orchestrates 40+ modules across passive OSINT, active port/service detection,\n"
            "web fingerprinting, vulnerability scanning, cloud enumeration, and AI analysis.\n\n"
            "Choose [bold cyan]--mode[/bold cyan] to control scope and depth:\n"
            "  • [cyan]passive[/cyan]   — OSINT only (no active probes, safe for pre-engagement)\n"
            "  • [cyan]light[/cyan]     — DNS + HTTP probe + tech stack (fast, ~5 min)\n"
            "  • [cyan]standard[/cyan]  — Full surface mapping (default, ~20 min)\n"
            "  • [cyan]deep[/cyan]      — Everything + AI analysis (slow, most comprehensive)\n"
            "  • [cyan]browser[/cyan]   — Headless browser recon (JS-heavy apps)\n"
            "  • [cyan]cloud[/cyan]     — AWS/GCP/Azure attack surface\n"
            "  • [cyan]vuln[/cyan]      — Vulnerability-focused (Nuclei, SQLMap, Dalfox)\n"
            "  • [cyan]subs[/cyan]      — Subdomain intelligence only\n"
            "  • [cyan]ports[/cyan]     — Port & service detection only\n"
            "  • [cyan]web[/cyan]       — Web attack surface only"
        ),
        synopsis="reconai scan <TARGET> [OPTIONS]",
        options=[
            ("-m, --mode", "Scan mode: passive | light | standard | deep | browser | cloud | vuln | subs | ports | web  (default: standard)"),
            ("-p, --profile", "Port scan profile: quick | standard | service | full  (default: quick)"),
            ("--timeout INT", "Override global per-module timeout in seconds"),
            ("--dry-run", "Print what would run WITHOUT executing anything — safe to use anytime"),
            ("--ai", "Enable AI-powered threat analysis via Ollama LLM"),
            ("--ai-url URL", "Ollama server URL — e.g. http://192.168.1.50:11434 for a remote GPU"),
            ("--ai-model NAME", "Ollama model — e.g. llama3, deepseek-r1:7b, mistral"),
            ("--strict-scope", "Block modules from touching hosts outside the stated target"),
            ("--scope-file PATH", "YAML file with explicit allow/deny scope rules"),
            ("--config PATH", "Custom config.yaml to override defaults"),
            ("--verbose", "Stream raw tool output to the terminal in real time"),
            ("--debug", "Enable debug-level logging for troubleshooting"),
        ],
        examples=[
            ("reconai scan example.com",                                     "Standard scan — the most common starting point"),
            ("reconai scan example.com --dry-run",                           "Preview what would run, touch nothing"),
            ("reconai scan example.com -m passive",                          "OSINT-only, zero active probes"),
            ("reconai scan example.com -m deep --ai",                        "Deepest scan + AI threat analysis"),
            ("reconai scan 192.168.1.0/24 -m ports -p full",                 "Full port scan on an internal subnet"),
            ("reconai scan example.com -m vuln --ai --ai-model deepseek-r1:7b", "Vuln scan with DeepSeek AI model"),
            ("reconai scan target.com --strict-scope --scope-file scope.yml","Strict scope enforcement from YAML file"),
            ("reconai scan 10.0.0.1 -m light --timeout 120",                "Fast light scan with 2-min timeout"),
        ],
        beginner_tip=(
            "Start with [cyan]reconai scan example.com --dry-run[/cyan] to preview the pipeline.\n"
            "Then run [cyan]reconai scan example.com -m passive[/cyan] — no active probes, completely safe."
        ),
    ),

    CommandDoc(
        name="subs",
        group="🔍 Scanning",
        tagline="Dedicated subdomain intelligence pipeline (CT logs, DNS brute, archive, DNSx)",
        description=(
            "Runs only the subdomain-discovery modules:\n"
            "  Certificate Transparency logs → passive DNS enum → archive.org → subfinder/amass →\n"
            "  DNSx validation → active brute-force (if tools installed)\n\n"
            "Results are saved to the scan database and can be fed to any post-scan command."
        ),
        synopsis="reconai subs <TARGET> [OPTIONS]",
        options=[
            ("--dry-run", "Show what would run without executing"),
            ("--timeout INT", "Override global timeout (seconds)"),
            ("--strict-scope", "Limit discovery strictly to the given target"),
            ("--scope-file PATH", "YAML scope rules file"),
        ],
        examples=[
            ("reconai subs example.com",                      "Full subdomain discovery on example.com"),
            ("reconai subs example.com --dry-run",            "Preview — what tools will run?"),
            ("reconai subs bugcrowd.com --strict-scope",      "Only enumerate *.bugcrowd.com, nothing else"),
        ],
        beginner_tip="Great first command! It's entirely passive by default — safe to run on any target.",
    ),

    CommandDoc(
        name="ports",
        group="🔍 Scanning",
        tagline="Dedicated port & service detection pipeline (Naabu + Nmap + CDN classifier)",
        description=(
            "Runs only the port-scanning and service-fingerprinting modules:\n"
            "  Naabu fast TCP scan → Nmap service detection → CDN classifier\n\n"
            "Profile controls depth:\n"
            "  • [cyan]quick[/cyan]   — Top 1 000 ports (~1 min)\n"
            "  • [cyan]standard[/cyan]— Top 10 000 ports (~5 min)\n"
            "  • [cyan]service[/cyan] — Top 10 000 + banner grab (~10 min)\n"
            "  • [cyan]full[/cyan]    — All 65 535 ports + full Nmap service scan (~30 min)"
        ),
        synopsis="reconai ports <TARGET> [OPTIONS]",
        options=[
            ("-p, --profile", "quick | standard | service | full  (default: quick)"),
            ("--dry-run", "Preview without executing"),
            ("--timeout INT", "Override timeout (seconds)"),
            ("--strict-scope", "Strict boundary enforcement"),
            ("--scope-file PATH", "YAML scope rules file"),
        ],
        examples=[
            ("reconai ports example.com",                     "Quick top-1000 port scan"),
            ("reconai ports 192.168.1.1 -p full",             "Complete 65 535-port scan on an IP"),
            ("reconai ports 10.0.0.0/24 -p service",         "Service fingerprint on internal subnet"),
        ],
        beginner_tip=(
            "Use [cyan]-p quick[/cyan] first to see what's open, then target interesting ports\n"
            "with [cyan]-p service[/cyan] for version/banner detail."
        ),
    ),

    CommandDoc(
        name="web",
        group="🔍 Scanning",
        tagline="Web attack surface pipeline (HTTP probe, WAF, tech stack, crawl, screenshots)",
        description=(
            "Runs only the web-fingerprinting and content-discovery modules:\n"
            "  HTTP probe → WAF detection → Technology fingerprint → Header analysis →\n"
            "  Web crawl → Directory bruteforce → JavaScript analysis → Screenshots"
        ),
        synopsis="reconai web <TARGET> [OPTIONS]",
        options=[
            ("--dry-run", "Preview without executing"),
            ("--timeout INT", "Override timeout (seconds)"),
            ("--strict-scope", "Strict boundary enforcement"),
            ("--scope-file PATH", "YAML scope rules file"),
        ],
        examples=[
            ("reconai web example.com",               "Full web surface mapping"),
            ("reconai web https://app.example.com",   "Target a specific subdomain URL"),
        ],
        beginner_tip="Useful when you already know what subdomains exist and want to map their web surface.",
    ),

    CommandDoc(
        name="cloud",
        group="🔍 Scanning",
        tagline="Cloud attack surface pipeline (S3/GCS/Azure buckets, subdomain takeover, SSRF)",
        description=(
            "Runs cloud-focused recon modules:\n"
            "  S3 / GCS / Azure blob bucket enumeration → Cloud metadata SSRF detection →\n"
            "  Subdomain takeover via CNAME analysis (Subzy) → SaaS service enumeration →\n"
            "  IAM misconfiguration analysis → ASN and cloud-asset correlation\n\n"
            "AI analysis is automatically enabled in this mode."
        ),
        synopsis="reconai cloud <TARGET> [OPTIONS]",
        options=[
            ("--ai", "Enable Ollama AI analysis (auto-enabled in cloud mode)"),
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model name"),
            ("--dry-run", "Preview without executing"),
            ("--timeout INT", "Override timeout (seconds)"),
            ("--strict-scope", "Strict scope enforcement"),
        ],
        examples=[
            ("reconai cloud example.com",                        "Full cloud attack surface mapping"),
            ("reconai cloud example.com --ai",                   "With AI-powered risk analysis"),
            ("reconai cloud example.com --dry-run",              "Preview — what cloud modules run?"),
        ],
        beginner_tip=(
            "Look for [bold red]CRITICAL[/bold red] S3 bucket findings — open buckets are common and\n"
            "often hold sensitive data or allow arbitrary file upload."
        ),
    ),

    CommandDoc(
        name="vuln",
        group="🔍 Scanning",
        tagline="Vulnerability pipeline (Nuclei, secrets, SQLMap, Dalfox, API miner)",
        description=(
            "Runs vulnerability-detection modules:\n"
            "  Nuclei (CVE templates) → Secret scanner (API keys, tokens) →\n"
            "  API endpoint mining → Dev artifact discovery → SQLMap → Dalfox (XSS)\n\n"
            "[bold red]WARNING:[/bold red] This mode is [bold]active and potentially destructive[/bold].\n"
            "Only run against targets you have explicit written permission to test."
        ),
        synopsis="reconai vuln <TARGET> [OPTIONS]",
        options=[
            ("--ai", "Enable Ollama AI exploit guidance (auto-enabled in vuln mode)"),
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model name"),
            ("--dry-run", "Preview without executing — ALWAYS do this first"),
            ("--timeout INT", "Override timeout (seconds)"),
            ("--strict-scope", "Strictly restrict to the stated target"),
        ],
        examples=[
            ("reconai vuln example.com --dry-run",               "⚠️  ALWAYS preview first"),
            ("reconai vuln example.com --ai",                    "Full vuln scan + AI exploit guidance"),
            ("reconai vuln example.com --strict-scope",         "Enforce strict scope during vuln testing"),
        ],
        beginner_tip=(
            "[bold red]Always get written authorisation before running vuln mode.[/bold red]\n"
            "Start with [cyan]--dry-run[/cyan] to review which tools will fire."
        ),
    ),

    # ── AI & ANALYSIS ─────────────────────────────────────────────────────────

    CommandDoc(
        name="ai",
        group="🤖 AI & Analysis",
        tagline="Dedicated AI threat intelligence pipeline — analyse an existing scan with an LLM",
        description=(
            "Re-runs AI analysis on an existing scan directory or scan ID.\n\n"
            "Useful when you completed a scan without [cyan]--ai[/cyan] and want to add LLM\n"
            "intelligence afterwards, or when you want to try a different model.\n\n"
            "Also accepts a bare target string — if no matching scan is found, it runs\n"
            "a fresh standard scan with AI enabled."
        ),
        synopsis="reconai ai <SCAN_ID_OR_TARGET> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL (default: http://localhost:11434)"),
            ("--ai-model NAME", "Ollama model (default: llama3)"),
        ],
        examples=[
            ("reconai ai a1b2c3d4",                                              "Analyse scan ID a1b2c3d4 with default model"),
            ("reconai ai example.com",                                           "Run standard scan + AI analysis on example.com"),
            ("reconai ai a1b2c3d4 --ai-model deepseek-r1:7b",                   "Re-analyse with DeepSeek model"),
            ("reconai ai a1b2c3d4 --ai-url http://192.168.1.50:11434",          "Use remote GPU Ollama server"),
        ],
        beginner_tip=(
            "Find your scan IDs with [cyan]reconai list[/cyan] (or browse the output directory).\n"
            "Scan IDs look like [cyan]a1b2c3d4[/cyan] — 8 hex characters."
        ),
    ),

    CommandDoc(
        name="agent",
        group="🤖 AI & Analysis",
        tagline="Autonomous AI Red Team Operator — full campaign planning from scan data",
        description=(
            "Runs the AI Red Team Agent on a completed scan.\n\n"
            "The agent reads all discovered assets, findings, and infrastructure data,\n"
            "then produces a structured offensive campaign plan including:\n"
            "  • Prioritised attack paths with rationale\n"
            "  • Lateral movement opportunities\n"
            "  • Credential harvesting vectors\n"
            "  • MITRE ATT&CK technique mapping\n"
            "  • Exploitation sequencing\n\n"
            "Output is saved as [cyan]reports/red_team_plan.md[/cyan] in the scan directory."
        ),
        synopsis="reconai agent <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai agent a1b2c3d4",                           "Run agent on scan a1b2c3d4"),
            ("reconai agent ./output/example.com/a1b2c3d4",      "Run agent using the scan directory path"),
            ("reconai agent a1b2c3d4 --ai-model deepseek-r1:7b", "Use DeepSeek R1 for deeper reasoning"),
        ],
        beginner_tip="Run [cyan]reconai scan example.com -m deep[/cyan] first, then point agent at the scan ID.",
    ),

    CommandDoc(
        name="ai-agent",
        group="🤖 AI & Analysis",
        tagline="Alias for 'agent' — same command, alternate name",
        description="Exactly identical to [cyan]reconai agent[/cyan]. See that command for full documentation.",
        synopsis="reconai ai-agent <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai ai-agent a1b2c3d4", "Same as: reconai agent a1b2c3d4"),
        ],
        beginner_tip="Use whichever name feels more natural — both do the same thing.",
    ),

    CommandDoc(
        name="chat",
        group="🤖 AI & Analysis",
        tagline="Interactive AI copilot — ask questions about scan findings in natural language",
        description=(
            "Opens an interactive chat session grounded in a completed scan's data.\n\n"
            "You can ask questions like:\n"
            "  • 'What are the most critical findings?'\n"
            "  • 'Is there any evidence of SQL injection?'\n"
            "  • 'What attack paths does this surface expose?'\n"
            "  • 'Explain the subdomain takeover finding'\n\n"
            "Built-in slash commands inside the session:\n"
            "  [cyan]/summary[/cyan]   — Print the AI threat summary\n"
            "  [cyan]/findings[/cyan]  — List all findings\n"
            "  [cyan]/paths[/cyan]     — List attack paths\n"
            "  [cyan]/help[/cyan]      — Show copilot commands\n"
            "  [cyan]exit[/cyan]       — Close the session"
        ),
        synopsis="reconai chat <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai chat a1b2c3d4",                         "Open copilot for scan a1b2c3d4"),
            ("reconai chat ./output/example.com/a1b2c3d4",    "Using directory path"),
            ("reconai chat a1b2c3d4 --ai-model llama3",       "Explicitly use llama3"),
        ],
        beginner_tip=(
            "This is the most beginner-friendly AI feature. After a scan, just ask questions\n"
            "in plain English about what was found."
        ),
    ),

    CommandDoc(
        name="copilot",
        group="🤖 AI & Analysis",
        tagline="Alias for 'chat' — interactive AI copilot",
        description="Exactly identical to [cyan]reconai chat[/cyan]. See that command for full documentation.",
        synopsis="reconai copilot <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai copilot a1b2c3d4", "Same as: reconai chat a1b2c3d4"),
        ],
        beginner_tip="Use [cyan]reconai chat[/cyan] or [cyan]reconai copilot[/cyan] — they're identical.",
    ),

    CommandDoc(
        name="threat-profile",
        group="🤖 AI & Analysis",
        tagline="AI threat actor & TTP profiler — MITRE ATT&CK mapping + adversary emulation",
        description=(
            "Analyses a completed scan and maps the discovered attack surface to:\n"
            "  • Relevant real-world threat actor groups (APT28, Lazarus, etc.)\n"
            "  • MITRE ATT&CK techniques most likely exploitable given the surface\n"
            "  • Actor motivations aligned to the target's industry\n"
            "  • Adversary emulation playbook recommendations\n\n"
            "Also available as: [cyan]reconai profile-threat[/cyan]"
        ),
        synopsis="reconai threat-profile <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai threat-profile a1b2c3d4",               "Profile threats for scan a1b2c3d4"),
            ("reconai profile-threat a1b2c3d4",               "Alias — same result"),
        ],
        beginner_tip=(
            "The more findings your scan has, the more accurate the threat mapping.\n"
            "Run with [cyan]-m deep[/cyan] first for best results."
        ),
    ),

    CommandDoc(
        name="profile-threat",
        group="🤖 AI & Analysis",
        tagline="Alias for 'threat-profile'",
        description="Exactly identical to [cyan]reconai threat-profile[/cyan].",
        synopsis="reconai profile-threat <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai profile-threat a1b2c3d4", "Same as: reconai threat-profile a1b2c3d4"),
        ],
        beginner_tip="Both names do the same thing — use whichever you prefer.",
    ),

    CommandDoc(
        name="prioritize",
        group="🤖 AI & Analysis",
        tagline="AI endpoint prioritizer — rank URLs by exploitation probability for fuzzing",
        description=(
            "Analyses all crawled URLs and API endpoints from a scan and ranks them by\n"
            "how likely they are to be vulnerable and high-value:\n"
            "  • Endpoints with parameters (GET/POST injection candidates)\n"
            "  • Authentication-adjacent paths\n"
            "  • Admin / management interfaces\n"
            "  • File upload handlers\n"
            "  • GraphQL / REST API endpoints\n\n"
            "Output includes suggested test vectors (SQLi, XSS, IDOR, SSRF, etc.) for each URL."
        ),
        synopsis="reconai prioritize <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--limit INT", "Number of prioritised endpoints to display (default: 25)"),
        ],
        examples=[
            ("reconai prioritize a1b2c3d4",           "Top 25 endpoints ranked by attack priority"),
            ("reconai prioritize a1b2c3d4 --limit 50","Show top 50 endpoints"),
        ],
        beginner_tip=(
            "Run this after a [cyan]web[/cyan] or [cyan]deep[/cyan] scan to get a ranked list\n"
            "of exactly where to focus your manual testing."
        ),
    ),

    CommandDoc(
        name="waf-advisor",
        group="🤖 AI & Analysis",
        tagline="AI WAF & perimeter evasion advisor — origin IP leakage & bypass vectors",
        description=(
            "Analyses WAF and CDN detection data from a scan to:\n"
            "  • Identify origin server IP leakage through DNS, historical records, certificates\n"
            "  • Suggest WAF bypass techniques relevant to the detected WAF vendor\n"
            "  • Rate perimeter defense strength\n"
            "  • Flag direct-to-origin paths that bypass the WAF entirely"
        ),
        synopsis="reconai waf-advisor <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai waf-advisor a1b2c3d4",           "Analyse WAF posture for scan a1b2c3d4"),
        ],
        beginner_tip=(
            "If the scan detected a CDN or WAF (Cloudflare, Akamai, etc.),\n"
            "this command tells you whether the origin IP is exposed and how to reach it directly."
        ),
    ),

    CommandDoc(
        name="verify",
        group="🤖 AI & Analysis",
        tagline="Closed-loop false-positive verifier — confirms real vulns, discards noise",
        description=(
            "Re-validates every finding in a completed scan using safe, non-destructive probes.\n\n"
            "Uses AI reasoning + light HTTP verification to classify each finding as:\n"
            "  • [bold green]VERIFIED[/bold green]   — Confirmed real, exploitable or mis-configured\n"
            "  • [yellow]POTENTIAL[/yellow] — Possibly valid but inconclusive evidence\n\n"
            "This dramatically reduces report noise before presenting to a client."
        ),
        synopsis="reconai verify <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai verify a1b2c3d4",                "Verify all findings in scan a1b2c3d4"),
        ],
        beginner_tip="Run this before writing your report — it filters out false positives automatically.",
    ),

    CommandDoc(
        name="exploit",
        group="🤖 AI & Analysis",
        tagline="Generate a runnable PoC exploit for a specific finding",
        description=(
            "Looks up a finding by title within a completed scan and generates:\n"
            "  • A Python proof-of-concept script ([cyan]poc_N_title.py[/cyan])\n"
            "  • A curl reproduction command ([cyan]poc_N_title.sh[/cyan])\n"
            "  • A Nuclei template for automated re-testing ([cyan]poc_N_title.yaml[/cyan])\n\n"
            "AI is used (if available) for deeper exploit reasoning — otherwise\n"
            "a deterministic PoC is generated from the finding metadata."
        ),
        synopsis="reconai exploit <SCAN_ID> <FINDING_TITLE> [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ('reconai exploit a1b2c3d4 "SQL Injection"',           "Generate PoC for a SQLi finding"),
            ('reconai exploit a1b2c3d4 "Exposed .env"',            "Generate PoC for an env file exposure"),
            ('reconai exploit a1b2c3d4 "XSS" --ai-model llama3',   "AI-enhanced exploit reasoning"),
        ],
        beginner_tip=(
            "Finding titles don't need to be exact — partial matches work.\n"
            "Run [cyan]reconai chat <SCAN_ID>[/cyan] and type [cyan]/findings[/cyan] to see all titles."
        ),
    ),

    # ── SHELL / NEXUS ─────────────────────────────────────────────────────────

    CommandDoc(
        name="shell",
        group="🧠 AI Shell",
        tagline="Interactive AI security shell — type tasks in plain English",
        description=(
            "Opens an AI-powered terminal where you describe what you want to do in\n"
            "natural language. The AI selects and runs the right tools automatically.\n\n"
            "Example prompts inside the shell:\n"
            "  [dim]>[/dim] scan example.com for open ports\n"
            "  [dim]>[/dim] find subdomains of target.com\n"
            "  [dim]>[/dim] check for XSS on https://target.com/search?q=test\n"
            "  [dim]>[/dim] what technologies does google.com use?\n"
            "  [dim]>[/dim] run full recon on 192.168.1.100\n"
            "  [dim]>[/dim] check for CVE-2023-44487 on target.com\n"
            "  [dim]>[/dim] /help   — show all shell commands\n\n"
            "[bold red]Requires Ollama to be running.[/bold red]"
        ),
        synopsis="reconai shell [OPTIONS]",
        options=[
            ("--ai-url URL", "Ollama server URL (default: http://localhost:11434)"),
            ("--ai-model NAME", "LLM model (default: llama3)"),
            ("--workspace PATH", "Directory for tool output files"),
            ("--verbose", "Show raw tool commands as they execute"),
        ],
        examples=[
            ("reconai shell",                                              "Open shell with default settings"),
            ("reconai shell --ai-model deepseek-r1:7b",                   "Use DeepSeek R1 for better reasoning"),
            ("reconai shell --ai-url http://192.168.1.50:11434",          "Connect to remote GPU Ollama"),
            ("reconai shell --workspace /tmp/recon --verbose",             "Custom workspace, verbose output"),
        ],
        beginner_tip=(
            "This is the easiest entry point for beginners. Just describe what you want\n"
            "and the AI handles everything. Type [cyan]/help[/cyan] inside for shell-specific commands."
        ),
    ),

    CommandDoc(
        name="nexus",
        group="🧠 AI Shell",
        tagline="NEXUS — AI Security Operations Platform with three operation modes",
        description=(
            "The most powerful ReconAI interface. Three modes:\n\n"
            "  [bold cyan]AUTOPILOT[/bold cyan]\n"
            "    AI defines the entire attack plan, executes it step by step.\n"
            "    You set the mission goal — AI does everything else.\n\n"
            "  [bold cyan]COPILOT[/bold cyan] (default)\n"
            "    AI proposes each step with rationale. You review and approve.\n"
            "    Best balance of power and control.\n\n"
            "  [bold cyan]MANUAL[/bold cyan]\n"
            "    You run any tool freely. AI analyses all output in real time,\n"
            "    extracts findings, and suggests next steps.\n\n"
            "NEXUS commands inside the platform:\n"
            "  [dim]>[/dim] mission find all vulnerabilities on target.com\n"
            "  [dim]>[/dim] target 192.168.1.100\n"
            "  [dim]>[/dim] mode autopilot\n"
            "  [dim]>[/dim] run\n"
            "  [dim]>[/dim] ask what is the blast radius of this SQLi?\n"
            "  [dim]>[/dim] exec nmap -sV -p- target.com\n"
            "  [dim]>[/dim] tools       — list discovered tools\n"
            "  [dim]>[/dim] findings    — show all findings so far\n"
            "  [dim]>[/dim] chain       — show kill-chain analysis\n"
            "  [dim]>[/dim] report      — generate report\n"
            "  [dim]>[/dim] save        — save session\n\n"
            "[bold red]Requires Ollama to be running.[/bold red]"
        ),
        synopsis="reconai nexus [OPTIONS]",
        options=[
            ("--mode MODE", "autopilot | copilot | manual  (default: copilot)"),
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "LLM model"),
            ("--workspace PATH", "Directory for tool output"),
            ("--no-risk-gate", "[RED WARNING] Disable confirmation prompts for dangerous tools"),
        ],
        examples=[
            ("reconai nexus",                                          "Open NEXUS in copilot mode (default)"),
            ("reconai nexus --mode autopilot",                         "Full AI autopilot — AI drives everything"),
            ("reconai nexus --mode manual",                            "Manual control + AI analysis"),
            ("reconai nexus --ai-model deepseek-r1:7b --mode copilot","DeepSeek copilot — best reasoning"),
            ("reconai nexus --ai-url http://192.168.1.50:11434",      "Remote GPU server"),
        ],
        beginner_tip=(
            "Start with [cyan]reconai nexus --mode copilot[/cyan]. Type a mission like:\n"
            "[dim]> mission find vulnerabilities on example.com[/dim]\n"
            "Then [dim]> run[/dim] and approve each step."
        ),
    ),

    # ── REPORTING ─────────────────────────────────────────────────────────────

    CommandDoc(
        name="report",
        group="📊 Reporting",
        tagline="Generate or regenerate reports (HTML, Markdown, JSON, PoCs) from a completed scan",
        description=(
            "Rebuilds all report formats from an existing scan database:\n"
            "  • [cyan]report.html[/cyan]      — Self-contained interactive HTML (open in any browser)\n"
            "  • [cyan]report.md[/cyan]         — Markdown for direct import into Confluence / Notion\n"
            "  • [cyan]report.json[/cyan]       — Structured JSON for toolchain integration\n"
            "  • [cyan]pocs/[/cyan]             — Runnable PoC scripts (Python, bash, Nuclei YAML)\n"
            "  • [cyan]ai_analysis.md[/cyan]    — Standalone AI threat assessment (if [cyan]--ai[/cyan] used)\n\n"
            "Useful when you forgot [cyan]--ai[/cyan] during the scan, want a fresh HTML after editing data,\n"
            "or want to export reports in a specific format."
        ),
        synopsis="reconai report <SCAN_ID_OR_PATH> [OPTIONS]",
        options=[
            ("--ai", "Run AI threat assessment and embed in reports"),
            ("--ai-url URL", "Ollama server URL"),
            ("--ai-model NAME", "Ollama model"),
        ],
        examples=[
            ("reconai report a1b2c3d4",                        "Regenerate all reports for scan a1b2c3d4"),
            ("reconai report a1b2c3d4 --ai",                   "Regenerate + add AI analysis"),
            ("reconai report ./output/example.com/a1b2c3d4",   "Using directory path instead of scan ID"),
        ],
        beginner_tip=(
            "HTML reports are self-contained — you can email them or open them offline.\n"
            "Find them at: [cyan]output/<target>/<scan_id>/reports/report.html[/cyan]"
        ),
    ),

    CommandDoc(
        name="compare",
        group="📊 Reporting",
        tagline="Compare two scans — diff subdomains, ports, and cloud assets between scan dates",
        description=(
            "Shows a colour-coded diff between two completed scans of the same target:\n"
            "  [bold green]+[/bold green] Newly discovered subdomains / ports / cloud assets\n"
            "  [bold red]-[/bold red] Removed / closed items (host hardened or decommissioned)\n\n"
            "Perfect for tracking attack surface changes over time, verifying remediations,\n"
            "or showing clients their exposure trend."
        ),
        synopsis="reconai compare <OLD_SCAN_ID> <NEW_SCAN_ID>",
        options=[],
        examples=[
            ("reconai compare abc12345 def67890",    "Diff two scans — shows what changed"),
            ("reconai compare last_month this_week", "Using partial scan ID matches"),
        ],
        beginner_tip=(
            "Run weekly scans with [cyan]reconai scan example.com -m passive[/cyan] and\n"
            "compare them to track new subdomains and exposed services over time."
        ),
    ),

    # ── UTILITIES ─────────────────────────────────────────────────────────────

    CommandDoc(
        name="doctor",
        group="🛠️ Utilities",
        tagline="Check which external tools are installed and available on PATH",
        description=(
            "Scans your system for all security tools that ReconAI can leverage:\n"
            "  nmap, amass, subfinder, httpx, nuclei, whatweb, waybackurls, gau,\n"
            "  wafw00f, trufflehog, naabu, masscan, gobuster, ffuf, dig, whois,\n"
            "  katana, sqlmap, dalfox, paramspider, dnsx, gowitness, arjun,\n"
            "  subzy, gitleaks, tlsx, cloud_enum\n\n"
            "Green = installed | Red = not found (module will be skipped during scans).\n\n"
            "Most tools can be installed with: [cyan]go install <tool>@latest[/cyan] or\n"
            "via your OS package manager (apt, brew, etc.)."
        ),
        synopsis="reconai doctor",
        options=[],
        examples=[
            ("reconai doctor",    "Check all tool availability"),
        ],
        beginner_tip="Run this first! It tells you exactly which tools are missing and which modules won't run.",
    ),

    CommandDoc(
        name="mcp",
        group="🛠️ Utilities",
        tagline="Start the Model Context Protocol (MCP) server for external AI agent integration",
        description=(
            "Starts a local MCP server that exposes ReconAI's intelligence functions\n"
            "as tools consumable by external AI agents (Claude, GPT-4, custom agents).\n\n"
            "MCP allows an external AI to:\n"
            "  • Query scan results programmatically\n"
            "  • Trigger targeted scans\n"
            "  • Retrieve findings in structured format\n"
            "  • Chain ReconAI with other security tooling\n\n"
            "Configure the MCP endpoint in your AI agent's tool definitions."
        ),
        synopsis="reconai mcp",
        options=[],
        examples=[
            ("reconai mcp",    "Start MCP server on default port"),
        ],
        beginner_tip=(
            "Only needed if you are integrating ReconAI with an external AI agent framework.\n"
            "Most users won't need this — use [cyan]reconai chat[/cyan] for interactive AI."
        ),
    ),

    CommandDoc(
        name="help",
        group="🛠️ Utilities",
        tagline="This help system — full command reference with examples",
        description=(
            "Shows the interactive command reference.\n\n"
            "Usage:\n"
            "  [cyan]reconai help[/cyan]           — Full overview of all commands\n"
            "  [cyan]reconai help <COMMAND>[/cyan]  — Deep-dive into a specific command\n\n"
            "Related commands for beginners:\n"
            "  [cyan]reconai examples[/cyan]        — Ready-to-run recipes by use-case\n"
            "  [cyan]reconai quickstart[/cyan]       — Step-by-step beginner walkthrough"
        ),
        synopsis="reconai help [COMMAND]",
        options=[],
        examples=[
            ("reconai help",          "Show all commands"),
            ("reconai help scan",     "Deep-dive into the scan command"),
            ("reconai help nexus",    "Deep-dive into NEXUS"),
        ],
        beginner_tip="You're already here! 🎉",
    ),

    CommandDoc(
        name="examples",
        group="🛠️ Utilities",
        tagline="Ready-to-run example recipes organised by use-case",
        description="Shows curated example commands organised by real-world use-case.",
        synopsis="reconai examples",
        options=[],
        examples=[
            ("reconai examples",    "Show all example recipes"),
        ],
        beginner_tip="Perfect starting point — copy-paste any example and replace the target.",
    ),

    CommandDoc(
        name="quickstart",
        group="🛠️ Utilities",
        tagline="Step-by-step beginner walkthrough — from zero to first scan",
        description="Prints a guided walkthrough for first-time users.",
        synopsis="reconai quickstart",
        options=[],
        examples=[
            ("reconai quickstart",    "Show the beginner walkthrough"),
        ],
        beginner_tip="Start here if you've never used ReconAI before.",
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Example recipes (shown by `reconai examples`)
# ─────────────────────────────────────────────────────────────────────────────

EXAMPLES: list[tuple[str, str, list[tuple[str, str]]]] = [
    (
        "🏁  First time using ReconAI",
        "Run these in order to get started from scratch",
        [
            ("reconai doctor",                                   "1. Check which tools are installed"),
            ("reconai scan example.com --dry-run",               "2. Preview what a scan does (no execution)"),
            ("reconai scan example.com -m passive",              "3. Safe OSINT-only scan — zero active probes"),
            ("reconai scan example.com -m light",                "4. Fast scan — DNS, HTTP, tech stack (~5 min)"),
            ("reconai scan example.com --ai",                    "5. Full scan + AI threat analysis"),
        ],
    ),
    (
        "🔎  Subdomain Discovery",
        "Find all subdomains of a target domain",
        [
            ("reconai subs example.com",                         "Dedicated subdomain pipeline"),
            ("reconai scan example.com -m subs",                 "Same via scan command"),
            ("reconai subs example.com --strict-scope",         "Only *.example.com — nothing adjacent"),
            ("reconai subs bugcrowd.com --dry-run",              "Preview — what tools will run?"),
        ],
    ),
    (
        "🌐  Web Attack Surface",
        "Map the HTTP/HTTPS surface of a target",
        [
            ("reconai web example.com",                          "Full web surface map"),
            ("reconai scan example.com -m web",                  "Same via scan command"),
            ("reconai scan example.com -m browser",              "Headless browser — good for SPA/JS apps"),
            ("reconai prioritize a1b2c3d4",                      "Rank endpoints by attack priority (post-scan)"),
        ],
    ),
    (
        "⚓  Port & Service Detection",
        "Find open ports and fingerprint services",
        [
            ("reconai ports example.com",                        "Quick top-1 000 port scan"),
            ("reconai ports 192.168.1.1 -p full",                "All 65 535 ports on an IP"),
            ("reconai ports 10.0.0.0/24 -p service",            "Service fingerprint on internal subnet"),
            ("reconai scan example.com -m ports -p standard",    "Via scan command"),
        ],
    ),
    (
        "☁️   Cloud Attack Surface",
        "Enumerate cloud assets, buckets, and misconfigurations",
        [
            ("reconai cloud example.com",                        "Full cloud recon"),
            ("reconai cloud example.com --ai",                   "With AI cloud risk analysis"),
            ("reconai scan example.com -m cloud",                "Via scan command"),
        ],
    ),
    (
        "🧪  Vulnerability Testing",
        "Scan for CVEs, secrets, injection, and misconfigs",
        [
            ("reconai scan example.com -m vuln --dry-run",       "⚠️  ALWAYS preview first"),
            ("reconai scan example.com -m vuln --ai",            "Full vuln scan + AI exploit guidance"),
            ("reconai exploit a1b2c3d4 'SQL Injection'",         "Generate PoC for a specific finding"),
            ("reconai verify a1b2c3d4",                          "Filter out false positives"),
        ],
    ),
    (
        "🤖  AI-Powered Analysis",
        "Leverage local LLM for threat intelligence and reasoning",
        [
            ("reconai scan example.com -m deep --ai",            "Full scan + AI — most comprehensive"),
            ("reconai ai a1b2c3d4",                              "Add AI analysis to an existing scan"),
            ("reconai chat a1b2c3d4",                            "Ask questions about findings in natural language"),
            ("reconai agent a1b2c3d4",                           "Autonomous red team campaign planning"),
            ("reconai threat-profile a1b2c3d4",                  "MITRE ATT&CK threat actor mapping"),
            ("reconai waf-advisor a1b2c3d4",                     "WAF bypass and origin IP leakage analysis"),
        ],
    ),
    (
        "🧠  NEXUS AI Platform",
        "The most powerful ReconAI experience",
        [
            ("reconai nexus",                                    "Open NEXUS copilot (default — human reviews each step)"),
            ("reconai nexus --mode autopilot",                   "Full AI autopilot — AI does everything"),
            ("reconai nexus --mode manual",                      "You run tools, AI analyses output"),
            ("reconai nexus --ai-model deepseek-r1:7b",         "Use DeepSeek R1 for deeper reasoning"),
        ],
    ),
    (
        "🗣️   Natural Language Shell",
        "Describe tasks in plain English — AI handles the rest",
        [
            ("reconai shell",                                    "Open the AI security shell"),
            ("reconai shell --ai-model deepseek-r1:7b",         "Better model for complex tasks"),
        ],
    ),
    (
        "📊  Reporting & Comparison",
        "Generate professional reports from scan data",
        [
            ("reconai report a1b2c3d4",                          "Regenerate all report formats"),
            ("reconai report a1b2c3d4 --ai",                     "Regenerate + embed AI analysis"),
            ("reconai compare abc12345 def67890",                "Diff two scans — track surface changes"),
        ],
    ),
    (
        "⚙️   Remote GPU / Ollama Setup",
        "Use a remote machine's GPU for AI inference",
        [
            ("# On the GPU server:",                             ""),
            ("OLLAMA_HOST=0.0.0.0:11434 ollama serve",           "Expose Ollama on all interfaces"),
            ("ollama pull deepseek-r1:7b",                       "Pull a good model for security tasks"),
            ("# On your scan machine:",                          ""),
            ("reconai scan example.com -m deep --ai --ai-url http://192.168.1.50:11434 --ai-model deepseek-r1:7b", "Use remote GPU"),
            ("# Or set permanently in config.yaml:",             ""),
            ("# ai:",                                            ""),
            ("#   url: http://192.168.1.50:11434",               ""),
            ("#   model: deepseek-r1:7b",                        ""),
            ("#   enabled: true",                                 ""),
        ],
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Rendering helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cmd_map() -> dict[str, CommandDoc]:
    return {c.name: c for c in COMMANDS}


def _render_overview(console: Console) -> None:
    """Print the full command overview table."""
    console.print()
    console.print(Panel(
        "[bold white]ReconAI[/bold white]  •  AI-Augmented Attack Surface Intelligence Platform\n"
        "[dim]Type [cyan]reconai help <command>[/cyan] for a deep-dive into any command.[/dim]\n"
        "[dim]Type [cyan]reconai examples[/cyan] for ready-to-run recipes by use-case.[/dim]\n"
        "[dim]Type [cyan]reconai quickstart[/cyan] for the beginner walkthrough.[/dim]",
        title="[bold cyan]📖 ReconAI Command Reference[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))

    # Group commands
    groups: dict[str, list[CommandDoc]] = {}
    for cmd in COMMANDS:
        groups.setdefault(cmd.group, []).append(cmd)

    for group_name, cmds in groups.items():
        table = Table(
            show_header=True,
            header_style="bold white on grey23",
            border_style="dim",
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Command", style=C_CMD, min_width=18, no_wrap=True)
        table.add_column("Description", style="white")

        for cmd in cmds:
            table.add_row(cmd.name, cmd.tagline)

        console.print()
        console.print(f"  [bold]{group_name}[/bold]")
        console.print(table)

    console.print()
    console.print(Panel(
        "[bold white]Global flags[/bold white] (available on [cyan]every[/cyan] command):\n"
        "  [yellow]--verbose[/yellow]         Stream raw tool output to terminal\n"
        "  [yellow]--debug[/yellow]           Enable debug-level logging\n"
        "  [yellow]--config PATH[/yellow]     Use a custom config.yaml\n"
        "  [yellow]--version[/yellow]         Print version and exit\n"
        "  [yellow]--help[/yellow]            Print Click's built-in short help for any command\n\n"
        "[dim]Tip: [cyan]reconai scan example.com --dry-run[/cyan] is always safe — no execution.[/dim]",
        border_style="dim",
        padding=(0, 2),
    ))
    console.print()


def _render_command_detail(console: Console, cmd: CommandDoc) -> None:
    """Print the full detail view for a single command."""
    console.print()
    console.print(Panel(
        f"[{C_CMD}]{cmd.name}[/{C_CMD}]  —  {cmd.tagline}",
        title=f"[bold cyan]📋 Command Detail: reconai {cmd.name}[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))

    # Synopsis
    console.print(f"\n[{C_HEAD}]SYNOPSIS[/{C_HEAD}]")
    console.print(f"  [{C_EX}]{escape(cmd.synopsis)}[/{C_EX}]\n")

    # Description
    console.print(f"[{C_HEAD}]DESCRIPTION[/{C_HEAD}]")
    for line in cmd.description.split("\n"):
        console.print(f"  {line}")

    # Options
    if cmd.options:
        console.print(f"\n[{C_HEAD}]OPTIONS[/{C_HEAD}]")
        tbl = Table(show_header=False, box=None, padding=(0, 2))
        tbl.add_column(style=C_OPT, no_wrap=True)
        tbl.add_column(style="white")
        for flag, desc in cmd.options:
            tbl.add_row(flag, desc)
        console.print(tbl)

    # Examples
    if cmd.examples:
        console.print(f"\n[{C_HEAD}]EXAMPLES[/{C_HEAD}]")
        for ex_cmd, ex_comment in cmd.examples:
            if ex_comment:
                console.print(f"  [dim]# {ex_comment}[/dim]")
            console.print(f"  [{C_EX}]{escape(ex_cmd)}[/{C_EX}]")

    # Beginner tip
    if cmd.beginner_tip:
        console.print()
        console.print(Panel(
            cmd.beginner_tip,
            title=f"[{C_TIP}]💡 Beginner Tip[/{C_TIP}]",
            border_style="blue",
            padding=(0, 2),
        ))

    console.print()


def _render_examples(console: Console) -> None:
    """Print the full examples catalogue."""
    console.print()
    console.print(Panel(
        "Copy-paste any command below — replace [bold yellow]example.com[/bold yellow] with your target\n"
        "and [bold yellow]a1b2c3d4[/bold yellow] with a real scan ID from your output directory.",
        title="[bold cyan]📋 ReconAI Example Recipes[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))

    for heading, subtitle, cmds in EXAMPLES:
        console.print()
        console.print(f"  [bold white]{heading}[/bold white]")
        if subtitle:
            console.print(f"  [{C_DIM}]{subtitle}[/{C_DIM}]")
        for cmd_str, comment in cmds:
            if comment:
                console.print(f"    [{C_DIM}]# {comment}[/{C_DIM}]")
            if not cmd_str.startswith("#"):
                console.print(f"    [{C_EX}]{escape(cmd_str)}[/{C_EX}]")

    console.print()


def _render_quickstart(console: Console) -> None:
    """Print the beginner step-by-step walkthrough."""
    console.print()
    console.print(Panel(
        "[bold white]Welcome to ReconAI![/bold white]  Follow these steps to run your first scan.",
        title="[bold cyan]🚀 Quickstart — Beginner Walkthrough[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))

    steps = [
        (
            "Step 1 — Check your tools",
            "reconai doctor",
            (
                "This tells you which security tools are installed.\n"
                "ReconAI works without them (skips missing modules), but more tools = more data.\n\n"
                "To install the most useful ones on Kali/Ubuntu:\n"
                "  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
                "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
                "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n"
                "  go install -v github.com/projectdiscovery/katana/cmd/katana@latest\n"
                "  go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
            ),
        ),
        (
            "Step 2 — Preview a scan (safe, no execution)",
            "reconai scan example.com --dry-run",
            (
                "Replace 'example.com' with your target.\n"
                "--dry-run shows you exactly what would run, without touching anything.\n"
                "Always do this first when trying a new mode."
            ),
        ),
        (
            "Step 3 — Run a passive scan (zero active probes)",
            "reconai scan example.com -m passive",
            (
                "This mode uses ONLY public data sources:\n"
                "  • Certificate Transparency logs\n"
                "  • Archive.org / Wayback Machine\n"
                "  • DNS records\n"
                "  • WHOIS data\n"
                "  • Email security records (SPF, DMARC, DKIM)\n\n"
                "Safe to run on any target, including targets you don't own."
            ),
        ),
        (
            "Step 4 — Upgrade to a standard scan",
            "reconai scan example.com",
            (
                "Standard mode runs active modules but stays non-destructive:\n"
                "  • HTTP probing and technology fingerprinting\n"
                "  • Port scanning (top 1 000 ports)\n"
                "  • Web crawling\n"
                "  • Directory discovery\n"
                "  • WAF detection\n"
                "  • Vulnerability intelligence (Nuclei CVE templates)\n\n"
                "Takes ~20 minutes. Output is saved to the [cyan]output/[/cyan] directory."
            ),
        ),
        (
            "Step 5 — Find your scan ID and view results",
            "ls output/example.com/",
            (
                "ReconAI saves everything under [cyan]output/<target>/<scan_id>/[/cyan].\n"
                "Your scan ID is the 8-character hex folder name, e.g. [cyan]a1b2c3d4[/cyan].\n\n"
                "Open the HTML report:\n"
                "  output/example.com/a1b2c3d4/reports/report.html\n\n"
                "Or read the markdown:\n"
                "  output/example.com/a1b2c3d4/reports/report.md"
            ),
        ),
        (
            "Step 6 — Add AI analysis (requires Ollama)",
            "reconai ai a1b2c3d4",
            (
                "If you have Ollama installed ([cyan]ollama serve[/cyan]):\n"
                "  First pull a model:   [cyan]ollama pull llama3[/cyan]\n"
                "  Then run:             [cyan]reconai ai a1b2c3d4[/cyan]\n\n"
                "Or enable AI during the scan:\n"
                "  [cyan]reconai scan example.com --ai[/cyan]\n\n"
                "The AI reads all findings and generates:\n"
                "  • Executive threat summary\n"
                "  • Correlated attack kill chain\n"
                "  • Risk-ranked remediation list"
            ),
        ),
        (
            "Step 7 — Ask questions about findings",
            "reconai chat a1b2c3d4",
            (
                "Open an interactive chat session about your scan:\n"
                "  > What are the most critical findings?\n"
                "  > Is there any evidence of SQL injection?\n"
                "  > Explain the subdomain takeover finding\n"
                "  > What should I fix first?\n\n"
                "Type [cyan]/help[/cyan] inside the chat for built-in commands.\n"
                "Type [cyan]exit[/cyan] to close."
            ),
        ),
        (
            "Step 8 — Go deeper with NEXUS",
            "reconai nexus",
            (
                "NEXUS is the full AI Security Operations Platform.\n"
                "Start in copilot mode (default) and type:\n"
                "  > mission find all vulnerabilities on example.com\n"
                "  > run\n\n"
                "The AI will propose each step — you review and approve before execution."
            ),
        ),
    ]

    for i, (title, example_cmd, explanation) in enumerate(steps, start=1):
        console.print()
        console.print(Panel(
            f"[{C_EX}]{escape(example_cmd)}[/{C_EX}]\n\n{explanation}",
            title=f"[bold white]{title}[/bold white]",
            border_style="green" if i <= 3 else ("yellow" if i <= 5 else "cyan"),
            padding=(0, 2),
        ))

    console.print()
    console.print(Panel(
        "You're all set! 🎉\n\n"
        "[dim]Common next steps:[/dim]\n"
        "  [cyan]reconai examples[/cyan]           — More copy-paste recipes\n"
        "  [cyan]reconai help <command>[/cyan]      — Deep-dive into any command\n"
        "  [cyan]reconai --help[/cyan]             — Click's built-in short help\n\n"
        "[dim]Remember: always get written authorisation before scanning targets you don't own.[/dim]",
        title="[bold cyan]🏁 You're Ready![/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Click commands
# ─────────────────────────────────────────────────────────────────────────────

def register_help_commands(cli: click.Group) -> None:
    """Attach help, examples, and quickstart commands to the root CLI group.

    Call this from main.py after the cli group is defined:
        from reconai.cli.help import register_help_commands
        register_help_commands(cli)
    """

    @cli.command("help", context_settings={"ignore_unknown_options": True})
    @click.argument("command", required=False, default=None)
    def help_cmd(command: str | None) -> None:
        """Interactive command reference — 'reconai help <command>' for details."""
        console = Console()
        cmd_map = _cmd_map()

        if command is None:
            _render_overview(console)
            return

        # Normalise: strip leading "reconai " if someone types it accidentally
        key = command.lower().strip().lstrip("reconai").strip()
        if key in cmd_map:
            _render_command_detail(console, cmd_map[key])
        else:
            # Fuzzy suggestion
            matches = [n for n in cmd_map if key in n or n in key]
            console.print(
                f"\n[bold red]Unknown command:[/bold red] '{command}'\n",
                highlight=False,
            )
            if matches:
                console.print(f"[dim]Did you mean: {', '.join(f'[cyan]{m}[/cyan]' for m in matches)}?[/dim]\n")
            else:
                console.print("[dim]Run [cyan]reconai help[/cyan] to see all commands.[/dim]\n")

    @cli.command("examples")
    def examples_cmd() -> None:
        """Ready-to-run example recipes organised by use-case."""
        console = Console()
        _render_examples(console)

    @cli.command("quickstart")
    def quickstart_cmd() -> None:
        """Step-by-step beginner walkthrough — from zero to first scan."""
        console = Console()
        _render_quickstart(console)

