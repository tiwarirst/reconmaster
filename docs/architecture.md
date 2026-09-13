# Architecture Guide

## Overview

ReconAI is a modular, asynchronous, event-driven attack surface intelligence platform. It is designed to run natively on Kali Linux and integrate with the full suite of existing Kali security tools.

## Core Design Principles

- **Non-Blocking**: Every external process (Nmap, Nuclei, etc.) runs asynchronously via `asyncio.create_subprocess_exec`.
- **Loosely Coupled**: Modules communicate via an event bus (`EventBus`), not direct function calls.
- **Scope-First**: Every target is validated against the `ScopeManager` before any tool is invoked.
- **Modular**: Every tool integration lives in its own file. Adding a new tool requires writing one adapter + one module.

## Directory Structure

```
reconai/
├── ai/              # AI/LLM adapters (Ollama)
├── cli/             # Click CLI commands
├── core/
│   ├── changes/     # Scan diff and change detection
│   ├── config/      # YAML-based config system
│   ├── correlation/ # Asset graph engine
│   ├── database/    # SQLite data layer
│   ├── events/      # Async event bus
│   ├── executor/    # Process runner & timeout manager
│   ├── logging/     # Structured logging & secret redaction
│   ├── normalizer/  # Data normalization (DNS, HTTP, Ports)
│   └── scope/       # Scope enforcement
├── integrations/    # One file per external tool
├── mcp/             # Model Context Protocol server
├── modules/
│   ├── active/      # Active scanning modules
│   ├── passive/     # Passive recon modules
│   ├── vuln/        # Vulnerability detection modules
│   └── web/         # Web-layer modules
├── reports/         # Report generators (HTML, JSON, MD)
└── ui/              # Rich terminal UI
```

## Pipeline Flow

```
CLI → Orchestrator → ScopeManager → EventBus → Modules → DB
                                    ↑
                              (loose coupling)
```

## Adding a New Tool

1. Create `reconai/integrations/mytool.py` — implement `build_command()` and `parse()`.
2. Create `reconai/modules/active/mytool.py` — implement `run()`, call the adapter, store results, emit events.
3. Add `@register_module` decorator.
4. Import it in `reconai/cli/main.py`.
5. Add its name to the appropriate scan modes in `reconai/core/config/defaults.py`.
