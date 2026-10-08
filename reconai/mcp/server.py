"""Full Model Context Protocol (MCP) Server for ReconAI.

Exposes ReconAI's attack surface database, findings, correlation graphs,
and PoC generators to AI assistants (Claude, Cursor, Antigravity, etc.)
over standard JSON-RPC 2.0 stdio transport.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from reconai.core.database.manager import DatabaseManager
from reconai.core.correlation.engine import CorrelationEngine
from reconai.intelligence.poc_generator import PoCGenerator


# ── Registered Tools Definitions ──────────────────────────────────────────
MCP_TOOLS = [
    {
        "name": "get_scan_summary",
        "description": "Retrieve high-level statistics and target info for a recon scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
            },
            "required": ["scan_path_or_id"],
        },
    },
    {
        "name": "get_subdomains",
        "description": "List discovered subdomains and resolved IP addresses.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
                "limit": {"type": "integer", "description": "Maximum subdomains to return (default: 50)"},
            },
            "required": ["scan_path_or_id"],
        },
    },
    {
        "name": "get_ports",
        "description": "List discovered open ports, services, and software versions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
            },
            "required": ["scan_path_or_id"],
        },
    },
    {
        "name": "get_findings",
        "description": "List identified security findings and vulnerabilities with optional severity filter.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
                "min_severity": {
                    "type": "string",
                    "enum": ["all", "critical", "high", "medium", "low"],
                    "description": "Minimum severity threshold",
                },
            },
            "required": ["scan_path_or_id"],
        },
    },
    {
        "name": "get_attack_graph",
        "description": "Retrieve full attack surface correlation graph with nodes, edges, and attack paths.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
            },
            "required": ["scan_path_or_id"],
        },
    },
    {
        "name": "generate_poc",
        "description": "Generate a runnable Python script and curl reproduction command for a specific finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
                "finding_title": {"type": "string", "description": "Title or keyword of the finding"},
            },
            "required": ["scan_path_or_id", "finding_title"],
        },
    },
    {
        "name": "get_threat_profile",
        "description": "Analyze target stack for threat actor profiles, motives, and MITRE ATT&CK TTPs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
            },
            "required": ["scan_path_or_id"],
        },
    },
    {
        "name": "get_prioritized_endpoints",
        "description": "Rank crawled URLs and APIs by offensive attack surface value.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
                "limit": {"type": "integer", "description": "Number of endpoints to return (default: 25)"},
            },
            "required": ["scan_path_or_id"],
        },
    },
    {
        "name": "get_waf_advisory",
        "description": "Analyze perimeter WAFs, origin IP leakage, and testing pacing guidance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
            },
            "required": ["scan_path_or_id"],
        },
    },
    {
        "name": "ask_copilot",
        "description": "Ask a question to the ReconAI Red Team Copilot about scan results, vulnerabilities, attack depth, or remediation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_path_or_id": {"type": "string", "description": "Scan directory path or Scan ID"},
                "question": {"type": "string", "description": "Question to ask the Copilot"},
            },
            "required": ["scan_path_or_id", "question"],
        },
    },
]


def _resolve_db(scan_path_or_id: str) -> tuple[DatabaseManager | None, str]:
    """Finds the SQLite database for a given scan path or scan ID."""
    p = Path(scan_path_or_id)
    if p.is_dir() and (p / "reconai.db").exists():
        db = DatabaseManager(db_path=p / "reconai.db")
        scans = db.list_scans(limit=1)
        scan_id = scans[0]["id"] if scans else p.name
        return db, scan_id

    # Search in default output directory
    from reconai.core.config.manager import ConfigManager
    cfg = ConfigManager()
    base_out = Path(cfg.config.output.base_dir)
    for cand in base_out.rglob(scan_path_or_id):
        if cand.is_dir() and (cand / "reconai.db").exists():
            db = DatabaseManager(db_path=cand / "reconai.db")
            scans = db.list_scans(limit=1)
            scan_id = scans[0]["id"] if scans else cand.name
            return db, scan_id

    return None, ""


def handle_tool_call(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatches tool execution to the appropriate ReconAI engine."""
    scan_ref = arguments.get("scan_path_or_id", "")
    db, scan_id = _resolve_db(scan_ref)
    if not db:
        return {"content": [{"type": "text", "text": f"Error: Scan database not found for '{scan_ref}'."}], "isError": True}

    if tool_name == "get_scan_summary":
        stats = db.get_scan_stats(scan_id)
        scan_rec = db.get_scan(scan_id) or {}
        return {"content": [{"type": "text", "text": json.dumps({"scan": scan_rec, "stats": stats}, indent=2)}]}

    elif tool_name == "get_subdomains":
        limit = int(arguments.get("limit", 50))
        subs = db.get_subdomains(scan_id)[:limit]
        return {"content": [{"type": "text", "text": json.dumps(subs, indent=2)}]}

    elif tool_name == "get_ports":
        ports = db.get_ports(scan_id)
        return {"content": [{"type": "text", "text": json.dumps(ports, indent=2)}]}

    elif tool_name == "get_findings":
        min_sev = str(arguments.get("min_severity", "all")).lower()
        findings = db.get_findings(scan_id)
        if min_sev != "all":
            rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            thresh = rank.get(min_sev, 5)
            findings = [f for f in findings if rank.get(str(f.get("severity", "")).lower(), 5) <= thresh]
        return {"content": [{"type": "text", "text": json.dumps(findings, indent=2)}]}

    elif tool_name == "get_attack_graph":
        engine = CorrelationEngine(db, scan_id)
        graph = engine.build_graph()
        paths = engine.find_attack_paths()
        return {"content": [{"type": "text", "text": json.dumps({"graph": graph, "attack_paths": paths}, indent=2)}]}

    elif tool_name == "generate_poc":
        title = str(arguments.get("finding_title", "")).lower()
        findings = db.get_findings(scan_id)
        matched = next((f for f in findings if title in str(f.get("title", "")).lower()), None)
        if not matched:
            return {"content": [{"type": "text", "text": f"No finding matching '{title}' was found."}], "isError": True}

        poc_gen = PoCGenerator()
        poc = poc_gen.generate(matched)
        output = {
            "title": matched.get("title"),
            "target": matched.get("affected_asset"),
            "python_script": poc.python_script,
            "curl_command": poc.curl_command,
            "nuclei_template": poc.nuclei_template,
        }
        return {"content": [{"type": "text", "text": json.dumps(output, indent=2)}]}

    elif tool_name == "get_threat_profile":
        import asyncio
        from reconai.ai.threat_profiler import ThreatActorProfiler
        profiler = ThreatActorProfiler(db, scan_id)
        res = asyncio.run(profiler.generate_threat_profile())
        return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}

    elif tool_name == "get_prioritized_endpoints":
        limit = int(arguments.get("limit", 25))
        from reconai.ai.fuzz_optimizer import AttackSurfacePrioritizer
        prioritizer = AttackSurfacePrioritizer(db, scan_id)
        ranked = prioritizer.prioritize_endpoints(limit=limit)
        return {"content": [{"type": "text", "text": json.dumps(ranked, indent=2)}]}

    elif tool_name == "get_waf_advisory":
        import asyncio
        from reconai.ai.defensive_advisor import DefensiveAdvisor
        advisor = DefensiveAdvisor(db, scan_id)
        adv_res = asyncio.run(advisor.analyze_perimeter_defenses())
        return {"content": [{"type": "text", "text": json.dumps(adv_res, indent=2)}]}

    elif tool_name == "ask_copilot":
        import asyncio
        from reconai.ai.copilot import ReconCopilot
        question = str(arguments.get("question", ""))
        copilot = ReconCopilot(db, scan_id)
        reply = asyncio.run(copilot.ask(question))
        return {"content": [{"type": "text", "text": reply}]}

    return {"content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}], "isError": True}


def run_mcp_server() -> None:
    """Stdio-based Model Context Protocol (MCP) server event loop."""
    sys.stderr.write("ReconAI Model Context Protocol (MCP) Server initialized.\n")
    sys.stderr.write("Listening for JSON-RPC 2.0 messages on stdin...\n")
    sys.stderr.flush()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break

            line_str = line.strip()
            if not line_str:
                continue

            try:
                req = json.loads(line_str)
            except json.JSONDecodeError:
                continue

            msg_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {})

            # ── 1. Protocol Handshake ─────────────────────────────────────
            if method == "initialize":
                res = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "reconai-mcp", "version": "2.0.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            elif method == "notifications/initialized":
                continue
            elif method == "ping":
                res = {"jsonrpc": "2.0", "id": msg_id, "result": {}}

            # ── 2. Tools Protocol ─────────────────────────────────────────
            elif method == "tools/list":
                res = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"tools": MCP_TOOLS},
                }
            elif method == "tools/call":
                t_name = params.get("name", "")
                t_args = params.get("arguments", {})
                tool_result = handle_tool_call(t_name, t_args)
                res = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": tool_result,
                }
            else:
                res = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Method '{method}' not implemented."},
                }

            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

        except KeyboardInterrupt:
            break
        except Exception as exc:
            sys.stderr.write(f"MCP Server error: {exc}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    run_mcp_server()
