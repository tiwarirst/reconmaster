"""Minimal MCP (Model Context Protocol) Server.

This acts as a bridge allowing AI agents to interact with ReconAI securely.
"""
from __future__ import annotations

import json
import sys


def run_mcp_server() -> None:
    """Minimal stdio-based MCP server stub.
    
    In a full implementation, this would use the official MCP Python SDK
    to expose tools like get_target, get_scope, get_findings, etc.
    """
    sys.stderr.write("ReconAI MCP Server started.\n")
    sys.stderr.write("Waiting for JSON-RPC requests on stdin...\n")
    
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
                
            try:
                request = json.loads(line)
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {
                        "code": -32601,
                        "message": "Method not found. Minimal stub implementation."
                    }
                }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError:
                pass
        except KeyboardInterrupt:
            break
