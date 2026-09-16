"""Asset Correlation Engine.

Builds relationships between discovered assets to form an attack surface graph.

Fixes applied:
  - Flaw 8: bare `except:` replaced with `except Exception` — never swallows
    KeyboardInterrupt, SystemExit, or MemoryError again.
  - Flaw 13/14: `import json` was inside the ip loop (repeated dict lookup
    on every iteration). Moved to the top of the file.
"""
from __future__ import annotations

import json

from reconai.core.database.manager import DatabaseManager


class CorrelationEngine:
    def __init__(self, db: DatabaseManager, scan_id: str) -> None:
        self.db = db
        self.scan_id = scan_id

    def build_graph(self) -> dict[str, list[dict[str, str]]]:
        """Build a JSON representation of the attack surface graph.

        Returns a hierarchical dict with 'nodes' and 'edges' lists.
        In a full implementation this could export GraphML via NetworkX.
        """
        graph: dict[str, list[dict[str, str]]] = {
            "nodes": [],
            "edges": [],
        }

        subs     = self.db.get_subdomains(self.scan_id)
        ips      = self.db.get_ips(self.scan_id)
        ports    = self.db.get_ports(self.scan_id)
        findings = self.db.get_findings(self.scan_id)

        # ── Subdomain nodes ───────────────────────────────────────────────
        for sub in subs:
            graph["nodes"].append({
                "id":    str(sub["subdomain"]),
                "label": str(sub["subdomain"]),
                "type":  "subdomain",
            })

        # ── IP nodes + subdomain → IP edges ──────────────────────────────
        for ip in ips:
            graph["nodes"].append({
                "id":    str(ip["ip"]),
                "label": str(ip["ip"]),
                "type":  "ip",
            })
            try:
                # hostnames is stored as a JSON-encoded list
                hostnames: list[str] = json.loads(ip.get("hostnames", "[]"))
                for hostname in hostnames:
                    graph["edges"].append({
                        "source": str(hostname),
                        "target": str(ip["ip"]),
                        "label":  "resolves_to",
                    })
            except (json.JSONDecodeError, TypeError):
                # Malformed hostnames field — skip edges for this IP, don't crash
                pass

        # ── Port nodes + IP → port edges ─────────────────────────────────
        for port in ports:
            port_id = f"{port['host']}:{port['port']}"
            graph["nodes"].append({
                "id":    port_id,
                "label": f"{port['port']}/{port['protocol']}",
                "type":  "port",
            })
            graph["edges"].append({
                "source": str(port["host"]),
                "target": port_id,
                "label":  "exposes",
            })

        # ── Finding nodes + finding → asset edges ─────────────────────────
        for finding in findings:
            find_id = f"finding_{finding['id']}"
            graph["nodes"].append({
                "id":       find_id,
                "label":    str(finding["title"]),
                "type":     "finding",
                "severity": str(finding["severity"]),
            })
            graph["edges"].append({
                "source": find_id,
                "target": str(finding["affected_asset"]),
                "label":  "affects",
            })

        return graph
