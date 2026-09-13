"""Asset Correlation Engine.

Builds relationships between discovered assets to form an attack surface graph.
"""
from __future__ import annotations

from reconai.core.database.manager import DatabaseManager


class CorrelationEngine:
    def __init__(self, db: DatabaseManager, scan_id: str):
        self.db = db
        self.scan_id = scan_id

    def build_graph(self) -> dict:
        """
        Builds a JSON representation of the asset graph.
        In a full implementation, this could use NetworkX to export GraphML or GML.
        For now, we build a hierarchical JSON structure.
        """
        graph = {
            "nodes": [],
            "edges": []
        }
        
        # Load all assets
        subs = self.db.get_subdomains(self.scan_id)
        ips = self.db.get_ips(self.scan_id)
        ports = self.db.get_ports(self.scan_id)
        techs = self.db.get_technologies(self.scan_id)
        findings = self.db.get_findings(self.scan_id)
        
        # Add Subdomain Nodes
        for sub in subs:
            graph["nodes"].append({"id": sub["subdomain"], "label": sub["subdomain"], "type": "subdomain"})
            
        # Add IP Nodes & Edges
        for ip in ips:
            graph["nodes"].append({"id": ip["ip"], "label": ip["ip"], "type": "ip"})
            import json
            try:
                hostnames = json.loads(ip["hostnames"])
                for h in hostnames:
                    graph["edges"].append({"source": h, "target": ip["ip"], "label": "resolves_to"})
            except:
                pass
                
        # Add Port Nodes & Edges
        for port in ports:
            port_id = f"{port['host']}:{port['port']}"
            graph["nodes"].append({"id": port_id, "label": f"{port['port']}/{port['protocol']}", "type": "port"})
            graph["edges"].append({"source": port['host'], "target": port_id, "label": "exposes"})
            
        # Add Finding Nodes & Edges
        for f in findings:
            find_id = f"finding_{f['id']}"
            graph["nodes"].append({"id": find_id, "label": f["title"], "type": "finding", "severity": f["severity"]})
            graph["edges"].append({"source": find_id, "target": f["affected_asset"], "label": "affects"})
            
        return graph
