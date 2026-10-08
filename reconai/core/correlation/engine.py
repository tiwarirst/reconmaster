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
from typing import Any

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

        # ── Cloud Asset nodes + edges ────────────────────────────────────
        cloud_assets = self.db.get_cloud_assets(self.scan_id)
        for ca in cloud_assets:
            ca_id = f"cloud_{ca['provider']}_{ca['asset_name']}"
            graph["nodes"].append({
                "id":        ca_id,
                "label":     f"{ca['provider'].upper()}: {ca['asset_name']}",
                "type":      "cloud_asset",
                "provider":  str(ca["provider"]),
                "asset_type": str(ca["asset_type"]),
                "is_public": str(bool(ca["is_public"])),
            })

            # If CNAME originated from a specific subdomain, link them
            meta = ca.get("metadata")
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            cname_from = (meta or {}).get("cname_from")
            if cname_from:
                graph["edges"].append({
                    "source": str(cname_from),
                    "target": ca_id,
                    "label":  "cloud_cname",
                })

        return graph

    def get_correlated_chains(self) -> list[dict[str, Any]]:
        """Extract multi-tier correlated attack surface chains: Host -> IP -> Ports -> Tech -> Findings."""
        subs = self.db.get_subdomains(self.scan_id)
        ips = self.db.get_ips(self.scan_id)
        ports = self.db.get_ports(self.scan_id)
        techs = self.db.get_technologies(self.scan_id)
        findings = self.db.get_findings(self.scan_id)

        # Map IPs by hostname
        ip_map: dict[str, list[str]] = {}
        for ip in ips:
            ip_val = str(ip.get("ip", ""))
            try:
                raw_h = ip.get("hostnames", "[]")
                hostnames = json.loads(raw_h) if isinstance(raw_h, str) else list(raw_h)
            except Exception:
                hostnames = []
            for h in hostnames:
                ip_map.setdefault(str(h).lower(), []).append(ip_val)

        # Map ports by host/ip
        port_map: dict[str, list[str]] = {}
        for p in ports:
            h = str(p.get("host", "")).lower()
            svc = f"{p.get('port')}/{p.get('protocol')} ({p.get('service') or 'unknown'})"
            port_map.setdefault(h, []).append(svc)

        # Map techs by host
        tech_map: dict[str, list[str]] = {}
        for t in techs:
            h = str(t.get("host", "")).lower()
            val = t.get("name", "")
            if t.get("version"):
                val += f" {t['version']}"
            tech_map.setdefault(h, []).append(val)

        # Map findings by affected asset
        find_map: dict[str, list[dict[str, str]]] = {}
        for f in findings:
            asset = str(f.get("affected_asset", "")).lower()
            find_map.setdefault(asset, []).append({
                "title": str(f.get("title", "")),
                "severity": str(f.get("severity", "")),
            })

        cloud_assets = self.db.get_cloud_assets(self.scan_id)

        chains: list[dict[str, Any]] = []
        host_list = [str(s.get("subdomain")) for s in subs]
        if not host_list:
            host_list = list({str(p.get("host")) for p in ports if p.get("host")})

        for host in host_list:
            h_lower = host.lower()
            associated_ips = ip_map.get(h_lower, [])

            associated_ports = list(port_map.get(h_lower, []))
            for ip in associated_ips:
                associated_ports.extend(port_map.get(ip.lower(), []))
            associated_ports = list(dict.fromkeys(associated_ports))

            associated_techs = list(tech_map.get(h_lower, []))
            for ip in associated_ips:
                associated_techs.extend(tech_map.get(ip.lower(), []))
            associated_techs = list(dict.fromkeys(associated_techs))

            associated_findings: list[dict[str, str]] = []
            for asset_key, f_list in find_map.items():
                if h_lower in asset_key or any(ip.lower() in asset_key for ip in associated_ips):
                    associated_findings.extend(f_list)

            # Deduplicate findings per host
            seen_finds = set()
            unique_findings = []
            for f in associated_findings:
                f_key = (f.get("title", ""), f.get("severity", ""))
                if f_key not in seen_finds:
                    seen_finds.add(f_key)
                    unique_findings.append(f)

            # Correlate cloud assets linked by CNAME or domain naming
            associated_clouds = []
            for ca in cloud_assets:
                meta = ca.get("metadata")
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                cname_from = str((meta or {}).get("cname_from", "")).lower()
                ca_name = str(ca.get("asset_name", "")).lower()
                ca_url = str(ca.get("url", "")).lower()
                if cname_from == h_lower or h_lower in ca_name or h_lower in ca_url:
                    associated_clouds.append(f"[{ca.get('provider', '').upper()}] {ca.get('asset_name')} ({ca.get('asset_type')})")

            chains.append({
                "host": host,
                "ips": associated_ips,
                "ports": associated_ports,
                "technologies": associated_techs,
                "cloud_assets": list(dict.fromkeys(associated_clouds)),
                "findings": unique_findings,
            })

        return chains

    def find_attack_paths(self) -> list[dict[str, Any]]:
        """Compute critical multi-hop attack paths from perimeter to sensitive assets.
        
        Evaluates cumulative risk per path: Internet -> Host -> Service -> Vulnerability/Storage.
        """
        chains = self.get_correlated_chains()
        paths: list[dict[str, Any]] = []

        sev_scores = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}

        for chain in chains:
            host = chain.get("host", "")
            findings = chain.get("findings", [])
            clouds = chain.get("cloud_assets", [])
            ports = chain.get("ports", [])
            ips = chain.get("ips", [])

            # Path A: Findings on this host
            for f in findings:
                sev = str(f.get("severity", "info")).lower()
                score = sev_scores.get(sev, 1)
                paths.append({
                    "entry_point": host,
                    "target": f.get("title"),
                    "type": "Vulnerability Path",
                    "severity": sev.upper(),
                    "score": score,
                    "path_nodes": [
                        {"label": "Internet Perimeter", "type": "entry"},
                        {"label": host, "type": "subdomain"},
                        {"label": ips[0] if ips else "Unknown IP", "type": "ip"},
                        {"label": ports[0] if ports else "Web (80/443)", "type": "service"},
                        {"label": f.get("title"), "type": "exploit", "severity": sev},
                    ],
                    "choke_point": host,
                })

            # Path B: Cloud assets linked to this host
            for ca in clouds:
                paths.append({
                    "entry_point": host,
                    "target": ca,
                    "type": "Cloud Takeover / Access Path",
                    "severity": "HIGH",
                    "score": 8,
                    "path_nodes": [
                        {"label": "Internet Perimeter", "type": "entry"},
                        {"label": host, "type": "subdomain"},
                        {"label": ca, "type": "cloud_storage"},
                    ],
                    "choke_point": host,
                })

        # Sort paths by risk score descending
        paths.sort(key=lambda x: x.get("score", 0), reverse=True)
        return paths

