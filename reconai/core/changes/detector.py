"""Change Detection Engine.

Compares two scans to find new assets, closed ports, or resolved findings.
"""
from __future__ import annotations

from reconai.core.database.manager import DatabaseManager


class ChangeDetector:
    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def compare(self, old_scan_id: str, new_scan_id: str) -> dict[str, list[str]]:
        """Compare two scans and return the differences."""
        
        old_data = self.db.get_scan_data_for_comparison(old_scan_id)
        new_data = self.db.get_scan_data_for_comparison(new_scan_id)
        
        diff: dict[str, list[str]] = {
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_ports": [],
            "closed_ports": [],
            "new_findings": [],
            "resolved_findings": [],
            "new_cloud_assets": [],
            "removed_cloud_assets": [],
        }
        
        # Compare Subdomains
        old_subs = {s["subdomain"] for s in old_data["subdomains"]}
        new_subs = {s["subdomain"] for s in new_data["subdomains"]}
        
        diff["new_subdomains"] = list(new_subs - old_subs)
        diff["removed_subdomains"] = list(old_subs - new_subs)
        
        # Compare Ports
        old_ports = {f"{p['host']}:{p['port']}" for p in old_data["ports"]}
        new_ports = {f"{p['host']}:{p['port']}" for p in new_data["ports"]}
        
        diff["new_ports"] = list(new_ports - old_ports)
        diff["closed_ports"] = list(old_ports - new_ports)
        
        # Compare Findings (by Title + Asset)
        old_finds = {f"{f['title']}:{f['affected_asset']}" for f in old_data["findings"]}
        new_finds = {f"{f['title']}:{f['affected_asset']}" for f in new_data["findings"]}
        
        diff["new_findings"] = list(new_finds - old_finds)
        diff["resolved_findings"] = list(old_finds - new_finds)

        # Compare Cloud Assets
        old_ca = {f"[{c['provider'].upper()}] {c['asset_name']} ({c['asset_type']})" for c in old_data.get("cloud_assets", [])}
        new_ca = {f"[{c['provider'].upper()}] {c['asset_name']} ({c['asset_type']})" for c in new_data.get("cloud_assets", [])}

        diff["new_cloud_assets"] = list(new_ca - old_ca)
        diff["removed_cloud_assets"] = list(old_ca - new_ca)
        
        return diff
