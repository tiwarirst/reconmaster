"""Report Generator.

Generates Markdown and HTML reports from scan data.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from reconai.core.database.manager import DatabaseManager
from reconai.reports.scoring import RiskScoringEngine
from reconai.core.correlation.engine import CorrelationEngine
from reconai.reports.html import generate_html_report


class ReportGenerator:
    def __init__(self, db: DatabaseManager, scan_id: str, output_dir: Path):
        self.db = db
        self.scan_id = scan_id
        self.output_dir = output_dir
        self.reports_dir = output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.scan_record = self.db.get_scan(self.scan_id)
        if not self.scan_record:
            raise ValueError(f"Scan ID {scan_id} not found in database.")
            
        self.target = self.scan_record["target"]

    def generate_json(self) -> Path:
        """Export all data to a single JSON file."""
        data = self.db.get_scan_data_for_comparison(self.scan_id)
        data["scan"] = self.scan_record
        data["stats"] = self.db.get_scan_stats(self.scan_id)
        
        # Add risk score and graph
        scoring = RiskScoringEngine(self.db, self.scan_id)
        data["risk"] = scoring.calculate_score()
        
        correlation = CorrelationEngine(self.db, self.scan_id)
        data["asset_graph"] = correlation.build_graph()
        
        out_file = self.reports_dir / "report.json"
        with open(out_file, "w") as f:
            json.dump(data, f, indent=2, default=str)
            
        return out_file

    def generate_markdown(self) -> Path:
        """Generate a human-readable Markdown report."""
        stats = self.db.get_scan_stats(self.scan_id)
        findings = self.db.get_findings(self.scan_id)
        subs = self.db.get_subdomains(self.scan_id)
        ports = self.db.get_ports(self.scan_id)
        techs = self.db.get_technologies(self.scan_id)
        
        scoring = RiskScoringEngine(self.db, self.scan_id)
        risk = scoring.calculate_score()
        
        lines = [
            f"# ReconAI Report: {self.target}",
            f"**Scan ID:** `{self.scan_id}`",
            f"**Date:** {self.scan_record['started_at']}",
            f"**Duration:** {self.scan_record['duration']:.1f}s",
            "",
            "## Risk Assessment",
            f"- **Overall Risk Score:** {risk['score']}/100",
            f"- **Security Grade:** {risk['grade']}",
            "",
            "## Executive Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Subdomains | {stats.get('subdomains', 0)} |",
            f"| Open Ports | {stats.get('ports', 0)} |",
            f"| URLs Discovered | {stats.get('urls', 0)} |",
            f"| Technologies | {stats.get('technologies', 0)} |",
            f"| Security Findings | {stats.get('findings', 0)} |",
            "",
            "## Findings",
            ""
        ]
        
        if not findings:
            lines.append("No security findings discovered.")
            
        for f in findings:
            lines.extend([
                f"### {f['title']}",
                f"- **Severity:** {f['severity'].upper()}",
                f"- **Confidence:** {f['confidence'].upper()}",
                f"- **Asset:** {f['affected_asset']}",
                "",
                f"**Description:** {f['description']}",
                "",
                f"**Impact:** {f['impact']}",
                "",
                f"**Remediation:** {f['remediation']}",
                "---"
            ])
            
        lines.extend([
            "",
            "## Asset Inventory",
            "### Subdomains",
            ""
        ])
        
        if subs:
            for s in subs[:50]: # Limit to 50 for markdown to avoid giant files
                lines.append(f"- {s['subdomain']}")
            if len(subs) > 50:
                lines.append(f"- ... and {len(subs) - 50} more (see JSON report)")
        else:
            lines.append("No subdomains discovered.")
            
        lines.extend([
            "",
            "### Open Ports & Services",
            ""
        ])
        
        if ports:
            lines.append("| Host | Port/Proto | Service | Version |")
            lines.append("|------|------------|---------|---------|")
            for p in ports:
                lines.append(f"| {p['host']} | {p['port']}/{p['protocol']} | {p['service']} | {p['version']} |")
        else:
            lines.append("No open ports discovered.")
            
        lines.extend([
            "",
            "### Technologies Detected",
            ""
        ])
        
        if techs:
            for t in techs:
                lines.append(f"- **{t['name']}** {t['version']} on {t['host']}")
        else:
            lines.append("No technologies detected.")
            
        out_file = self.reports_dir / "report.md"
        with open(out_file, "w") as f:
            f.write("\n".join(lines))
            
        return out_file
        
    def generate_all(self) -> dict[str, Path]:
        """Generate all report formats."""
        html_path = generate_html_report(self.db, self.scan_id, self.reports_dir)
        return {
            "json": self.generate_json(),
            "markdown": self.generate_markdown(),
            "html": html_path,
        }
