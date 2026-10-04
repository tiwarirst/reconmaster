"""Report Generator.

Generates Markdown, JSON, and HTML reports from scan data.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from reconai.core.database.manager import DatabaseManager
from reconai.core.correlation.engine import CorrelationEngine
from reconai.reports.html import generate_html_report
from reconai.reports.scoring import RiskScoringEngine


class ReportGenerator:
    """Generates scan reports in multiple formats."""

    def __init__(self, db: DatabaseManager, scan_id: str, output_dir: Path) -> None:
        self.db = db
        self.scan_id = scan_id
        self.output_dir = output_dir
        self.reports_dir = output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        scan_record = self.db.get_scan(self.scan_id)
        if not scan_record:
            raise ValueError(f"Scan ID {scan_id} not found in database.")

        self.scan_record: dict[str, Any] = dict(scan_record)
        self.target: str = str(self.scan_record["target"])

    def generate_json(self) -> Path:
        """Export all data to a single JSON file."""
        # Use Any-typed dict so we can freely add heterogeneous values
        data: dict[str, Any] = dict(self.db.get_scan_data_for_comparison(self.scan_id))
        data["scan"] = self.scan_record
        data["stats"] = self.db.get_scan_stats(self.scan_id)

        # Add risk score and graph
        scoring = RiskScoringEngine(self.db, self.scan_id)
        data["risk"] = scoring.calculate_score()

        correlation = CorrelationEngine(self.db, self.scan_id)
        data["asset_graph"] = correlation.build_graph()

        out_file = self.reports_dir / "report.json"
        with open(out_file, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2, default=str)

        return out_file

    def generate_markdown(self) -> Path:
        """Generate a human-readable Markdown report."""
        stats: dict[str, Any] = dict(self.db.get_scan_stats(self.scan_id))
        findings = self.db.get_findings(self.scan_id)
        subs = self.db.get_subdomains(self.scan_id)
        ports = self.db.get_ports(self.scan_id)
        techs = self.db.get_technologies(self.scan_id)
        cloud_assets = self.db.get_cloud_assets(self.scan_id)

        scoring = RiskScoringEngine(self.db, self.scan_id)
        risk: dict[str, Any] = scoring.calculate_score()

        lines: list[str] = [
            f"# ReconAI Report: {self.target}",
            f"**Scan ID:** `{self.scan_id}`",
            f"**Date:** {self.scan_record['started_at']}",
            f"**Duration:** {self.scan_record.get('duration', 0):.1f}s",
            "",
            "## Risk Assessment",
            f"- **Overall Risk Score:** {risk.get('score', 0)}/100",
            f"- **Security Grade:** {risk.get('grade', 'N/A')}",
            "",
            "## Executive Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Subdomains | {stats.get('subdomains', 0)} |",
            f"| Open Ports | {stats.get('ports', 0)} |",
            f"| URLs | {stats.get('urls', 0)} |",
            f"| Technologies | {stats.get('technologies', 0)} |",
            f"| Cloud Assets | {stats.get('cloud_assets', 0)} |",
            f"| Findings | {stats.get('findings', 0)} |",
            "",
            "## Findings",
            "",
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
                "---",
            ])

        lines.extend([
            "",
            "## Asset Inventory",
            "### Subdomains",
            "",
        ])

        if subs:
            for s in subs[:50]:  # Limit to 50 for markdown to avoid giant files
                lines.append(f"- {s['subdomain']}")
            if len(subs) > 50:
                lines.append(f"- ... and {len(subs) - 50} more (see JSON report)")
        else:
            lines.append("No subdomains discovered.")

        lines.extend([
            "",
            "### Open Ports & Services",
            "",
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
            "",
        ])

        if techs:
            for t in techs:
                lines.append(f"- **{t['name']}** {t['version']} on {t['host']}")
        else:
            lines.append("No technologies detected.")

        lines.extend([
            "",
            "### Cloud Assets & Storage",
            "",
        ])

        if cloud_assets:
            lines.append("| Provider | Type | Asset Name | Public | Writable | URL |")
            lines.append("|----------|------|------------|--------|----------|-----|")
            for c in cloud_assets:
                pub = "YES" if c.get("is_public") else "No"
                writ = "YES" if c.get("is_writable") else "No"
                url = c.get("url", "")
                lines.append(f"| {c.get('provider', '').upper()} | {c.get('asset_type')} | {c.get('asset_name')} | {pub} | {writ} | {url} |")
        else:
            lines.append("No cloud assets or storage buckets discovered.")

        out_file = self.reports_dir / "report.md"
        with open(out_file, "w", encoding="utf-8") as fp:
            fp.write("\n".join(lines))

        return out_file

    def generate_csv(self) -> dict[str, Path]:
        """Export tabular scan data to CSV spreadsheets for enterprise/reporting workflows."""
        import csv

        csv_dir = self.reports_dir / "csv"
        csv_dir.mkdir(parents=True, exist_ok=True)
        csv_files: dict[str, Path] = {}

        # 1. Findings CSV
        findings_path = csv_dir / "findings.csv"
        findings = self.db.get_findings(self.scan_id)
        f_fields = ["title", "severity", "confidence", "status", "affected_asset", "affected_asset_type", "description", "remediation", "cvss"]
        with open(findings_path, "w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=f_fields, extrasaction="ignore")
            writer.writeheader()
            for f in findings:
                writer.writerow(f)
        csv_files["findings"] = findings_path

        # 2. Cloud Assets CSV
        cloud_path = csv_dir / "cloud_assets.csv"
        cloud_assets = self.db.get_cloud_assets(self.scan_id)
        c_fields = ["provider", "asset_type", "asset_name", "url", "is_public", "is_writable", "region", "source"]
        with open(cloud_path, "w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=c_fields, extrasaction="ignore")
            writer.writeheader()
            for c in cloud_assets:
                writer.writerow(c)
        csv_files["cloud_assets"] = cloud_path

        # 3. Subdomains CSV
        subs_path = csv_dir / "subdomains.csv"
        subs = self.db.get_subdomains(self.scan_id)
        s_fields = ["subdomain", "is_alive", "resolved_ips", "http_status", "title"]
        with open(subs_path, "w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=s_fields, extrasaction="ignore")
            writer.writeheader()
            for s in subs:
                writer.writerow(s)
        csv_files["subdomains"] = subs_path

        # 4. API Endpoints CSV
        api_path = csv_dir / "api_endpoints.csv"
        apis = self.db.get_api_endpoints(self.scan_id)
        a_fields = ["host", "method", "path", "full_url", "api_type", "auth_required", "source"]
        with open(api_path, "w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=a_fields, extrasaction="ignore")
            writer.writeheader()
            for a in apis:
                writer.writerow(a)
        csv_files["api_endpoints"] = api_path

        # 5. Ports CSV
        ports_path = csv_dir / "ports.csv"
        ports = self.db.get_ports(self.scan_id)
        p_fields = ["host", "port", "protocol", "state", "service", "product", "version"]
        with open(ports_path, "w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=p_fields, extrasaction="ignore")
            writer.writeheader()
            for p in ports:
                writer.writerow(p)
        csv_files["ports"] = ports_path

        return csv_files

    def generate_all(self) -> dict[str, Any]:
        """Generate all report formats."""
        html_path = generate_html_report(self.db, self.scan_id, self.reports_dir)
        return {
            "json": self.generate_json(),
            "markdown": self.generate_markdown(),
            "html": html_path,
            "csv": self.generate_csv(),
        }
