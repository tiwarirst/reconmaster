"""Main CLI entry point for ReconAI.

Uses Click to provide a professional, structured command-line interface.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import click

from reconai.core.config.manager import ConfigManager
from reconai.core.orchestrator import Orchestrator
from reconai.core.scope.manager import ScopeManager
from reconai.reports.generator import ReportGenerator
from reconai.ui.console import ReconConsole
from reconai.version import FULL_VERSION

# Force import modules to register them
import reconai.modules.passive.dns_enum
import reconai.modules.passive.cert_transparency
import reconai.modules.passive.whois
import reconai.modules.passive.archive
import reconai.modules.passive.paramspider
import reconai.modules.passive.dnsx
import reconai.modules.active.subdomains
import reconai.modules.active.http_probe
import reconai.modules.active.port_scan
import reconai.modules.active.naabu
import reconai.modules.web.crawler
import reconai.modules.web.directory
import reconai.modules.web.technologies
import reconai.modules.web.headers
import reconai.modules.web.javascript
import reconai.modules.web.browser
import reconai.modules.web.waf
import reconai.modules.web.ffuf
import reconai.modules.web.katana
import reconai.modules.vuln.intelligence
import reconai.modules.vuln.nuclei
import reconai.modules.vuln.secrets
import reconai.modules.vuln.sqlmap
import reconai.modules.vuln.dalfox
import reconai.modules.web.host_browser
# Cloud enumeration modules
import reconai.modules.cloud.bucket_enum
import reconai.modules.cloud.cloud_enum
import reconai.modules.cloud.metadata_ssrf
import reconai.modules.cloud.iam_analyzer


@click.group()
@click.version_option(version=FULL_VERSION)
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option("--verbose", is_flag=True, help="Stream raw tool output to terminal")
@click.option("--config", type=click.Path(exists=True), help="Path to custom config.yaml")
@click.pass_context
def cli(ctx: click.Context, debug: bool, verbose: bool, config: str | None) -> None:
    """ReconAI — Modular Attack Surface Intelligence Platform"""
    ctx.ensure_object(dict)
    
    # Initialize Core UI & Config
    console = ReconConsole(verbose=verbose, debug=debug)
    config_mgr = ConfigManager(Path(config) if config else None)
    
    # Apply CLI overrides
    config_mgr.override(debug=debug, verbose=verbose)
    
    ctx.obj["console"] = console
    ctx.obj["config_mgr"] = config_mgr


@cli.command()
@click.argument("target")
@click.option("-m", "--mode", type=click.Choice(["passive", "light", "standard", "deep", "browser", "authenticated", "cloud"]), default="standard", help="Scan mode")
@click.option("-p", "--profile", type=click.Choice(["quick", "standard", "service", "full"]), default="quick", help="Port scan profile")
@click.option("--timeout", type=int, help="Global timeout override (seconds)")
@click.option("--dry-run", is_flag=True, help="Show what would be run without executing")
@click.option("--ai", is_flag=True, help="Use local Ollama LLM for AI-powered analysis")
@click.pass_context
def scan(ctx: click.Context, target: str, mode: str, profile: str, timeout: int | None, dry_run: bool, ai: bool) -> None:
    """Run a reconnaissance scan against a target."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]
    
    if timeout:
        config_mgr.override(default_timeout=timeout)

    if dry_run:
        from reconai.core.config.defaults import SCAN_MODES
        mode_def = SCAN_MODES.get(mode, {})
        console.info(f"[DRY RUN] Target: {target}")
        console.info(f"[DRY RUN] Mode: {mode} — {mode_def.get('description', '')}")
        console.info(f"[DRY RUN] Profile: {profile}")
        console.info(f"[DRY RUN] Modules to run:")
        for m in mode_def.get("modules", []):
            console.console.print(f"  [dim]  • {m}[/dim]")
        return

    scope = ScopeManager.for_target(target)
    orchestrator = Orchestrator(target, config_mgr, scope, console)
    
    async def _run() -> None:
        await orchestrator.prepare_scan(mode=mode, profile=profile)
        await orchestrator.run()
        
        # Generate Report
        console.info("Generating reports...")
        generator = ReportGenerator(orchestrator.db, orchestrator.scan_id, orchestrator.out_dir)
        reports = generator.generate_all()
        console.success(f"HTML report: {reports.get('html', '')}")
        console.success(f"All reports saved to: {reports['markdown'].parent}")
        
        # AI Analysis (optional)
        if ai:
            from reconai.ai.local import OllamaAdapter
            from reconai.ai.analyzer import Analyzer
            llm = OllamaAdapter()
            if await llm.is_available():
                console.info("Running AI analysis...")
                analyzer = Analyzer(llm, orchestrator.db, orchestrator.scan_id)
                summary = await analyzer.summarize_findings()
                console.console.print(f"\n[bold cyan]AI Summary:[/bold cyan]\n{summary}\n")
            else:
                console.warning("Ollama not available. Skipping AI analysis. Install with: curl -fsSL https://ollama.ai/install.sh | sh")
        
    asyncio.run(_run())


@cli.command()
@click.argument("scan_id")
@click.option("--out", type=click.Path(), help="Output directory for report")
@click.pass_context
def report(ctx: click.Context, scan_id: str, out: str | None) -> None:
    """Generate a report for a past scan."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]
    
    base_out = Path(config_mgr.config.output.base_dir)
    # Search for scan_id in all target dirs (crude but works for now)
    scan_dir = None
    for path in base_out.rglob(scan_id):
        if path.is_dir():
            scan_dir = path
            break
            
    if not scan_dir:
        console.error(f"Scan ID {scan_id} not found in {base_out}")
        sys.exit(1)
        
    from reconai.core.database.manager import DatabaseManager
    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    
    try:
        generator = ReportGenerator(db, scan_id, scan_dir)
        reports = generator.generate_all()
        console.success(f"Reports regenerated at {reports['markdown'].parent}")
    except Exception as e:
        console.error(f"Failed to generate report: {e}")


@cli.command()
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Check system dependencies and tools."""
    console: ReconConsole = ctx.obj["console"]
    console.banner()
    
    console.info("Checking environment...")
    import shutil
    import platform
    
    console.console.print(f"OS: {platform.system()} {platform.release()}")
    console.console.print(f"Python: {sys.version.split()[0]}")
    console.console.print("")
    
    tools = [
        "nmap", "amass", "subfinder", "httpx", "nuclei", "whatweb",
        "waybackurls", "wafw00f", "trufflehog", "naabu", "masscan",
        "gobuster", "ffuf", "dig", "whois", "katana", "sqlmap",
        "dalfox", "paramspider", "dnsx", "gowitness",
        # Cloud enumeration tools
        "cloud_enum",
    ]
    
    results = {}
    for tool in tools:
        path = shutil.which(tool)
        results[tool] = (bool(path), path or "Not installed")
        
    console.tool_availability(results)


@cli.command()
@click.pass_context
def mcp(ctx: click.Context) -> None:
    """Start the ReconAI MCP Server (Model Context Protocol)."""
    console: ReconConsole = ctx.obj["console"]
    console.info("Starting minimal MCP Server on stdio...")
    
    from reconai.mcp.server import run_mcp_server
    try:
        run_mcp_server()
    except ImportError:
        console.error("MCP Server dependencies not found. This is a minimal stub.")


@cli.command()
@click.argument("old_scan_id")
@click.argument("new_scan_id")
@click.pass_context
def compare(ctx: click.Context, old_scan_id: str, new_scan_id: str) -> None:
    """Compare two scans and show the differences."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]
    
    base_out = Path(config_mgr.config.output.base_dir)
    
    # Locate scan DBs
    def find_db(scan_id: str) -> Path | None:
        for path in base_out.rglob(scan_id):
            if path.is_dir():
                return path / "reconai.db"
        return None

    old_db_path = find_db(old_scan_id)
    new_db_path = find_db(new_scan_id)

    if not old_db_path or not new_db_path:
        console.error("Could not locate database for one or both scans.")
        sys.exit(1)

    from reconai.core.database.manager import DatabaseManager
    from reconai.core.changes.detector import ChangeDetector
    
    # We use the new db manager for the detector, but we need both paths.
    # For a true implementation we would attach the old DB or query separately.
    # To keep this simple, we just instantiate two DBs and query them.
    db_old = DatabaseManager(db_path=old_db_path)
    db_new = DatabaseManager(db_path=new_db_path)
    
    old_data = db_old.get_scan_data_for_comparison(old_scan_id)
    new_data = db_new.get_scan_data_for_comparison(new_scan_id)
    
    # Compare
    console.banner()
    console.info(f"Comparing {old_scan_id} -> {new_scan_id}")
    
    # Compare Subdomains
    old_subs = {s["subdomain"] for s in old_data["subdomains"]}
    new_subs = {s["subdomain"] for s in new_data["subdomains"]}
    for sub in (new_subs - old_subs):
        console.console.print(f"[bold green]+ New Subdomain:[/bold green] {sub}")
    for sub in (old_subs - new_subs):
        console.console.print(f"[bold red]- Removed Subdomain:[/bold red] {sub}")

    # Compare Ports
    old_ports = {f"{p['host']}:{p['port']}" for p in old_data["ports"]}
    new_ports = {f"{p['host']}:{p['port']}" for p in new_data["ports"]}
    for port in (new_ports - old_ports):
        console.console.print(f"[bold green]+ New Port:[/bold green] {port}")
    for port in (old_ports - new_ports):
        console.console.print(f"[bold red]- Closed Port:[/bold red] {port}")

    # Compare Cloud Assets
    old_ca = {f"[{c['provider'].upper()}] {c['asset_name']} ({c['asset_type']})" for c in old_data.get("cloud_assets", [])}
    new_ca = {f"[{c['provider'].upper()}] {c['asset_name']} ({c['asset_type']})" for c in new_data.get("cloud_assets", [])}
    for ca in (new_ca - old_ca):
        console.console.print(f"[bold green]+ New Cloud Asset:[/bold green] {ca}")
    for ca in (old_ca - new_ca):
        console.console.print(f"[bold red]- Removed Cloud Asset:[/bold red] {ca}")

    if old_subs == new_subs and old_ports == new_ports and old_ca == new_ca:
        console.success("No changes detected in subdomains, ports, or cloud assets.")


@cli.command()
@click.argument("scan_id")
@click.argument("finding_title")
@click.pass_context
def exploit(ctx: click.Context, scan_id: str, finding_title: str) -> None:
    """Generate a Proof of Concept (PoC) exploit for a finding."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]
    
    base_out = Path(config_mgr.config.output.base_dir)
    scan_dir = None
    for path in base_out.rglob(scan_id):
        if path.is_dir():
            scan_dir = path
            break
            
    if not scan_dir:
        console.error(f"Scan ID {scan_id} not found.")
        sys.exit(1)
        
    from reconai.core.database.manager import DatabaseManager
    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    findings = db.get_findings(scan_id)
    
    # Simple search
    target_finding = None
    for f in findings:
        if finding_title.lower() in f["title"].lower():
            target_finding = f
            break
            
    if not target_finding:
        console.error(f"Finding matching '{finding_title}' not found in scan {scan_id}.")
        sys.exit(1)
        
    from reconai.ai.local import OllamaAdapter
    from reconai.ai.analyzer import Analyzer
    llm = OllamaAdapter()
    
    async def _run() -> None:
        if not await llm.is_available():
            console.error("Local LLM (Ollama) is not available. Please install and run it.")
            sys.exit(1)
            
        analyzer = Analyzer(llm, db, scan_id)
        console.info(f"Generating PoC exploit and analysis for: {target_finding['title']}...")
        result = await analyzer.generate_exploit_poc(target_finding)
        
        console.banner()
        console.console.print(f"[bold red]Exploit Analysis & PoC:[/bold red]\n\n{result}")

    asyncio.run(_run())


if __name__ == "__main__":
    cli()
