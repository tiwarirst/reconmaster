"""Main CLI entry point for ReconAI.

Uses Click to provide a professional, structured command-line interface.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path
from typing import Any

import click

from reconai.core.config.manager import ConfigManager
from reconai.core.database.manager import DatabaseManager
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
# Extended enterprise & posture modules
import reconai.modules.passive.email_security
import reconai.modules.passive.saas_enum
import reconai.modules.passive.asn_enum
import reconai.modules.passive.osint_fusion
import reconai.modules.web.api_miner
import reconai.modules.web.dev_artifacts
import reconai.modules.active.cdn_classifier
import reconai.modules.web.screenshot
import reconai.modules.web.arjun_miner
import reconai.modules.cloud.subzy_takeover
import reconai.modules.active.tlsx_probe


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


def _execute_pipeline(
    ctx: click.Context,
    target: str,
    mode: str,
    profile: str = "quick",
    timeout: int | None = None,
    dry_run: bool = False,
    ai: bool = False,
    strict_scope: bool = False,
    scope_file: str | None = None,
    ai_url: str | None = None,
    ai_model: str | None = None,
    config: str | None = None,
) -> None:
    """Shared execution engine for all pipeline commands."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]

    if config:
        config_mgr = ConfigManager(Path(config))
        ctx.obj["config_mgr"] = config_mgr

    if timeout:
        config_mgr.override(default_timeout=timeout)

    from reconai.core.config.defaults import SCAN_MODES
    mode_def = SCAN_MODES.get(mode, {})

    if dry_run:
        console.info(f"[DRY RUN] Target: {target}")
        console.info(f"[DRY RUN] Mode: {mode} — {mode_def.get('description', '')}")
        console.info(f"[DRY RUN] Profile: {profile}")
        console.info(f"[DRY RUN] Scope: {'Strict (Enforced)' if strict_scope or scope_file else 'Permissive (Deep AI & Correlation)'}")
        console.info(f"[DRY RUN] Modules to run ({len(mode_def.get('modules', []))} total):")
        for m in mode_def.get("modules", []):
            console.console.print(f"  [dim]  • {m}[/dim]")
        return

    # Scope configuration: permissive by default so maximum data is gathered for AI synthesis and correlation!
    if scope_file and Path(scope_file).is_file():
        scope = ScopeManager.from_yaml(Path(scope_file), strict=True)
    else:
        scope = ScopeManager.for_target(target, strict=strict_scope)

    orchestrator = Orchestrator(target, config_mgr, scope, console)

    async def _run() -> None:
        await orchestrator.prepare_scan(mode=mode, profile=profile, timeout_override=timeout)
        await orchestrator.run()

        # Automated PoC Generation for all confirmed findings (fail-safe)
        findings = orchestrator.db.get_findings(orchestrator.scan_id)
        if findings:
            try:
                from reconai.intelligence.poc_generator import PoCGenerator
                poc_gen = PoCGenerator()
                pocs_dir = orchestrator.out_dir / "pocs"
                pocs_dir.mkdir(parents=True, exist_ok=True)
                pocs_created = 0
                for idx, finding in enumerate(findings, start=1):
                    try:
                        poc = poc_gen.generate(finding)
                        raw_title = str(finding.get("title") or f"vuln_{idx}")
                        clean_slug = re.sub(r"[^a-zA-Z0-9_-]", "_", raw_title).strip("_").lower()[:40]
                        slug = clean_slug if clean_slug else f"finding_{idx}"
                        if poc.python_script:
                            py_path = pocs_dir / f"poc_{idx}_{slug}.py"
                            py_path.write_text(poc.python_script, encoding="utf-8")
                        if poc.curl_command:
                            sh_path = pocs_dir / f"poc_{idx}_{slug}.sh"
                            sh_path.write_text(f"#!/usr/bin/env bash\n# Reproduction curl for: {raw_title}\n{poc.curl_command}\n", encoding="utf-8")
                        if poc.nuclei_template:
                            yaml_path = pocs_dir / f"poc_{idx}_{slug}.yaml"
                            yaml_path.write_text(poc.nuclei_template, encoding="utf-8")
                        pocs_created += 1
                    except Exception as exc:
                        console.debug(f"Could not generate PoC verification artifact for finding #{idx}: {exc}")
                if pocs_created:
                    console.success(f"Generated {pocs_created} runnable PoC verification packages in: {pocs_dir}")
            except Exception as exc:
                console.warning(f"PoC generation skipped due to unexpected error: {exc}")

        # AI Analysis (when requested or in deep/cloud/vuln mode) - fail-safe against remote network/GPU disconnects
        ai_summary = ""
        ai_model_name = ""
        attack_chain = ""
        effective_ai_url = (
            ai_url
            or os.getenv("OLLAMA_BASE_URL")
            or os.getenv("OLLAMA_HOST")
            or getattr(getattr(config_mgr.config, "ai", None), "url", None)
            or "http://localhost:11434"
        )
        effective_ai_model = (
            ai_model
            or os.getenv("OLLAMA_MODEL")
            or getattr(getattr(config_mgr.config, "ai", None), "model", None)
            or "llama3"
        )
        if ai or mode in ("deep", "cloud", "vuln"):
            try:
                from reconai.ai.local import OllamaAdapter
                from reconai.ai.analyzer import Analyzer
                llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)
                if await llm.is_available():
                    ai_model_name = llm.model
                    console.info(f"Running AI analysis with LLM ('{llm.model}') at {llm.base_url}...")
                    analyzer = Analyzer(llm, orchestrator.db, orchestrator.scan_id)
                    ai_summary = await analyzer.summarize_findings()
                    attack_chain = await analyzer.generate_attack_chain()
                    console.console.print(f"\n[bold cyan]AI Summary ({llm.model} @ {llm.base_url}):[/bold cyan]\n{ai_summary}\n")
                    if attack_chain and "Not enough findings" not in attack_chain:
                        console.console.print(f"\n[bold magenta]AI Correlated Attack Kill Chain ({llm.model}):[/bold magenta]\n{attack_chain}\n")

                    # Persist standalone AI report to reports directory
                    reports_dir = orchestrator.out_dir / "reports"
                    reports_dir.mkdir(parents=True, exist_ok=True)
                    ai_file = reports_dir / "ai_analysis.md"
                    content = f"# AI Threat Assessment: {target}\n\n**Model:** `{llm.model}` (`{llm.base_url}`)\n\n{ai_summary}\n"
                    if attack_chain and "Not enough findings" not in attack_chain:
                        content += f"\n## Correlated Attack Kill Chain\n\n{attack_chain}\n"
                    ai_file.write_text(content, encoding="utf-8")
                    console.success(f"AI Report saved to: {ai_file}")
                elif ai:
                    console.warning(
                        f"Could not connect to Ollama at '{llm.base_url}'. "
                        "If your GPU machine is running Ollama remotely, ensure OLLAMA_HOST=0.0.0.0:11434 is set on the GPU host, "
                        "or create an SSH tunnel: ssh -L 11434:localhost:11434 user@<gpu-ip>"
                    )
            except Exception as exc:
                console.warning(f"AI intelligence analysis failed: {exc}")

        # Generate Report (incorporating AI findings & threat intelligence) - fail-safe
        try:
            console.info("Generating reports...")
            generator = ReportGenerator(
                orchestrator.db,
                orchestrator.scan_id,
                orchestrator.out_dir,
                ai_summary=ai_summary,
                ai_model=ai_model_name,
                attack_chain=attack_chain,
            )
            reports = generator.generate_all()
            if "html" in reports:
                console.success(f"HTML report: {reports['html']}")
            if "markdown" in reports:
                console.success(f"All reports saved to: {reports['markdown'].parent}")
        except Exception as exc:
            console.error(f"Error during report file generation: {exc}")

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.warning("\nScan interrupted by user (Ctrl+C). Partial scan results were safely preserved in database.")
    except Exception as exc:
        console.error(f"Scan pipeline execution error: {exc}")
        # Emergency attempt to output collected scan artifacts if possible
        try:
            generator = ReportGenerator(orchestrator.db, orchestrator.scan_id, orchestrator.out_dir)
            reports = generator.generate_all()
            if "markdown" in reports:
                console.info(f"Emergency report saved to: {reports['markdown'].parent}")
        except Exception:
            pass
    finally:
        try:
            orchestrator.db.close()
        except Exception:
            pass


@cli.command()
@click.argument("target")
@click.option("-m", "--mode", type=click.Choice(["passive", "light", "standard", "deep", "browser", "authenticated", "cloud", "subs", "ports", "web", "vuln"]), default="standard", help="Scan mode")
@click.option("-p", "--profile", type=click.Choice(["quick", "standard", "service", "full"]), default="quick", help="Port scan profile")
@click.option("--timeout", type=int, help="Global timeout override (seconds)")
@click.option("--dry-run", is_flag=True, help="Show what would be run without executing")
@click.option("--ai", is_flag=True, help="Use local or remote Ollama LLM for AI-powered analysis")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://192.168.1.50:11434 for remote GPU)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. llama3, deepseek-r1:7b)")
@click.option("--strict-scope", is_flag=True, help="Strictly limit discovery to provided target (default is permissive for deep AI data)")
@click.option("--scope-file", type=click.Path(exists=True), help="Path to scope YAML file for explicit boundary rules")
@click.option("--config", type=click.Path(exists=True), help="Path to custom config.yaml")
@click.pass_context
def scan(ctx: click.Context, target: str, mode: str, profile: str, timeout: int | None, dry_run: bool, ai: bool, ai_url: str | None, ai_model: str | None, strict_scope: bool, scope_file: str | None, config: str | None = None) -> None:
    """Run an orchestrated reconnaissance scan against a target."""
    _execute_pipeline(ctx, target, mode=mode, profile=profile, timeout=timeout, dry_run=dry_run, ai=ai, ai_url=ai_url, ai_model=ai_model, strict_scope=strict_scope, scope_file=scope_file, config=config)


@cli.command()
@click.argument("target")
@click.option("--dry-run", is_flag=True, help="Show what would be run without executing")
@click.option("--timeout", type=int, help="Global timeout override (seconds)")
@click.option("--strict-scope", is_flag=True, help="Strictly limit discovery to provided target (default is permissive for deep AI data)")
@click.option("--scope-file", type=click.Path(exists=True), help="Path to scope YAML file")
@click.pass_context
def subs(ctx: click.Context, target: str, dry_run: bool, timeout: int | None, strict_scope: bool, scope_file: str | None) -> None:
    """Dedicated Subdomain Intelligence Pipeline (DNS, CT logs, archive, DNSx, active tools)."""
    _execute_pipeline(ctx, target, mode="subs", dry_run=dry_run, timeout=timeout, strict_scope=strict_scope, scope_file=scope_file)


@cli.command()
@click.argument("target")
@click.option("-p", "--profile", type=click.Choice(["quick", "standard", "service", "full"]), default="quick", help="Port scan profile")
@click.option("--dry-run", is_flag=True, help="Show what would be run without executing")
@click.option("--timeout", type=int, help="Global timeout override (seconds)")
@click.option("--strict-scope", is_flag=True, help="Strictly limit discovery to provided target (default is permissive for deep AI data)")
@click.option("--scope-file", type=click.Path(exists=True), help="Path to scope YAML file")
@click.pass_context
def ports(ctx: click.Context, target: str, profile: str, dry_run: bool, timeout: int | None, strict_scope: bool, scope_file: str | None) -> None:
    """Dedicated Port & Service Detection Pipeline (DNS, Naabu, Nmap, TCP connect, CDN classifier)."""
    _execute_pipeline(ctx, target, mode="ports", profile=profile, dry_run=dry_run, timeout=timeout, strict_scope=strict_scope, scope_file=scope_file)


@cli.command()
@click.argument("target")
@click.option("--dry-run", is_flag=True, help="Show what would be run without executing")
@click.option("--timeout", type=int, help="Global timeout override (seconds)")
@click.option("--strict-scope", is_flag=True, help="Strictly limit discovery to provided target (default is permissive for deep AI data)")
@click.option("--scope-file", type=click.Path(exists=True), help="Path to scope YAML file")
@click.pass_context
def web(ctx: click.Context, target: str, dry_run: bool, timeout: int | None, strict_scope: bool, scope_file: str | None) -> None:
    """Dedicated Web Attack Surface Pipeline (HTTP probe, tech stack, headers, WAF, crawl, dir, screenshot)."""
    _execute_pipeline(ctx, target, mode="web", dry_run=dry_run, timeout=timeout, strict_scope=strict_scope, scope_file=scope_file)


@cli.command()
@click.argument("target")
@click.option("--dry-run", is_flag=True, help="Show what would be run without executing")
@click.option("--timeout", type=int, help="Global timeout override (seconds)")
@click.option("--ai", is_flag=True, help="Use local or remote Ollama LLM for AI-powered cloud risk analysis")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://192.168.1.50:11434 for remote GPU)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. llama3, deepseek-r1:7b)")
@click.option("--strict-scope", is_flag=True, help="Strictly limit discovery to provided target (default is permissive for deep AI data)")
@click.option("--scope-file", type=click.Path(exists=True), help="Path to scope YAML file")
@click.pass_context
def cloud(ctx: click.Context, target: str, dry_run: bool, timeout: int | None, ai: bool, ai_url: str | None, ai_model: str | None, strict_scope: bool, scope_file: str | None) -> None:
    """Dedicated Cloud Attack Surface Pipeline (S3/GCS/Azure buckets, CNAME takeovers, SaaS, SSRF)."""
    _execute_pipeline(ctx, target, mode="cloud", dry_run=dry_run, timeout=timeout, ai=ai, ai_url=ai_url, ai_model=ai_model, strict_scope=strict_scope, scope_file=scope_file)


@cli.command()
@click.argument("target")
@click.option("--dry-run", is_flag=True, help="Show what would be run without executing")
@click.option("--timeout", type=int, help="Global timeout override (seconds)")
@click.option("--ai", is_flag=True, help="Use local or remote Ollama LLM for AI-powered exploit guidance")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://192.168.1.50:11434 for remote GPU)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. llama3, deepseek-r1:7b)")
@click.option("--strict-scope", is_flag=True, help="Strictly limit discovery to provided target (default is permissive for deep AI data)")
@click.option("--scope-file", type=click.Path(exists=True), help="Path to scope YAML file")
@click.pass_context
def vuln(ctx: click.Context, target: str, dry_run: bool, timeout: int | None, ai: bool, ai_url: str | None, ai_model: str | None, strict_scope: bool, scope_file: str | None) -> None:
    """Dedicated Vulnerability Pipeline (Nuclei, secrets, API miner, dev artifacts, Dalfox, SQLMap)."""
    _execute_pipeline(ctx, target, mode="vuln", dry_run=dry_run, timeout=timeout, ai=ai, ai_url=ai_url, ai_model=ai_model, strict_scope=strict_scope, scope_file=scope_file)


@cli.command()
@click.argument("target_or_scan_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://192.168.1.50:11434 for remote GPU)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. llama3, deepseek-r1:7b)")
@click.pass_context
def ai(ctx: click.Context, target_or_scan_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """Dedicated AI Intelligence & Threat Assessment Pipeline."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]
    base_out = Path(config_mgr.config.output.base_dir)

    # Check if target_or_scan_id is an existing scan directory
    scan_dir = DatabaseManager.find_scan_dir(target_or_scan_id, base_out)

    effective_ai_url = (
        ai_url
        or os.getenv("OLLAMA_BASE_URL")
        or os.getenv("OLLAMA_HOST")
        or getattr(getattr(config_mgr.config, "ai", None), "url", None)
        or "http://localhost:11434"
    )
    effective_ai_model = (
        ai_model
        or os.getenv("OLLAMA_MODEL")
        or getattr(getattr(config_mgr.config, "ai", None), "model", None)
        or "llama3"
    )

    if scan_dir:
        from reconai.ai.local import OllamaAdapter
        from reconai.ai.analyzer import Analyzer
        db = DatabaseManager(db_path=scan_dir / "reconai.db")
        llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)

        async def _run_ai_on_scan() -> None:
            if not await llm.is_available():
                console.warning(
                    f"Could not connect to Ollama at '{llm.base_url}'. "
                    "If your GPU machine is running Ollama remotely, ensure OLLAMA_HOST=0.0.0.0:11434 is set on the GPU host, "
                    "or create an SSH tunnel: ssh -L 11434:localhost:11434 user@<gpu-ip>"
                )
                return
            analyzer = Analyzer(llm, db, target_or_scan_id)
            summary = await analyzer.summarize_findings()
            attack_chain = await analyzer.generate_attack_chain()
            console.console.print(f"\n[bold cyan]AI Threat Assessment ({llm.model} @ {llm.base_url}):[/bold cyan]\n{summary}\n")
            if attack_chain and "Not enough findings" not in attack_chain:
                console.console.print(f"\n[bold magenta]AI Correlated Attack Kill Chain ({llm.model}):[/bold magenta]\n{attack_chain}\n")

            reports_dir = scan_dir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            ai_file = reports_dir / "ai_analysis.md"
            content = f"# AI Threat Assessment: {target_or_scan_id}\n\n**Model:** `{llm.model}` (`{llm.base_url}`)\n\n{summary}\n"
            if attack_chain and "Not enough findings" not in attack_chain:
                content += f"\n## Correlated Attack Kill Chain\n\n{attack_chain}\n"
            ai_file.write_text(content, encoding="utf-8")
            console.success(f"Saved AI report to: {ai_file}")

            try:
                gen = ReportGenerator(db, target_or_scan_id, scan_dir, ai_summary=summary, ai_model=llm.model, attack_chain=attack_chain)
                gen.generate_all()
                console.success(f"Updated HTML & Markdown reports with AI insights.")
            except Exception as e:
                console.debug(f"Report update skipped: {e}")

        asyncio.run(_run_ai_on_scan())
    else:
        # Run targeted standard scan with AI enabled
        _execute_pipeline(ctx, target_or_scan_id, mode="standard", ai=True, ai_url=ai_url, ai_model=ai_model)



@cli.command()
@click.argument("scan_id")
@click.option("--out", type=click.Path(), help="Output directory for report")
@click.pass_context
def report(ctx: click.Context, scan_id: str, out: str | None) -> None:
    """Generate a report for a past scan."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]
    
    base_out = Path(config_mgr.config.output.base_dir)
    scan_dir = DatabaseManager.find_scan_dir(scan_id, base_out)
            
    if not scan_dir:
        console.error(f"Scan ID {scan_id} not found in {base_out}")
        sys.exit(1)
        
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
        "waybackurls", "gau", "wafw00f", "trufflehog", "naabu", "masscan",
        "gobuster", "ffuf", "dig", "whois", "katana", "sqlmap",
        "dalfox", "paramspider", "dnsx", "gowitness", "arjun", "subzy", "gitleaks",
        "tlsx",
        # Cloud enumeration tools
        "cloud_enum",
    ]
    
    results = {}
    for tool in tools:
        path = shutil.which(tool)
        if not path and tool == "cloud_enum":
            path = shutil.which("cloud-enum")
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
        sd = DatabaseManager.find_scan_dir(scan_id, base_out)
        return (sd / "reconai.db") if sd else None

    old_db_path = find_db(old_scan_id)
    new_db_path = find_db(new_scan_id)

    if not old_db_path or not new_db_path:
        console.error("Could not locate database for one or both scans.")
        sys.exit(1)

    from reconai.core.changes.detector import ChangeDetector
    
    # We use the new db manager for the detector, but we need both paths.
    # For a true implementation we would attach the old DB or query separately.
    # To keep this simple, we just instantiate two DBs and query them.
    db_old = DatabaseManager(db_path=old_db_path)
    db_new = DatabaseManager(db_path=new_db_path)
    try:
        old_data = db_old.get_scan_data_for_comparison(old_scan_id)
        new_data = db_new.get_scan_data_for_comparison(new_scan_id)
    finally:
        db_old.close()
        db_new.close()
    
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
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://192.168.1.50:11434 for remote GPU)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. llama3, deepseek-r1:7b)")
@click.pass_context
def exploit(ctx: click.Context, scan_id: str, finding_title: str, ai_url: str | None, ai_model: str | None) -> None:
    """Generate a Proof of Concept (PoC) exploit for a finding."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]
    
    base_out = Path(config_mgr.config.output.base_dir)
    scan_dir = DatabaseManager.find_scan_dir(scan_id, base_out)
            
    if not scan_dir:
        console.error(f"Scan ID {scan_id} not found.")
        sys.exit(1)
        
    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    try:
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
        effective_ai_url = ai_url or getattr(getattr(config_mgr.config, "ai", None), "url", None)
        effective_ai_model = ai_model or getattr(getattr(config_mgr.config, "ai", None), "model", None)
        llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)
        
        async def _run() -> None:
            has_ai = await llm.is_available()
            if not has_ai:
                console.warning("Local/Remote LLM (Ollama) is not running. Generating deterministic verification PoC package...")
            else:
                console.info(f"Generating PoC exploit and analysis for: {target_finding['title']} using {llm.model} at {llm.base_url}...")

            analyzer = Analyzer(llm, db, scan_id)
            result = await analyzer.generate_exploit_poc(target_finding)

            console.banner()
            console.console.print(f"[bold red]Exploit Analysis & PoC:[/bold red]\n\n{result}")

        asyncio.run(_run())
    finally:
        db.close()


@cli.command()
@click.argument("scan_path_or_id")
@click.option("--ai", is_flag=True, help="Run AI threat assessment with Ollama during report generation")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def report(ctx: click.Context, scan_path_or_id: str, ai: bool, ai_url: str | None, ai_model: str | None) -> None:
    """Generate or re-generate reports (HTML, Markdown, JSON, PoCs) from an existing scan directory or scan ID."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]

    # 1. Locate the scan directory and database
    scan_dir = DatabaseManager.find_scan_dir(scan_path_or_id, Path(config_mgr.config.output.base_dir))

    if not scan_dir:
        console.error(f"Scan directory with 'reconai.db' not found for: {scan_path_or_id}")
        sys.exit(1)

    db_path = scan_dir / "reconai.db"
    db = DatabaseManager(db_path=db_path)
    try:
        # Resolve scan metadata from db or directory structure
        scans = db.list_scans(limit=1)
        scan_id = scans[0]["id"] if scans else scan_dir.name
        target = scans[0]["target"] if scans else scan_dir.parent.name

        console.banner()
        console.info(f"Generating reports for target: [bold cyan]{target}[/bold cyan] (Scan: {scan_id})")

        # Generate PoCs for findings
        findings = db.get_findings(scan_id)
        if findings:
            from reconai.intelligence.poc_generator import PoCGenerator
            poc_gen = PoCGenerator()
            pocs_dir = scan_dir / "pocs"
            pocs_dir.mkdir(parents=True, exist_ok=True)
            pocs_created = 0
            for idx, finding in enumerate(findings, start=1):
                try:
                    poc = poc_gen.generate(finding)
                    raw_title = str(finding.get("title") or f"vuln_{idx}")
                    clean_slug = re.sub(r"[^a-zA-Z0-9_-]", "_", raw_title).strip("_").lower()[:40]
                    slug = clean_slug if clean_slug else f"finding_{idx}"
                    if poc.python_script:
                        (pocs_dir / f"poc_{idx}_{slug}.py").write_text(poc.python_script, encoding="utf-8")
                    if poc.curl_command:
                        (pocs_dir / f"poc_{idx}_{slug}.sh").write_text(
                            f"#!/usr/bin/env bash\n# Reproduction curl for: {raw_title}\n{poc.curl_command}\n", encoding="utf-8"
                        )
                    if poc.nuclei_template:
                        (pocs_dir / f"poc_{idx}_{slug}.yaml").write_text(poc.nuclei_template, encoding="utf-8")
                    pocs_created += 1
                except Exception as exc:
                    console.debug(f"PoC generation skipped for finding #{idx}: {exc}")
            if pocs_created:
                console.success(f"Generated {pocs_created} runnable PoC verification packages in: {pocs_dir}")

        # Optional AI analysis
        ai_summary = ""
        ai_model_name = ""
        attack_chain = ""
        effective_ai_url = ai_url or getattr(getattr(config_mgr.config, "ai", None), "url", None)
        effective_ai_model = ai_model or getattr(getattr(config_mgr.config, "ai", None), "model", None)
        if ai:
            from reconai.ai.local import OllamaAdapter
            from reconai.ai.analyzer import Analyzer
            llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)

            async def _run_ai() -> None:
                nonlocal ai_summary, ai_model_name, attack_chain
                if await llm.is_available():
                    ai_model_name = llm.model
                    console.info(f"Running AI analysis with LLM ('{llm.model}') at {llm.base_url}...")
                    analyzer = Analyzer(llm, db, scan_id)
                    ai_summary = await analyzer.summarize_findings()
                    attack_chain = await analyzer.generate_attack_chain()
                    console.console.print(f"\n[bold cyan]AI Summary ({llm.model} @ {llm.base_url}):[/bold cyan]\n{ai_summary}\n")
                    if attack_chain and "Not enough findings" not in attack_chain:
                        console.console.print(f"\n[bold magenta]AI Correlated Attack Kill Chain ({llm.model}):[/bold magenta]\n{attack_chain}\n")
                    reports_dir = scan_dir / "reports"
                    reports_dir.mkdir(parents=True, exist_ok=True)
                    ai_file = reports_dir / "ai_analysis.md"
                    content = f"# AI Threat Assessment: {target}\n\n**Model:** `{llm.model}` (`{llm.base_url}`)\n\n{ai_summary}\n"
                    if attack_chain and "Not enough findings" not in attack_chain:
                        content += f"\n## Correlated Attack Kill Chain\n\n{attack_chain}\n"
                    ai_file.write_text(content, encoding="utf-8")
                else:
                    console.warning(f"Could not connect to Ollama at '{llm.base_url}'.")

            asyncio.run(_run_ai())

        # Generate Reports
        reports_dir = scan_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        generator = ReportGenerator(
            db,
            scan_id,
            scan_dir,
            ai_summary=ai_summary,
            ai_model=ai_model_name,
            attack_chain=attack_chain,
        )
        reports = generator.generate_all()
        if "html" in reports:
            console.success(f"HTML report: {reports['html']}")
        if "markdown" in reports:
            console.success(f"Markdown report: {reports['markdown']}")
        if "json" in reports:
            console.success(f"JSON report: {reports['json']}")
        console.success(f"All reports saved to: {reports_dir}")
    finally:
        db.close()


@cli.command()
@click.argument("scan_path_or_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def agent(ctx: click.Context, scan_path_or_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """Autonomous AI Red Team Operator Agent (Attack surface reasoning & campaign planning)."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]

    # 1. Locate scan directory and database
    scan_dir = DatabaseManager.find_scan_dir(scan_path_or_id, Path(config_mgr.config.output.base_dir))

    if not scan_dir:
        console.error(f"Scan directory with 'reconai.db' not found for: {scan_path_or_id}")
        sys.exit(1)

    from reconai.ai.local import OllamaAdapter
    from reconai.ai.agent import RedTeamAgent

    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    try:
        scans = db.list_scans(limit=1)
        scan_id = scans[0]["id"] if scans else scan_dir.name
        target = scans[0]["target"] if scans else scan_dir.parent.name

        effective_ai_url = ai_url or getattr(getattr(config_mgr.config, "ai", None), "url", None)
        effective_ai_model = ai_model or getattr(getattr(config_mgr.config, "ai", None), "model", None)
        llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)

        console.banner()
        console.info(f"Initializing AI Red Team Autonomous Agent for: [bold cyan]{target}[/bold cyan] (Scan: {scan_id})")

        async def _run() -> None:
            has_ai = await llm.is_available()
            if not has_ai:
                console.warning(f"Ollama server not reachable at '{llm.base_url}'. Running deterministic attack graph reasoning engine...")
            else:
                console.info(f"Connected to Red Team Brain model '{llm.model}' at {llm.base_url}.")

            agent_engine = RedTeamAgent(db, scan_id, ai=llm if has_ai else None)
            result = await agent_engine.run_campaign_analysis()

            plan_md = result["plan_markdown"]
            console.console.print(f"\n[bold magenta]Autonomous Red Team Campaign Plan:[/bold magenta]\n\n{plan_md}\n")

            reports_dir = scan_dir / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            plan_file = reports_dir / "red_team_plan.md"
            plan_file.write_text(plan_md, encoding="utf-8")
            console.success(f"Red Team Plan saved to: {plan_file}")

        asyncio.run(_run())
    finally:
        db.close()


@cli.command()
@click.argument("scan_path_or_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def verify(ctx: click.Context, scan_path_or_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """Closed-Loop Safe Vulnerability Verifier (Eliminates false positives with non-destructive validation)."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]

    scan_dir = DatabaseManager.find_scan_dir(scan_path_or_id, Path(config_mgr.config.output.base_dir))

    if not scan_dir:
        console.error(f"Scan directory with 'reconai.db' not found for: {scan_path_or_id}")
        sys.exit(1)

    from reconai.ai.local import OllamaAdapter
    from reconai.ai.verifier import ClosedLoopVerifier

    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    try:
        scans = db.list_scans(limit=1)
        scan_id = scans[0]["id"] if scans else scan_dir.name
        target = scans[0]["target"] if scans else scan_dir.parent.name

        effective_ai_url = ai_url or getattr(getattr(config_mgr.config, "ai", None), "url", None)
        effective_ai_model = ai_model or getattr(getattr(config_mgr.config, "ai", None), "model", None)
        llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)

        console.banner()
        console.info(f"Running Closed-Loop False-Positive Verification for: [bold cyan]{target}[/bold cyan]")

        async def _run() -> None:
            has_ai = await llm.is_available()
            verifier = ClosedLoopVerifier(db, scan_id, ai=llm if has_ai else None)
            results = await verifier.verify_all_findings()

            verified_count = sum(1 for r in results if r.get("verified"))
            console.success(f"Verification complete: {verified_count}/{len(results)} findings confirmed.")

            for r in results:
                tag = "[bold green][VERIFIED][/bold green]" if r.get("verified") else "[yellow][UNVERIFIED / POTENTIAL][/yellow]"
                console.console.print(f"  {tag} {r.get('title')} ({r.get('asset')})")
                if r.get("evidence"):
                    console.console.print(f"    [dim]Evidence: {r.get('evidence')[:120]}[/dim]")

        asyncio.run(_run())
    finally:
        db.close()


@cli.command()
@click.pass_context
def mcp(ctx: click.Context) -> None:
    """Start the Model Context Protocol (MCP) server for external AI agents."""
    from reconai.mcp.server import run_mcp_server
    run_mcp_server()


@cli.command("threat-profile")
@click.argument("scan_path_or_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def threat_profile(ctx: click.Context, scan_path_or_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """AI Threat Actor & TTP Profiler (Adversary emulation & MITRE ATT&CK mapping)."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]

    scan_dir = DatabaseManager.find_scan_dir(scan_path_or_id, Path(config_mgr.config.output.base_dir))

    if not scan_dir:
        console.error(f"Scan directory with 'reconai.db' not found for: {scan_path_or_id}")
        sys.exit(1)

    from reconai.ai.local import OllamaAdapter
    from reconai.ai.threat_profiler import ThreatActorProfiler

    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    try:
        scans = db.list_scans(limit=1)
        scan_id = scans[0]["id"] if scans else scan_dir.name
        target = scans[0]["target"] if scans else scan_dir.parent.name

        effective_ai_url = ai_url or getattr(getattr(config_mgr.config, "ai", None), "url", None)
        effective_ai_model = ai_model or getattr(getattr(config_mgr.config, "ai", None), "model", None)
        llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)

        console.banner()
        console.info(f"Synthesizing Threat Actor Profiles for: [bold cyan]{target}[/bold cyan]")

        async def _run() -> None:
            has_ai = await llm.is_available()
            profiler = ThreatActorProfiler(db, scan_id, ai=llm if has_ai else None)
            result = await profiler.generate_threat_profile()

            console.console.print(f"\n[bold magenta]Relevant Threat Actor Groups & Motives:[/bold magenta]")
            for a in result["relevant_actors"]:
                console.console.print(f"  • [bold red]{a['actor']}[/bold red] — [dim]{a['motive']}[/dim]")
                console.console.print(f"    [yellow]{a['technique']}[/yellow]")

            console.console.print(f"\n[bold cyan]Adversary Emulation Strategy:[/bold cyan]\n")
            console.console.print(result["narrative_markdown"])

        asyncio.run(_run())
    finally:
        db.close()


@cli.command("prioritize")
@click.argument("scan_path_or_id")
@click.option("--limit", type=int, default=25, help="Number of priority endpoints to display")
@click.pass_context
def prioritize(ctx: click.Context, scan_path_or_id: str, limit: int) -> None:
    """AI Smart Attack Surface & URL Prioritizer (Focus fuzzers on high-value targets)."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]

    scan_dir = DatabaseManager.find_scan_dir(scan_path_or_id, Path(config_mgr.config.output.base_dir))

    if not scan_dir:
        console.error(f"Scan directory with 'reconai.db' not found for: {scan_path_or_id}")
        sys.exit(1)

    from reconai.ai.fuzz_optimizer import AttackSurfacePrioritizer

    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    try:
        scans = db.list_scans(limit=1)
        scan_id = scans[0]["id"] if scans else scan_dir.name
        target = scans[0]["target"] if scans else scan_dir.parent.name

        console.banner()
        console.info(f"Prioritizing Attack Surface Endpoints for: [bold cyan]{target}[/bold cyan]")

        prioritizer = AttackSurfacePrioritizer(db, scan_id)
        endpoints = prioritizer.prioritize_endpoints(limit=limit)

        if not endpoints:
            console.warning("No crawled URLs or API endpoints found to prioritize.")
            return

        console.success(f"Ranked {len(endpoints)} high-leverage entry points for fuzzing & testing:\n")
        for idx, ep in enumerate(endpoints, start=1):
            prio_color = "red" if ep["priority"] == "CRITICAL" else ("yellow" if ep["priority"] == "HIGH" else "cyan")
            console.console.print(f"[{prio_color}][{ep['priority']} - Score {ep['score']}][/{prio_color}] #{idx}: {ep['url']}")
            if ep["categories"]:
                console.console.print(f"  [dim]Category:[/dim] {', '.join(ep['categories'])}")
            if ep["suggested_vectors"]:
                console.console.print(f"  [bold green]Test Vectors:[/bold green] {', '.join(ep['suggested_vectors'])}")
            console.console.print("")
    finally:
        db.close()


@cli.command("waf-advisor")
@click.argument("scan_path_or_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def waf_advisor(ctx: click.Context, scan_path_or_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """AI WAF & Perimeter Evasion Strategy Advisor (Origin IP leakage & bypass vectors)."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]

    scan_dir = DatabaseManager.find_scan_dir(scan_path_or_id, Path(config_mgr.config.output.base_dir))

    if not scan_dir:
        console.error(f"Scan directory with 'reconai.db' not found for: {scan_path_or_id}")
        sys.exit(1)

    from reconai.ai.local import OllamaAdapter
    from reconai.ai.defensive_advisor import DefensiveAdvisor

    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    try:
        scans = db.list_scans(limit=1)
        scan_id = scans[0]["id"] if scans else scan_dir.name
        target = scans[0]["target"] if scans else scan_dir.parent.name

        effective_ai_url = ai_url or getattr(getattr(config_mgr.config, "ai", None), "url", None)
        effective_ai_model = ai_model or getattr(getattr(config_mgr.config, "ai", None), "model", None)
        llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)

        console.banner()
        console.info(f"Analyzing Perimeter Defenses & Origin Leakage for: [bold cyan]{target}[/bold cyan]")

        async def _run() -> None:
            has_ai = await llm.is_available()
            advisor = DefensiveAdvisor(db, scan_id, ai=llm if has_ai else None)
            result = await advisor.analyze_perimeter_defenses()

            console.console.print(f"\n[bold magenta]Perimeter Defense Advisory:[/bold magenta]\n")
            console.console.print(result["narrative_markdown"])

            if result["potential_origin_ips"]:
                console.console.print("[bold red]Potential Direct Origin IP Leakage Detected:[/bold red]")
                for o in result["potential_origin_ips"]:
                    console.console.print(f"  • [bold yellow]{o['ip']}[/bold yellow] ({o['asn_org']}) — {o['note']}")

        asyncio.run(_run())
    finally:
        db.close()


@cli.command("chat")
@click.argument("scan_path_or_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def chat(ctx: click.Context, scan_path_or_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """Interactive Red Team AI Copilot (Ask questions about scan findings, attack depth, & verification)."""
    console: ReconConsole = ctx.obj["console"]
    config_mgr: ConfigManager = ctx.obj["config_mgr"]

    scan_dir = DatabaseManager.find_scan_dir(scan_path_or_id, Path(config_mgr.config.output.base_dir))

    if not scan_dir:
        console.error(f"Scan directory with 'reconai.db' not found for: {scan_path_or_id}")
        sys.exit(1)

    from reconai.ai.local import OllamaAdapter
    from reconai.ai.copilot import ReconCopilot

    db = DatabaseManager(db_path=scan_dir / "reconai.db")
    try:
        scans = db.list_scans(limit=1)
        scan_id = scans[0]["id"] if scans else scan_dir.name
        target = scans[0]["target"] if scans else scan_dir.parent.name

        effective_ai_url = ai_url or getattr(getattr(config_mgr.config, "ai", None), "url", None)
        effective_ai_model = ai_model or getattr(getattr(config_mgr.config, "ai", None), "model", None)
        llm = OllamaAdapter(model=effective_ai_model, base_url=effective_ai_url)

        console.banner()

        async def _run_session() -> None:
            has_ai = await llm.is_available()
            engine_label = f"Local/Remote LLM ('{llm.model}' @ {llm.base_url})" if has_ai else "Deterministic Grounded Intelligence"
            
            console.console.print(f"[bold cyan]🤖 ReconAI Red Team Copilot — Interactive Assessment Session[/bold cyan]")
            console.console.print(f"[dim]Target: {target} | Scan: {scan_id} | Brain: {engine_label}[/dim]\n")
            console.console.print("[dim]Commands: '/summary', '/findings', '/paths', '/help', or type 'exit' to quit.[/dim]\n")

            copilot = ReconCopilot(db, scan_id, ai=llm if has_ai else None)

            while True:
                try:
                    user_msg = click.prompt(click.style("You ❯", fg="green", bold=True), type=str).strip()
                except (KeyboardInterrupt, EOFError):
                    console.console.print("\n[dim]Session closed.[/dim]")
                    break

                if not user_msg:
                    continue

                if user_msg.lower() in ("exit", "quit", "q", ":q"):
                    console.console.print("[dim]Exiting ReconAI Copilot session. Happy hunting![/dim]")
                    break

                with console.console.status("[bold cyan]Copilot is analyzing scan intelligence...[/bold cyan]"):
                    reply = await copilot.ask(user_msg)

                console.console.print(f"\n[bold cyan]Copilot ❯[/bold cyan]\n{reply}\n")

        asyncio.run(_run_session())
    finally:
        db.close()


@cli.command("copilot")
@click.argument("scan_path_or_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def copilot_cmd(ctx: click.Context, scan_path_or_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """Interactive Red Team AI Copilot (alias for chat)."""
    ctx.invoke(chat, scan_path_or_id=scan_path_or_id, ai_url=ai_url, ai_model=ai_model)


@cli.command("ai-agent")
@click.argument("scan_path_or_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def ai_agent_cmd(ctx: click.Context, scan_path_or_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """Autonomous AI Red Team Operator Agent (alias for agent)."""
    ctx.invoke(agent, scan_path_or_id=scan_path_or_id, ai_url=ai_url, ai_model=ai_model)


@cli.command("profile-threat")
@click.argument("scan_path_or_id")
@click.option("--ai-url", type=str, help="Ollama server URL (e.g. http://<GPU_IP>:11434)")
@click.option("--ai-model", type=str, help="Ollama model name (e.g. deepseek-r1:8b)")
@click.pass_context
def profile_threat_cmd(ctx: click.Context, scan_path_or_id: str, ai_url: str | None, ai_model: str | None) -> None:
    """AI Threat Actor & TTP Profiler (alias for threat-profile)."""
    ctx.invoke(threat_profile, scan_path_or_id=scan_path_or_id, ai_url=ai_url, ai_model=ai_model)


if __name__ == "__main__":
    cli()
