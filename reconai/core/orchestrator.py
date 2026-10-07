"""Core Pipeline Orchestrator.

Manages the entire execution flow:
- Validates scope
- Loads configuration
- Initializes database, event bus, logger, and executor
- Runs modules according to the selected mode
- Handles interruptions gracefully
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from reconai.core.config.manager import ConfigManager
from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import ScanRecord, ScanStatus
from reconai.core.events.bus import EventBus
from reconai.core.events.types import Event, EventType
from reconai.core.executor.command_runner import CommandRunner
from reconai.core.executor.process_manager import ProcessManager
from reconai.core.executor.timeout_manager import TimeoutManager
from reconai.core.logging.logger import ReconLogger
from reconai.core.scope.manager import ScopeManager
from reconai.modules.registry import ModuleRegistry
from reconai.ui.console import ReconConsole

TOOL_INSTALL_GUIDES: dict[str, str] = {
    "nmap": "sudo apt install nmap  (Windows: winget install Insecure.Nmap)",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "go install -v github.com/owasp-amass/amass/v4/...@master",
    "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "dnsx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
    "sqlmap": "pip install sqlmap  (or sudo apt install sqlmap)",
    "ffuf": "go install github.com/ffuf/ffuf/v2@latest  (or sudo apt install ffuf)",
    "trufflehog": "go install github.com/trufflesecurity/trufflehog/v3@latest",
    "paramspider": "git clone https://github.com/devanshbatham/paramspider && pip install ./paramspider",
    "gowitness": "go install github.com/sensepost/gowitness@latest",
    "whois": "sudo apt install whois",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "whatweb": "sudo apt install whatweb",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "wafw00f": "pip install wafw00f",
    "masscan": "sudo apt install masscan",
    "gobuster": "go install github.com/OJ/gobuster/v3@latest",
    "dig": "sudo apt install dnsutils",
    "cloud_enum": "pip install cloud-enum  (or git clone https://github.com/initstring/cloud_enum)",
    "boto3": "pip install boto3",
    "playwright": "pip install playwright && playwright install chromium",
}


class Orchestrator:
    """The central brain of ReconAI. Ties all components together."""

    def __init__(self, target: str, config: ConfigManager, scope: ScopeManager, console: ReconConsole):
        self.target = target
        self.config = config
        self.scope = scope
        self.console = console
        
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        
        # Setup Output Directory
        base_out = Path(self.config.config.output.base_dir)
        self.out_dir = base_out / target.replace("://", "_").replace("/", "_") / self.scan_id
        self.out_dir.mkdir(parents=True, exist_ok=True)
        
        # Core Services
        self.logger = ReconLogger(log_dir=self.out_dir / "logs", debug=self.config.config.debug)
        self.db = DatabaseManager(db_path=self.out_dir / "reconai.db")
        self.events = EventBus()
        self.process_mgr = ProcessManager()
        self.timeout_mgr = TimeoutManager()
        self.runner = CommandRunner(
            process_manager=self.process_mgr,
            timeout_manager=self.timeout_mgr,
            on_output=self.console.output_line if self.config.config.verbose else None
        )
        
        self.db.connect()
        self._register_event_handlers()
        
        self.mode: str = "standard"
        self.profile: str = "quick"
        self.modules_to_run: list[Any] = []
        self.results: dict[str, Any] = {}

    def _register_event_handlers(self) -> None:
        """Register central event handlers."""
        self.events.subscribe(EventType.SCAN_STARTED, self._on_scan_started)
        self.events.subscribe(EventType.SCAN_COMPLETED, self._on_scan_completed)
        self.events.subscribe(EventType.SCAN_FAILED, self._on_scan_failed)
        
        # Logging bridge
        async def log_event(event: Event) -> None:
            if event.is_error:
                self.logger.error(f"Event Error [{event.source}]: {event.data.get('error', 'unknown')}")
        self.events.subscribe("*", log_event)

    async def _on_scan_started(self, event: Event) -> None:
        self.logger.info(f"Scan started for target: {self.target} (ID: {self.scan_id})")
        
    async def _on_scan_completed(self, event: Event) -> None:
        self.logger.info(f"Scan completed for target: {self.target} (ID: {self.scan_id})")
        
    async def _on_scan_failed(self, event: Event) -> None:
        self.logger.error(f"Scan failed for target: {self.target} (ID: {self.scan_id})")

    async def prepare_scan(self, mode: str, profile: str) -> None:
        """Initialize the scan record and plan module execution."""
        self.mode = mode
        self.profile = profile
        self.console.banner()
        self.console.target(self.target)
        
        # Show scope
        self.console.scope_info(self.scope.summary())
        
        # Load mode config
        modes = self.config.config.model_dump().get("scan_modes", {})
        # Note: defaults.py defines SCAN_MODES, but if not available in config schema dump, we fallback
        from reconai.core.config.defaults import SCAN_MODES
        
        mode_def = SCAN_MODES.get(mode, SCAN_MODES["standard"])
        module_names = mode_def.get("modules", [])
        
        self.modules_to_run = []
        for name in module_names:
            try:
                mod_class = ModuleRegistry.get(name)
                mod_instance = mod_class(
                    db=self.db,
                    events=self.events,
                    logger=self.logger,
                    runner=self.runner,
                    out_dir=self.out_dir,
                    timeout=self.config.config.timeouts.get("default"),
                )
                mod_instance.scan_id = self.scan_id
                mod_instance.target = self.target
                self.modules_to_run.append(mod_instance)
            except KeyError:
                self.console.warning(f"Module '{name}' requested by mode '{mode}' not found in registry.")

        # Create DB record
        scan_record = ScanRecord(
            id=self.scan_id,
            target=self.target,
            mode=mode,
            profile=profile,
            status=ScanStatus.PENDING,
            modules_total=len(self.modules_to_run),
            output_dir=str(self.out_dir)
        )
        self.db.create_scan(scan_record)

    async def run(self) -> None:
        """Execute all planned modules sequentially.

        Every module receives a standardized kwargs dict containing at minimum:
          - target:  the raw target string (may include scheme/path)
          - domain:  the clean hostname (scheme and path stripped)
          - domains: list[str] — same as [domain], provided for convenience
                     so modules don't each have to re-parse the target.

        Modules that need nothing beyond the DB (e.g. port_scan reading IPs)
        simply ignore the kwargs they don't need. Modules that need domains
        (passive scanners) use kwargs["domains"] directly.

        This eliminates the previous pattern where only passive modules received
        meaningful input and all others silently fell through to empty-list DB
        reads — which would produce zero output if a previous module failed.
        """
        start_time = time.monotonic()
        self.db.update_scan_status(self.scan_id, ScanStatus.RUNNING)
        await self.events.emit(Event(type=EventType.SCAN_STARTED, source="orchestrator", scan_id=self.scan_id, target=self.target))
        
        modules_completed = 0
        modules_failed = 0
        warnings = []
        
        try:
            for module in self.modules_to_run:
                self.console.info(f"Starting module: {module.config.description}", module=module.config.name)
                
                # Check requirements
                avail, reason = await module.check_requirements()
                if not avail:
                    hints = []
                    for tool in getattr(module.config, "requires_tools", []):
                        if tool in TOOL_INSTALL_GUIDES:
                            hints.append(f"Install {tool}: {TOOL_INSTALL_GUIDES[tool]}")
                    hint_str = f" | Fix: {'; '.join(hints)}" if hints else ""
                    self.console.warning(f"Skipping module: {reason}{hint_str}", module=module.config.name)
                    modules_failed += 1
                    warnings.append(f"{module.config.name}: {reason}{hint_str}")
                    continue
                    
                # Run module
                try:
                    mod_start = time.monotonic()

                    # Build dynamic kwargs context from current scan database state
                    # Modules receive subdomains discovered so far, live URLs, IPs, profile, and mode
                    module_kwargs = self._build_module_kwargs()
                    await module.run(**module_kwargs)

                    mod_duration = time.monotonic() - mod_start
                    self.console.success(
                        f"Completed in {mod_duration:.1f}s", module=module.config.name
                    )
                    modules_completed += 1

                    # Collect actionable warnings and tool install guidance from module
                    if hasattr(module, "warnings") and module.warnings:
                        for w in module.warnings:
                            if w not in warnings:
                                warnings.append(f"{module.config.name}: {w}")
                except Exception as e:
                    self.console.error(f"Module failed: {e}", module=module.config.name)
                    self.logger.error(f"Module {module.config.name} exception: {e}")
                    modules_failed += 1
                    warnings.append(f"{module.config.name}: {type(e).__name__}: {e}")
                    
        except asyncio.CancelledError:
            self.console.warning("Scan cancelled by user")
            self.db.update_scan_status(self.scan_id, ScanStatus.CANCELLED, duration=time.monotonic() - start_time)
            await self.events.emit(Event(type=EventType.SCAN_FAILED, source="orchestrator", scan_id=self.scan_id, target=self.target))
            return
            
        except Exception as e:
            self.console.error(f"Critical orchestrator error: {e}")
            self.db.update_scan_status(self.scan_id, ScanStatus.FAILED, duration=time.monotonic() - start_time)
            await self.events.emit(Event(type=EventType.SCAN_FAILED, source="orchestrator", scan_id=self.scan_id, target=self.target))
            return
            
        finally:
            await self.process_mgr.kill_all()
            
        duration = time.monotonic() - start_time
        self.db.update_scan_status(
            self.scan_id, 
            ScanStatus.COMPLETED, 
            duration=duration, 
            completed_at=datetime.now(),
            modules_completed=modules_completed,
            modules_failed=modules_failed
        )
        
        await self.events.emit(Event(type=EventType.SCAN_COMPLETED, source="orchestrator", scan_id=self.scan_id, target=self.target))
        
        # Display Summary — copy into Any-typed dict so we can add string values
        raw_stats = self.db.get_scan_stats(self.scan_id)
        display_stats: dict[str, Any] = dict(raw_stats)
        display_stats["Duration"] = f"{duration:.1f}s"
        display_stats["Modules run"] = f"{modules_completed} / {len(self.modules_to_run)}"

        report_path = ""
        # TODO: Trigger report generation here if requested

        self.console.summary(display_stats, warnings, report_path)

    def _build_module_kwargs(self) -> dict[str, Any]:
        """Build a dynamic, rich kwargs dict for every module's run().

        Gathers up-to-date state from the database:
          - target: raw target
          - domain: clean apex domain
          - domains: [domain]
          - subdomains: list of discovered subdomains
          - hosts: target domain + discovered subdomains (for HTTP probe, port scan)
          - urls: live URLs discovered in database (or fallback to target schemes)
          - ips: IP addresses resolved in database
          - profile: port scan profile selected by user ('quick', 'standard', etc.)
          - mode: current scan mode ('passive', 'standard', 'deep', etc.)
        """
        target = self.target
        if "://" in target:
            raw = target.split("://", 1)[1]
        else:
            raw = target

        domain = raw.split("/")[0].split("#")[0].split("?")[0].split(":")[0]

        # Fetch discovered subdomains from DB
        sub_records = self.db.get_subdomains(self.scan_id)
        subdomains = [str(s["subdomain"]) for s in sub_records if s.get("subdomain")]
        all_hosts = list(dict.fromkeys([domain] + subdomains))

        # Fetch discovered URLs from DB (fallback to target root if none probed yet)
        url_records = self.db.get_urls(self.scan_id)
        live_urls = [str(r["url"]) for r in url_records if r.get("url")]
        if not live_urls:
            live_urls = [f"https://{domain}", f"http://{domain}"]

        # Fetch discovered IPs from DB
        ip_records = self.db.get_ips(self.scan_id)
        ips = [str(r["ip"]) for r in ip_records if r.get("ip")]

        return {
            "target": target,
            "domain": domain,
            "domains": [domain],
            "hosts": all_hosts,
            "subdomains": subdomains,
            "urls": live_urls,
            "ips": ips,
            "profile": self.profile,
            "mode": self.mode,
        }
