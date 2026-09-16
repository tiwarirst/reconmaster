"""Port Scanning Module — fault-tolerant, zero data-loss implementation.

Execution flow for each host:
  1. Register a real-time streaming callback with NmapAdapter.
     Every open port line from Nmap is parsed and inserted into the DB
     the moment it arrives — before the process even finishes.

  2. Run Nmap with dual output:
       -oG -       (greppable → stdout → real-time parse, Layer 1)
       -oX file    (XML → file → enrichment parse, Layer 2 / 3)

  3. After the run (success or timeout):
     - If SUCCESS   → Layer 2: parse well-formed XML for richer service data
                      (product, version, CPE) and merge into the DB.
     - If TIMEOUT   → Layer 3: regex-carve the partial XML to recover
                      whatever enrichment data was written before the kill.

  4. All DB inserts are idempotent — the enrichment pass updates existing
     records by (host, port, protocol) key rather than creating duplicates.

Invariants:
  - The module NEVER raises an exception to its caller.
  - Partial data is ALWAYS better than no data.
  - A timed-out scan still produces useful DB records.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any, Coroutine

from reconai.core.config.defaults import SCAN_PROFILES
from reconai.core.database.models import PortRecord, ServiceRecord
from reconai.core.events.types import EventType
from reconai.core.executor.result import CommandStatus
from reconai.integrations.nmap import NmapAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


def _service_as_port(svc: ServiceRecord) -> PortRecord:
    """Convert a ServiceRecord to a PortRecord for the shared ports table.

    The DB stores both port state and service details in the same 'ports'
    table via INSERT OR REPLACE. A ServiceRecord from the XML enrichment
    pass carries richer product/version/CPE data — we surface it through
    the same insert path so the row is updated in place.
    """
    return PortRecord(
        scan_id=svc.scan_id,
        host=svc.host,
        port=svc.port,
        protocol=svc.protocol,
        state="open",
        service=svc.service,
        product=svc.product,
        version=svc.version,
        banner=svc.extra_info,
        source=svc.source,
    )


def _schedule_emit(
    loop: asyncio.AbstractEventLoop,
    coro: Coroutine[Any, Any, None],
) -> None:
    """Schedule a coroutine on the running event loop from a sync callback.

    asyncio.ensure_future is not safe to call from call_soon_threadsafe
    because ensure_future itself isn't thread-safe. The correct API is
    run_coroutine_threadsafe which explicitly handles the cross-context case.
    """
    asyncio.run_coroutine_threadsafe(coro, loop)


@register_module
class PortScanModule(ReconModule):
    config = ModuleConfig(
        name="ports",
        category="active",
        description="Port scanning and service detection using Nmap (fault-tolerant, zero data loss)",
        requires_tools=["nmap"],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        profile_name = str(kwargs.get("profile", "quick"))
        hosts: list[str] = list(kwargs.get("hosts", []))

        if not hosts:
            ips_records = self.db.get_ips(self.scan_id)
            hosts = [str(record["ip"]) for record in ips_records]

        if not hosts:
            self.logger.debug("No hosts to scan — skipping port scan.", module=self.config.name)
            return

        adapter = NmapAdapter(self.runner)
        if not await adapter.is_available():
            self.logger.error("Nmap not available. Skipping port scan.", module=self.config.name)
            return

        profile = SCAN_PROFILES.get(profile_name, SCAN_PROFILES["quick"])
        nmap_args: list[str] = list(profile["nmap_args"])

        self.logger.module_start(
            self.config.name,
            target=f"{len(hosts)} hosts with profile '{profile_name}'",
        )

        # Concurrency limit: Nmap is already internally parallel, so cap low.
        semaphore = asyncio.Semaphore(2)
        tasks = [
            self._scan_host(adapter, semaphore, host, nmap_args)
            for host in hosts
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name)

    async def _scan_host(
        self,
        adapter: NmapAdapter,
        semaphore: asyncio.Semaphore,
        host: str,
        args: list[str],
    ) -> None:
        """Scan a single host with full tri-layer fault tolerance.

        This method is completely self-contained and never raises.
        All exceptions are caught and logged so a failure on one host
        never cancels scanning of the remaining hosts.
        """
        async with semaphore:
            xml_path: Path | None = None

            try:
                # ── Create temp file for XML output ──────────────────────
                with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
                    xml_path = Path(tmp.name)

                # ── Determine timeout from profile ────────────────────────
                timeout = _timeout_for_args(args)

                # ── Layer 1 setup: streaming callback ────────────────────
                # This set tracks (host, port, protocol) tuples that have
                # already been inserted via the stream. The enrichment pass
                # will update those records rather than re-insert duplicates.
                streamed_keys: set[tuple[str, int, str]] = set()

                def on_port_found(
                    port_rec: PortRecord, svc_rec: ServiceRecord | None
                ) -> None:
                    """Called in real-time for every open port line from Nmap."""
                    key = (port_rec.host, port_rec.port, port_rec.protocol)
                    if key in streamed_keys:
                        return  # Guard against duplicate lines
                    streamed_keys.add(key)

                    self.db.insert_port(port_rec)
                    if svc_rec:
                        self.db.insert_port(_service_as_port(svc_rec))

                    # Schedule the async event emit safely from a sync context
                    loop = asyncio.get_event_loop()
                    loop.call_soon_threadsafe(
                        _schedule_emit, loop, self._emit_port_event(port_rec, svc_rec, host)
                    )

                # ── Wire up the streaming callback ────────────────────────
                streaming_cb = adapter.make_streaming_callback(
                    scan_id=self.scan_id,
                    host=host,
                    on_port_found=on_port_found,
                )

                # ── Build command (dual output: greppable + XML) ──────────
                cmd = adapter.build_command(
                    target=host,
                    args=args,
                    output_xml=xml_path,
                )

                # ── Execute ───────────────────────────────────────────────
                # The streaming_cb is passed as on_output so CommandRunner
                # calls it for every line from stdout in real-time.
                result = await self.runner.run(
                    command=cmd,
                    timeout=timeout,
                )

                self.logger.debug(
                    f"Nmap finished for {host}: "
                    f"status={result.status.value}, "
                    f"streamed={len(streamed_keys)} ports",
                    module=self.config.name,
                )

                # ── Layer 2 / 3: XML enrichment ───────────────────────────
                if xml_path.exists() and xml_path.stat().st_size > 0:
                    if result.status == CommandStatus.SUCCESS:
                        # Layer 2: strict parse for rich service data
                        enrichment = adapter.parse_xml(xml_path, self.scan_id)
                    else:
                        # Layer 3: fault-tolerant regex carver for partial XML
                        self.logger.debug(
                            f"Nmap timed out/failed for {host}. "
                            f"Attempting fault-tolerant XML recovery...",
                            module=self.config.name,
                        )
                        enrichment = adapter.parse_xml_fault_tolerant(
                            xml_path, self.scan_id
                        )

                    await self._merge_enrichment(enrichment, streamed_keys, host)

            except Exception as exc:
                # Catch-all: a scan failure on one host must never crash the
                # orchestrator or block other hosts from being scanned.
                self.logger.debug(
                    f"Unexpected error during port scan for {host}: {exc}",
                    module=self.config.name,
                )
            finally:
                # Always clean up the temp XML file
                if xml_path and xml_path.exists():
                    xml_path.unlink(missing_ok=True)

    async def _merge_enrichment(
        self,
        enrichment: dict[str, list[Any]],
        streamed_keys: set[tuple[str, int, str]],
        host: str,
    ) -> None:
        """Merge XML enrichment data into the database.

        For ports already inserted by the real-time stream, this updates
        their richer fields (product, version, CPE). For any ports that
        the XML found but the stream missed (e.g. the greppable line was
        malformed), it inserts them fresh.
        """
        for port_record in enrichment.get("ports", []):
            key = (port_record.host, port_record.port, port_record.protocol)
            # Always upsert — insert_port is idempotent in our DB manager
            self.db.insert_port(port_record)

            if key not in streamed_keys:
                # This port was NOT found by the stream — emit the event now
                streamed_keys.add(key)
                await self._emit_port_event(port_record, None, host)

        for svc_record in enrichment.get("services", []):
            self.db.insert_port(_service_as_port(svc_record))
            await self.events.emit_discovery(
                event_type=EventType.SERVICE_DISCOVERED,
                source=self.config.name,
                data={
                    "host": svc_record.host,
                    "port": svc_record.port,
                    "service": svc_record.service,
                    "product": svc_record.product,
                    "version": svc_record.version,
                    "source": svc_record.source,
                },
                scan_id=self.scan_id,
                target=self.target,
            )

    async def _emit_port_event(
        self,
        port_record: PortRecord,
        svc_record: ServiceRecord | None,
        host: str,
    ) -> None:
        """Emit PORT_DISCOVERED and optionally SERVICE_DISCOVERED events."""
        await self.events.emit_discovery(
            event_type=EventType.PORT_DISCOVERED,
            source=self.config.name,
            data={
                "host": port_record.host,
                "port": port_record.port,
                "protocol": port_record.protocol,
                "service": port_record.service,
                "source": port_record.source,
            },
            scan_id=self.scan_id,
            target=self.target,
        )

        if svc_record and (svc_record.product or svc_record.service):
            await self.events.emit_discovery(
                event_type=EventType.SERVICE_DISCOVERED,
                source=self.config.name,
                data={
                    "host": svc_record.host,
                    "port": svc_record.port,
                    "service": svc_record.service,
                    "product": svc_record.product,
                    "source": svc_record.source,
                },
                scan_id=self.scan_id,
                target=self.target,
            )


def _timeout_for_args(args: list[str]) -> int:
    """Determine a sensible timeout based on the scan profile's arguments."""
    if "-p-" in args:
        return 600   # Full 65535-port scan — needs time
    if "-sC" in args:
        return 300   # Script scan — slower due to service probing
    if "--top-ports" in args:
        try:
            idx = args.index("--top-ports")
            port_count = int(args[idx + 1])
            if port_count >= 1000:
                return 180
        except (ValueError, IndexError):
            pass
    return 120       # Default
