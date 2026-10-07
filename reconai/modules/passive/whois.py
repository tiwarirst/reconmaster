"""WHOIS & RDAP Enumeration Module.

Retrieves domain registration, registrar, and organization details.
Uses the system whois CLI if available; seamlessly falls back to standard RDAP (ICANN) via HTTP.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class WhoisModule(ReconModule):
    config = ModuleConfig(
        name="whois",
        category="passive",
        description="Retrieves domain WHOIS/RDAP registration details",
        requires_tools=[],  # Optional: has built-in RDAP HTTP fallback
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains = list(kwargs.get("domains", []))
        if not domains and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            if clean:
                domains = [clean]

        if not domains:
            return

        for domain in domains:
            start = time.monotonic()
            self.logger.module_start(self.config.name, target=domain)

            # Try CLI tool first
            tool_avail, _ = await self.runner.check_tool("whois")
            registrar = ""
            created_date = ""
            expiry_date = ""
            raw_text = ""

            if tool_avail:
                result = await self.runner.run(["whois", domain], timeout=20)
                if result.succeeded and result.stdout:
                    raw_text = result.stdout[:1500]
                    # Regex extraction of unredacted core metadata
                    import re
                    reg_match = re.search(r"Registrar:\s*([^\r\n]+)", raw_text, re.IGNORECASE)
                    if reg_match:
                        registrar = reg_match.group(1).strip()
                    created_match = re.search(r"(?:Creation Date|Created):\s*([^\r\n]+)", raw_text, re.IGNORECASE)
                    if created_match:
                        created_date = created_match.group(1).strip()
                    exp_match = re.search(r"(?:Registry Expiry Date|Expir\w+ Date):\s*([^\r\n]+)", raw_text, re.IGNORECASE)
                    if exp_match:
                        expiry_date = exp_match.group(1).strip()

            # If CLI tool not available or missing registrar, query ICANN RDAP over HTTP
            if not registrar or not raw_text:
                rdap_info = await self._query_rdap_structured(domain)
                if rdap_info:
                    registrar = registrar or rdap_info.get("registrar", "")
                    created_date = created_date or rdap_info.get("created", "")
                    expiry_date = expiry_date or rdap_info.get("expires", "")
                    raw_text = raw_text or rdap_info.get("raw", "")

            # If registrar found, save to technologies so it is surfaced in reports & graph
            if registrar:
                from reconai.core.database.models import TechnologyRecord
                tech = TechnologyRecord(
                    scan_id=self.scan_id,
                    host=domain,
                    name=f"Registrar: {registrar}",
                    category="domain_registrar",
                    version=created_date[:10] if created_date else "",
                    confidence=1.0,
                    source=self.config.name,
                    evidence=[f"Created: {created_date}", f"Expires: {expiry_date}"],
                )
                self.db.insert_technology(tech)
                self.logger.info(f"[WHOIS] Registrar: {registrar} (Created: {created_date[:10] if created_date else 'N/A'})", module=self.config.name)

            if raw_text or registrar:
                await self.events.emit_discovery(
                    event_type=EventType.ASSET_DISCOVERED,
                    source=self.config.name,
                    data={
                        "type": "whois",
                        "domain": domain,
                        "registrar": registrar,
                        "created_date": created_date,
                        "expiry_date": expiry_date,
                        "raw": raw_text[:500] if raw_text else "",
                    },
                    scan_id=self.scan_id,
                    target=self.target,
                )

            duration = time.monotonic() - start
            self.logger.module_complete(self.config.name, duration=duration)

    async def _query_rdap_structured(self, domain: str) -> dict[str, str]:
        """Query public ICANN RDAP registry for unredacted authoritative metadata."""
        out: dict[str, str] = {}
        try:
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(f"https://rdap.org/domain/{domain}")
                if resp.status_code == 200:
                    data = resp.json()
                    handle = data.get("handle", "")
                    events = data.get("events", [])
                    for e in events:
                        action = e.get("eventAction", "")
                        date = e.get("eventDate", "")
                        if "registration" in action:
                            out["created"] = date
                        elif "expiration" in action:
                            out["expires"] = date

                    # Extract registrar entity
                    entities = data.get("entities", [])
                    for ent in entities:
                        roles = ent.get("roles", [])
                        if "registrar" in roles:
                            out["registrar"] = ent.get("handle", "") or ent.get("vcardArray", [None, [["fn", {}, "text", ""]]])[1][0][3]
                            break

                    dates_summary = "\n".join([f"{e.get('eventAction')}: {e.get('eventDate')}" for e in events if e.get("eventAction")])
                    out["raw"] = f"Domain: {domain}\nHandle: {handle}\nRegistrar: {out.get('registrar','')}\n" + dates_summary
        except Exception:
            pass
        return out
