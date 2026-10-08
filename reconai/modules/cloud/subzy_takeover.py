"""Subdomain Takeover Detection Module.

Identifies dangling DNS CNAME records vulnerable to subdomain takeover
using Subzy CLI with pure-Python fingerprinting fallback.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from reconai.core.database.models import Confidence, FindingRecord, FindingStatus, Severity
from reconai.core.events.types import EventType
from reconai.integrations.subzy import SubzyAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

# Known dangling cloud service fingerprint signatures for pure-Python fallback
TAKEOVER_SIGNATURES: list[tuple[str, str, str]] = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("herokudns.com", "Heroku | No such app", "Heroku"),
    ("azurewebsites.net", "404 Web Site not found", "Azure App Service"),
    ("myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly CDN"),
    ("pantheonsite.io", "The gods are wise, but do not know of the site which you seek", "Pantheon"),
    ("zendesk.com", "Help Center Closed", "Zendesk"),
    ("bitbucket.io", "Repository not found", "Bitbucket"),
    ("ghost.io", "The thing you were looking for is no longer here", "Ghost"),
    ("surge.sh", "project not found", "Surge.sh"),
]


@register_module
class SubzyTakeoverModule(ReconModule):
    config = ModuleConfig(
        name="subzy_takeover",
        category="cloud",
        description="Automated subdomain takeover detection using Subzy (with pure-Python DNS CNAME fallback)",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        subs = self.db.get_subdomains(self.scan_id)
        subdomains = [str(s["subdomain"]) for s in subs if s.get("subdomain")]

        if not subdomains and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            if clean:
                subdomains = [clean]

        if not subdomains:
            return

        adapter = SubzyAdapter(self.runner)
        has_subzy = await adapter.is_available()

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(subdomains)} subdomains")

        if has_subzy:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf_in:
                tf_in.write("\n".join(subdomains))
                targets_file = Path(tf_in.name)

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf_out:
                output_file = Path(tf_out.name)

            try:
                cmd = adapter.build_command(targets_file=targets_file, output_file=output_file)
                await self.runner.run(command=cmd, timeout=self.timeout)
                findings = adapter.parse_output_file(output_file)

                for f in findings:
                    f.scan_id = self.scan_id
                    await self.emit_finding(f)

            finally:
                targets_file.unlink(missing_ok=True)
                output_file.unlink(missing_ok=True)
        else:
            self.record_warning(
                "Subzy not installed in PATH. Install: 'go install -v github.com/pentest-io/subzy@latest'. "
                "Ran pure-Python CNAME dangling DNS fingerprint fallback."
            )
            await self._python_takeover_check(subdomains[:100])

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _python_takeover_check(self, subdomains: list[str]) -> None:
        """Pure-Python CNAME inspection and HTTP response fingerprinting."""
        cname_records = self.db.get_dns_records(self.scan_id)
        cname_map = {
            r["hostname"].lower(): r["value"].lower()
            for r in cname_records
            if r.get("record_type") == "CNAME"
        }

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0"}) as client:
            for sub in subdomains:
                sub_lower = sub.lower()
                cname = cname_map.get(sub_lower, "")

                # Check if CNAME points to known cloud services or test HTTP response directly
                for cname_indicator, err_pattern, service_name in TAKEOVER_SIGNATURES:
                    if (cname and cname_indicator in cname) or not cname:
                        try:
                            resp = await client.get(f"https://{sub}")
                            if err_pattern.lower() in resp.text.lower():
                                finding = FindingRecord(
                                    scan_id=self.scan_id,
                                    title=f"Potential Subdomain Takeover ({service_name})",
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.LIKELY,
                                    status=FindingStatus.POTENTIAL,
                                    affected_asset=sub,
                                    affected_asset_type="subdomain",
                                    description=(
                                        f"Subdomain {sub} points to {cname or 'cloud provider'} and returns '{err_pattern}', "
                                        f"indicating the backend {service_name} resource is unclaimed."
                                    ),
                                    impact="Full subdomain takeover allowing cookie theft, credential harvesting, and phishing under a trusted domain.",
                                    remediation=f"Remove the dangling DNS record or claim the resource on {service_name}.",
                                    attack_class="subdomain takeover",
                                    source=self.config.name,
                                    verified=True,
                                )
                                await self.emit_finding(finding)
                                self.logger.info(f"[TAKEOVER] Discovered potential takeover on {sub} ({service_name})", module=self.config.name)
                                break
                        except Exception:
                            continue
