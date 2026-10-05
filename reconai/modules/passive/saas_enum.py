"""SaaS & Organizational Workspace Enumeration Module.

Passively discovers third-party cloud and SaaS workspaces registered under
the target company's name or domain:
  - Atlassian Jira & Confluence ({target}.atlassian.net)
  - Slack Workspaces ({target}.slack.com)
  - Notion Public Workspaces ({target}.notion.site)
  - Postman Workspaces ({target}.postman.co)
  - Public GitHub Organization (api.github.com/orgs/{keyword})

Zero cost — utilizes standard asynchronous DNS resolution and public unauthenticated HTTP requests.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

import dns.asyncresolver
import httpx

from reconai.core.database.models import CloudAssetRecord, TechnologyRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class SAASEnumModule(ReconModule):
    config = ModuleConfig(
        name="saas_enum",
        category="passive",
        description="Discovers organizational SaaS workspaces (Atlassian, Slack, Notion, Postman, GitHub).",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domain = kwargs.get("domain", self.target)
        domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0].strip()
        if not domain:
            return

        # Extract primary brand / company keyword from domain
        # e.g. "acme-corp.com" -> "acme-corp", "acme"
        parts = domain.lower().replace(".com", "").replace(".io", "").replace(".org", "").replace(".net", "")
        base_keyword = parts.split(".")[0]
        keywords = {base_keyword}
        if "-" in base_keyword:
            keywords.add(base_keyword.replace("-", ""))

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{domain} (keywords: {', '.join(keywords)})")

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 5.0

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(6.0, connect=3.0),
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        ) as client:
            tasks = []
            for kw in keywords:
                if len(kw) < 3:
                    continue
                tasks.extend([
                    self._check_atlassian(resolver, kw),
                    self._check_slack(resolver, kw),
                    self._check_notion(client, kw),
                    self._check_postman(client, kw),
                    self._check_github_org(client, kw),
                ])

            await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _check_atlassian(
        self, resolver: dns.asyncresolver.Resolver, keyword: str
    ) -> None:
        """Check if {keyword}.atlassian.net resolves."""
        target_host = f"{keyword}.atlassian.net"
        try:
            answers = await resolver.resolve(target_host, "A")
            if answers:
                url = f"https://{target_host}"
                await self._save_saas_asset(
                    provider="atlassian",
                    asset_type="jira_confluence_workspace",
                    asset_name=target_host,
                    url=url,
                    is_public=True,
                    metadata={"service": "Atlassian Cloud"},
                )
        except Exception:
            pass

    async def _check_slack(
        self, resolver: dns.asyncresolver.Resolver, keyword: str
    ) -> None:
        """Check if {keyword}.slack.com resolves."""
        target_host = f"{keyword}.slack.com"
        try:
            answers = await resolver.resolve(target_host, "A")
            if answers:
                url = f"https://{target_host}"
                await self._save_saas_asset(
                    provider="slack",
                    asset_type="slack_workspace",
                    asset_name=target_host,
                    url=url,
                    is_public=True,
                    metadata={"service": "Slack Workspace"},
                )
        except Exception:
            pass

    async def _check_notion(
        self, client: httpx.AsyncClient, keyword: str
    ) -> None:
        """Check if {keyword}.notion.site exists."""
        target_url = f"https://{keyword}.notion.site"
        try:
            resp = await client.get(target_url)
            # A 200 or 401/403 with Notion markers means workspace exists
            if resp.status_code in (200, 401, 403) and ("notion" in resp.text.lower() or "notion.site" in resp.text):
                await self._save_saas_asset(
                    provider="notion",
                    asset_type="notion_workspace",
                    asset_name=f"{keyword}.notion.site",
                    url=target_url,
                    is_public=(resp.status_code == 200),
                    metadata={"status_code": resp.status_code},
                )
        except Exception:
            pass

    async def _check_postman(
        self, client: httpx.AsyncClient, keyword: str
    ) -> None:
        """Check if {keyword}.postman.co exists."""
        target_url = f"https://{keyword}.postman.co"
        try:
            resp = await client.get(target_url)
            if resp.status_code in (200, 301, 302, 401, 403):
                await self._save_saas_asset(
                    provider="postman",
                    asset_type="postman_workspace",
                    asset_name=f"{keyword}.postman.co",
                    url=target_url,
                    is_public=True,
                    metadata={"status_code": resp.status_code},
                )
        except Exception:
            pass

    async def _check_github_org(
        self, client: httpx.AsyncClient, keyword: str
    ) -> None:
        """Check for public GitHub organization via public unauthenticated API."""
        api_url = f"https://api.github.com/orgs/{keyword}"
        try:
            resp = await client.get(api_url)
            if resp.status_code == 200:
                data = resp.json()
                html_url = data.get("html_url", f"https://github.com/{keyword}")
                public_repos = data.get("public_repos", 0)
                await self._save_saas_asset(
                    provider="github",
                    asset_type="github_organization",
                    asset_name=keyword,
                    url=html_url,
                    is_public=True,
                    metadata={
                        "public_repos": public_repos,
                        "description": data.get("description", ""),
                        "blog": data.get("blog", ""),
                    },
                )
        except Exception:
            pass

    async def _save_saas_asset(
        self,
        provider: str,
        asset_type: str,
        asset_name: str,
        url: str,
        is_public: bool,
        metadata: dict[str, Any],
    ) -> None:
        """Record discovered SaaS asset in database and emit event."""
        record = CloudAssetRecord(
            scan_id=self.scan_id,
            provider=provider,
            asset_type=asset_type,
            asset_name=asset_name,
            url=url,
            is_public=is_public,
            is_writable=False,
            region="global",
            metadata=metadata,
            source=self.config.name,
        )
        self.db.insert_cloud_asset(record)

        self.logger.info(
            f"[SAAS] Discovered {provider.upper()} Workspace: {asset_name} ({url})",
            module=self.config.name,
        )

        await self.event_bus.emit_discovery(
            event_type=EventType.CLOUD_ASSET_DISCOVERED,
            source=self.config.name,
            data={
                "provider": provider,
                "asset_type": asset_type,
                "asset_name": asset_name,
                "url": url,
                "is_public": is_public,
            },
            scan_id=self.scan_id,
            target=self.target,
        )
