"""API Route & Schema Miner Module.

Discovers, parses, and maps REST and GraphQL APIs on live target hosts:
  1. OpenAPI / Swagger Specifications:
     Probes for /swagger.json, /openapi.json, /v2/api-docs, /v3/api-docs, etc.
     Parses all paths, parameters, and HTTP methods, inserting them directly into
     the `api_endpoints` and `urls` database tables.
  2. GraphQL Introspection:
     Probes /graphql, /api/graphql, /v1/graphql.
     Sends a standard schema introspection query to detect if the data model
     and available queries/mutations are publicly exposed.

Zero external costs — uses asynchronous HTTP probing via httpx.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from reconai.core.database.models import (
    APIEndpoint, Confidence, FindingRecord, FindingStatus, Severity, URLRecord,
)
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

_SWAGGER_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api/v1/api-docs",
]

_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
]

_INTROSPECTION_QUERY = {"query": "{ __schema { types { name } } }"}


@register_module
class APIMinerModule(ReconModule):
    config = ModuleConfig(
        name="api_miner",
        category="web",
        description="Discovers and parses OpenAPI/Swagger specifications and tests for GraphQL introspection.",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        # Collect live base URLs from DB
        live_urls: set[str] = set()
        for r in self.db.get_urls(self.scan_id):
            u = r.get("url", "")
            if u.startswith("http"):
                parsed = urlparse(u)
                base = f"{parsed.scheme}://{parsed.netloc}"
                live_urls.add(base)

        if not live_urls:
            # Fallback to target
            target = kwargs.get("target", self.target)
            if not target.startswith("http"):
                live_urls.add(f"https://{target}")
                live_urls.add(f"http://{target}")
            else:
                live_urls.add(target)

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(live_urls)} base host(s)")

        semaphore = asyncio.Semaphore(10)
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(8.0, connect=4.0),
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "ReconAI-APIMiner/1.0", "Accept": "application/json, */*"},
        ) as client:
            tasks = [
                self._mine_host(client, semaphore, base_url)
                for base_url in list(live_urls)[:25]  # Cap at 25 hosts to stay fast
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _mine_host(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        base_url: str,
    ) -> None:
        """Scan a single base host for OpenAPI and GraphQL schemas."""
        async with semaphore:
            await asyncio.gather(
                self._check_openapi(client, base_url),
                self._check_graphql(client, base_url),
                return_exceptions=True,
            )

    async def _check_openapi(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Probe for OpenAPI/Swagger JSON and parse all documented routes."""
        for path in _SWAGGER_PATHS:
            target_url = urljoin(base_url, path)
            try:
                resp = await client.get(target_url)
                if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
                    try:
                        spec = resp.json()
                    except Exception:
                        continue

                    if not isinstance(spec, dict):
                        continue

                    # Validate that it's a real Swagger or OpenAPI document
                    if "swagger" not in spec and "openapi" not in spec and "paths" not in spec:
                        continue

                    self.logger.info(
                        f"[API] Found OpenAPI/Swagger Spec at {target_url}",
                        module=self.config.name,
                    )
                    await self._parse_openapi_spec(base_url, target_url, spec)
                    return  # Found primary spec for this host, move on
            except Exception:
                continue

    async def _parse_openapi_spec(
        self, base_url: str, spec_url: str, spec: dict[str, Any]
    ) -> None:
        """Extract all endpoints from the OpenAPI specification and insert into DB."""
        netloc = urlparse(base_url).netloc
        paths: dict[str, Any] = spec.get("paths", {})
        discovered_count = 0

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                    continue

                full_url = urljoin(base_url, path_str.lstrip("/"))
                content_type = "application/json"
                if isinstance(operation, dict):
                    consumes = operation.get("consumes", [])
                    if consumes and isinstance(consumes, list):
                        content_type = consumes[0]

                # Save to api_endpoints table
                api_rec = APIEndpoint(
                    scan_id=self.scan_id,
                    host=netloc,
                    method=method.upper(),
                    path=path_str,
                    full_url=full_url,
                    content_type=content_type,
                    auth_required=bool(isinstance(operation, dict) and operation.get("security")),
                    source=self.config.name,
                    api_type="openapi",
                )
                self.db.insert_api_endpoint(api_rec)

                # Also save to urls table for crawler/fuzzer awareness
                url_rec = URLRecord(
                    scan_id=self.scan_id,
                    url=full_url,
                    method=method.upper(),
                    source=self.config.name,
                )
                self.db.insert_url(url_rec)
                discovered_count += 1

        self.logger.info(
            f"[API] Parsed and saved {discovered_count} API routes from {spec_url}",
            module=self.config.name,
        )

        # Register a finding for the exposed Swagger documentation
        finding = FindingRecord(
            scan_id=self.scan_id,
            title=f"Publicly Exposed OpenAPI/Swagger Specification: {netloc}",
            severity=Severity.LOW,
            confidence=Confidence.VERIFIED,
            status=FindingStatus.VERIFIED,
            affected_asset=spec_url,
            affected_asset_type="api_documentation",
            description=(
                f"A public OpenAPI/Swagger API specification was discovered at '{spec_url}'. "
                f"ReconAI extracted {discovered_count} documented API endpoints and parameters."
            ),
            impact="Exposes the entire internal REST API attack surface, input models, and parameter schemas to unauthenticated parties.",
            evidence=f"HTTP 200 JSON specification at {spec_url} ({discovered_count} routes extracted)",
            detection_method="Direct OpenAPI specification probing and JSON parsing",
            remediation="Restrict access to OpenAPI / Swagger documentation in production environments or place behind authentication.",
            references=["https://swagger.io/specification/"],
            what_is_it="A machine-readable API definition describing operations, parameters, and data models of an application.",
            attack_class="Information Disclosure / API Surface Exposure",
            prevention="Disable Swagger UI and OpenAPI JSON endpoints in production builds.",
            source=self.config.name,
        )
        await self.emit_finding(finding)

    async def _check_graphql(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Probe for GraphQL endpoint and check if introspection is active."""
        for path in _GRAPHQL_PATHS:
            target_url = urljoin(base_url, path)
            try:
                resp = await client.post(target_url, json=_INTROSPECTION_QUERY)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        continue

                    # Introspection signature check
                    if (
                        isinstance(data, dict)
                        and "data" in data
                        and isinstance(data["data"], dict)
                        and "__schema" in data["data"]
                    ):
                        schema_data = data["data"]["__schema"]
                        types = schema_data.get("types", [])
                        type_names = [t.get("name") for t in types if isinstance(t, dict) and t.get("name")]
                        custom_types = [t for t in type_names if not t.startswith("__")][:15]

                        self.logger.info(
                            f"[API] 🔥 GraphQL Introspection ENABLED at {target_url} ({len(type_names)} types)",
                            module=self.config.name,
                        )

                        # Save endpoint
                        api_rec = APIEndpoint(
                            scan_id=self.scan_id,
                            host=urlparse(base_url).netloc,
                            method="POST",
                            path=path,
                            full_url=target_url,
                            content_type="application/json",
                            auth_required=False,
                            source=self.config.name,
                            api_type="graphql",
                        )
                        self.db.insert_api_endpoint(api_rec)

                        # Register finding
                        finding = FindingRecord(
                            scan_id=self.scan_id,
                            title=f"GraphQL Introspection Enabled: {urlparse(base_url).netloc}",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.VERIFIED,
                            status=FindingStatus.VERIFIED,
                            affected_asset=target_url,
                            affected_asset_type="api_endpoint",
                            description=(
                                f"The GraphQL API at '{target_url}' allows unauthenticated schema introspection. "
                                f"An attacker can query the full data model, queries, mutations, and internal entity relationships.\n\n"
                                f"Discovered Custom Types: {', '.join(custom_types[:10])}..."
                            ),
                            impact="Allows complete schema exfiltration, enabling attackers to target hidden queries, sensitive fields, and administrative mutations.",
                            evidence=f"Introspection query response returned {len(type_names)} types from {target_url}",
                            detection_method="GraphQL __schema introspection POST probe",
                            remediation="Disable GraphQL introspection in production environments.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                            ],
                            what_is_it="A GraphQL feature that enables clients to query the schema for details about what queries and mutations are supported.",
                            attack_class="API Information Disclosure",
                            prevention="Disable introspection queries in Apollo Server, Yoga, or whichever GraphQL engine is in use.",
                            source=self.config.name,
                        )
                        await self.emit_finding(finding)
                        return
            except Exception:
                continue
