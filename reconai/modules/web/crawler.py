"""Advanced Web Crawler & Attack Surface Spider Module.

Features:
- High-concurrency asynchronous worker pool (8-10 workers per host) with connection reuse.
- Fast-path regex extraction for links, assets, scripts, and endpoints.
- Form intelligence: extracts input parameters and synthesizes test URLs with query parameters.
- Single Page Application (SPA) endpoint miner: scans scripts and HTML for REST routes, GraphQL paths, and Fetch/Axios calls.
- Automated robots.txt and sitemap.xml seed ingestion.
- 401/403 access-control disclosure preservation (never drops protected paths).
- Path template deduplication (prevents pagination loops).
- High-throughput batch database insertion via WAL mode.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from reconai.core.database.models import APIEndpoint, URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

_RE_TITLE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_RE_HREF_SRC = re.compile(r'(?:href|src)=["\']([^"\'#\s>]+)["\']', re.IGNORECASE)
_RE_SCRIPT_SRC = re.compile(r'<script\b[^>]*src=["\']([^"\'#\s>]+)["\']', re.IGNORECASE)
_RE_API_PATH = re.compile(
    r'["\'](/(?:api|v[0-9]|rest|graphql|auth|admin|user|users|account|item|items|data|query|search|dashboard)[a-zA-Z0-9_\-\./?=&]*)["\']',
    re.IGNORECASE,
)
_RE_FETCH_AXIOS = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete)|\.open\s*\(\s*["\'](?:GET|POST)["\']\s*,)\s*\(?["\']([^"\'\s><)]+)["\']',
    re.IGNORECASE,
)

# File extensions to record as assets but not crawl for hyperlinks
_STATIC_ASSET_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z", ".exe",
)


def _normalize_host(host: str) -> str:
    """Normalize hostname by stripping port and leading www."""
    h = host.split(":")[0].strip().lower()
    return h[4:] if h.startswith("www.") else h


def _path_template(path: str) -> str:
    """Convert numeric and UUID path segments to template placeholders for loop prevention."""
    p = re.sub(r"/\d+(?=/|$)", "/{id}", path)
    return re.sub(r"/[a-f0-9\-]{36}(?=/|$)", "/{uuid}", p)


@register_module
class CrawlerModule(ReconModule):
    config = ModuleConfig(
        name="crawler",
        category="web",
        description="High-speed concurrent web spider for links, forms, input parameters, scripts, and SPA routes",
        requires_tools=[],
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        start_urls: list[str] = []

        # 1. Gather URLs from kwargs
        for u in kwargs.get("urls", []):
            if str(u).startswith("http"):
                start_urls.append(str(u))

        # 2. Gather live URLs from DB
        if not start_urls:
            url_records = self.db.get_urls(self.scan_id)
            for r in url_records:
                u = str(r.get("url", ""))
                if u.startswith("http") and u not in start_urls:
                    start_urls.append(u)

        # 3. Fallback to target
        if not start_urls and self.target:
            clean = self.target.split("://")[-1].split("/")[0].split(":")[0]
            start_urls = [f"https://{clean}", f"http://{clean}"]

        if not start_urls:
            return

        # Deduplicate and pick unique host entry points
        unique_entry_points: list[str] = []
        seen_hosts: set[str] = set()
        for u in start_urls:
            try:
                host = urlparse(u).netloc.lower()
                if host and host not in seen_hosts:
                    seen_hosts.add(host)
                    unique_entry_points.append(u)
            except Exception:
                continue

        start = time.monotonic()
        self.logger.module_start(self.config.name, target=f"{len(unique_entry_points)} entry points")

        max_depth = 3
        max_pages_per_host = 60

        limits = httpx.Limits(max_keepalive_connections=40, max_connections=80, keepalive_expiry=30.0)
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=10.0,
            limits=limits,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconAI-Spider/2.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        ) as client:
            tasks = [
                self._crawl_host(client, start_url, max_depth, max_pages_per_host)
                for start_url in unique_entry_points[:8]  # Concurrently crawl top origins
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _crawl_host(
        self,
        client: httpx.AsyncClient,
        start_url: str,
        max_depth: int,
        max_pages: int,
    ) -> None:
        """High-speed asynchronous concurrent crawl of a target origin."""
        visited: set[str] = set()
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        parsed_start = urlparse(start_url)
        origin = f"{parsed_start.scheme}://{parsed_start.netloc}"
        start_base_domain = _normalize_host(parsed_start.netloc)

        template_counts: dict[str, int] = {}
        batch_urls: list[URLRecord] = []
        batch_apis: list[APIEndpoint] = []
        lock = asyncio.Lock()

        # Ingest robots.txt and sitemap.xml seeds
        seed_links = await self._fetch_robots_and_sitemaps(client, origin)
        await queue.put((start_url, 0))
        for s in seed_links:
            if s not in visited:
                await queue.put((s, 1))

        CONCURRENCY = 8
        active_workers = 0

        async def worker() -> None:
            nonlocal active_workers
            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=1.8)
                except (asyncio.TimeoutError, asyncio.QueueEmpty):
                    if active_workers == 0:
                        break
                    continue

                active_workers += 1
                try:
                    clean_url = url.split("#")[0]
                    async with lock:
                        if clean_url in visited or len(visited) >= max_pages or depth > max_depth:
                            continue
                        parsed_url = urlparse(clean_url)
                        tmpl = _path_template(parsed_url.path)
                        if template_counts.get(tmpl, 0) >= 4:
                            continue
                        visited.add(clean_url)
                        template_counts[tmpl] = template_counts.get(tmpl, 0) + 1

                    path_lower = parsed_url.path.lower()
                    if any(path_lower.endswith(ext) for ext in _STATIC_ASSET_EXTENSIONS):
                        async with lock:
                            batch_urls.append(URLRecord(
                                scan_id=self.scan_id,
                                url=clean_url,
                                method="GET",
                                status_code=200,
                                source="crawler_static",
                                depth=depth,
                            ))
                        continue

                    # Fetch page
                    try:
                        response = await client.get(clean_url)
                        content_type = response.headers.get("content-type", "")

                        title = ""
                        title_match = _RE_TITLE.search(response.text)
                        if title_match:
                            title = title_match.group(1).strip()[:150]

                        record = URLRecord(
                            scan_id=self.scan_id,
                            url=str(response.url),
                            method="GET",
                            status_code=response.status_code,
                            content_type=content_type,
                            content_length=len(response.content),
                            title=title,
                            source="crawler",
                            depth=depth,
                        )

                        async with lock:
                            batch_urls.append(record)

                        if depth > 0:
                            await self.events.emit_discovery(
                                event_type=EventType.URL_DISCOVERED,
                                source=self.config.name,
                                data={"url": str(response.url), "status": response.status_code, "depth": depth},
                                scan_id=self.scan_id,
                                target=self.target,
                            )

                        if response.status_code >= 400:
                            continue

                        if "text/html" not in content_type and "application/xhtml" not in content_type:
                            continue

                        html_text = response.text

                        # 1. Fast regex extraction of hyperlinks and sources (<a href>, <link href>, <iframe>)
                        raw_links = _RE_HREF_SRC.findall(html_text)
                        for href in raw_links:
                            if not href or href.startswith("data:") or href.startswith("javascript:"):
                                continue
                            abs_url = urljoin(str(response.url), href).split("#")[0]
                            if self._is_in_scope(abs_url, start_base_domain):
                                async with lock:
                                    if abs_url not in visited and len(visited) < max_pages:
                                        await queue.put((abs_url, depth + 1))
                            elif self.scope and hasattr(self.scope, "strict") and not self.scope.strict:
                                # In permissive mode, capture external APIs/assets for AI correlation
                                if abs_url.startswith("http"):
                                    async with lock:
                                        batch_urls.append(URLRecord(
                                            scan_id=self.scan_id,
                                            url=abs_url,
                                            method="GET",
                                            source="crawler_external",
                                            depth=depth + 1,
                                        ))

                        # 2. Process Script Tags (<script src="...">)
                        for script_match in _RE_SCRIPT_SRC.finditer(html_text):
                            s_src = script_match.group(1)
                            abs_script = urljoin(str(response.url), s_src).split("#")[0]
                            if abs_script.startswith("http"):
                                async with lock:
                                    batch_urls.append(URLRecord(
                                        scan_id=self.scan_id,
                                        url=abs_script,
                                        method="GET",
                                        source="crawler_script",
                                        depth=depth + 1,
                                    ))
                                    if self._is_in_scope(abs_script, start_base_domain):
                                        if abs_script not in visited:
                                            visited.add(abs_script)

                        # 3. Process Forms & Parameter Extraction (<form action="..." method="...">)
                        if "<form" in html_text.lower():
                            soup = BeautifulSoup(html_text, "html.parser")
                            for form in soup.find_all("form"):
                                action = form.get("action") or ""
                                if isinstance(action, list):
                                    action = action[0]
                                form_action = urljoin(str(response.url), str(action)).split("#")[0]
                                form_method = str(form.get("method", "GET")).upper()

                                inputs = form.find_all(["input", "textarea", "select"])
                                param_names = [inp.get("name") for inp in inputs if inp.get("name")]

                                if param_names:
                                    query_pairs = {str(name): "test" for name in param_names}
                                    if form_method == "GET":
                                        parsed_action = urlparse(form_action)
                                        existing_q = dict(parse_qsl(parsed_action.query))
                                        existing_q.update(query_pairs)
                                        full_param_url = f"{parsed_action.scheme}://{parsed_action.netloc}{parsed_action.path}?{urlencode(existing_q)}"
                                        async with lock:
                                            batch_urls.append(URLRecord(
                                                scan_id=self.scan_id,
                                                url=full_param_url,
                                                method="GET",
                                                source="crawler_form",
                                                depth=depth + 1,
                                            ))
                                            if full_param_url not in visited and self._is_in_scope(full_param_url, start_base_domain):
                                                await queue.put((full_param_url, depth + 1))
                                    else:
                                        async with lock:
                                            batch_apis.append(APIEndpoint(
                                                scan_id=self.scan_id,
                                                host=str(response.url),
                                                method="POST",
                                                path=urlparse(form_action).path or "/",
                                                full_url=form_action,
                                                source="crawler_form",
                                                api_type="Form-POST",
                                            ))

                        # 4. Process Modern SPA & AJAX Endpoints from Inline JS
                        found_api_paths = _RE_API_PATH.findall(html_text)
                        found_fetches = _RE_FETCH_AXIOS.findall(html_text)
                        for ep in set(found_api_paths + found_fetches):
                            abs_ep = urljoin(str(response.url), ep).split("#")[0]
                            if self._is_in_scope(abs_ep, start_base_domain):
                                async with lock:
                                    batch_apis.append(APIEndpoint(
                                        scan_id=self.scan_id,
                                        host=str(response.url),
                                        method="GET",
                                        path=urlparse(abs_ep).path or ep,
                                        full_url=abs_ep,
                                        source="crawler_spa",
                                        api_type="REST",
                                    ))
                                    if abs_ep not in visited:
                                        await queue.put((abs_ep, depth + 1))

                    except Exception as exc:
                        self.logger.debug(f"Crawl error for {url}: {exc}", module=self.config.name)
                finally:
                    active_workers -= 1
                    queue.task_done()

        # Run concurrent workers
        workers = [asyncio.create_task(worker()) for _ in range(CONCURRENCY)]
        await asyncio.gather(*workers, return_exceptions=True)

        # Batch insert all discovered records into SQLite
        if batch_urls:
            self.db.insert_urls_batch(batch_urls)
        if batch_apis:
            self.db.insert_api_endpoints_batch(batch_apis)

    async def _fetch_robots_and_sitemaps(self, client: httpx.AsyncClient, origin: str) -> list[str]:
        """Auto-seed crawl queue with endpoints from robots.txt and sitemap.xml."""
        discovered: list[str] = []
        for path in ("/robots.txt", "/sitemap.xml"):
            target_url = urljoin(origin, path)
            try:
                resp = await client.get(target_url, timeout=5.0)
                if resp.status_code == 200:
                    self.db.insert_url(URLRecord(
                        scan_id=self.scan_id,
                        url=target_url,
                        method="GET",
                        status_code=200,
                        source="crawler_seed",
                    ))
                    # Extract Disallow, Allow, Sitemap, and <loc>
                    matches = re.findall(r"(?:Disallow|Allow|Sitemap|loc):\s*([^\s<]+)", resp.text, re.IGNORECASE)
                    for link in matches:
                        if not link.strip() or link.strip() == "/":
                            continue
                        clean_link = link.strip()
                        full = urljoin(origin, clean_link) if clean_link.startswith("/") else clean_link
                        if full.startswith("http"):
                            discovered.append(full)
            except Exception:
                pass
        return discovered

    def _is_in_scope(self, url: str, base_domain: str) -> bool:
        """Verify URL belongs to the target domain or its subdomains."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            host = _normalize_host(parsed.netloc)
            return host == base_domain or host.endswith(f".{base_domain}")
        except Exception:
            return False
