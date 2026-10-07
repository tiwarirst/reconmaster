"""Advanced Web Crawler & Attack Surface Spider Module.

Features:
- Multi-tier discovery: HTML links, forms, input parameters, scripts, and SPA routes.
- Form intelligence: extracts form fields and synthesizes parameterized endpoints.
- Single Page Application (SPA) endpoint miner: scans inline scripts and JSON blobs
  for REST API routes, GraphQL paths, and Fetch/Axios calls.
- Automated robots.txt and sitemap.xml seed ingestion.
- 401/403 access-control disclosure preservation (never drops protected paths).
- Path template deduplication (prevents pagination loops).
"""
from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from reconai.core.database.models import APIEndpoint, URLRecord
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

_RE_TITLE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_RE_API_PATH = re.compile(
    r'["\'](/(?:api|v[0-9]|rest|graphql|auth|admin|user|users|account|item|items|data|query|search|dashboard)[a-zA-Z0-9_\-\./?=&]*)["\']',
    re.IGNORECASE,
)
_RE_FETCH_AXIOS = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete)|\.open\s*\(\s*["\'](?:GET|POST)["\']\s*,)\s*\(?["\']([^"\'\s><)]+)["\']',
    re.IGNORECASE,
)
_RE_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_SENSITIVE_COMMENT_KEYWORDS = ("api", "key", "secret", "token", "admin", "internal", "todo", "debug", "password", "endpoint")

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
        description="Comprehensive web spider for links, forms, input parameters, scripts, and SPA routes",
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

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=12.0,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconAI-Spider/2.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        ) as client:
            tasks = [
                self._crawl_host(client, start_url, max_depth, max_pages_per_host)
                for start_url in unique_entry_points[:6]  # Concurrently crawl top 6 origins
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
        """Full breadth-first crawl of a target origin."""
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        parsed_start = urlparse(start_url)
        origin = f"{parsed_start.scheme}://{parsed_start.netloc}"
        start_base_domain = _normalize_host(parsed_start.netloc)

        # Template frequency tracking to avoid pagination traps
        template_counts: dict[str, int] = {}

        # Ingest robots.txt and sitemap.xml seeds
        seed_links = await self._fetch_robots_and_sitemaps(client, origin)
        for s in seed_links:
            if s not in visited:
                queue.append((s, 1))

        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()

            clean_url = url.split("#")[0]
            if clean_url in visited or depth > max_depth:
                continue

            parsed_url = urlparse(clean_url)
            tmpl = _path_template(parsed_url.path)
            if template_counts.get(tmpl, 0) >= 4:
                # Skip duplicate pattern beyond 4 instances
                continue

            visited.add(clean_url)
            template_counts[tmpl] = template_counts.get(tmpl, 0) + 1

            # Skip fetching binary static assets into the queue, but record them in DB
            path_lower = parsed_url.path.lower()
            if any(path_lower.endswith(ext) for ext in _STATIC_ASSET_EXTENSIONS):
                self.db.insert_url(URLRecord(
                    scan_id=self.scan_id,
                    url=clean_url,
                    method="GET",
                    status_code=200,
                    source="crawler_static",
                    depth=depth,
                ))
                continue

            try:
                response = await client.get(clean_url)
                content_type = response.headers.get("content-type", "")

                # Extract HTML title
                title = ""
                title_match = _RE_TITLE.search(response.text)
                if title_match:
                    title = title_match.group(1).strip()[:150]

                # Save URLRecord in DB (Preserve 200, 301, 302, 401, 403, 500)
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
                self.db.insert_url(record)

                if depth > 0:
                    await self.events.emit_discovery(
                        event_type=EventType.URL_DISCOVERED,
                        source=self.config.name,
                        data={"url": str(response.url), "status": response.status_code, "depth": depth},
                        scan_id=self.scan_id,
                        target=self.target,
                    )

                # If protected endpoint (401/403) or error (500), don't parse links
                if response.status_code >= 400:
                    continue

                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    continue

                html_text = response.text
                soup = BeautifulSoup(html_text, "html.parser")

                # 1. Process Standard Links (<a href>, <link href>, <iframe>)
                for tag in soup.find_all(["a", "link", "iframe", "area"]):
                    href = tag.get("href") or tag.get("src")
                    if not href:
                        continue
                    if isinstance(href, list):
                        href = href[0]
                    abs_url = urljoin(str(response.url), str(href)).split("#")[0]
                    if self._is_in_scope(abs_url, start_base_domain):
                        if abs_url not in visited:
                            queue.append((abs_url, depth + 1))

                # 2. Process Script Tags (<script src="...">)
                for script in soup.find_all("script"):
                    src = script.get("src")
                    if src:
                        if isinstance(src, list):
                            src = src[0]
                        abs_script = urljoin(str(response.url), str(src)).split("#")[0]
                        if abs_script.startswith("http"):
                            self.db.insert_url(URLRecord(
                                scan_id=self.scan_id,
                                url=abs_script,
                                method="GET",
                                source="crawler_script",
                                depth=depth + 1,
                            ))
                            if self._is_in_scope(abs_script, start_base_domain) and abs_script not in visited:
                                visited.add(abs_script)

                # 3. Process Forms & Parameter Extraction (<form action="..." method="...">)
                for form in soup.find_all("form"):
                    action = form.get("action") or ""
                    if isinstance(action, list):
                        action = action[0]
                    form_action = urljoin(str(response.url), str(action)).split("#")[0]
                    form_method = str(form.get("method", "GET")).upper()

                    # Extract input names
                    inputs = form.find_all(["input", "textarea", "select"])
                    param_names = [inp.get("name") for inp in inputs if inp.get("name")]

                    if param_names:
                        query_pairs = {str(name): "test" for name in param_names}
                        if form_method == "GET":
                            parsed_action = urlparse(form_action)
                            existing_q = dict(parse_qsl(parsed_action.query))
                            existing_q.update(query_pairs)
                            full_param_url = f"{parsed_action.scheme}://{parsed_action.netloc}{parsed_action.path}?{urlencode(existing_q)}"
                            
                            self.db.insert_url(URLRecord(
                                scan_id=self.scan_id,
                                url=full_param_url,
                                method="GET",
                                source="crawler_form",
                                depth=depth + 1,
                            ))
                            if full_param_url not in visited and self._is_in_scope(full_param_url, start_base_domain):
                                queue.append((full_param_url, depth + 1))
                        else:
                            # Record POST form as an API/endpoint record
                            self.db.insert_api_endpoint(APIEndpoint(
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
                        self.db.insert_api_endpoint(APIEndpoint(
                            scan_id=self.scan_id,
                            host=str(response.url),
                            method="GET",
                            path=urlparse(abs_ep).path or ep,
                            full_url=abs_ep,
                            source="crawler_spa",
                            api_type="REST",
                        ))
                        if abs_ep not in visited:
                            queue.append((abs_ep, depth + 1))

            except Exception as exc:
                self.logger.debug(f"Crawl error for {url}: {exc}", module=self.config.name)

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
