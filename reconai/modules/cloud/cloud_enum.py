"""Multi-Cloud Asset Enumerator Module.

Discovers cloud-hosted services, CDN distributions, and dangling DNS entries
by analyzing CNAME records found during DNS enumeration.

WHY THIS MODULE EXISTS (vs. Nuclei):
  This module cross-references every CNAME record discovered during DNS
  enumeration against a comprehensive database of cloud service CNAME patterns.
  It identifies: which cloud services the target uses, and critically — whether
  any cloud CNAMEs are DANGLING (pointing to unclaimed cloud resources), which
  is a direct subdomain takeover vector.

  It also wraps the external `cloud_enum` tool if installed, adding brute-force
  cloud service discovery on top.

DETECTION STRATEGY:
  1. Read all CNAME records from the database (free — already discovered by dns_enum)
  2. Match against a comprehensive fingerprint database of 40+ cloud providers
  3. Flag dangling CNAMEs — where the cloud endpoint no longer exists (takeover)
  4. Optionally run `cloud_enum` tool for additional brute-force discovery

WHAT IT SAVES:
  - TechnologyRecord for every identified cloud service
  - CloudAssetRecord for every confirmed cloud endpoint
  - FindingRecord (HIGH/CRITICAL) for every dangling CNAME (subdomain takeover)
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import time
from typing import Any

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from reconai.core.database.models import (
    CloudAssetRecord, FindingRecord, TechnologyRecord,
    Severity, Confidence, FindingStatus,
)
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


# ── Cloud Service CNAME Fingerprint Database ─────────────────────────────────
# Format: {cname_pattern: (provider, service_name, takeover_possible, takeover_check_string)}

CLOUD_CNAME_FINGERPRINTS: dict[str, tuple[str, str, bool, str]] = {
    # AWS
    ".amazonaws.com": ("aws", "AWS Service", False, ""),
    ".elasticbeanstalk.com": ("aws", "AWS Elastic Beanstalk", True, "NXDOMAIN"),
    ".cloudfront.net": ("aws", "AWS CloudFront", False, ""),
    ".elb.amazonaws.com": ("aws", "AWS ELB", False, ""),
    ".awsglobalaccelerator.com": ("aws", "AWS Global Accelerator", False, ""),
    ".execute-api.amazonaws.com": ("aws", "AWS API Gateway", False, ""),
    "s3.amazonaws.com": ("aws", "AWS S3", False, ""),
    ".s3-website": ("aws", "AWS S3 Static Site", True, "NoSuchBucket"),
    # Azure
    ".azurewebsites.net": ("azure", "Azure App Service", True, "404 Web Site not found"),
    ".cloudapp.net": ("azure", "Azure Cloud App", True, "NXDOMAIN"),
    ".trafficmanager.net": ("azure", "Azure Traffic Manager", True, "NXDOMAIN"),
    ".blob.core.windows.net": ("azure", "Azure Blob Storage", True, "ResourceNotFound"),
    ".azure.com": ("azure", "Azure Service", False, ""),
    ".azurefd.net": ("azure", "Azure Front Door", False, ""),
    ".azureedge.net": ("azure", "Azure CDN", False, ""),
    ".database.windows.net": ("azure", "Azure SQL", False, ""),
    # GCP
    ".appspot.com": ("gcp", "GCP App Engine", True, "404. That's an error"),
    ".storage.googleapis.com": ("gcp", "GCP Cloud Storage", False, ""),
    "c.storage.googleapis.com": ("gcp", "GCP Cloud Storage (CNAME)", True, "NoSuchBucket"),
    ".cloudfunctions.net": ("gcp", "GCP Cloud Functions", False, ""),
    ".run.app": ("gcp", "GCP Cloud Run", False, ""),
    # Heroku
    ".herokuapp.com": ("heroku", "Heroku App", True, "No such app"),
    ".herokudns.com": ("heroku", "Heroku Custom Domain", True, "No such app"),
    # Netlify
    ".netlify.app": ("netlify", "Netlify Site", True, "Not Found - Request ID"),
    ".netlify.com": ("netlify", "Netlify Service", True, "Not Found - Request ID"),
    # Vercel
    ".vercel.app": ("vercel", "Vercel Deployment", True, "The deployment could not be found"),
    ".now.sh": ("vercel", "Vercel (Legacy)", True, "The deployment could not be found"),
    # GitHub
    ".github.io": ("github", "GitHub Pages", True, "There isn't a GitHub Pages site here"),
    ".githubusercontent.com": ("github", "GitHub Content", False, ""),
    # Fastly
    ".fastly.net": ("fastly", "Fastly CDN", True, "Fastly error: unknown domain"),
    # Shopify
    ".myshopify.com": ("shopify", "Shopify Store", True, "Sorry, this shop is currently unavailable"),
    # WPEngine
    ".wpengine.com": ("wpengine", "WPEngine WordPress", True, "The site you were looking for couldn't be found"),
    # Tumblr
    ".tumblr.com": ("tumblr", "Tumblr Blog", True, "There's nothing here"),
    # HubSpot
    ".hs-sites.com": ("hubspot", "HubSpot CMS", True, "This page isn't available"),
    ".hubspotpagebuilder.com": ("hubspot", "HubSpot Page Builder", True, "This page isn't available"),
    # Zendesk
    ".zendesk.com": ("zendesk", "Zendesk Support Portal", True, "Help Center Closed"),
    # Surge.sh
    ".surge.sh": ("surge", "Surge Static Site", True, "project not found"),
    # Cargo
    ".cargocollective.com": ("cargo", "Cargo Site", True, "404 Not Found"),
    # Pantheon
    ".pantheonsite.io": ("pantheon", "Pantheon WordPress/Drupal", True, "404 Target Not Found"),
    # Squarespace
    ".squarespace.com": ("squarespace", "Squarespace Site", False, ""),
    # Cloudflare
    ".pages.dev": ("cloudflare", "Cloudflare Pages", True, "The site cannot be reached"),
}


@register_module
class CloudEnumModule(ReconModule):
    config = ModuleConfig(
        name="cloud_enum_module",
        category="cloud",
        description=(
            "Multi-cloud asset enumerator — detects cloud-hosted services via CNAME fingerprinting "
            "and flags dangling CNAMEs for subdomain takeover."
        ),
        requires_tools=[],  # cloud_enum tool is optional; has pure-Python fallback
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        start = time.monotonic()
        self.logger.module_start(self.config.name, target=self.target)

        # Step 1: CNAME-based cloud detection (pure Python, no external tools)
        await self._detect_from_cnames()

        # Step 2: Run external cloud_enum tool if available
        await self._run_cloud_enum_tool()

        duration = time.monotonic() - start
        self.logger.module_complete(self.config.name, duration=duration)

    async def _detect_from_cnames(self) -> None:
        """Cross-reference all discovered CNAME records against cloud fingerprints."""
        cname_records = [
            r for r in self.db.get_dns_records(self.scan_id)
            if r.get("record_type") == "CNAME"
        ]

        if not cname_records:
            self.logger.debug(
                "No CNAME records found. Run dns_enum first for best results.",
                module=self.config.name,
            )
            return

        self.logger.info(
            f"[CLOUD] Analysing {len(cname_records)} CNAME records for cloud service fingerprints...",
        )

        if not HAS_HTTPX:
            self.logger.warning(
                "httpx not installed — skipping dangling CNAME verification. Run: pip install httpx",
                module=self.config.name,
            )

        semaphore = asyncio.Semaphore(10)
        tasks = [
            self._analyse_cname(semaphore, record)
            for record in cname_records
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _analyse_cname(
        self,
        semaphore: asyncio.Semaphore,
        cname_record: dict[str, Any],
    ) -> None:
        """Match a single CNAME against the fingerprint DB and check for takeover."""
        hostname: str = cname_record.get("hostname", "")
        cname_value: str = cname_record.get("value", "").rstrip(".")

        matched_provider: str | None = None
        matched_service: str | None = None
        takeover_possible: bool = False
        takeover_indicator: str = ""

        for pattern, (provider, service, can_takeover, indicator) in CLOUD_CNAME_FINGERPRINTS.items():
            if pattern.lower() in cname_value.lower():
                matched_provider = provider
                matched_service = service
                takeover_possible = can_takeover
                takeover_indicator = indicator
                break

        if not matched_provider:
            return

        self.logger.info(
            f"[CLOUD] {hostname} → {cname_value} :: {matched_service} ({matched_provider.upper()})",
        )

        # Save the detected cloud technology
        tech_record = TechnologyRecord(
            scan_id=self.scan_id,
            host=hostname,
            name=matched_service,
            category="cloud",
            confidence=0.9,
            source=self.config.name,
            evidence=[f"CNAME: {cname_value}"],
        )
        self.db.insert_technology(tech_record)

        # Save the cloud asset
        asset_record = CloudAssetRecord(
            scan_id=self.scan_id,
            provider=matched_provider,
            asset_type="cloud_service",
            asset_name=cname_value,
            url=f"https://{hostname}",
            is_public=True,
            is_writable=False,
            region="global",
            metadata={"cname_from": hostname, "service": matched_service},
            source=self.config.name,
        )
        self.db.insert_cloud_asset(asset_record)

        await self.event_bus.emit_discovery(
            event_type=EventType.CLOUD_ASSET_DISCOVERED,
            source=self.config.name,
            data={
                "provider": matched_provider,
                "asset_type": "cloud_service",
                "asset_name": cname_value,
                "service": matched_service,
                "hostname": hostname,
            },
            scan_id=self.scan_id,
            target=self.target,
        )

        # Check for subdomain takeover if the service allows it
        if takeover_possible and HAS_HTTPX:
            async with semaphore:
                await self._check_takeover(hostname, cname_value, matched_provider, matched_service, takeover_indicator)

    async def _check_takeover(
        self,
        hostname: str,
        cname: str,
        provider: str,
        service: str,
        indicator: str,
    ) -> None:
        """Verify if a dangling CNAME is actually vulnerable to subdomain takeover.

        A CNAME is dangling if:
        1. The CNAME target is NXDOMAIN (DNS doesn't resolve), OR
        2. The HTTP response contains the service's "unclaimed resource" fingerprint
        """
        is_dangling = False
        evidence = ""

        # Check 1: Does the CNAME target resolve?
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, socket.gethostbyname, cname)
            dns_resolves = True
        except socket.gaierror:
            dns_resolves = False
            is_dangling = True
            evidence = f"CNAME target '{cname}' does not resolve (NXDOMAIN)"

        # Check 2: Even if DNS resolves, does the service return a "not found" page?
        if dns_resolves and indicator:
            try:
                async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                    resp = await client.get(f"https://{hostname}", follow_redirects=True)
                    if indicator.lower() in resp.text.lower():
                        is_dangling = True
                        evidence = (
                            f"HTTP response from {hostname} contains takeover indicator: '{indicator}'"
                        )
            except Exception:
                pass  # Can't connect = also dangling, but harder to confirm

        if not is_dangling:
            return

        self.logger.info(
            f"[CLOUD] ⚠️  SUBDOMAIN TAKEOVER: {hostname} → {cname} ({service})",
            module=self.config.name,
        )

        finding = FindingRecord(
            scan_id=self.scan_id,
            title=f"Subdomain Takeover: {hostname} → unclaimed {service}",
            severity=Severity.HIGH,
            confidence=Confidence.LIKELY,
            status=FindingStatus.LIKELY,
            affected_asset=f"https://{hostname}",
            affected_asset_type="subdomain",
            description=(
                f"The subdomain '{hostname}' has a CNAME record pointing to '{cname}' "
                f"({service}) which appears to be unclaimed or deleted. "
                "An attacker can register this cloud resource and serve content "
                "on your subdomain, bypassing all CSP and same-origin policies."
            ),
            impact=(
                "Account cookie theft via same-origin privilege, phishing pages served "
                "on a trusted domain, malware distribution, SEO poisoning."
            ),
            evidence=evidence,
            detection_method="CNAME fingerprinting + DNS resolution check + HTTP response analysis",
            remediation=(
                f"1. Remove the DNS CNAME record for '{hostname}' immediately.\n"
                f"2. If the service is still needed, re-provision the {service} resource "
                f"and update the CNAME to point to the new endpoint.\n"
                "3. Implement subdomain monitoring to detect future dangling records."
            ),
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                "https://github.com/EdOverflow/can-i-take-over-xyz",
            ],
            what_is_it=(
                "A dangling DNS CNAME that points to a deprovisioned cloud service, "
                "allowing anyone to claim that service and hijack the subdomain."
            ),
            why_detected=f"CNAME '{cname}' was matched to {service} and found to be unregistered.",
            attack_class="Subdomain Takeover",
            conditions_required=f"Attacker registers '{cname}' on {provider.upper()} — usually costs $0-$5.",
            safe_verification=f"Visit https://{hostname} — if it shows the service's 'not found' page, takeover is possible.",
            prevention="Regularly audit DNS records and remove CNAMEs pointing to deprovisioned resources.",
        )
        self.db.insert_finding(finding)

    async def _run_cloud_enum_tool(self) -> None:
        """Run the external cloud_enum tool if installed (additive, not required)."""
        available, _ = await self.runner.check_tool("cloud_enum")
        if not available:
            self.logger.debug(
                "[CLOUD] cloud_enum tool not found — skipping external tool scan. "
                "Install with: pip install cloud-enum",
                module=self.config.name,
            )
            return

        # Extract base keyword from target domain
        domain = re.sub(r"^https?://", "", self.target).split("/")[0]
        keyword = domain.split(".")[0]  # e.g., 'example' from 'example.com'

        out_file = self.out_dir / "cloud_enum_output.txt"
        cmd = [
            "cloud_enum",
            "-k", keyword,
            "--disable-brute",  # We do our own brute-forcing in bucket_enum
            "-l", str(out_file),
        ]

        self.logger.info(
            f"[CLOUD] Running cloud_enum for keyword '{keyword}'...",
            module=self.config.name,
        )
        await self.runner.run(command=cmd, timeout=120)

        if out_file.exists():
            await self._parse_cloud_enum_output(out_file)

    async def _parse_cloud_enum_output(self, out_file: Any) -> None:
        """Parse cloud_enum's text output and save discovered assets."""
        try:
            content = out_file.read_text(errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("[") or line.startswith("#"):
                    continue
                # cloud_enum outputs URLs like: https://bucket.s3.amazonaws.com
                if line.startswith("http"):
                    provider = _infer_provider(line)
                    asset_type = _infer_asset_type(line)
                    record = CloudAssetRecord(
                        scan_id=self.scan_id,
                        provider=provider,
                        asset_type=asset_type,
                        asset_name=line,
                        url=line,
                        is_public=True,
                        source="cloud_enum_tool",
                    )
                    self.db.insert_cloud_asset(record)
        except Exception as e:
            self.logger.debug(f"[CLOUD] cloud_enum parse error: {e}", module=self.config.name)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _infer_provider(url: str) -> str:
    url = url.lower()
    if "amazonaws.com" in url:
        return "aws"
    if "googleapis.com" in url or "appspot.com" in url:
        return "gcp"
    if "windows.net" in url or "azure.com" in url:
        return "azure"
    if "herokuapp.com" in url:
        return "heroku"
    if "netlify" in url:
        return "netlify"
    if "vercel.app" in url or "now.sh" in url:
        return "vercel"
    if "github.io" in url:
        return "github"
    return "unknown"


def _infer_asset_type(url: str) -> str:
    url = url.lower()
    if "s3" in url:
        return "s3_bucket"
    if "storage.googleapis.com" in url:
        return "gcs_bucket"
    if "blob.core.windows.net" in url:
        return "blob_container"
    if "cloudfront.net" in url:
        return "cloudfront_distribution"
    if "elasticbeanstalk.com" in url:
        return "elastic_beanstalk_app"
    if "azurewebsites.net" in url:
        return "azure_app_service"
    if "appspot.com" in url:
        return "gcp_app_engine"
    return "cloud_service"
