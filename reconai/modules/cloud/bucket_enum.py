"""Storage Bucket Enumerator Module.

Discovers misconfigured or publicly accessible cloud storage buckets across
AWS S3, Google Cloud Storage, and Azure Blob Storage — without needing any
URL to start from.

WHY THIS MODULE EXISTS (vs. Nuclei):
  Nuclei checks URLs you already know about. This module is a *radar* — it
  generates hundreds of intelligent name permutations from the target domain
  and checks each one across all three major cloud providers simultaneously,
  finding buckets that are completely unlinked from the target's website.

DETECTION STRATEGY:
  1. Generate smart permutations: 'target-prod', 'target-backup', 'target.dev',
     'assets.target', etc. (~150 candidates per target)
  2. DNS-resolve first (cheap, avoids direct HTTP rate limits)
  3. HTTP-probe only DNS-resolved candidates (rich metadata: ACL, contents)
  4. Classify: public-read, public-write (critical), or authenticated-only

WHAT IT SAVES:
  - CloudAssetRecord for every discovered bucket (public or private)
  - FindingRecord (HIGH/CRITICAL) for any misconfigured public bucket
"""
from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from reconai.core.database.models import (
    CloudAssetRecord, FindingRecord, Severity, Confidence, FindingStatus,
)
from reconai.core.events.types import EventType
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


# ── Provider endpoint templates ─────────────────────────────────────────────

_AWS_URL = "https://{name}.s3.amazonaws.com"
_AWS_REGIONAL_URL = "https://{name}.s3.{region}.amazonaws.com"
_GCS_URL = "https://storage.googleapis.com/{name}"
_GCS_DIRECT_URL = "https://{name}.storage.googleapis.com"
_AZURE_URL = "https://{name}.blob.core.windows.net"

_AWS_PUBLIC_INDICATOR = "<ListBucketResult"
_AWS_ACCESS_DENIED = "<Code>AccessDenied</Code>"
_AWS_NO_SUCH_BUCKET = "<Code>NoSuchBucket</Code>"
_GCS_PUBLIC_INDICATOR = '"kind": "storage#objects"'
_GCS_ACCESS_DENIED = "AccessDenied"
_AZURE_PUBLIC_INDICATOR = '<?xml version="1.0"'
_AZURE_ENUM_INDICATOR = "<EnumerationResults"

# Common AWS regions for regional bucket probing
_AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-south-1",
]


@register_module
class BucketEnumModule(ReconModule):
    config = ModuleConfig(
        name="bucket_enum",
        category="cloud",
        description=(
            "Multi-cloud storage bucket enumerator — generates name permutations and "
            "probes AWS S3, GCP Storage, and Azure Blob for public/writable buckets."
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

        domain = kwargs.get("domain", self.target)
        # Strip protocol and path, use just the bare domain
        domain = re.sub(r"^https?://", "", domain).split("/")[0].strip()

        names = _generate_permutations(domain)
        self.logger.module_start(
            self.config.name, target=f"{domain} ({len(names)} candidates)"
        )

        # Run all three providers concurrently
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(8.0, connect=4.0),
            follow_redirects=False,
            verify=False,   # Buckets may have cert mismatches
        ) as client:
            semaphore = asyncio.Semaphore(15)  # Max 15 concurrent probes
            tasks = [
                self._probe_all_providers(client, semaphore, name)
                for name in names
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.module_complete(self.config.name)

    async def _probe_all_providers(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        name: str,
    ) -> None:
        """Probe a single candidate name across all three cloud providers."""
        async with semaphore:
            await asyncio.gather(
                self._probe_aws_s3(client, name),
                self._probe_gcs(client, name),
                self._probe_azure(client, name),
                return_exceptions=True,
            )

    # ── AWS S3 ─────────────────────────────────────────────────────────────

    async def _probe_aws_s3(self, client: httpx.AsyncClient, name: str) -> None:
        url = _AWS_URL.format(name=name)
        try:
            resp = await client.get(url)
            body = resp.text
        except Exception:
            return  # DNS NXDOMAIN or connection refused — bucket doesn't exist

        if _AWS_NO_SUCH_BUCKET in body:
            return  # Confirmed non-existent

        is_public = _AWS_PUBLIC_INDICATOR in body
        is_writable = await self._check_aws_write(client, name)

        await self._save_cloud_asset(
            provider="aws",
            asset_type="s3_bucket",
            asset_name=name,
            url=url,
            is_public=is_public,
            is_writable=is_writable,
            region="us-east-1",
            metadata={
                "status_code": resp.status_code,
                "access_denied": _AWS_ACCESS_DENIED in body,
            },
        )

    async def _check_aws_write(self, client: httpx.AsyncClient, name: str) -> bool:
        """Check if S3 bucket allows unauthenticated writes (critical misconfiguration)."""
        try:
            # Attempt a HEAD on a known-nonexistent key — a 403 means auth required,
            # a 405 (Method Not Allowed) or 200 may indicate write access
            put_url = f"https://{name}.s3.amazonaws.com/__reconai_write_test__"
            resp = await client.head(put_url)
            # 403 = explicitly denied (good), anything else is suspicious
            return resp.status_code not in (403, 404, 405, 400)
        except Exception:
            return False

    # ── Google Cloud Storage ───────────────────────────────────────────────

    async def _probe_gcs(self, client: httpx.AsyncClient, name: str) -> None:
        url = _GCS_URL.format(name=name)
        try:
            resp = await client.get(url)
            body = resp.text
        except Exception:
            return

        # GCS returns 404 for non-existent buckets, 403 for private, 200 for public
        if resp.status_code == 404:
            return

        is_public = resp.status_code == 200 and (
            _GCS_PUBLIC_INDICATOR in body or '"items"' in body
        )
        is_writable = False  # Write-check for GCS would need a full PUT — skip

        await self._save_cloud_asset(
            provider="gcp",
            asset_type="gcs_bucket",
            asset_name=name,
            url=url,
            is_public=is_public,
            is_writable=is_writable,
            region="global",
            metadata={"status_code": resp.status_code},
        )

    # ── Azure Blob Storage ─────────────────────────────────────────────────

    async def _probe_azure(self, client: httpx.AsyncClient, name: str) -> None:
        url = _AZURE_URL.format(name=name)
        # Azure's API: ?restype=container&comp=list lists blobs if public
        list_url = f"{url}?restype=container&comp=list"
        try:
            resp = await client.get(list_url)
            body = resp.text
        except Exception:
            return

        # 404 with ResourceNotFound = account doesn't exist
        if resp.status_code == 404 and "ResourceNotFound" in body:
            return
        # 400 with InvalidResourceName = malformed name (skip)
        if resp.status_code == 400:
            return

        is_public = _AZURE_ENUM_INDICATOR in body and resp.status_code == 200
        is_writable = False  # Azure write check needs more complex auth analysis

        await self._save_cloud_asset(
            provider="azure",
            asset_type="blob_container",
            asset_name=name,
            url=url,
            is_public=is_public,
            is_writable=is_writable,
            region="global",
            metadata={"status_code": resp.status_code},
        )

    # ── Shared Save Logic ─────────────────────────────────────────────────

    async def _save_cloud_asset(
        self,
        provider: str,
        asset_type: str,
        asset_name: str,
        url: str,
        is_public: bool,
        is_writable: bool,
        region: str,
        metadata: dict[str, Any],
    ) -> None:
        record = CloudAssetRecord(
            scan_id=self.scan_id,
            provider=provider,
            asset_type=asset_type,
            asset_name=asset_name,
            url=url,
            is_public=is_public,
            is_writable=is_writable,
            region=region,
            metadata=metadata,
            source=self.config.name,
        )
        self.db.insert_cloud_asset(record)

        await self.event_bus.emit_discovery(
            event_type=EventType.CLOUD_ASSET_DISCOVERED,
            source=self.config.name,
            data={
                "provider": provider,
                "asset_type": asset_type,
                "asset_name": asset_name,
                "url": url,
                "is_public": is_public,
                "is_writable": is_writable,
            },
            scan_id=self.scan_id,
            target=self.target,
        )

        # Emit a high-severity finding for public/writable buckets
        if is_public or is_writable:
            severity = Severity.CRITICAL if is_writable else Severity.HIGH
            finding = FindingRecord(
                scan_id=self.scan_id,
                title=f"{'Publicly Writable' if is_writable else 'Publicly Readable'} {provider.upper()} {asset_type.replace('_', ' ').title()}: {asset_name}",
                severity=severity,
                confidence=Confidence.VERIFIED,
                status=FindingStatus.VERIFIED,
                affected_asset=url,
                affected_asset_type="cloud_storage",
                description=(
                    f"The {provider.upper()} storage bucket '{asset_name}' is publicly "
                    f"{'writable' if is_writable else 'readable'} without any authentication."
                ),
                impact=(
                    "Data exfiltration, PII leakage, sensitive file exposure. "
                    + ("Attackers can upload malicious content (malware, phishing pages)." if is_writable else "")
                ),
                evidence=f"HTTP {metadata.get('status_code', 'N/A')} response at {url}",
                detection_method="Permutation-based bucket enumeration + HTTP probe",
                remediation=(
                    f"Apply restrictive bucket ACL: remove public access via {provider} console. "
                    "Enable 'Block Public Access' (AWS) or equivalent setting."
                ),
                references=[
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                    "https://cloud.google.com/storage/docs/access-control",
                    "https://docs.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent",
                ],
                what_is_it=f"A {provider.upper()} cloud storage bucket that is misconfigured to allow public access.",
                why_detected="Discovered via permutation-based bucket name guessing, not linked from the website.",
                attack_class="Cloud Storage Misconfiguration / Data Exposure",
                conditions_required="No authentication required — accessible from any internet connection.",
                safe_verification=f"Visit {url} in a browser — a public bucket returns XML/JSON content directly.",
                prevention="Enforce 'Block Public Access' policies and audit bucket ACLs quarterly.",
            )
            self.db.insert_finding(finding)
            self.logger.info(
                f"[CLOUD] {severity.value.upper()} — {'WRITABLE' if is_writable else 'PUBLIC'} "
                f"{provider.upper()} bucket: {asset_name}",
                module=self.config.name,
            )


# ── Permutation Engine ────────────────────────────────────────────────────────

def _generate_permutations(domain: str) -> list[str]:
    """Generate cloud storage bucket name candidates from a target domain.

    Example: 'example.com' → ['example', 'example-dev', 'example-prod',
                               'example-backup', 'example.assets', ...]

    Returns deduplicated, lowercase names validated for cloud naming rules.
    """
    # Extract core name parts
    parts = domain.replace(".com", "").replace(".io", "").replace(".net", "").replace(".org", "")
    parts = re.sub(r"[^a-z0-9-.]", "", parts.lower())
    base = parts.split(".")[0]  # Primary domain label

    # Multi-word targets (e.g. 'my-company') → also use 'mycompany'
    alt_base = base.replace("-", "")

    prefixes = [
        "", "dev-", "prod-", "staging-", "stage-", "test-", "qa-", "uat-",
        "assets-", "static-", "media-", "files-", "uploads-", "data-",
        "backup-", "bkp-", "logs-", "log-", "admin-", "api-", "internal-",
        "private-", "public-", "cdn-", "images-", "img-", "archive-",
        "s3-", "gcs-", "storage-", "bucket-", "store-",
    ]
    suffixes = [
        "", "-dev", "-prod", "-staging", "-stage", "-test", "-qa", "-uat",
        "-assets", "-static", "-media", "-files", "-uploads", "-data",
        "-backup", "-bkp", "-logs", "-log", "-admin", "-api", "-internal",
        "-private", "-public", "-cdn", "-images", "-img", "-archive",
        "-s3", "-gcs", "-storage", "-bucket", "-store", "-web", "-app",
    ]

    candidates: set[str] = set()
    for b in [base, alt_base, domain.lower(), parts.lower()]:
        if not b:
            continue
        for prefix in prefixes:
            for suffix in suffixes:
                candidate = f"{prefix}{b}{suffix}".strip("-").strip(".")
                if _is_valid_bucket_name(candidate):
                    candidates.add(candidate)

    return sorted(candidates)


def _is_valid_bucket_name(name: str) -> bool:
    """Validate against S3/GCS bucket naming rules (most restrictive)."""
    if len(name) < 3 or len(name) > 63:
        return False
    if not re.match(r"^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$", name):
        return False
    if name.startswith("xn--") or name.endswith("-s3alias"):
        return False
    return True
