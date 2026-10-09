"""cloud_enum tool integration adapter.

Adapter for the `cloud_enum` Python CLI tool:
  https://github.com/initstring/cloud_enum

  pip install cloud-enum

Follows the exact adapter pattern used by NucleiAdapter, FFuFAdapter, etc.
All state is isolated per call — no shared mutable state.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reconai.core.database.models import CloudAssetRecord
from reconai.core.executor.command_runner import CommandRunner
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class CloudEnumAdapter(ToolAdapter):
    """Adapter for the cloud_enum CLI tool."""

    name = "cloud_enum"

    def __init__(self, runner: CommandRunner) -> None:
        super().__init__(runner)
        self.binary_name = "cloud_enum"

    async def is_available(self) -> bool:
        """Check if cloud_enum or cloud-enum is installed and callable."""
        for binary in ("cloud_enum", "cloud-enum"):
            available, _ = await self.runner.check_tool(binary)
            if available:
                self.binary_name = binary
                return True
        return False

    def build_command(
        self,
        keyword: str,
        output_file: Path | None = None,
        extra_keywords: list[str] | None = None,
        mutations_file: Path | None = None,
    ) -> list[str]:
        """Build the cloud_enum command.

        Args:
            keyword:         Primary keyword to search (e.g., target domain label)
            output_file:     Optional path to save raw output
            extra_keywords:  Additional keywords to search (e.g., company abbreviation)
            mutations_file:  Custom mutations wordlist
        """
        cmd = [
            self.binary_name,
            "-k", keyword,
        ]

        if extra_keywords:
            for kw in extra_keywords:
                cmd.extend(["-k", kw])

        if output_file:
            cmd.extend(["-l", str(output_file)])

        if mutations_file and mutations_file.exists():
            cmd.extend(["-m", str(mutations_file)])

        # Use all three cloud providers
        # (default behaviour of cloud_enum — no flag needed)

        return cmd

    def parse_output_file(
        self,
        output_file: Path,
        scan_id: str,
        source: str = "cloud_enum_tool",
    ) -> list[CloudAssetRecord]:
        """Parse cloud_enum output file into CloudAssetRecord objects.

        cloud_enum writes one URL per line in its output file.
        Lines starting with [*], [+], or [-] are status messages.
        Actual resource URLs start with http.

        Example output:
          [+] Checking for AWS resources
          [*] https://target-backup.s3.amazonaws.com (OPEN - AuthorizedOpenBucket)
          [*] https://target-dev.azurewebsites.net (CLOSED)
        """
        records: list[CloudAssetRecord] = []

        if not output_file.exists():
            return records

        try:
            content = output_file.read_text(errors="ignore")
        except Exception:
            return records

        for line in content.splitlines():
            line = line.strip()

            # Extract URLs from output lines
            url_match = re.search(r"(https?://[^\s\)]+)", line)
            if not url_match:
                continue

            url = url_match.group(1).rstrip(".,;")

            # Parse status from the line
            is_public = any(
                marker in line for marker in [
                    "OPEN", "AuthorizedOpenBucket", "PublicAccessEnabled",
                    "AllowPublicAccess", "public",
                ]
            )

            provider = _infer_provider(url)
            asset_type = _infer_asset_type(url)

            record = CloudAssetRecord(
                scan_id=scan_id,
                provider=provider,
                asset_type=asset_type,
                asset_name=_extract_resource_name(url),
                url=url,
                is_public=is_public,
                is_writable=False,  # cloud_enum doesn't check write access
                region=_infer_region(url),
                metadata={"raw_line": line[:200]},
                source=source,
            )
            records.append(record)

        return records

    def parse(self, result: CommandResult) -> list[Any]:
        """Required by ToolAdapter — cloud_enum writes to a file; use parse_output_file()."""
        return []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _infer_provider(url: str) -> str:
    url = url.lower()
    if "amazonaws.com" in url:
        return "aws"
    if "googleapis.com" in url or "appspot.com" in url:
        return "gcp"
    if "windows.net" in url or "azure.com" in url or "azurewebsites.net" in url:
        return "azure"
    if "herokuapp.com" in url:
        return "heroku"
    if "netlify" in url:
        return "netlify"
    if "vercel.app" in url or "now.sh" in url:
        return "vercel"
    if "github.io" in url:
        return "github"
    if "pages.dev" in url:
        return "cloudflare"
    return "unknown"


def _infer_asset_type(url: str) -> str:
    url = url.lower()
    if "s3" in url and "amazonaws" in url:
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
    if "github.io" in url:
        return "github_pages"
    if "netlify" in url:
        return "netlify_site"
    if "vercel.app" in url:
        return "vercel_deployment"
    if "pages.dev" in url:
        return "cloudflare_pages"
    return "cloud_service"


def _infer_region(url: str) -> str:
    """Extract cloud region from URL if embedded (e.g., s3.us-east-1.amazonaws.com)."""
    # AWS regional endpoints: bucket.s3.us-east-1.amazonaws.com
    aws_region = re.search(
        r"s3[.-](us|eu|ap|ca|sa|me|af)-[a-z]+-\d+\.amazonaws\.com", url
    )
    if aws_region:
        return aws_region.group(0).split("s3.")[-1].split(".amazonaws")[0]

    # Azure: storage account regions are not in URL — return global
    return "global"


def _extract_resource_name(url: str) -> str:
    """Extract the resource name from a cloud URL.

    Examples:
      https://my-bucket.s3.amazonaws.com → my-bucket
      https://storage.googleapis.com/my-bucket → my-bucket
      https://myaccount.blob.core.windows.net → myaccount
    """
    url = url.rstrip("/")
    # S3-style: bucket.s3.amazonaws.com
    s3_match = re.match(r"https?://([^.]+)\.s3(?:\.[^.]+)?\.amazonaws\.com", url)
    if s3_match:
        return s3_match.group(1)
    # GCS path-style: storage.googleapis.com/bucket
    gcs_match = re.match(r"https?://storage\.googleapis\.com/([^/]+)", url)
    if gcs_match:
        return gcs_match.group(1)
    # Azure: account.blob.core.windows.net
    azure_match = re.match(r"https?://([^.]+)\.blob\.core\.windows\.net", url)
    if azure_match:
        return azure_match.group(1)
    # Generic: use the first subdomain
    generic = re.match(r"https?://([^./]+)", url)
    if generic:
        return generic.group(1)
    return url
