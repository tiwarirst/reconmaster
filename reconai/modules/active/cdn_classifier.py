"""CDN & Origin Infrastructure Classifier Module.

Performs zero-cost, high-speed in-memory IP classification by matching discovered
IP addresses against known public CIDR ranges for major Content Delivery Networks (CDNs)
and cloud proxies:
  - Cloudflare
  - AWS CloudFront
  - Fastly
  - Akamai
  - Azure Front Door / Edge

Classifies whether an IP is a reverse-proxy CDN edge (shielded by WAF/DDoS protection)
or a direct Origin host. Updates IP records in the database with provider tags.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from reconai.core.database.models import TechnologyRecord
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

# Known public CDN IPv4 subnets
_CDN_SUBNETS: dict[str, list[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "AWS CloudFront": [
        "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15", "54.192.0.0/16",
        "54.230.0.0/16", "54.239.128.0/18", "54.239.192.0/19", "54.240.128.0/18",
        "99.84.0.0/16", "99.86.0.0/16", "130.176.0.0/16", "204.246.164.0/22",
        "205.251.200.0/21", "205.251.208.0/21", "205.251.216.0/22",
    ],
    "Fastly": [
        "151.101.0.0/16", "199.232.0.0/16", "146.75.0.0/16", "167.82.0.0/16",
    ],
    "Akamai": [
        "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11", "104.64.0.0/10",
        "184.84.0.0/14", "184.24.0.0/13", "96.16.0.0/15",
    ],
    "Azure Front Door": [
        "13.107.246.0/24", "13.107.213.0/24", "199.27.128.0/21", "204.79.197.0/24",
    ],
}

# Pre-compile IP networks for fast lookup
_COMPILED_CDN_NETWORKS: list[tuple[str, list[ipaddress.IPv4Network]]] = [
    (provider, [ipaddress.ip_network(cidr) for cidr in cidrs])
    for provider, cidrs in _CDN_SUBNETS.items()
]


@register_module
class CDNClassifierModule(ReconModule):
    config = ModuleConfig(
        name="cdn_classifier",
        category="active",
        description="Classifies discovered IPs as CDN edge proxies (Cloudflare, CloudFront, Fastly) or Direct Origin.",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        ip_records = self.db.get_ips(self.scan_id)
        if not ip_records:
            return

        self.logger.module_start(self.config.name, target=f"{len(ip_records)} IP(s)")

        cdn_count = 0
        origin_count = 0

        for record in ip_records:
            ip_str = record.get("ip", "")
            if not ip_str:
                continue

            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            matched_cdn: str | None = None
            for provider, networks in _COMPILED_CDN_NETWORKS:
                for net in networks:
                    if ip_obj in net:
                        matched_cdn = provider
                        break
                if matched_cdn:
                    break

            if matched_cdn:
                cdn_count += 1
                self.logger.info(
                    f"[CDN] IP {ip_str} is a {matched_cdn} CDN Edge Proxy",
                    module=self.config.name,
                )

                # Record technology
                tech = TechnologyRecord(
                    scan_id=self.scan_id,
                    host=ip_str,
                    name=f"{matched_cdn} CDN/WAF",
                    category="cdn_proxy",
                    confidence=1.0,
                    source=self.config.name,
                    evidence=[f"IP {ip_str} matches known {matched_cdn} CIDR range"],
                )
                self.db.insert_technology(tech)

                # Update IP record asn_org with the CDN provider if currently unset
                try:
                    self.db.conn.execute(
                        "UPDATE ips SET asn_org = ? WHERE scan_id = ? AND ip = ? AND (asn_org = '' OR asn_org IS NULL)",
                        (f"{matched_cdn} CDN Proxy", self.scan_id, ip_str),
                    )
                    self.db.conn.commit()
                except Exception:
                    pass
            else:
                origin_count += 1

        self.logger.info(
            f"[CDN] Classification complete: {cdn_count} CDN Edge IP(s), {origin_count} Direct Origin IP(s)",
            module=self.config.name,
        )
        self.logger.module_complete(self.config.name)
