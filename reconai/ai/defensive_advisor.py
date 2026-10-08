"""AI WAF & Perimeter Evasion Strategy Advisor.

Analyzes detected Web Application Firewalls (WAFs), Content Delivery Networks (CDNs),
and discovered origin IP addresses to identify potential origin IP leaks (bypassing
cloud firewalls directly) and provides red team testing advisories.
"""
from __future__ import annotations

import json
from typing import Any

from reconai.ai.adapter import AIAdapter
from reconai.core.database.manager import DatabaseManager


class DefensiveAdvisor:
    """Advises on perimeter defenses, origin IP leakage, and safe testing pacing."""

    def __init__(self, db: DatabaseManager, scan_id: str, ai: AIAdapter | None = None) -> None:
        self.db = db
        self.scan_id = scan_id
        self.ai = ai

    async def analyze_perimeter_defenses(self) -> dict[str, Any]:
        """Examines detected WAFs, CDNs, and IP allocations."""
        techs = self.db.get_technologies(self.scan_id)
        ips = self.db.get_ips(self.scan_id)
        stats = self.db.get_scan_stats(self.scan_id)
        target = stats.get("target", "target.com")

        # 1. Detect WAF & CDN technologies
        waf_names = []
        for t in techs:
            name = str(t.get("name", "")).lower()
            cat = str(t.get("category", "")).lower()
            if any(k in name or k in cat for k in ["cloudflare", "akamai", "aws waf", "imperva", "sucuri", "waf", "cdn", "fastly"]):
                waf_names.append(t.get("name", ""))

        waf_names = list(dict.fromkeys(waf_names))

        # 2. Origin IP Leakage Analysis
        # If Cloudflare/Akamai is present, check if any IP has non-CDN ASN or exposes raw ports
        potential_origin_ips: list[dict[str, str]] = []
        for ip in ips:
            ip_str = ip.get("ip", "")
            asn_org = str(ip.get("asn_org", "")).lower()
            # If IP is not Cloudflare/Akamai/Fastly, it could be the genuine backend server!
            if waf_names and not any(c in asn_org for c in ["cloudflare", "akamai", "fastly"]):
                potential_origin_ips.append({
                    "ip": ip_str,
                    "asn_org": ip.get("asn_org", "Unknown"),
                    "note": "IP does not belong to the detected CDN provider ASN (potential origin backend)",
                })

        # 3. Strategy recommendations
        recommendations = self._generate_recommendations(waf_names, potential_origin_ips)

        # 4. AI Strategic Narrative
        narrative = await self._generate_ai_narrative(target, waf_names, potential_origin_ips, recommendations)

        return {
            "target": target,
            "detected_wafs": waf_names,
            "potential_origin_ips": potential_origin_ips,
            "recommendations": recommendations,
            "narrative_markdown": narrative,
        }

    def _generate_recommendations(
        self, waf_names: list[str], origin_ips: list[dict[str, str]]
    ) -> list[str]:
        """Generates defensive and offensive testing recommendations."""
        recs = []
        if origin_ips:
            recs.append(
                f"Origin IP Leakage Detected: Validate whether direct HTTP/HTTPS requests to {origin_ips[0]['ip']} "
                "reach the web application directly without traversing the cloud WAF."
            )
        if any("cloudflare" in w.lower() for w in waf_names):
            recs.append("Cloudflare Detected: Inspect SSL certificate SAN fields on discovered IPs to locate genuine origin server.")
            recs.append("Header Testing: Test backend response with 'True-Client-IP' and 'CF-Connecting-IP' header tampering.")
        elif any("aws" in w.lower() for w in waf_names):
            recs.append("AWS WAF Detected: Monitor for '403 Forbidden' with 'x-amzn-waf-action: block' and calibrate scan rate below 100 req/5min.")
        else:
            recs.append("No Major Cloud WAF Detected: Standard rate-limiting safeguards apply; maintain 10-20 req/s to avoid socket exhaustion.")

        return recs

    async def _generate_ai_narrative(
        self,
        target: str,
        wafs: list[str],
        origin_ips: list[dict[str, str]],
        recommendations: list[str],
    ) -> str:
        """Generates executive defense advisory markdown."""
        waf_summary = ", ".join(wafs) if wafs else "No dedicated cloud WAF fingerprinted"
        origin_summary = ", ".join([f"`{o['ip']}` ({o['asn_org']})" for o in origin_ips[:3]]) or "None identified"
        recs_text = "\n".join([f"- {r}" for r in recommendations])

        if self.ai and await self.ai.is_available():
            prompt = (
                f"You are a Red Team Technical Director assessing perimeter defenses for '{target}'.\n"
                f"Detected Firewalls/CDNs: {waf_summary}\n"
                f"Potential Origin Server IPs: {origin_summary}\n\n"
                "Write a concise Red Team Perimeter Strategy Advisory in Markdown:\n"
                "1. **Defensive Posture Assessment**: What protection layers are active.\n"
                "2. **Origin IP & Evasion Analysis**: Assessment of whether backend origin servers can be directly engaged.\n"
                "3. **Pacing & Operational Guidance**: Recommended concurrency and headers to avoid disruption.\n"
            )
            res = await self.ai.analyze(prompt)
            if res:
                return res

        # Deterministic Fallback
        return (
            f"## Red Team Perimeter Strategy Advisory: `{target}`\n\n"
            f"**Detected Protective Controls:** {waf_summary}\n\n"
            "### 1. Defensive Posture Overview\n"
            "Modern web perimeters rely on edge reverse proxies to filter malicious payloads and absorb traffic spikes. "
            "However, direct-to-origin access remains a common high-impact exposure.\n\n"
            "### 2. Origin IP Leakage & Bypass Opportunities\n"
            f"Potential origin IP addresses: {origin_summary}\n\n"
            "### 3. Recommended Red Team Pacing & Guidance\n"
            f"{recs_text}\n"
        )
