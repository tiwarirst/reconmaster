"""Email Security & Anti-Spoofing Posture Module.

Evaluates an organization's email authentication configuration using pure,
standard DNS lookups:
  - SPF (Sender Policy Framework) policy strength
  - DMARC (Domain-based Message Authentication, Reporting, and Conformance)
  - MX Gateway fingerprinting (Microsoft 365, Google Workspace, Proofpoint, etc.)
  - BIMI (Brand Indicators for Message Identification) posture

Zero external API keys or subscriptions required — uses standard asynchronous DNS.
"""
from __future__ import annotations

import re
from typing import Any

import dns.asyncresolver
import dns.resolver

from reconai.core.database.models import (
    Confidence, FindingRecord, FindingStatus, Severity, TechnologyRecord,
)
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module

# Known Mail Transfer Agent / Security Gateway fingerprints
MAIL_PROVIDER_FINGERPRINTS: dict[str, tuple[str, str]] = {
    "google.com": ("Google Workspace", "cloud_email"),
    "googlemail.com": ("Google Workspace", "cloud_email"),
    "outlook.com": ("Microsoft 365 / Exchange Online", "cloud_email"),
    "pphosted.com": ("Proofpoint Email Protection", "email_security_gateway"),
    "mimecast.com": ("Mimecast Email Security", "email_security_gateway"),
    "barracudanetworks.com": ("Barracuda Email Security", "email_security_gateway"),
    "trendmicro.com": ("Trend Micro Email Security", "email_security_gateway"),
    "cisco.com": ("Cisco IronPort Email Security", "email_security_gateway"),
    "zoho.com": ("Zoho Mail", "cloud_email"),
    "protonmail.ch": ("ProtonMail", "cloud_email"),
}


@register_module
class EmailSecurityModule(ReconModule):
    config = ModuleConfig(
        name="email_security",
        category="passive",
        description="Audits SPF, DMARC, MX gateway providers, and BIMI email anti-spoofing posture.",
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        domains: list[str] = list(kwargs.get("domains", []))
        if not domains:
            domain = kwargs.get("domain", self.target)
            domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0].strip()
            domains = [domain] if domain else []

        if not domains:
            return

        self.logger.module_start(self.config.name, target=", ".join(domains[:3]))

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 6.0

        for domain in domains:
            await self._audit_domain_email_security(resolver, domain)

        self.logger.module_complete(self.config.name)

    async def _audit_domain_email_security(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> None:
        """Run all email posture checks for a specific domain."""
        await self._audit_mx_records(resolver, domain)
        await self._audit_spf_record(resolver, domain)
        await self._audit_dmarc_record(resolver, domain)
        await self._audit_bimi_record(resolver, domain)

    async def _audit_mx_records(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> None:
        """Query MX records and fingerprint mail security gateway."""
        try:
            answers = await resolver.resolve(domain, "MX")
        except Exception:
            return

        for rdata in answers:
            exchange = str(rdata.exchange).rstrip(".").lower()
            for pattern, (provider_name, category) in MAIL_PROVIDER_FINGERPRINTS.items():
                if pattern in exchange:
                    tech = TechnologyRecord(
                        scan_id=self.scan_id,
                        host=domain,
                        name=provider_name,
                        category=category,
                        confidence=1.0,
                        source=self.config.name,
                        evidence=[f"MX Record: {exchange} (preference {rdata.preference})"],
                    )
                    self.db.insert_technology(tech)
                    self.logger.info(
                        f"[EMAIL] Identified Mail Provider: {provider_name} for {domain}",
                        module=self.config.name,
                    )
                    break

    async def _audit_spf_record(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> None:
        """Evaluate SPF record policy for email spoofing vulnerability."""
        spf_text: str | None = None
        try:
            answers = await resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                if txt.startswith("v=spf1"):
                    spf_text = txt
                    break
        except Exception:
            pass

        if not spf_text:
            finding = FindingRecord(
                scan_id=self.scan_id,
                title=f"Missing SPF Record: {domain}",
                severity=Severity.MEDIUM,
                confidence=Confidence.VERIFIED,
                status=FindingStatus.VERIFIED,
                affected_asset=domain,
                affected_asset_type="domain",
                description=(
                    f"The domain '{domain}' does not publish an SPF (Sender Policy Framework) TXT record. "
                    "Receiving mail servers cannot verify whether incoming emails originating from this domain "
                    "are sent by authorized mail servers."
                ),
                impact="Attackers can easily spoof emails appearing to originate from this domain, enabling targeted spear-phishing.",
                evidence="No TXT record starting with 'v=spf1' found via DNS.",
                detection_method="DNS TXT query for SPF record",
                remediation="Publish a valid SPF record in DNS (e.g. 'v=spf1 include:_spf.google.com ~all' or '-all').",
                references=["https://tools.ietf.org/html/rfc7208"],
                what_is_it="SPF allows domain owners to specify which IP addresses or services are authorized to send email on their behalf.",
                attack_class="Email Spoofing / Phishing",
                prevention="Configure and maintain an explicit SPF record specifying all authorized mail sending infrastructure.",
            )
            self.db.insert_finding(finding)
            return

        # Check SPF ending policy (+all, ?all, ~all, -all)
        policy_match = re.search(r"([+~?-])all\b", spf_text)
        if policy_match:
            qualifier = policy_match.group(1)
            if qualifier == "+":
                # +all allows anyone on the internet to send email on behalf of this domain!
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title=f"Critically Permissive SPF Record (+all): {domain}",
                    severity=Severity.HIGH,
                    confidence=Confidence.VERIFIED,
                    status=FindingStatus.VERIFIED,
                    affected_asset=domain,
                    affected_asset_type="domain",
                    description=(
                        f"The SPF record for '{domain}' uses '+all' qualifier: '{spf_text}'. "
                        "This explicitly instructs receiving mail servers to authorize ANY host on the internet "
                        "to send mail for this domain."
                    ),
                    impact="Trivial domain spoofing. Attackers can forge emails from any address at this domain without failing SPF checks.",
                    evidence=f"SPF record: {spf_text}",
                    detection_method="SPF policy qualifier parsing",
                    remediation="Change '+all' to '-all' (hardfail) or '~all' (softfail).",
                    what_is_it="An SPF misconfiguration where all IP addresses on the internet are whitelisted as legitimate mail senders.",
                    attack_class="Email Spoofing / Phishing",
                    prevention="Never use +all in production SPF records.",
                )
                self.db.insert_finding(finding)
            elif qualifier == "?":
                # ?all is Neutral
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title=f"Weak SPF Neutral Policy (?all): {domain}",
                    severity=Severity.LOW,
                    confidence=Confidence.VERIFIED,
                    status=FindingStatus.VERIFIED,
                    affected_asset=domain,
                    affected_asset_type="domain",
                    description=(
                        f"The SPF record for '{domain}' ends with '?all' (neutral): '{spf_text}'. "
                        "Mail servers treat unauthorized senders as neutral rather than failing them."
                    ),
                    impact="Reduced protection against email spoofing.",
                    evidence=f"SPF record: {spf_text}",
                    remediation="Transition to '~all' (softfail) and subsequently '-all' (hardfail).",
                    what_is_it="A neutral SPF policy indicating no definitive authorization statement.",
                    attack_class="Email Spoofing",
                )
                self.db.insert_finding(finding)

    async def _audit_dmarc_record(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> None:
        """Evaluate DMARC record policy at _dmarc.{domain}."""
        dmarc_text: str | None = None
        dmarc_host = f"_dmarc.{domain}"
        try:
            answers = await resolver.resolve(dmarc_host, "TXT")
            for rdata in answers:
                txt = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                if txt.startswith("v=DMARC1"):
                    dmarc_text = txt
                    break
        except Exception:
            pass

        if not dmarc_text:
            finding = FindingRecord(
                scan_id=self.scan_id,
                title=f"Missing DMARC Record: {domain}",
                severity=Severity.MEDIUM,
                confidence=Confidence.VERIFIED,
                status=FindingStatus.VERIFIED,
                affected_asset=dmarc_host,
                affected_asset_type="dns_record",
                description=(
                    f"The domain '{domain}' does not have a DMARC policy published at '{dmarc_host}'. "
                    "Without DMARC, receiving email servers have no instructions on how to handle emails "
                    "that fail SPF or DKIM checks."
                ),
                impact="High risk of brand impersonation and spoofing. Unauthorized senders can bypass SPF alignment.",
                evidence=f"No TXT record found at {dmarc_host}",
                detection_method="DNS TXT lookup at _dmarc.{domain}",
                remediation="Deploy a DMARC record starting with 'v=DMARC1; p=none; rua=mailto:...' and progress to 'p=reject'.",
                references=["https://dmarc.org/overview/"],
                what_is_it="DMARC ties SPF and DKIM authentication to the domain displayed in the email 'From' header.",
                attack_class="Domain Impersonation / Phishing",
                prevention="Publish and enforce a DMARC policy with quarantine or reject actions.",
            )
            self.db.insert_finding(finding)
            return

        # Parse DMARC policy tag: p=none, p=quarantine, p=reject
        p_match = re.search(r"\bp=([a-zA-Z]+)", dmarc_text)
        policy = p_match.group(1).lower() if p_match else "unknown"

        if policy == "none":
            finding = FindingRecord(
                scan_id=self.scan_id,
                title=f"DMARC Policy Not Enforced (p=none): {domain}",
                severity=Severity.LOW,
                confidence=Confidence.VERIFIED,
                status=FindingStatus.VERIFIED,
                affected_asset=dmarc_host,
                affected_asset_type="dns_record",
                description=(
                    f"The DMARC policy for '{domain}' is set to 'p=none': '{dmarc_text}'. "
                    "This is a monitoring-only policy. Mail servers that receive spoofed emails will NOT reject or quarantine them."
                ),
                impact="Spoofed emails purporting to be from the organization will still be delivered to recipients' inboxes.",
                evidence=f"DMARC record: {dmarc_text}",
                detection_method="DMARC policy tag parsing",
                remediation="Review DMARC reports and upgrade policy to 'p=quarantine' or 'p=reject'.",
                references=["https://tools.ietf.org/html/rfc7489"],
                what_is_it="A DMARC policy configured in report-only mode with zero active enforcement.",
                attack_class="Domain Spoofing",
                prevention="Enforce p=reject once all legitimate sending services are aligned.",
            )
            self.db.insert_finding(finding)

    async def _audit_bimi_record(
        self, resolver: dns.asyncresolver.Resolver, domain: str
    ) -> None:
        """Check for BIMI (Brand Indicators for Message Identification) record."""
        bimi_host = f"default._bimi.{domain}"
        try:
            answers = await resolver.resolve(bimi_host, "TXT")
            for rdata in answers:
                txt = "".join(s.decode("utf-8", errors="ignore") for s in rdata.strings)
                if txt.startswith("v=BIMI1"):
                    tech = TechnologyRecord(
                        scan_id=self.scan_id,
                        host=domain,
                        name="BIMI Email Authentication",
                        category="email_security",
                        confidence=1.0,
                        source=self.config.name,
                        evidence=[f"BIMI Record at {bimi_host}: {txt}"],
                    )
                    self.db.insert_technology(tech)
                    break
        except Exception:
            pass
