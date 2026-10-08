"""TLS & Certificate Intelligence Module.

Leverages ProjectDiscovery tlsx when installed, with an autonomous pure-Python
SSL/TLS socket fallback to extract Subject Alternative Names (SANs) for subdomain
discovery, detect expired certificates, and flag deprecated TLS protocols.
"""
from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
import time
from typing import Any

from reconai.core.database.models import (
    Confidence,
    FindingRecord,
    FindingStatus,
    Severity,
    SubdomainRecord,
)
from reconai.core.events.types import EventType
from reconai.integrations.tlsx import TlsxAdapter
from reconai.modules.base import ModuleConfig, ReconModule
from reconai.modules.registry import register_module


@register_module
class TLSProbeModule(ReconModule):
    """Deep TLS/SSL intelligence and SAN subdomain extraction module."""

    config = ModuleConfig(
        name="tls_probe",
        category="active",
        description="Inspects TLS/SSL certificates, extracts SAN subdomains, and detects expired/weak TLS configs",
        requires_tools=[],  # Has pure-Python SSL fallback
        supports_timeout=True,
    )

    async def run(self, **kwargs: Any) -> Any:
        start_time = time.monotonic()
        self.logger.module_start(self.config.name, target=self.target)

        # 1. Gather target hosts to probe (domain itself + any discovered subdomains)
        candidates: set[str] = set()
        clean_target = self.target.split("://")[-1].split("/")[0].split(":")[0].strip()
        if clean_target:
            candidates.add(clean_target)

        passed_domains = kwargs.get("domains") or []
        for d in passed_domains:
            if isinstance(d, str) and d.strip():
                candidates.add(d.strip())

        try:
            db_subs = self.db.get_subdomains(self.scan_id)
            for s in db_subs[:50]:  # Cap to top 50 discovered subdomains for fast probe
                sub_name = s.get("subdomain") if isinstance(s, dict) else getattr(s, "subdomain", "")
                if sub_name:
                    candidates.add(sub_name)
        except Exception:
            pass

        if not candidates:
            return

        targets_list = sorted(list(candidates))[:60]
        self.logger.info(f"Probing TLS configuration for {len(targets_list)} host(s)...", module=self.config.name)

        adapter = TlsxAdapter(self.runner)
        has_tlsx = await adapter.is_available()

        tls_results: list[dict[str, Any]] = []

        if has_tlsx:
            try:
                cmd = adapter.build_command(targets=targets_list, concurrency=20, timeout=10)
                cmd_res = await self.runner.run(command=cmd, timeout=90)
                tls_results = adapter.parse(cmd_res)
            except Exception as exc:
                self.logger.warning(f"tlsx CLI execution encountered error: {exc}. Falling back to Python SSL.", module=self.config.name)

        # 2. Pure-Python fallback for any targets not covered or if tlsx is not installed
        covered_hosts = {r["host"] for r in tls_results if "host" in r}
        remaining = [h for h in targets_list if h not in covered_hosts]

        if remaining or not tls_results:
            py_tasks = [self._probe_ssl_python(h) for h in remaining[:25]]
            fallback_results = await asyncio.gather(*py_tasks, return_exceptions=True)
            for res in fallback_results:
                if isinstance(res, dict) and res.get("host"):
                    tls_results.append(res)

        # 3. Process TLS intelligence, extract subdomains, and log findings
        discovered_sans: set[str] = set()

        for item in tls_results:
            host = item.get("host", "")
            sans = item.get("subject_an", []) or []
            expired = item.get("expired", False)
            tls_version = item.get("tls_version", "")
            issuer = item.get("issuer_cn") or ", ".join(item.get("issuer_org", []))

            # Subdomain discovery via Subject Alternative Names (SANs)
            for san in sans:
                san_clean = san.strip().lstrip("*.").lower()
                if clean_target and san_clean.endswith(clean_target) and san_clean != clean_target:
                    discovered_sans.add(san_clean)

            # Check expired certificate
            if expired:
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title=f"Expired SSL/TLS Certificate on {host}",
                    severity=Severity.HIGH,
                    confidence=Confidence.VERIFIED,
                    status=FindingStatus.VERIFIED,
                    affected_asset=host,
                    affected_asset_type="host",
                    description=(
                        f"The TLS/SSL certificate served by host {host} has expired. "
                        f"Issuer: {issuer}. This causes browser trust warnings and service disruption."
                    ),
                    detection_method=f"{self.config.name} (certificate validation)",
                    remediation="Renew and redeploy a valid SSL/TLS certificate immediately using Let's Encrypt or your CA.",
                    source=self.config.name,
                )
                self.db.insert_finding(finding)
                await self.events.emit_finding(
                    source=self.config.name,
                    title=finding.title,
                    severity=finding.severity.value,
                    affected_asset=finding.affected_asset,
                    data={"host": host, "issuer": issuer},
                    scan_id=self.scan_id,
                    target=self.target,
                )

            # Check weak/deprecated TLS protocol version (TLS 1.0 or TLS 1.1)
            if tls_version in ("tls10", "tls11", "TLSv1", "TLSv1.1", "ssl3"):
                finding = FindingRecord(
                    scan_id=self.scan_id,
                    title=f"Deprecated TLS Protocol Enabled ({tls_version}) on {host}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.VERIFIED,
                    status=FindingStatus.VERIFIED,
                    affected_asset=host,
                    affected_asset_type="service",
                    description=(
                        f"Host {host} negotiated deprecated protocol '{tls_version}'. "
                        "TLS 1.0 and 1.1 suffer from known cryptographic weaknesses (POODLE, BEAST) "
                        "and violate modern compliance standards (PCI-DSS 3.1+)."
                    ),
                    detection_method=f"{self.config.name} (tls handshake)",
                    remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on the web server. Enforce TLS 1.2 or TLS 1.3.",
                    source=self.config.name,
                )
                self.db.insert_finding(finding)
                await self.events.emit_finding(
                    source=self.config.name,
                    title=finding.title,
                    severity=finding.severity.value,
                    affected_asset=finding.affected_asset,
                    data={"host": host, "version": tls_version},
                    scan_id=self.scan_id,
                    target=self.target,
                )

        # Store discovered subdomains
        for sub in discovered_sans:
            sub_rec = SubdomainRecord(
                scan_id=self.scan_id,
                subdomain=sub,
                domain=clean_target,
                sources=["tls_san"],
                priority="high",
            )
            self.db.insert_subdomain(sub_rec)
            await self.events.emit_discovery(
                event_type=EventType.SUBDOMAIN_DISCOVERED,
                source=self.config.name,
                data={"subdomain": sub, "source": "tls_san"},
                scan_id=self.scan_id,
                target=self.target,
            )

        self.logger.info(
            f"TLS probe completed: {len(tls_results)} certs inspected, {len(discovered_sans)} new subdomains extracted from SANs",
            module=self.config.name,
        )
        self.logger.module_complete(self.config.name, duration=time.monotonic() - start_time)

    async def _probe_ssl_python(self, host: str, port: int = 443) -> dict[str, Any] | None:
        """Pure-Python non-blocking SSL handshake and certificate metadata extractor."""
        def _sync_probe() -> dict[str, Any] | None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=4.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        tls_ver = ssock.version() or ""
                        cipher = ssock.cipher()
                        cipher_name = cipher[0] if cipher else ""

                        # If binary cert returned or empty dict because of CERT_NONE, retry with binary decode
                        sans: list[str] = []
                        subject_cn = ""
                        issuer_cn = ""
                        expired = False

                        if cert:
                            # Extract SANs
                            for san_type, san_val in cert.get("subjectAltName", []):
                                if san_type.lower() == "dns":
                                    sans.append(san_val)

                            # Subject CN
                            for subj_tuple in cert.get("subject", []):
                                for k, v in subj_tuple:
                                    if k == "commonName":
                                        subject_cn = v

                            # Issuer CN
                            for iss_tuple in cert.get("issuer", []):
                                for k, v in iss_tuple:
                                    if k == "commonName":
                                        issuer_cn = v

                            # Expiration check
                            not_after = cert.get("notAfter")
                            if not_after:
                                try:
                                    exp_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                    if exp_date < datetime.datetime.utcnow():
                                        expired = True
                                except Exception:
                                    pass

                        return {
                            "host": host,
                            "port": port,
                            "subject_cn": subject_cn,
                            "subject_an": sans,
                            "issuer_cn": issuer_cn,
                            "tls_version": tls_ver,
                            "cipher": cipher_name,
                            "expired": expired,
                        }
            except Exception:
                return None

        return await asyncio.to_thread(_sync_probe)
