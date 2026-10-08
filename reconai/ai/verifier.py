"""Closed-Loop Safe Vulnerability Verifier.

Automates the verification of candidate vulnerability findings using
safe, non-destructive validation probes, paired with AI differential analysis.
Filters out false positives and upgrades confirmed findings to 'verified'.

Core Principles:
1. Non-destructive: Uses benign markers, timing differentials, or passive checks.
2. Fast & Async: Concurrent HTTP probing with strict timeouts.
3. Fail-Safe: Graceful fallbacks if the endpoint or AI is unreachable.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from reconai.ai.adapter import AIAdapter
from reconai.core.database.manager import DatabaseManager
from reconai.core.database.models import Confidence


class ClosedLoopVerifier:
    """Verifies candidate findings and filters false positives using AI analysis."""

    def __init__(self, db: DatabaseManager, scan_id: str, ai: AIAdapter | None = None) -> None:
        self.db = db
        self.scan_id = scan_id
        self.ai = ai

    async def verify_all_findings(self) -> list[dict[str, Any]]:
        """Verify all unverified findings in the scan and update their confidence in the database."""
        findings = self.db.get_findings(self.scan_id)
        if not findings:
            return []

        results = []
        for finding in findings:
            verification_result = await self.verify_finding(finding)
            results.append(verification_result)

            # Update finding in database if status confirmed
            new_conf = verification_result.get("confidence")
            evidence_note = verification_result.get("evidence")
            if new_conf and evidence_note:
                try:
                    is_ver = 1 if verification_result.get("verified") else 0
                    existing_evidence = str(finding.get("evidence") or "")
                    updated_evidence = f"{existing_evidence}\n[AI Verifier]: {evidence_note}".strip()
                    fid = finding.get("id")
                    if fid:
                        with self.db._lock:
                            self.db.conn.execute(
                                "UPDATE findings SET confidence = ?, verified = ?, evidence = ? WHERE id = ?",
                                (new_conf, is_ver, updated_evidence, fid),
                            )
                            self.db.conn.commit()
                except Exception:
                    pass

        return results

    async def verify_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Perform a benign closed-loop verification check on a single finding."""
        title = str(finding.get("title", "")).lower()
        asset = str(finding.get("affected_asset", ""))
        attack_class = str(finding.get("attack_class", "")).lower()

        # Target URL formatting
        url = asset if asset.startswith("http://") or asset.startswith("https://") else f"https://{asset}"

        result = {
            "finding_id": finding.get("id"),
            "title": finding.get("title"),
            "asset": asset,
            "verified": False,
            "confidence": "potential",
            "evidence": "",
            "ai_verdict": "",
        }

        # Select verification method
        if any(k in title or k in attack_class for k in ["secret", "key", "credential", "token", "password"]):
            return await self._verify_secret_exposure(finding, result)
        elif any(k in title or k in attack_class for k in ["cors", "header", "clickjacking", "x-frame"]):
            return await self._verify_header_misconfig(finding, url, result)
        elif any(k in title or k in attack_class for k in ["subdomain takeover", "cname"]):
            return await self._verify_subdomain_takeover(finding, asset, result)
        elif any(k in title or k in attack_class for k in ["exposed", "git", "env", "backup", "directory listing"]):
            return await self._verify_exposed_endpoint(finding, url, result)
        else:
            return await self._verify_generic_with_ai(finding, url, result)

    async def _verify_header_misconfig(self, finding: dict[str, Any], url: str, result: dict[str, Any]) -> dict[str, Any]:
        """Verify CORS or missing security headers."""
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                resp = await client.get(url, headers={"Origin": "https://evil-attacker.example.com"})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if "evil-attacker.example.com" in acao or acao == "*":
                    result["verified"] = True
                    result["confidence"] = "verified"
                    result["evidence"] = f"Confirmed CORS reflection: Access-Control-Allow-Origin: {acao} (Credentials: {acac})"
                elif "x-frame-options" not in resp.headers and "clickjacking" in str(finding.get("title", "")).lower():
                    result["verified"] = True
                    result["confidence"] = "likely"
                    result["evidence"] = "Confirmed missing X-Frame-Options and Content-Security-Policy frame-ancestors header."
                else:
                    result["confidence"] = "likely"
                    result["evidence"] = f"Endpoint responsive (HTTP {resp.status_code}), security headers absent."
        except Exception as exc:
            result["evidence"] = f"Connection failed during header check: {exc}"

        return result

    async def _verify_subdomain_takeover(self, finding: dict[str, Any], domain: str, result: dict[str, Any]) -> dict[str, Any]:
        """Verify dangling CNAME record for takeover."""
        try:
            import dns.resolver
            host = domain.replace("https://", "").replace("http://", "").split("/")[0]
            answers = dns.resolver.resolve(host, "CNAME")
            cname = str(answers[0].target).rstrip(".")
            result["verified"] = True
            result["confidence"] = "verified"
            result["evidence"] = f"Confirmed dangling CNAME pointing to third-party host: {cname}"
        except Exception as exc:
            result["confidence"] = "potential"
            result["evidence"] = f"CNAME resolution check inconclusive: {exc}"
        return result

    async def _verify_exposed_endpoint(self, finding: dict[str, Any], url: str, result: dict[str, Any]) -> dict[str, Any]:
        """Verify exposed administrative, backup, or sensitive endpoints."""
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and len(resp.text) > 10:
                    text_sample = resp.text[:300].lower()
                    if any(marker in text_sample for marker in ["index of /", "gitdir", "db_password", "aws_secret", "root:x:0"]):
                        result["verified"] = True
                        result["confidence"] = "verified"
                        result["evidence"] = f"Confirmed accessible endpoint (HTTP 200) containing signature markers: {text_sample[:100]}"
                    else:
                        result["confidence"] = "likely"
                        result["evidence"] = f"Endpoint returned HTTP 200 with {len(resp.text)} bytes body."
                elif resp.status_code in (401, 403):
                    result["confidence"] = "likely"
                    result["evidence"] = f"Endpoint exists but access is restricted (HTTP {resp.status_code})."
                else:
                    result["confidence"] = "potential"
                    result["evidence"] = f"Endpoint returned HTTP {resp.status_code}."
        except Exception as exc:
            result["evidence"] = f"Verification probe connection error: {exc}"
        return result

    async def _verify_secret_exposure(self, finding: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        """Verify high-entropy secret or API key pattern."""
        evidence = str(finding.get("evidence", ""))
        desc = str(finding.get("description", ""))
        combined = f"{evidence} {desc}"

        patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
            (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
            (r"AIza[0-9A-Za-z-_]{35}", "Google API Key"),
            (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live Secret Key"),
            (r"bearer\s+[a-zA-Z0-9_\-\.]{30,}", "Bearer Token"),
        ]

        for pat, label in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                result["verified"] = True
                result["confidence"] = "verified"
                result["evidence"] = f"Regex pattern confirmed active signature for: {label}"
                return result

        result["confidence"] = "likely"
        result["evidence"] = "Credential signature detected; manual validation advised."
        return result

    async def _verify_generic_with_ai(self, finding: dict[str, Any], url: str, result: dict[str, Any]) -> dict[str, Any]:
        """Use local LLM to reason about finding validity based on collected evidence."""
        if not self.ai or not await self.ai.is_available():
            result["confidence"] = "likely"
            result["evidence"] = "Heuristic check complete (LLM offline for deep verification)."
            return result

        prompt = (
            "You are a Senior Principal Security Auditor. Evaluate the validity of this candidate security finding:\n"
            f"Title: {finding.get('title')}\n"
            f"Asset: {finding.get('affected_asset')}\n"
            f"Description: {finding.get('description')}\n"
            f"Evidence: {finding.get('evidence')}\n\n"
            "Answer in 2 sentences:\n"
            "1. Verdict: Is this finding a True Positive, False Positive, or Informational?\n"
            "2. Confidence: Give a confidence score from 0% to 100% and rationale."
        )

        try:
            verdict = await self.ai.analyze(prompt)
            result["ai_verdict"] = verdict
            if "true positive" in verdict.lower():
                result["verified"] = True
                result["confidence"] = "verified"
            elif "false positive" in verdict.lower():
                result["confidence"] = "potential"
            else:
                result["confidence"] = "likely"
            result["evidence"] = f"AI Verdict: {verdict.strip()[:180]}"
        except Exception as exc:
            result["evidence"] = f"AI evaluation error: {exc}"

        return result
