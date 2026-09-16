"""Nuclei adapter — template-based vulnerability scanning.

Design: The adapter is stateless. All temp file lifecycle is managed
by the *module* that calls it, not by the adapter. This makes concurrent
module invocations safe — each gets its own path, no shared state.

The module passes output_file via build_command kwargs, and calls
parse_output_file(path) directly. The base-class parse(result) is a
no-op retained for interface compliance.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from reconai.core.database.models import FindingRecord, FindingStatus, Severity, Confidence
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "unknown":  Severity.INFO,
}


class NucleiAdapter(ToolAdapter):
    """Stateless Nuclei adapter.

    Concurrency contract:
      - build_command() does NOT mutate self. The caller passes the output
        file path as a kwarg and holds the reference.
      - parse_output_file() is a pure function of the given path.
      - Multiple concurrent calls with different paths are fully safe.
    """

    name = "nuclei"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build a Nuclei command.

        Args:
            target:      URL to scan.
            output_file: Path where Nuclei writes JSONL output.
                         The caller (module) creates and owns this file.
            tags:        Optional additional template tags.
        """
        target: str = kwargs.get("target", "")
        output_file: Path | str = kwargs.get("output_file", "")
        tags: str = kwargs.get("tags", "")

        cmd = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-tags", "cve,rce,sqli,xss,ssrf,ssti,lfi,idor,xxe,redirect,exposure,misconfig",
            "-severity", "critical,high,medium,low",
            "-timeout", "30",
            "-rate-limit", "50",
            "-retries", "1",
        ]

        if output_file:
            cmd.extend(["-o", str(output_file)])

        if tags:
            # Append additional tags on top of the defaults
            cmd.extend(["-tags", tags])

        return cmd

    def parse_output_file(self, path: Path) -> list[FindingRecord]:
        """Parse a Nuclei JSONL output file into FindingRecord objects.

        This is the primary parse entry point. Called by the module after
        the Nuclei process exits (success or timeout — JSONL is always
        valid line-by-line).

        Args:
            path: The output_file path provided to build_command.

        Returns:
            List of FindingRecord objects (may be empty, never raises).
        """
        findings: list[FindingRecord] = []

        try:
            if not path.exists() or path.stat().st_size == 0:
                return findings

            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        item: dict[str, Any] = json.loads(line)
                        finding = self._parse_nuclei_item(item)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        # Malformed line — skip and continue; partial output is fine
                        continue

        except Exception:
            # IO errors, permission errors — return whatever we have
            pass

        return findings

    def parse(self, result: CommandResult) -> list[Any]:
        """Required by ToolAdapter base class — not used for Nuclei.

        Nuclei writes to a file via -o, not to stdout. The module calls
        parse_output_file(path) directly instead.
        """
        return []

    # ── Private parsing helpers ───────────────────────────────────────────

    def _parse_nuclei_item(self, item: dict[str, Any]) -> FindingRecord | None:
        """Parse a single Nuclei JSONL record into a FindingRecord."""
        info: dict[str, Any] = item.get("info", {})
        template_id: str = item.get("template-id", "")
        matched_at: str = item.get("matched-at") or item.get("host", "")

        severity_str = str(info.get("severity", "info")).lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

        cve_ids   = self._extract_cves(template_id, info)
        cwe_ids   = self._extract_cwes(info)
        cvss      = self._extract_cvss(info)
        references = self._extract_refs(info)
        attack_class = self._infer_attack_class(template_id, info)

        # Build evidence string from all available fields
        evidence_parts: list[str] = []
        matcher_name: str = item.get("matcher-name", "")
        extracted: list[Any] = item.get("extracted-results", [])
        if matcher_name:
            evidence_parts.append(f"Matcher: {matcher_name}")
        if extracted:
            evidence_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")
        if item.get("request"):
            evidence_parts.append(f"Request: {str(item['request'])[:500]}")
        if item.get("response"):
            evidence_parts.append(f"Response snippet: {str(item['response'])[:300]}")
        evidence = "\n".join(evidence_parts)

        remediation: str = info.get("remediation", "")
        if not remediation and cve_ids:
            remediation = (
                f"Apply the vendor patch for {', '.join(cve_ids)}. "
                "Check NVD for the official advisory and affected versions."
            )

        return FindingRecord(
            scan_id="",  # Filled in by the module
            title=str(info.get("name", template_id) or template_id),
            severity=severity,
            confidence=Confidence.VERIFIED,
            status=FindingStatus.VERIFIED,
            affected_asset=matched_at,
            affected_asset_type="URL",
            description=str(info.get("description", "")),
            impact=self._infer_impact(attack_class, severity_str),
            evidence=evidence,
            detection_method=f"Nuclei Template: {template_id}",
            remediation=remediation,
            references=references,
            cve=cve_ids,
            cwe=cwe_ids,
            cvss=cvss,
            verified=True,
            attack_class=attack_class,
            what_is_it=str(info.get("description", "")),
            why_detected=f"Nuclei template {template_id} matched the response.",
        )

    def _extract_cves(self, template_id: str, info: dict[str, Any]) -> list[str]:
        cves: set[str] = set()

        for match in re.findall(r"CVE-\d{4}-\d+", template_id, re.IGNORECASE):
            cves.add(match.upper())

        classification = info.get("classification", {})
        if isinstance(classification, dict):
            raw_cves = classification.get("cve-id", [])
            if isinstance(raw_cves, str):
                raw_cves = [raw_cves]
            cves.update(c.upper() for c in raw_cves if isinstance(c, str))

        tags = info.get("tags", "")
        if isinstance(tags, str):
            cves.update(m.upper() for m in re.findall(r"CVE-\d{4}-\d+", tags, re.IGNORECASE))

        for ref in info.get("reference", []):
            if isinstance(ref, str):
                cves.update(m.upper() for m in re.findall(r"CVE-\d{4}-\d+", ref, re.IGNORECASE))

        return sorted(cves)

    def _extract_cwes(self, info: dict[str, Any]) -> list[str]:
        cwes: set[str] = set()
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            raw = classification.get("cwe-id", [])
            if isinstance(raw, str):
                raw = [raw]
            for c in raw:
                if isinstance(c, str) and c.startswith("CWE-"):
                    cwes.add(c)
        return sorted(cwes)

    def _extract_cvss(self, info: dict[str, Any]) -> float | None:
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            score = classification.get("cvss-score")
            if isinstance(score, (int, float)):
                return float(score)
        return None

    def _extract_refs(self, info: dict[str, Any]) -> list[str]:
        refs = info.get("reference", [])
        if isinstance(refs, str):
            refs = [refs]
        return [r for r in refs if isinstance(r, str) and r.startswith("http")][:10]

    def _infer_attack_class(self, template_id: str, info: dict[str, Any]) -> str:
        tags_str = " ".join([
            template_id,
            info.get("tags", "") if isinstance(info.get("tags"), str) else "",
        ]).lower()

        class_map = {
            "rce":       "Remote Code Execution",
            "sqli":      "SQL Injection",
            "xss":       "Cross-Site Scripting",
            "ssrf":      "Server-Side Request Forgery",
            "ssti":      "Server-Side Template Injection",
            "lfi":       "Local File Inclusion",
            "idor":      "Insecure Direct Object Reference",
            "xxe":       "XML External Entity",
            "redirect":  "Open Redirect",
            "exposure":  "Sensitive Data Exposure",
            "misconfig": "Security Misconfiguration",
            "cve":       "Known CVE",
            "takeover":  "Subdomain Takeover",
        }
        for key, value in class_map.items():
            if key in tags_str:
                return value
        return "Security Issue"

    def _infer_impact(self, attack_class: str, severity: str) -> str:
        impact_map = {
            "Remote Code Execution":       "Full server compromise — attacker gains code execution on the host.",
            "SQL Injection":               "Database exfiltration, credential theft, potential RCE via INTO OUTFILE.",
            "Cross-Site Scripting":        "Session hijacking, credential theft, phishing via trusted domain.",
            "Server-Side Request Forgery": "Internal network access, cloud metadata theft (AWS/GCP/Azure IMDSv1).",
            "Server-Side Template Injection": "Remote code execution via template engine sandbox escape.",
            "Local File Inclusion":        "Arbitrary file read, potential RCE via log poisoning.",
            "Insecure Direct Object Reference": "Unauthorized access to other users' data.",
            "XML External Entity":         "Arbitrary file read, SSRF, denial of service.",
            "Open Redirect":               "Phishing, OAuth token theft, session fixation.",
            "Sensitive Data Exposure":     "Credential and configuration leakage.",
            "Security Misconfiguration":   "Increased attack surface, data exposure.",
            "Known CVE":                   "Known vulnerability with public exploit code available.",
            "Subdomain Takeover":          "Serve malicious content from a trusted domain.",
        }
        return impact_map.get(attack_class, f"Security vulnerability of {severity} severity.")
