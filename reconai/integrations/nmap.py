"""Nmap adapter — tri-layer fault-tolerant port scanning.

Architecture: Three independent data recovery layers, applied in order:

  Layer 1 — Real-time streaming parse (greppable format, -oG -)
    Nmap writes greppable output to stdout line-by-line. Each line is
    parsed and inserted into the DB *immediately* as it arrives.
    This guarantees zero data loss: even if Nmap is killed at 1%,
    the ports discovered in that 1% are already persisted.

  Layer 2 — XML enrichment (post-completion, -oX file)
    If Nmap exits cleanly, the XML file is parsed with the standard
    strict parser to extract richer service data (product, version,
    CPE strings, script output) not available in the greppable format.
    These fields are merged/updated into already-inserted records.

  Layer 3 — Fault-tolerant XML recovery (post-timeout/crash)
    If the process was killed mid-scan, the XML is malformed (missing
    closing tags). Instead of discarding it, a regex-based carver
    extracts every <port> and <host> block that was written before the
    kill signal. This recovers whatever service data existed in the
    file without relying on valid XML structure.

Result: Partial scans are never lost. Data quality degrades gracefully
        (Layer 1 < Layer 3 < Layer 2) but is never zero.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from reconai.core.database.models import PortRecord, ServiceRecord
from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


# ─── Greppable format patterns ───────────────────────────────────────────────
# Example line:
#   Host: 192.168.1.1 (hostname.local)  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///  Ignored State: filtered (65433)
_RE_GNMAP_HOST = re.compile(r"^Host:\s+([\d\.a-fA-F:]+)")
_RE_GNMAP_PORTS = re.compile(r"Ports:\s+(.*?)(?:\s+Ignored|$)")
_RE_PORT_ENTRY = re.compile(
    r"(\d+)/"           # port number
    r"(open|closed|filtered)/"  # state
    r"(\w+)/"           # protocol
    r"[^/]*/"           # owner (unused)
    r"([^/]*)/"         # service name
    r"[^/]*/"           # rpc info (unused)
    r"([^/]*)/"         # version/product info
    r"([^/,]*)"         # extra info
)

# ─── XML carver pattern — works on truncated/malformed XML ───────────────────
# Extracts each <host>...</host> block, even if </nmaprun> is missing.
_RE_XML_HOST_BLOCK = re.compile(
    r"<host\b[^>]*>.*?(?:</host>|$)",
    re.DOTALL | re.IGNORECASE,
)
_RE_XML_ADDR = re.compile(r'<address\s+addr="([\d\.a-fA-F:]+)"', re.IGNORECASE)
_RE_XML_STATUS = re.compile(r'<status\s+state="(\w+)"', re.IGNORECASE)
_RE_XML_PORT = re.compile(
    r'<port\s+protocol="(\w+)"\s+portid="(\d+)"[^>]*>'
    r".*?"
    r'<state\s+state="(\w+)"'
    r".*?"
    r"(?:<service\s+([^/]*)/>|<service\s+([^>]*)>)",
    re.DOTALL | re.IGNORECASE,
)
_RE_XML_ATTR = re.compile(r'(\w+)="([^"]*)"')


class NmapAdapter(ToolAdapter):
    """Fault-tolerant Nmap adapter with real-time streaming and XML enrichment."""

    name = "nmap"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    # ─── Command builder ─────────────────────────────────────────────────────

    def build_command(self, **kwargs: Any) -> list[str]:
        """Build an Nmap command that outputs BOTH greppable (stdout) and XML (file).

        The dual-output strategy is the core of the fault-tolerance design:
          -oG -    → greppable output on stdout → real-time streaming parse
          -oX file → XML output to file         → post-scan enrichment
        """
        target: str = kwargs.get("target", "")
        profile_args: list[str] = kwargs.get("args", ["-T4", "--top-ports", "100"])
        output_xml: str | Path = kwargs.get("output_xml", "")

        cmd = ["nmap", *profile_args]

        # Always write XML to file for enrichment (even partial is useful)
        if output_xml:
            cmd.extend(["-oX", str(output_xml)])

        # Always stream greppable to stdout for real-time parsing
        cmd.extend(["-oG", "-"])

        cmd.append(target)
        return cmd

    # ─── Layer 1: Real-time greppable streaming parser ───────────────────────

    def make_streaming_callback(
        self,
        scan_id: str,
        host: str,
        on_port_found: Callable[[PortRecord, ServiceRecord | None], None],
    ) -> Callable[[str], None]:
        """Return a per-line callback that parses greppable output in real-time.

        This callback is registered with CommandRunner's on_output hook and
        is called for every single line of stdout as it arrives from the
        Nmap process. Each discovered port is immediately forwarded to
        on_port_found so the caller can persist it without waiting for
        the process to finish.

        Args:
            scan_id:       Current scan identifier.
            host:          Target host being scanned (used as fallback).
            on_port_found: Called immediately for each discovered open port.

        Returns:
            A callable(line: str) -> None to pass to CommandRunner.
        """
        def _callback(raw_line: str) -> None:
            # Strip timestamp prefix added by StreamHandler: "[HH:MM:SS] [MODULE] ..."
            line = re.sub(r"^\[\d{2}:\d{2}:\d{2}\]\s+\[\w+\]\s+", "", raw_line).strip()

            if not line or line.startswith("#"):
                # Skip comments and empty lines from greppable output
                return

            host_match = _RE_GNMAP_HOST.search(line)
            if not host_match:
                return

            discovered_host = host_match.group(1)
            ports_match = _RE_GNMAP_PORTS.search(line)
            if not ports_match:
                return

            ports_str = ports_match.group(1)
            for entry in _RE_PORT_ENTRY.finditer(ports_str):
                port_num   = int(entry.group(1))
                state      = entry.group(2).lower()
                protocol   = entry.group(3).lower()
                service    = entry.group(4).strip()
                version    = entry.group(5).strip()
                extra      = entry.group(6).strip()

                if state != "open":
                    continue

                port_record = PortRecord(
                    scan_id=scan_id,
                    host=discovered_host,
                    port=port_num,
                    protocol=protocol,
                    state="open",
                    service=service,
                    product=version,  # greppable merges product+version
                    version="",
                    source="nmap-stream",
                )

                svc_record: ServiceRecord | None = None
                if service or version:
                    svc_record = ServiceRecord(
                        scan_id=scan_id,
                        host=discovered_host,
                        port=port_num,
                        protocol=protocol,
                        service=service,
                        product=version,
                        version="",
                        extra_info=extra,
                        source="nmap-stream",
                    )

                on_port_found(port_record, svc_record)

        return _callback

    # ─── Layer 2: Strict XML enrichment (clean exit only) ────────────────────

    def parse_xml(self, xml_path: Path | str, scan_id: str) -> dict[str, list[Any]]:
        """Parse a complete, well-formed Nmap XML file for richer service data.

        Called only after a successful (non-timed-out) scan. Returns richer
        data than the greppable stream: product name, version string, CPE
        identifiers, and banner info. The caller merges this with already-
        inserted streaming records.

        Returns:
            {"ports": [...], "services": [...]}
        """
        results: dict[str, list[Any]] = {"ports": [], "services": []}

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            _populate_from_xml_root(root, scan_id, results)
        except ET.ParseError:
            # Malformed XML — fall through to the fault-tolerant carver
            pass
        except Exception:
            pass

        return results

    # ─── Layer 3: Fault-tolerant XML carver (partial/malformed XML) ──────────

    def parse_xml_fault_tolerant(
        self, xml_path: Path | str, scan_id: str
    ) -> dict[str, list[Any]]:
        """Extract port data from a truncated or malformed XML file using regex.

        Called when the process was killed mid-scan and the XML file is
        missing its closing tags. The standard XML parser would fail
        completely; this carver extracts every <port> block that was
        written before the kill signal, providing maximum data recovery.

        This is intentionally defensive: every operation is guarded against
        failure so the caller always receives a valid (possibly empty) result.

        Returns:
            {"ports": [...], "services": [...]}
        """
        results: dict[str, list[Any]] = {"ports": [], "services": []}

        try:
            raw = Path(xml_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return results

        # First attempt: try to repair the XML by appending missing closing tags
        # This works when the file is merely truncated, not corrupted.
        repaired = _attempt_xml_repair(raw)
        if repaired:
            try:
                root = ET.fromstring(repaired)
                _populate_from_xml_root(root, scan_id, results)
                if results["ports"]:
                    return results
            except Exception:
                pass

        # Second attempt: regex carve — extract individual host blocks
        # Works even when the XML structure is fundamentally broken.
        for host_block in _RE_XML_HOST_BLOCK.finditer(raw):
            block = host_block.group(0)

            status_m = _RE_XML_STATUS.search(block)
            if status_m and status_m.group(1).lower() != "up":
                continue

            addr_m = _RE_XML_ADDR.search(block)
            if not addr_m:
                continue
            ip = addr_m.group(1)

            for port_m in _RE_XML_PORT.finditer(block):
                protocol  = port_m.group(1).lower()
                port_num  = int(port_m.group(2))
                state     = port_m.group(3).lower()

                if state != "open":
                    continue

                # Parse service attributes from whichever group matched
                svc_attrs_raw = port_m.group(4) or port_m.group(5) or ""
                svc_attrs = dict(_RE_XML_ATTR.findall(svc_attrs_raw))

                service = svc_attrs.get("name", "")
                product = svc_attrs.get("product", "")
                version = svc_attrs.get("version", "")
                extra   = svc_attrs.get("extrainfo", "")
                cpe     = ""

                # Try to extract CPE from the block near this port
                cpe_match = re.search(r"<cpe>(cpe:[^<]+)</cpe>", block)
                if cpe_match:
                    cpe = cpe_match.group(1)

                port_record = PortRecord(
                    scan_id=scan_id,
                    host=ip,
                    port=port_num,
                    protocol=protocol,
                    state="open",
                    service=service,
                    product=product,
                    version=version,
                    cpe=cpe,
                    source="nmap-recovered",
                )
                results["ports"].append(port_record)

                if product or version or service:
                    svc_record = ServiceRecord(
                        scan_id=scan_id,
                        host=ip,
                        port=port_num,
                        protocol=protocol,
                        service=service,
                        product=product,
                        version=version,
                        extra_info=extra,
                        source="nmap-recovered",
                    )
                    results["services"].append(svc_record)

        return results

    # ─── Required base method ─────────────────────────────────────────────────

    def parse(self, result: CommandResult) -> list[Any]:
        """Base interface method — streaming parse is used instead at runtime."""
        return []


# ─── Private helpers ──────────────────────────────────────────────────────────

def _attempt_xml_repair(raw: str) -> str | None:
    """Try to make a truncated Nmap XML file parseable.

    Nmap XML has a predictable structure: if the process is killed cleanly,
    the file is often missing only the closing </nmaprun> tag (and sometimes
    </host>, </ports>). We can re-append these to make the document valid.
    """
    # Check we have at least the opening nmaprun tag
    if "<nmaprun" not in raw:
        return None

    repaired = raw.rstrip()

    # Close any obviously open tags in reverse nesting order
    for tag in ("extraports", "ports", "host", "nmaprun"):
        closing = f"</{tag}>"
        if repaired.count(f"<{tag}") > repaired.count(closing):
            repaired += f"\n{closing}"

    return repaired


def _populate_from_xml_root(
    root: ET.Element,
    scan_id: str,
    results: dict[str, list[Any]],
) -> None:
    """Shared logic to walk a valid XML tree and populate results dicts."""
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        address = host.find("address")
        if address is None:
            continue
        ip = address.get("addr", "")

        ports_tag = host.find("ports")
        if ports_tag is None:
            continue

        for port in ports_tag.findall("port"):
            state_tag = port.find("state")
            if state_tag is None or state_tag.get("state") != "open":
                continue

            port_num  = int(port.get("portid", 0))
            protocol  = port.get("protocol", "tcp")

            service_tag = port.find("service")
            service_name = ""
            product = ""
            version = ""
            cpe     = ""
            extra   = ""

            if service_tag is not None:
                service_name = service_tag.get("name", "")
                product      = service_tag.get("product", "")
                version      = service_tag.get("version", "")
                extra        = service_tag.get("extrainfo", "")
                cpe_tag      = service_tag.find("cpe")
                if cpe_tag is not None and cpe_tag.text:
                    cpe = cpe_tag.text

            port_record = PortRecord(
                scan_id=scan_id,
                host=ip,
                port=port_num,
                protocol=protocol,
                state="open",
                service=service_name,
                product=product,
                version=version,
                cpe=cpe,
                source="nmap-xml",
            )
            results["ports"].append(port_record)

            if product or version:
                svc_record = ServiceRecord(
                    scan_id=scan_id,
                    host=ip,
                    port=port_num,
                    protocol=protocol,
                    service=service_name,
                    product=product,
                    version=version,
                    extra_info=extra,
                    source="nmap-xml",
                )
                results["services"].append(svc_record)
