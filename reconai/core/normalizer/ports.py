"""Ports data normalizer."""
from __future__ import annotations

from reconai.core.database.models import PortRecord


def normalize_port_record(host: str, port: int, protocol: str, state: str, service: str = "", product: str = "", version: str = "", source: str = "", scan_id: str = "") -> PortRecord | None:
    """Validate and normalize a port record."""
    if port < 1 or port > 65535:
        return None
    if protocol not in ("tcp", "udp"):
        protocol = "tcp"
    if state not in ("open", "closed", "filtered"):
        state = "open"

    return PortRecord(
        scan_id=scan_id,
        host=host,
        port=port,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        source=source
    )
