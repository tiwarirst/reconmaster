"""Event type definitions for the ReconAI event-driven pipeline."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """All event types in the system."""
    # Scan lifecycle
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    # Module lifecycle
    MODULE_STARTED = "module.started"
    MODULE_PROGRESS = "module.progress"
    MODULE_COMPLETED = "module.completed"
    MODULE_FAILED = "module.failed"
    MODULE_SKIPPED = "module.skipped"

    # Asset discovery
    ASSET_DISCOVERED = "asset.discovered"
    DOMAIN_DISCOVERED = "domain.discovered"
    SUBDOMAIN_DISCOVERED = "subdomain.discovered"
    IP_DISCOVERED = "ip.discovered"
    HOST_RESOLVED = "host.resolved"
    PORT_DISCOVERED = "port.discovered"
    SERVICE_DISCOVERED = "service.discovered"
    URL_DISCOVERED = "url.discovered"
    API_DISCOVERED = "api.discovered"
    TECHNOLOGY_DETECTED = "technology.detected"
    CERTIFICATE_DISCOVERED = "certificate.discovered"
    CLOUD_ASSET_DISCOVERED = "cloud.asset.discovered"

    # Findings
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    FINDING_DISCOVERED = "finding.discovered"

    # Tool events
    TOOL_STARTED = "tool.started"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"
    TOOL_TIMEOUT = "tool.timeout"

    # System
    LOG_MESSAGE = "log.message"
    ERROR = "error"


class Event(BaseModel):
    """An event in the ReconAI event system.

    Events are the primary mechanism for inter-module communication.
    Modules emit events when they discover assets, and other modules
    can subscribe to process those discoveries.
    """
    type: EventType
    source: str = Field(description="Module or component that emitted the event")
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    scan_id: str = ""
    target: str = ""
    priority: int = Field(default=0, description="Higher = more important")

    @property
    def is_discovery(self) -> bool:
        return self.type.value.endswith(".discovered") or self.type == EventType.HOST_RESOLVED

    @property
    def is_module_event(self) -> bool:
        return self.type.value.startswith("module.")

    @property
    def is_error(self) -> bool:
        return self.type in (EventType.ERROR, EventType.MODULE_FAILED, EventType.TOOL_FAILED)
