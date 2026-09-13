"""Lightweight async event bus for inter-module communication.

Enables loose coupling between modules:
- Subdomain module discovers → emits SUBDOMAIN_DISCOVERED
- DNS module listens → resolves the subdomain
- HTTP module listens → probes the resolved host

No module needs to know about any other module.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Callable, Coroutine, Any

from reconai.core.events.types import Event, EventType


# Type alias for event handlers
EventHandler = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """Async event bus for the ReconAI pipeline.

    Supports:
    - Subscribe/unsubscribe to event types
    - Emit events to all subscribers
    - Wildcard subscriptions (subscribe to all events)
    - Event history for debugging
    - Async handlers
    """

    def __init__(self, max_history: int = 1000):
        self._handlers: dict[EventType | str, list[EventHandler]] = defaultdict(list)
        self._history: list[Event] = []
        self._max_history = max_history
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: EventType | str, handler: EventHandler) -> None:
        """Subscribe a handler to an event type.

        Args:
            event_type: The event type to listen for, or "*" for all events.
            handler: Async function that receives an Event.
        """
        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: EventType | str, handler: EventHandler) -> None:
        """Remove a handler from an event type."""
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def emit(self, event: Event) -> None:
        """Emit an event to all subscribed handlers.

        Handlers are called concurrently. A failing handler
        does not prevent other handlers from receiving the event.
        """
        # Store in history
        async with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

        # Collect handlers
        handlers = list(self._handlers.get(event.type, []))
        handlers.extend(self._handlers.get("*", []))

        if not handlers:
            return

        # Execute handlers concurrently, isolating failures
        tasks = []
        for handler in handlers:
            tasks.append(self._safe_call(handler, event))

        await asyncio.gather(*tasks)

    async def emit_discovery(
        self,
        event_type: EventType,
        source: str,
        data: dict[str, Any],
        scan_id: str = "",
        target: str = "",
    ) -> None:
        """Convenience method for emitting discovery events."""
        event = Event(
            type=event_type,
            source=source,
            data=data,
            scan_id=scan_id,
            target=target,
        )
        await self.emit(event)

    @staticmethod
    async def _safe_call(handler: EventHandler, event: Event) -> None:
        """Call a handler with error isolation."""
        try:
            await handler(event)
        except Exception:
            # Log but don't propagate — one handler failure shouldn't break others
            pass

    def get_history(
        self,
        event_type: EventType | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Get event history, optionally filtered."""
        events = self._history
        if event_type:
            events = [e for e in events if e.type == event_type]
        if source:
            events = [e for e in events if e.source == source]
        return events[-limit:]

    def get_discoveries(self) -> list[Event]:
        """Get all discovery events."""
        return [e for e in self._history if e.is_discovery]

    def clear_history(self) -> None:
        """Clear event history."""
        self._history.clear()

    @property
    def subscriber_count(self) -> int:
        return sum(len(h) for h in self._handlers.values())
