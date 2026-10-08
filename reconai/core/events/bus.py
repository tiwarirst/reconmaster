"""Lightweight async event bus for inter-module communication.

Enables loose coupling between modules:
- Subdomain module discovers → emits SUBDOMAIN_DISCOVERED
- DNS module listens → resolves the subdomain
- HTTP module listens → probes the resolved host

No module needs to know about any other module.

Fix applied (Flaw 13):
  Event history previously used a plain list with a slice assignment
  (_history = _history[-max_history:]) on every overflow. Two problems:
    1. The slice is O(n) — copies the whole list.
    2. It discards the EARLIEST events (scan start, first discoveries)
       which are the most useful for debugging.

  Fix: collections.deque(maxlen=N) — O(1) append, auto-evicts from the
  LEFT (oldest first), and requires zero manual trimming logic.
"""
from __future__ import annotations

import asyncio
from collections import deque
from typing import Any, Callable, Coroutine

from reconai.core.events.types import Event, EventType


# Type alias for event handlers
EventHandler = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """Async event bus for the ReconAI pipeline.

    Supports:
    - Subscribe/unsubscribe to event types
    - Emit events to all subscribers
    - Wildcard subscriptions (subscribe to all events with "*")
    - Fixed-size circular event history (oldest events auto-evicted)
    - Async handlers with failure isolation
    """

    def __init__(self, max_history: int = 1000) -> None:
        self._handlers: dict[EventType | str, list[EventHandler]] = {}
        # deque with maxlen: O(1) append, auto-evicts oldest from left,
        # no manual slice trimming needed, no O(n) copy on overflow.
        self._history: deque[Event] = deque(maxlen=max_history)
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: EventType | str, handler: EventHandler) -> None:
        """Subscribe a handler to an event type.

        Args:
            event_type: The event type to listen for, or "*" for all events.
            handler:    Async function that receives an Event.
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: EventType | str, handler: EventHandler) -> None:
        """Remove a handler from an event type."""
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def emit(self, event: Event, wait: bool = True) -> None:
        """Emit an event to all subscribed handlers.

        Handlers are called concurrently. A failing handler
        does not prevent other handlers from receiving the event.
        When wait=False, handlers run as decoupled background tasks.
        """
        async with self._lock:
            self._history.append(event)  # O(1), auto-evicts oldest if full

        # Collect specific + wildcard handlers
        handlers = list(self._handlers.get(event.type, []))
        handlers.extend(self._handlers.get("*", []))

        if not handlers:
            return

        if wait:
            await asyncio.gather(
                *(self._safe_call(h, event) for h in handlers)
            )
        else:
            for h in handlers:
                asyncio.create_task(self._safe_call(h, event))

    async def emit_discovery(
        self,
        event_type: EventType,
        source: str,
        data: dict[str, Any],
        scan_id: str = "",
        target: str = "",
        wait: bool = False,
    ) -> None:
        """Convenience method for emitting discovery events non-blockingly."""
        event = Event(
            type=event_type,
            source=source,
            data=data,
            scan_id=scan_id,
            target=target,
        )
        await self.emit(event, wait=wait)

    @staticmethod
    async def _safe_call(handler: EventHandler, event: Event) -> None:
        """Call a handler with error isolation."""
        try:
            await handler(event)
        except Exception:
            # One handler failure must never prevent other handlers
            # from receiving the event — swallow and continue.
            pass

    def get_history(
        self,
        event_type: EventType | None = None,
        source: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Get event history, optionally filtered."""
        events: list[Event] = list(self._history)
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
