from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from seclens.domain.events import DomainEvent
from seclens.ports.event_bus import EventBus

logger = logging.getLogger(__name__)


class InMemoryEventBus(EventBus):
    """Simple synchronous in-memory event bus.

    Suitable for local/single-process use. Can be swapped for
    Redis/Kafka/NATS by implementing the EventBus port.
    """

    def __init__(self) -> None:
        self._handlers: dict[type, list[Callable]] = defaultdict(list)

    def publish(self, event: DomainEvent) -> None:
        event_type = type(event)
        handlers = self._handlers.get(event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                logger.exception("Event handler failed for %s", event_type.__name__)

    def subscribe(self, event_type: type[DomainEvent], handler: Callable[[DomainEvent], Any]) -> None:
        self._handlers[event_type].append(handler)
        logger.debug("Subscribed %s to %s", handler.__name__, event_type.__name__)
