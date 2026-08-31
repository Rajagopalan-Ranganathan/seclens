from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

from seclens.domain.events import DomainEvent


class EventBus(ABC):
    """Port for publishing and subscribing to domain events."""

    @abstractmethod
    def publish(self, event: DomainEvent) -> None:
        """Publish a domain event to all subscribers."""

    @abstractmethod
    def subscribe(
        self, event_type: type[DomainEvent], handler: Callable[[DomainEvent], Any]
    ) -> None:
        """Register a handler for a specific event type."""
