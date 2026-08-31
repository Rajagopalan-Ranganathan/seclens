from __future__ import annotations

import logging

from seclens.domain.events import DataSyncCompleted
from seclens.observability.metrics import MetricsCollector
from seclens.ports.event_bus import EventBus

logger = logging.getLogger(__name__)


class SyncProbe:
    """Observes data sync events and records metrics."""

    def __init__(self, event_bus: EventBus, metrics: MetricsCollector) -> None:
        self._metrics = metrics
        event_bus.subscribe(DataSyncCompleted, self._on_sync)

    def _on_sync(self, event: DataSyncCompleted) -> None:
        self._metrics.increment("sync_total", source=event.source)
        self._metrics.observe("sync_duration_ms", event.duration_ms, source=event.source)
        self._metrics.observe("sync_records", float(event.records_synced), source=event.source)
        if event.errors:
            self._metrics.increment("sync_errors", len(event.errors), source=event.source)
        logger.info(
            "Sync: source=%s records=%d duration=%.1fms errors=%d",
            event.source,
            event.records_synced,
            event.duration_ms,
            len(event.errors),
        )
