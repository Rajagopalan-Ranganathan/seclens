from __future__ import annotations

import logging

from seclens.domain.events import SearchPerformed
from seclens.observability.metrics import MetricsCollector
from seclens.ports.event_bus import EventBus

logger = logging.getLogger(__name__)


class SearchProbe:
    """Observes search events and records metrics."""

    def __init__(self, event_bus: EventBus, metrics: MetricsCollector) -> None:
        self._metrics = metrics
        event_bus.subscribe(SearchPerformed, self._on_search)

    def _on_search(self, event: SearchPerformed) -> None:
        self._metrics.increment("search_total")
        self._metrics.observe("search_duration_ms", event.duration_ms)
        self._metrics.observe("search_results_count", float(event.results_count))
        if event.cache_hit:
            self._metrics.increment("search_cache_hits")
        logger.info(
            "Search: query=%r results=%d duration=%.1fms cache_hit=%s",
            event.query,
            event.results_count,
            event.duration_ms,
            event.cache_hit,
        )
