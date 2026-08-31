from __future__ import annotations

import logging

from seclens.domain.events import ScoreComputed
from seclens.observability.metrics import MetricsCollector
from seclens.ports.event_bus import EventBus

logger = logging.getLogger(__name__)


class ScoringProbe:
    """Observes score computation events and records metrics."""

    def __init__(self, event_bus: EventBus, metrics: MetricsCollector) -> None:
        self._metrics = metrics
        event_bus.subscribe(ScoreComputed, self._on_score)

    def _on_score(self, event: ScoreComputed) -> None:
        self._metrics.increment("score_computations_total")
        self._metrics.observe("score_computation_ms", event.computation_ms)
        self._metrics.observe("score_value", event.score)
        logger.info(
            "Score: product=%r cpe=%r score=%.1f grade=%s duration=%.1fms",
            event.product_name,
            event.cpe_uri,
            event.score,
            event.grade,
            event.computation_ms,
        )
