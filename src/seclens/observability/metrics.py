"""Metrics collector — structured logging for now, swappable to Prometheus/OTel later."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger("seclens.metrics")


@dataclass
class MetricsCollector:
    """Collects and logs domain metrics as structured JSON."""

    _counters: dict[str, int] = field(default_factory=dict)
    _histograms: dict[str, list[float]] = field(default_factory=dict)

    def increment(self, name: str, value: int = 1, **labels: str) -> None:
        key = self._key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value
        self._emit("counter", name, value, labels)

    def observe(self, name: str, value: float, **labels: str) -> None:
        key = self._key(name, labels)
        self._histograms.setdefault(key, []).append(value)
        self._emit("histogram", name, value, labels)

    def timer(self, name: str, **labels: str) -> _Timer:
        return _Timer(self, name, labels)

    def summary(self) -> dict:
        return {
            "counters": dict(self._counters),
            "histogram_counts": {k: len(v) for k, v in self._histograms.items()},
        }

    @staticmethod
    def _key(name: str, labels: dict) -> str:
        if labels:
            label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
            return f"{name}{{{label_str}}}"
        return name

    @staticmethod
    def _emit(metric_type: str, name: str, value: float, labels: dict) -> None:
        record = {"metric": name, "type": metric_type, "value": value, **labels}
        logger.info(json.dumps(record))


class _Timer:
    def __init__(self, collector: MetricsCollector, name: str, labels: dict):
        self._collector = collector
        self._name = name
        self._labels = labels
        self._start = 0.0

    def __enter__(self) -> _Timer:
        self._start = time.monotonic()
        return self

    def __exit__(self, *exc: object) -> None:
        elapsed_ms = (time.monotonic() - self._start) * 1000
        self._collector.observe(self._name, elapsed_ms, **self._labels)
