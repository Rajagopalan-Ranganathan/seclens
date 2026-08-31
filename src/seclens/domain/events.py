from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class DomainEvent:
    """Base class for all domain events."""

    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass(frozen=True)
class SearchPerformed(DomainEvent):
    query: str = ""
    results_count: int = 0
    duration_ms: float = 0.0
    cache_hit: bool = False


@dataclass(frozen=True)
class ScoreComputed(DomainEvent):
    product_name: str = ""
    cpe_uri: str = ""
    score: float = 0.0
    grade: str = ""
    computation_ms: float = 0.0


@dataclass(frozen=True)
class DataSyncCompleted(DomainEvent):
    source: str = ""
    records_synced: int = 0
    duration_ms: float = 0.0
    errors: list[str] = field(default_factory=list)
