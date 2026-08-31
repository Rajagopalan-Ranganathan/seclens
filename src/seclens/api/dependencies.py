"""FastAPI dependency injection — wires ports to adapters."""

from __future__ import annotations

from pathlib import Path

from seclens.adapters.events.in_memory_bus import InMemoryEventBus
from seclens.adapters.fetchers.epss_fetcher import EPSSDataFetcher
from seclens.adapters.fetchers.github_fetcher import GitHubApiFetcher
from seclens.adapters.fetchers.kev_fetcher import CISAKEVFetcher
from seclens.adapters.fetchers.nvd_fetcher import NVDFetcher
from seclens.adapters.fetchers.osv_fetcher import OSVApiFetcher
from seclens.adapters.fetchers.redhat_fetcher import RedHatAdvisoryFetcher
from seclens.adapters.persistence.sqlite_repository import (
    SQLiteProductRepository,
    SQLiteVulnRepository,
)
from seclens.application.project_service import ProjectService
from seclens.application.scoring_service import ScoringService
from seclens.application.search_service import SearchService
from seclens.application.sync_service import SyncService
from seclens.observability.metrics import MetricsCollector
from seclens.observability.probes.scoring_probe import ScoringProbe
from seclens.observability.probes.search_probe import SearchProbe
from seclens.observability.probes.sync_probe import SyncProbe

_DB_PATH = Path(__file__).resolve().parents[3] / "data" / "seclens.db"

# Singletons (created once, reused across requests)
_event_bus = InMemoryEventBus()
_metrics = MetricsCollector()
_vuln_repo = SQLiteVulnRepository(_DB_PATH)
_product_repo = SQLiteProductRepository(_DB_PATH)
_nvd_fetcher = NVDFetcher()
_epss_fetcher = EPSSDataFetcher()
_kev_fetcher = CISAKEVFetcher()
_redhat_fetcher = RedHatAdvisoryFetcher()
_github_fetcher = GitHubApiFetcher()
_osv_fetcher = OSVApiFetcher()

# Wire probes to event bus
_search_probe = SearchProbe(_event_bus, _metrics)
_scoring_probe = ScoringProbe(_event_bus, _metrics)
_sync_probe = SyncProbe(_event_bus, _metrics)


def get_search_service() -> SearchService:
    return SearchService(_product_repo, _vuln_repo, _event_bus, vuln_fetcher=_nvd_fetcher)


def get_scoring_service() -> ScoringService:
    return ScoringService(_product_repo, _vuln_repo, _event_bus, advisory_fetcher=_redhat_fetcher)


def get_sync_service() -> SyncService:
    return SyncService(
        _vuln_repo,
        _product_repo,
        _nvd_fetcher,
        _epss_fetcher,
        _kev_fetcher,
        _event_bus,
        advisory_fetcher=_redhat_fetcher,
    )


def get_vuln_repo() -> SQLiteVulnRepository:
    return _vuln_repo


def get_metrics() -> MetricsCollector:
    return _metrics


def get_project_service() -> ProjectService:
    return ProjectService(_github_fetcher, _osv_fetcher)


async def initialize_db() -> None:
    await _vuln_repo.initialize()
