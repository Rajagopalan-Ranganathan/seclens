"""Orchestrates privacy data collection and scoring."""

from __future__ import annotations

import asyncio
import logging

from seclens.domain.models.privacy import PrivacyResult, PrivacyScore
from seclens.domain.models.product import SERVICE_MAPPINGS, ServiceInfo
from seclens.domain.privacy_scoring import compute_privacy_score
from seclens.ports.privacy_fetchers import (
    BreachFetcher,
    PrivacySpyFetcher,
    ToSDRFetcher,
    TrackerRegistry,
)

logger = logging.getLogger(__name__)


class PrivacyService:
    """Collects privacy data from all sources and computes a privacy score."""

    def __init__(
        self,
        tosdr: ToSDRFetcher,
        hibp: BreachFetcher,
        trackers: TrackerRegistry,
        privacyspy: PrivacySpyFetcher,
    ) -> None:
        self._tosdr = tosdr
        self._hibp = hibp
        self._trackers = trackers
        self._privacyspy = privacyspy

    async def score_product(self, vendor: str, product: str) -> PrivacyScore | None:
        """Compute a privacy score for a product identified by CPE vendor/product."""
        svc_info = SERVICE_MAPPINGS.get((vendor, product))
        if svc_info is None:
            svc_info = self._guess_service(vendor, product)

        return await self._analyze_service(svc_info)

    async def score_service(
        self, service_name: str, domain: str, tosdr_id: int | None = None
    ) -> PrivacyScore | None:
        """Compute a privacy score for a named service."""
        svc_info = ServiceInfo(name=service_name, domain=domain, tosdr_id=tosdr_id)
        return await self._analyze_service(svc_info)

    async def _analyze_service(self, svc: ServiceInfo) -> PrivacyScore | None:
        result = PrivacyResult(service_name=svc.name, domain=svc.domain)

        tosdr_task = self._fetch_tosdr(svc, result)
        hibp_task = self._fetch_breaches(svc, result)
        tracker_task = self._fetch_trackers(svc, result)
        pspy_task = self._fetch_privacyspy(svc, result)

        await asyncio.gather(tosdr_task, hibp_task, tracker_task, pspy_task)

        return compute_privacy_score(result)

    async def _fetch_tosdr(self, svc: ServiceInfo, result: PrivacyResult) -> None:
        try:
            grade, signals = await self._tosdr.fetch_service(svc.name, tosdr_id=svc.tosdr_id)
            if grade or signals:
                result.tosdr_grade = grade
                result.tosdr_points = signals
                result.sources_used.append("tosdr")
        except Exception:  # noqa: BLE001 — best-effort source
            logger.warning("ToS;DR fetch failed for %s", svc.name)

    async def _fetch_breaches(self, svc: ServiceInfo, result: PrivacyResult) -> None:
        try:
            breaches = await self._hibp.fetch_breaches(svc.domain)
            result.breaches = breaches
            result.sources_used.append("hibp")
        except Exception:  # noqa: BLE001
            logger.warning("HIBP fetch failed for %s", svc.domain)

    async def _fetch_trackers(self, svc: ServiceInfo, result: PrivacyResult) -> None:
        try:
            categories = await self._trackers.lookup(svc.domain)
            result.tracker_categories = categories
            result.sources_used.append("disconnect")
        except Exception:  # noqa: BLE001
            logger.warning("Disconnect lookup failed for %s", svc.domain)

    async def _fetch_privacyspy(self, svc: ServiceInfo, result: PrivacyResult) -> None:
        try:
            score, signals = await self._privacyspy.fetch_score(svc.name, svc.domain)
            if score is not None:
                result.privacyspy_score = score
                result.privacyspy_signals = signals
                result.sources_used.append("privacyspy")
        except Exception:  # noqa: BLE001
            logger.warning("PrivacySpy fetch failed for %s", svc.name)

    @staticmethod
    def _guess_service(vendor: str, product: str) -> ServiceInfo:
        """Best-effort mapping when no curated entry exists."""
        name = product.replace("_", " ").title()
        vendor_display = vendor.replace("_", " ").title()
        if vendor_display.lower() != name.lower():
            name = f"{vendor_display} {name}"
        domain = f"{vendor}.com"
        return ServiceInfo(name=name, domain=domain)
