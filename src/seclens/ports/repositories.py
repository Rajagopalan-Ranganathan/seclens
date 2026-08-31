from __future__ import annotations

from abc import ABC, abstractmethod

from seclens.domain.models import PatchInfo, Product, Vulnerability


class VulnRepository(ABC):
    """Port for vulnerability persistence."""

    @abstractmethod
    async def save_vulnerabilities(self, vulns: list[Vulnerability]) -> int:
        """Persist vulnerabilities, returning count of new/updated records."""

    @abstractmethod
    async def find_by_cpe(self, cpe_uri: str) -> list[Vulnerability]:
        """Find all vulnerabilities affecting a CPE."""

    @abstractmethod
    async def find_by_cve_id(self, cve_id: str) -> Vulnerability | None:
        """Find a single vulnerability by CVE ID."""

    @abstractmethod
    async def search(self, query: str, limit: int = 50) -> list[Vulnerability]:
        """Full-text search across CVE descriptions."""

    @abstractmethod
    async def update_patches(self, cve_id: str, patches: list[PatchInfo]) -> bool:
        """Merge new patches into an existing CVE's patch list."""

    @abstractmethod
    async def find_redhat_cve_ids(self, limit: int = 5000) -> list[str]:
        """Find CVE IDs affecting Red Hat products without Red Hat patch data."""

    @abstractmethod
    async def count(self) -> int:
        """Total number of stored vulnerabilities."""


class ProductRepository(ABC):
    """Port for product/CPE persistence."""

    @abstractmethod
    async def save_products(self, products: list[Product]) -> int:
        """Persist products, returning count of new/updated records."""

    @abstractmethod
    async def search_products(self, query: str, limit: int = 20) -> list[Product]:
        """Fuzzy search products by name, vendor, or CPE."""

    @abstractmethod
    async def find_by_cpe(self, cpe_uri: str) -> Product | None:
        """Find a product by its CPE URI."""

    @abstractmethod
    async def save_cpe_dictionary(self, cpes: list[dict]) -> int:
        """Bulk import CPE dictionary entries for search resolution."""

    @abstractmethod
    async def resolve_cpe(self, query: str, limit: int = 10) -> list[dict]:
        """Resolve a free-text query to matching CPE entries."""
