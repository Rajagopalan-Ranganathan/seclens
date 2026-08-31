import tempfile
from datetime import date
from pathlib import Path

import pytest
import pytest_asyncio

from seclens.adapters.persistence.sqlite_repository import (
    SQLiteProductRepository,
    SQLiteVulnRepository,
)
from seclens.domain.models import PatchInfo, Severity, Vulnerability


@pytest_asyncio.fixture
async def db_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "test.db"
        repo = SQLiteVulnRepository(path)
        await repo.initialize()
        yield path


@pytest_asyncio.fixture
async def vuln_repo(db_path):
    return SQLiteVulnRepository(db_path)


@pytest_asyncio.fixture
async def product_repo(db_path):
    return SQLiteProductRepository(db_path)


def _sample_vuln(cve_id: str = "CVE-2024-0001") -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        description="A test vulnerability in the widget library",
        cvss_score=7.5,
        severity=Severity.HIGH,
        published=date(2024, 1, 15),
        last_modified=date(2024, 2, 1),
        affected_cpes=["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
        epss_score=0.25,
        in_kev=False,
        patches=[PatchInfo(fixed_version="1.1.0", source="nvd")],
    )


@pytest.mark.asyncio
async def test_save_and_find_by_cve(vuln_repo):
    vuln = _sample_vuln()
    saved = await vuln_repo.save_vulnerabilities([vuln])
    assert saved == 1

    found = await vuln_repo.find_by_cve_id("CVE-2024-0001")
    assert found is not None
    assert found.cve_id == "CVE-2024-0001"
    assert found.cvss_score == 7.5
    assert found.severity == Severity.HIGH
    assert found.is_patched is True
    assert found.patches[0].fixed_version == "1.1.0"


@pytest.mark.asyncio
async def test_find_by_cpe(vuln_repo):
    vuln = _sample_vuln()
    await vuln_repo.save_vulnerabilities([vuln])

    results = await vuln_repo.find_by_cpe("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2024-0001"


@pytest.mark.asyncio
async def test_count(vuln_repo):
    assert await vuln_repo.count() == 0
    await vuln_repo.save_vulnerabilities([_sample_vuln()])
    assert await vuln_repo.count() == 1


@pytest.mark.asyncio
async def test_upsert(vuln_repo):
    vuln = _sample_vuln()
    await vuln_repo.save_vulnerabilities([vuln])
    await vuln_repo.save_vulnerabilities([vuln])
    assert await vuln_repo.count() == 1


@pytest.mark.asyncio
async def test_search_fts(vuln_repo):
    await vuln_repo.save_vulnerabilities([_sample_vuln()])
    results = await vuln_repo.search("widget library")
    assert len(results) == 1


@pytest.mark.asyncio
async def test_not_found(vuln_repo):
    found = await vuln_repo.find_by_cve_id("CVE-9999-9999")
    assert found is None


@pytest.mark.asyncio
async def test_save_and_resolve_cpe(product_repo):
    entries = [
        {
            "cpe_uri": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*",
            "part": "a",
            "vendor": "apache",
            "product": "http_server",
            "version": "2.4.51",
            "title": "Apache HTTP Server 2.4.51",
        }
    ]
    saved = await product_repo.save_cpe_dictionary(entries)
    assert saved == 1

    results = await product_repo.resolve_cpe("apache")
    assert len(results) >= 1
    assert results[0]["vendor"] == "apache"


@pytest.mark.asyncio
async def test_search_products(product_repo):
    entries = [
        {
            "cpe_uri": "cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*",
            "part": "o",
            "vendor": "redhat",
            "product": "enterprise_linux",
            "version": "9.0",
            "title": "Red Hat Enterprise Linux 9",
        }
    ]
    await product_repo.save_cpe_dictionary(entries)

    products = await product_repo.search_products("redhat")
    assert len(products) >= 1
    assert products[0].vendor == "redhat"
