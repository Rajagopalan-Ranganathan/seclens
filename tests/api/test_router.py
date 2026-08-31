import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from seclens.api.dependencies import initialize_db
from seclens.main import create_app


@pytest_asyncio.fixture
async def client():
    app = create_app()
    await initialize_db()
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "vuln_count" in data


@pytest.mark.asyncio
async def test_metrics(client):
    resp = await client.get("/api/v1/metrics")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_search_empty_db(client):
    resp = await client.get("/api/v1/search", params={"q": "apache"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["query"] == "apache"
    assert isinstance(data["results"], list)


@pytest.mark.asyncio
async def test_search_requires_query(client):
    resp = await client.get("/api/v1/search")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_cve_not_found(client):
    resp = await client.get("/api/v1/vulns/CVE-9999-9999")
    assert resp.status_code == 404
