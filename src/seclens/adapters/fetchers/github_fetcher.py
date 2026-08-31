"""GitHub REST API adapter for SBOM, manifests, and repo metadata."""

from __future__ import annotations

import base64
import logging
import os
from datetime import date

import httpx

from seclens.domain.models import Dependency, RepoSecuritySignals
from seclens.ports.github_fetcher import GitHubFetcher as GitHubFetcherPort

from .manifest_parser import PREFERRED_MANIFESTS, parse_manifest

logger = logging.getLogger(__name__)

GH_API = "https://api.github.com"


class GitHubApiFetcher(GitHubFetcherPort):
    """Concrete GitHub REST API adapter.

    Uses GITHUB_TOKEN env var for authenticated requests (5000 req/hr).
    Falls back to unauthenticated (60 req/hr) otherwise.
    """

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def fetch_sbom(self, owner: str, repo: str) -> list[Dependency]:
        url = f"{GH_API}/repos/{owner}/{repo}/dependency-graph/sbom"
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(url, headers=self._headers())
                if resp.status_code == 404:
                    logger.info(
                        "SBOM not available for %s/%s, will use manifest fallback", owner, repo
                    )
                    return []
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, OSError, ValueError):
            logger.warning("Failed to fetch SBOM for %s/%s", owner, repo)
            return []

        return self._parse_spdx(data)

    def _parse_spdx(self, data: dict) -> list[Dependency]:
        deps: list[Dependency] = []
        sbom = data.get("sbom", data)
        for pkg in sbom.get("packages", []):
            name = pkg.get("name", "")
            version = pkg.get("versionInfo", "")

            if name.startswith("com.github.") or name == sbom.get("name"):
                continue

            ecosystem = "unknown"
            for ref in pkg.get("externalRefs", []):
                ref_type = ref.get("referenceType", "")
                locator = ref.get("referenceLocator", "")
                if ref_type == "purl" and ":" in locator:
                    eco_part = locator.split(":")[0].removeprefix("pkg:")
                    ecosystem = _PURL_TO_ECOSYSTEM.get(eco_part, eco_part)
                    break

            if not name or name == "SPDXRef-DOCUMENT":
                continue

            # SPDX "DESCRIBES" relationships mark root packages
            is_direct = "DESCRIBES" in str(pkg.get("relationshipType", ""))

            deps.append(
                Dependency(
                    name=name,
                    version=version.removeprefix("v") if version else "",
                    ecosystem=ecosystem,
                    is_direct=is_direct,
                    license=pkg.get("licenseDeclared"),
                )
            )
        return deps

    async def fetch_manifests(self, owner: str, repo: str) -> list[Dependency]:
        deps: list[Dependency] = []
        async with httpx.AsyncClient(timeout=20.0) as client:
            for filename in PREFERRED_MANIFESTS:
                content = await self._fetch_file(client, owner, repo, filename)
                if content is not None:
                    parsed = parse_manifest(filename, content)
                    if parsed:
                        logger.info(
                            "Parsed %d deps from %s/%s/%s", len(parsed), owner, repo, filename
                        )
                        deps.extend(parsed)
                        break
        return deps

    async def _fetch_file(
        self, client: httpx.AsyncClient, owner: str, repo: str, path: str
    ) -> str | None:
        url = f"{GH_API}/repos/{owner}/{repo}/contents/{path}"
        try:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            if data.get("encoding") == "base64":
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            return data.get("content", "")
        except (httpx.HTTPError, OSError, ValueError, KeyError):
            return None

    async def fetch_repo_signals(self, owner: str, repo: str) -> RepoSecuritySignals:
        async with httpx.AsyncClient(timeout=20.0) as client:
            headers = self._headers()

            repo_data = await self._get_json(client, f"{GH_API}/repos/{owner}/{repo}", headers)
            if not repo_data:
                return RepoSecuritySignals()

            last_push = None
            pushed_at = repo_data.get("pushed_at", "")
            if pushed_at:
                try:
                    last_push = date.fromisoformat(pushed_at[:10])
                except (ValueError, TypeError):
                    pass

            branch_protected = None
            default_branch = repo_data.get("default_branch", "main")
            branch_data = await self._get_json(
                client,
                f"{GH_API}/repos/{owner}/{repo}/branches/{default_branch}",
                headers,
            )
            if branch_data:
                branch_protected = branch_data.get("protected", False)

            sec_features = repo_data.get("security_and_analysis", {}) or {}
            secret_scanning = None
            if "secret_scanning" in sec_features:
                secret_scanning = sec_features["secret_scanning"].get("status") == "enabled"

            dep_updates = await self._detect_dependency_updates(client, owner, repo, headers)

            return RepoSecuritySignals(
                default_branch_protected=branch_protected,
                secret_scanning_enabled=secret_scanning,
                code_scanning_enabled=None,
                dependency_updates_enabled=dep_updates,
                license_name=(repo_data.get("license") or {}).get("spdx_id"),
                last_push_date=last_push,
                archived=repo_data.get("archived", False),
                fork=repo_data.get("fork", False),
                stargazers_count=repo_data.get("stargazers_count", 0),
                open_issues_count=repo_data.get("open_issues_count", 0),
            )

    async def fetch_repo_description(self, owner: str, repo: str) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            data = await self._get_json(client, f"{GH_API}/repos/{owner}/{repo}", self._headers())
            return (data or {}).get("description", "") or ""

    async def _detect_dependency_updates(
        self,
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        headers: dict,
    ) -> bool | None:
        """Check for Dependabot, Renovate, or Konflux/Tekton dependency management."""
        vuln_alerts = await self._get_json(
            client,
            f"{GH_API}/repos/{owner}/{repo}/vulnerability-alerts",
            headers,
            accept_404=True,
        )
        if vuln_alerts is not None:
            return True

        config_files = [
            ".github/dependabot.yml",
            ".github/dependabot.yaml",
            "renovate.json",
            "renovate.json5",
            ".renovaterc",
            ".renovaterc.json",
            ".tekton",
        ]
        for path in config_files:
            resp = await self._head_file(client, owner, repo, path, headers)
            if resp:
                return True

        return None

    @staticmethod
    async def _head_file(
        client: httpx.AsyncClient,
        owner: str,
        repo: str,
        path: str,
        headers: dict,
    ) -> bool:
        url = f"{GH_API}/repos/{owner}/{repo}/contents/{path}"
        try:
            resp = await client.head(url, headers=headers)
            return resp.status_code == 200
        except (httpx.HTTPError, OSError):
            return False

    @staticmethod
    async def _get_json(
        client: httpx.AsyncClient,
        url: str,
        headers: dict,
        accept_404: bool = False,
    ) -> dict | None:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                return {} if accept_404 else None
            if resp.status_code == 204:
                return {}
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, OSError, ValueError):
            logger.debug("GitHub API request failed: %s", url)
            return None


_PURL_TO_ECOSYSTEM: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
    "swift": "SwiftURL",
    "cocoapods": "CocoaPods",
}
