# API Reference

All endpoints are served under `/api/v1`. The server runs on `http://localhost:8000` by default.

## Endpoints

### Product Search

#### `GET /api/v1/search`

Search for software products by name, CPE, or keyword.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | Yes | Search query (e.g., "RHEL 9", "openssl", "openshift 4.0") |

**Response** (`SearchResponse`):

```json
{
  "query": "RHEL 9",
  "results": [
    {
      "name": "Red Hat Enterprise Linux 9.0",
      "cpe_uri": "cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*",
      "vendor": "Red Hat",
      "version": "9.0",
      "vuln_count": 529,
      "score": {
        "overall": 75.2,
        "grade": "C",
        "computed_at": "2026-08-31T21:12:11Z",
        "total_cves": 529,
        "critical_count": 9,
        "high_count": 179,
        "medium_count": 303,
        "low_count": 38,
        "none_count": 0,
        "breakdown": {
          "vuln_density": 27.8,
          "avg_severity": 63.4,
          "exploit_likelihood": 70.0,
          "kev_exposure": 100.0,
          "patch_velocity": 75.2,
          "unpatched_ratio": 87.0
        }
      }
    }
  ],
  "total": 1
}
```

### Product Score

#### `GET /api/v1/products/{cpe}/score`

Get the security scorecard for a specific product by CPE URI.

**Path parameter**: Full CPE 2.3 URI (URL-encoded)

**Response** (`SecurityScoreResponse`): Same `score` object as in search results.

### Product Vulnerabilities

#### `GET /api/v1/products/{cpe}/vulns`

List all vulnerabilities affecting a product.

**Response**: Array of `VulnerabilityResponse`:

```json
[
  {
    "cve_id": "CVE-2024-1086",
    "description": "A use-after-free vulnerability in the Linux kernel...",
    "cvss_score": 7.8,
    "severity": "HIGH",
    "published": "2024-01-31",
    "last_modified": "2024-04-01",
    "epss_score": null,
    "in_kev": false,
    "is_patched": true,
    "patches": [
      {
        "fixed_version": "3.10.0",
        "advisory_id": "RHSA-2024:1332",
        "advisory_url": "https://access.redhat.com/errata/RHSA-2024:1332",
        "patch_date": "2024-03-14",
        "source": "redhat"
      }
    ],
    "references": []
  }
]
```

### Product Patches

#### `GET /api/v1/products/{cpe}/patches`

List only the patched vulnerabilities (enriched with vendor advisory data for Red Hat products).

### GitHub Project Analysis

#### `GET /api/v1/project`

Analyze a GitHub repository's security posture.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | GitHub repository URL |

**Response** (`ProjectResponse`):

```json
{
  "owner": "pallets",
  "repo": "flask",
  "full_name": "pallets/flask",
  "url": "https://github.com/pallets/flask",
  "description": "The Python micro framework for building web applications.",
  "score": {
    "overall": 89.3,
    "grade": "B+",
    "computed_at": "2026-08-31T21:25:00Z",
    "total_deps": 120,
    "vulnerable_deps": 0,
    "critical_vulns": 0,
    "high_vulns": 0,
    "breakdown": {
      "dependency_risk": 100.0,
      "repo_posture": 75.0,
      "supply_chain": 84.2
    }
  },
  "repo_signals": {
    "default_branch_protected": true,
    "secret_scanning_enabled": null,
    "code_scanning_enabled": null,
    "dependabot_enabled": true,
    "license_name": "BSD-3-Clause",
    "last_push_date": "2026-08-28",
    "archived": false,
    "fork": false,
    "stargazers_count": 68500,
    "is_actively_maintained": true
  },
  "dependencies": [
    {
      "name": "werkzeug",
      "version": "3.0.1",
      "ecosystem": "PyPI",
      "is_direct": true,
      "license": null,
      "is_vulnerable": false,
      "vuln_count": 0,
      "critical_count": 0,
      "high_count": 0,
      "vulnerabilities": []
    }
  ],
  "total_deps": 120,
  "vulnerable_deps": 0
}
```

### Data Sync

#### `POST /api/v1/sync`

Trigger a full data sync from all sources (NVD, EPSS, KEV, Red Hat).

**Response** (`SyncResponse`):

```json
{
  "status": "completed",
  "counts": {
    "nvd": 5000,
    "epss": 230000,
    "kev": 1100,
    "redhat": 476
  }
}
```

#### `POST /api/v1/sync/redhat`

Trigger Red Hat advisory enrichment only.

### Operational

#### `GET /api/v1/health`

Health check with local database stats.

```json
{
  "status": "ok",
  "vuln_count": 5000,
  "version": "0.1.0"
}
```

#### `GET /api/v1/metrics`

Structured metrics from observability probes.

### Vulnerability Detail

#### `GET /api/v1/vulns/{cve_id}`

Look up a single CVE by ID (e.g., `CVE-2024-1086`).

## Error Responses

All errors follow the FastAPI standard format:

```json
{
  "detail": "Product not found: cpe:2.3:..."
}
```

| Status | Meaning |
|--------|---------|
| 400 | Invalid request (bad URL, missing parameter) |
| 404 | Resource not found |
| 502 | Upstream API failure (GitHub, NVD, etc.) |
