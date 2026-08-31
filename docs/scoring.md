# Scoring Algorithms

Seclens uses two distinct scoring algorithms: one for **products** (identified by CPE) and one for **GitHub projects** (identified by repository URL). Both produce a 0-100 score where higher = more secure.

## Product Scoring (`domain/scoring.py`)

The product score evaluates the security posture of a software product based on its CVE history.

### Factor Weights

```
Overall = Vuln Density    × 0.10
        + Avg Severity    × 0.15
        + Exploit Likelih × 0.15
        + KEV Exposure    × 0.20
        + Patch Velocity  × 0.20
        + Unpatched Ratio × 0.20
```

The weights emphasize **risk management** (KEV, patching) over **volume** (density). A product with many CVEs that are quickly patched scores higher than one with few CVEs that linger unpatched.

### Individual Factors

#### 1. Vulnerability Density (10% weight)

**What**: CVEs per year relative to product age.

**Formula**: Logarithmic scale to avoid penalizing heavily-audited products.

```
score = 100 - 15 × ln(density)
```

where `density = total_cves / years_since_earliest_cve`.

| CVEs/year | Score |
|-----------|-------|
| 1 | 100 |
| 10 | 65 |
| 50 | 41 |
| 200 | 20 |
| 500 | 7 |

**Rationale**: A product like RHEL or Linux Kernel has hundreds of CVEs/year because it's heavily audited. More CVEs found and fixed can indicate a healthy security process, not a weak one.

#### 2. Average Severity (15% weight)

**What**: Mean effective CVSS across all CVEs.

**Key insight**: Patched CVEs count at **half their CVSS** since the active risk is substantially reduced once a fix exists.

```python
effective_cvss = cvss_score * 0.5 if is_patched else cvss_score
score = (10.0 - mean_effective_cvss) × 10
```

| Mean effective CVSS | Score |
|---------------------|-------|
| 2.0 | 80 |
| 4.0 | 60 |
| 6.0 | 40 |
| 8.0 | 20 |

#### 3. Exploit Likelihood (15% weight)

**What**: Mean EPSS (Exploit Prediction Scoring System) probability.

```
score = (1.0 - mean_epss) × 100
```

When no EPSS data is available, defaults to **70.0** (lean positive -- no evidence of exploitation).

#### 4. KEV Exposure (20% weight)

**What**: Ratio of CVEs on the CISA Known Exploited Vulnerabilities catalog.

```
score = (1.0 - kev_count / total_cves) × 100
```

Any CVE on KEV means it's been actively exploited in the wild. This is the strongest negative signal.

#### 5. Patch Velocity (20% weight)

**What**: Median days between CVE publication and fix release.

**Formula**: Logistic decay curve centered at 90 days.

```
score = 100 / (1 + (median_days / 90)^1.5)
```

| Median days | Score |
|-------------|-------|
| 0 | 100 |
| 7 | 97 |
| 30 | 82 |
| 45 | 73 |
| 90 | 50 |
| 180 | 26 |
| 365 | 11 |

When no patch data exists, defaults to **40.0**.

**Rationale**: A logistic curve is generous to typical enterprise patch cycles (30-60 days) while sharply penalizing products that take months to patch.

#### 6. Unpatched Ratio (20% weight)

**What**: Percentage of CVEs without any known fix.

```
score = max(30, 100 - ratio × 70)
```

The floor of 30 accounts for NVD's incomplete patch data -- many CVEs are patched via vendor advisories (RHSA, USN) that NVD doesn't always record.

### Grade Scale

| Grade | Score Range |
|-------|------------|
| A+ | 97-100 |
| A | 93-96 |
| A- | 90-92 |
| B+ | 87-89 |
| B | 83-86 |
| B- | 80-82 |
| C+ | 77-79 |
| C | 73-76 |
| C- | 70-72 |
| D+ | 67-69 |
| D | 63-66 |
| D- | 60-62 |
| F | < 60 |

### Example: RHEL 9

```
529 CVEs, 9 critical, 179 high, 303 medium, 38 low
Median patch time: ~43 days, ~87% patched

Vuln Density:      27.8  (176 CVEs/yr, log scale)
Avg Severity:      63.4  (mean ~3.7 effective CVSS after halving patched)
Exploit Likelihood: 70.0  (no EPSS data, default positive)
KEV Exposure:     100.0  (zero on KEV)
Patch Velocity:    75.2  (43-day median, logistic curve)
Unpatched Ratio:   87.0  (87% have patches)

Overall: 75.2 (C grade)
```

---

## Project Scoring (`domain/project_scoring.py`)

The project score evaluates the security posture of a GitHub repository.

### Factor Weights

```
Overall = Dependency Risk   × 0.50
        + Repo Posture      × 0.30
        + Supply Chain      × 0.20
```

### Individual Factors

#### 1. Dependency Risk (50% weight)

Evaluates the vulnerability landscape of the project's dependencies.

**Scoring**:
- Starts at 100
- Subtracts based on percentage of vulnerable deps (-30 max)
- Subtracts for critical CVEs (-8 per, capped at -30)
- Subtracts for high CVEs (-3 per, capped at -20)
- Subtracts for other vulns (-0.5 per, capped at -10)
- Adds back if fixes are available (+15 max)

#### 2. Repo Security Posture (30% weight)

Evaluates the repository's security configuration via GitHub API.

| Signal | Points |
|--------|--------|
| Default branch protection | 25 |
| Secret scanning enabled | 20 |
| Code scanning (CodeQL) | 15 |
| Dependabot enabled | 15 |
| License declared | 10 |
| Actively maintained | 15 |

Unknown signals receive 50% credit (may not be visible without admin access).

#### 3. Supply Chain Signals (20% weight)

Evaluates dependency management hygiene.

- Base score: 70
- Pinned versions bonus: +15 (proportional)
- Clean direct deps bonus: +10
- Direct dep vulns penalty: -15 (proportional)
- Transitive vuln penalty: -2 per, capped at -10

### Example: pallets/flask

```
120 deps, 0 vulnerable, branch protected, BSD-3-Clause

Dependency Risk: 100.0  (zero vulnerable deps)
Repo Posture:     75.0  (protected, licensed, maintained, some signals unknown)
Supply Chain:     84.2  (all pinned, no direct vulns)

Overall: 89.3 (B+ grade)
```
