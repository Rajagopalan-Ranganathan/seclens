const API = '/api/v1';
const VULNS_PER_PAGE = 25;

const $ = (sel) => document.querySelector(sel);
const show = (el) => el.classList.remove('hidden');
const hide = (el) => el.classList.add('hidden');

function formatCpe(uri) {
    if (!uri || !uri.startsWith('cpe:2.3:')) return escapeHtml(uri || '');
    const parts = uri.split(':');
    // parts: [cpe, 2.3, part, vendor, product, version, update, edition, lang, sw_ed, tgt_sw, tgt_hw, other]
    const part = parts[2], vendor = parts[3], product = parts[4], version = parts[5];
    const meaningful = [part, vendor, product];
    if (version && version !== '*') meaningful.push(version);
    return escapeHtml('cpe:2.3:' + meaningful.join(':'));
}

let _currentVulns = [];
let _currentVulnPage = 1;
let _currentVulnFilter = 'all';

const hero = $('#hero');
const resultsSection = $('#results');
const resultsList = $('#results-list');
const resultsSummary = $('#results-summary');
const scorecardSection = $('#scorecard');
const loading = $('#loading');
const errorMsg = $('#error');
const searchInput = $('#search-input');
const searchForm = $('#search-form');

function toggleScoringInfo() {
    const info = $('#scoring-info');
    const btn = $('#scoring-toggle');
    if (info.classList.contains('hidden')) {
        show(info);
        btn.textContent = 'Hide scoring details';
    } else {
        hide(info);
        btn.textContent = 'How does scoring work?';
    }
}

searchForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = searchInput.value.trim();
    if (q) performSearch(q);
});

$('#back-btn').addEventListener('click', (e) => {
    e.preventDefault();
    showHome();
});

document.querySelectorAll('.quick-links a').forEach((link) => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const q = link.dataset.query;
        searchInput.value = q;
        performSearch(q);
    });
});

function showHome() {
    hero.classList.remove('compact');
    hide(resultsSection);
    hide(scorecardSection);
    hide(errorMsg);
    show(hero);
    searchInput.focus();
}

function showLoading(msg) {
    const loadingText = document.getElementById('loading-text');
    if (loadingText) loadingText.textContent = msg || 'Searching...';
    hide(errorMsg);
    hide(resultsSection);
    hide(scorecardSection);
    show(loading);
}

function hideLoading() {
    hide(loading);
}

function showError(msg) {
    errorMsg.textContent = msg;
    show(errorMsg);
}

function isGitHubUrl(q) {
    return /^(https?:\/\/)?(www\.)?github\.com\/[a-zA-Z0-9_.\-]+\/[a-zA-Z0-9_.\-]+/.test(q);
}

async function performSearch(query) {
    hero.classList.add('compact');

    if (isGitHubUrl(query)) {
        showLoading('Analyzing GitHub project...');
        await analyzeProject(query);
        return;
    }

    showLoading('Searching vulnerability databases...');

    try {
        const resp = await fetch(`${API}/search?q=${encodeURIComponent(query)}`);
        if (!resp.ok) throw new Error(`Search failed: ${resp.status}`);
        const data = await resp.json();

        hideLoading();
        renderResults(data);
    } catch (err) {
        hideLoading();
        showError(`Search failed: ${err.message}`);
    }
}

async function analyzeProject(url) {
    try {
        const resp = await fetch(`${API}/project?url=${encodeURIComponent(url)}`);
        if (!resp.ok) {
            const body = await resp.json().catch(() => ({}));
            throw new Error(body.detail || `Analysis failed: ${resp.status}`);
        }
        const project = await resp.json();

        hideLoading();
        renderProjectScorecard(project);
    } catch (err) {
        hideLoading();
        showError(`Project analysis failed: ${err.message}`);
    }
}

function renderResults(data) {
    resultsSummary.textContent = `${data.total} product${data.total !== 1 ? 's' : ''} found for "${data.query}"`;
    resultsList.innerHTML = '';

    if (data.results.length === 0) {
        resultsList.innerHTML = `
            <div class="no-results">
                <p>No products found. Try a different search term.</p>
                <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.5rem;">
                    Make sure you've synced data first: <code>make sync</code>
                </p>
            </div>
        `;
    }

    for (const product of data.results) {
        const card = document.createElement('div');
        card.className = 'product-card';
        card.addEventListener('click', () => loadScorecard(product.cpe_uri, product.name));

        const gradeClass = product.score ? getGradeClass(product.score.grade) : '';
        const scoreHTML = product.score
            ? `<div class="score-badge">
                   <span class="score-value ${gradeClass}">${product.score.overall}</span>
                   <span class="score-grade ${gradeClass}">${product.score.grade}</span>
               </div>`
            : `<div class="score-badge">
                   <span class="score-value" style="font-size:1rem; color:var(--text-muted)">N/A</span>
               </div>`;

        card.innerHTML = `
            <div class="product-info">
                <h3>${escapeHtml(product.name)}</h3>
                <div class="product-meta">
                    <span class="vendor">${escapeHtml(product.vendor)}</span>
                    <span>${product.vuln_count} CVEs</span>
                    ${product.version ? `<span>v${escapeHtml(product.version)}</span>` : ''}
                </div>
            </div>
            ${scoreHTML}
        `;

        resultsList.appendChild(card);
    }

    show(resultsSection);
    hide(scorecardSection);
}

async function loadScorecard(cpeUri, productName) {
    showLoading();

    try {
        const [scoreResp, vulnsResp] = await Promise.all([
            fetch(`${API}/products/${encodeURIComponent(cpeUri)}/score`),
            fetch(`${API}/products/${encodeURIComponent(cpeUri)}/vulns`),
        ]);

        hideLoading();

        let score = null;
        if (scoreResp.ok) {
            score = await scoreResp.json();
        }

        let vulns = [];
        if (vulnsResp.ok) {
            vulns = await vulnsResp.json();
        }

        renderScorecard(productName, cpeUri, score, vulns);
    } catch (err) {
        hideLoading();
        showError(`Failed to load scorecard: ${err.message}`);
    }
}

function renderScorecard(name, cpe, score, vulns) {
    hide(resultsSection);

    const gradeClass = score ? getGradeClass(score.grade) : '';

    let html = `
        <div class="results-header">
            <a href="#" class="back-link" onclick="event.preventDefault(); hide(scorecardSection); show(resultsSection);">&larr; Back to results</a>
        </div>
        <div class="scorecard-header">
            <div class="scorecard-title">
                <h2>${escapeHtml(name)}</h2>
                <details class="cpe-details">
                    <summary class="cpe-summary">CPE identifier</summary>
                    <code class="cpe">${formatCpe(cpe)}</code>
                </details>
            </div>
    `;

    if (score) {
        html += `
            <div class="big-score">
                <div class="value ${gradeClass}">${score.overall}</div>
                <div class="score-grade ${gradeClass}" style="font-size:1.2rem; margin-top:0.3rem;">${score.grade}</div>
                <div class="label">seclens score</div>
            </div>
        `;
    }

    html += `</div>`;

    if (score) {
        html += `
            <div class="severity-summary">
                ${score.critical_count ? `<span class="severity-chip severity-critical">${score.critical_count} Critical</span>` : ''}
                ${score.high_count ? `<span class="severity-chip severity-high">${score.high_count} High</span>` : ''}
                ${score.medium_count ? `<span class="severity-chip severity-medium">${score.medium_count} Medium</span>` : ''}
                ${score.low_count ? `<span class="severity-chip severity-low">${score.low_count} Low</span>` : ''}
            </div>
            <div class="breakdown-grid">
                ${breakdownItem('Vuln Density', score.breakdown.vuln_density, 'Fewer CVEs per year of product life = higher')}
                ${breakdownItem('Avg Severity', score.breakdown.avg_severity, 'Lower mean CVSS across all CVEs = higher')}
                ${breakdownItem('Exploit Likelihood', score.breakdown.exploit_likelihood, 'Lower EPSS exploitation probability = higher')}
                ${breakdownItem('KEV Exposure', score.breakdown.kev_exposure, 'Fewer confirmed exploited CVEs = higher')}
                ${breakdownItem('Patch Velocity', score.breakdown.patch_velocity, 'Faster median time to fix = higher')}
                ${breakdownItem('Unpatched Ratio', score.breakdown.unpatched_ratio, 'Fewer CVEs without a known fix = higher')}
            </div>
            <p class="score-explainer">Score is 0&ndash;100 (higher = more secure). Weighted: KEV Exposure 20%, Patch Velocity 20%, Unpatched Ratio 20%, Avg Severity 15%, Exploit Likelihood 15%, Vuln Density 10%.</p>
        `;
    }

    if (vulns.length > 0) {
        _currentVulns = vulns;
        _currentVulnPage = 1;
        _currentVulnFilter = 'all';
        html += `<div class="vuln-list">
            <div class="vuln-list-header">
                <h3>Vulnerabilities (<span id="vuln-shown-count">${vulns.length}</span>)</h3>
                <div class="vuln-filters">
                    <button class="filter-btn active" data-filter="all" onclick="filterVulns('all')">All</button>
                    <button class="filter-btn" data-filter="critical" onclick="filterVulns('critical')">Critical</button>
                    <button class="filter-btn" data-filter="high" onclick="filterVulns('high')">High</button>
                    <button class="filter-btn" data-filter="medium" onclick="filterVulns('medium')">Medium</button>
                    <button class="filter-btn" data-filter="patched" onclick="filterVulns('patched')">Patched</button>
                    <button class="filter-btn" data-filter="unpatched" onclick="filterVulns('unpatched')">Unpatched</button>
                </div>
            </div>
            <div id="vuln-items"></div>
            <div id="vuln-pagination" class="pagination"></div>
        </div>`;
    }

    scorecardSection.innerHTML = html;
    show(scorecardSection);

    if (vulns.length > 0) {
        renderVulnPage();
    }
}


// ---- GitHub Project Scorecard ----

let _projectDeps = [];
let _projectDepPage = 1;
let _projectDepFilter = 'all';
const PROJECT_DEPS_PER_PAGE = 20;

function renderProjectScorecard(project) {
    hide(resultsSection);

    const score = project.score;
    const signals = project.repo_signals;
    const gradeClass = score ? getGradeClass(score.grade) : '';

    let html = `
        <div class="results-header">
            <a href="#" class="back-link" onclick="event.preventDefault(); showHome();">&larr; New search</a>
        </div>
        <div class="scorecard-header">
            <div class="scorecard-title">
                <h2><a href="${escapeHtml(project.url)}" target="_blank" rel="noopener">${escapeHtml(project.full_name)}</a></h2>
                ${project.description ? `<p class="project-desc">${escapeHtml(project.description)}</p>` : ''}
            </div>
    `;

    if (score) {
        html += `
            <div class="big-score">
                <div class="value ${gradeClass}">${score.overall}</div>
                <div class="score-grade ${gradeClass}" style="font-size:1.2rem; margin-top:0.3rem;">${score.grade}</div>
                <div class="label">project score</div>
            </div>
        `;
    }
    html += `</div>`;

    if (score) {
        html += `
            <div class="severity-summary">
                <span class="severity-chip">${score.total_deps} deps</span>
                ${score.vulnerable_deps ? `<span class="severity-chip severity-high">${score.vulnerable_deps} vulnerable</span>` : '<span class="severity-chip" style="background:var(--green);color:#fff;">0 vulnerable</span>'}
                ${score.critical_vulns ? `<span class="severity-chip severity-critical">${score.critical_vulns} critical</span>` : ''}
                ${score.high_vulns ? `<span class="severity-chip severity-high">${score.high_vulns} high</span>` : ''}
            </div>
            <div class="breakdown-grid">
                ${breakdownItem('Dependency Risk', score.breakdown.dependency_risk, 'Vulnerability count, severity, and fix availability (50%)')}
                ${breakdownItem('Repo Posture', score.breakdown.repo_posture, 'Branch protection, scanning, dependency updates, maintenance (30%)')}
                ${breakdownItem('Supply Chain', score.breakdown.supply_chain, 'Pinned versions, direct vs transitive vulns (20%)')}
            </div>
        `;
    }

    if (signals) {
        html += `<div class="repo-signals">
            <h3>Repository Security Signals</h3>
            <div class="signals-grid">
                ${signalItem('Branch Protection', signals.default_branch_protected)}
                ${signalItem('Secret Scanning', signals.secret_scanning_enabled)}
                ${signalItem('Code Scanning', signals.code_scanning_enabled)}
                ${signalItem('Dependency Updates', signals.dependency_updates_enabled)}
                ${signalItem('License', signals.license_name ? true : false, signals.license_name || 'None')}
                ${signalItem('Actively Maintained', signals.is_actively_maintained)}
            </div>
            <div class="signals-meta">
                ${signals.stargazers_count ? `<span>&#9733; ${signals.stargazers_count.toLocaleString()}</span>` : ''}
                ${signals.last_push_date ? `<span>Last push: ${signals.last_push_date}</span>` : ''}
                ${signals.archived ? '<span class="tag tag-kev">Archived</span>' : ''}
                ${signals.fork ? '<span class="tag" style="background:var(--surface)">Fork</span>' : ''}
            </div>
        </div>`;
    }

    if (project.dependencies.length > 0) {
        _projectDeps = project.dependencies;
        _projectDepPage = 1;
        _projectDepFilter = 'all';

        const vulnCount = project.dependencies.filter(d => d.is_vulnerable).length;

        html += `<div class="dep-list">
            <div class="vuln-list-header">
                <h3>Dependencies (<span id="dep-shown-count">${project.dependencies.length}</span>)</h3>
                <div class="vuln-filters">
                    <button class="filter-btn active" data-filter="all" onclick="filterDeps('all')">All</button>
                    <button class="filter-btn" data-filter="vulnerable" onclick="filterDeps('vulnerable')">Vulnerable (${vulnCount})</button>
                    <button class="filter-btn" data-filter="safe" onclick="filterDeps('safe')">Safe</button>
                </div>
            </div>
            <div id="dep-items"></div>
            <div id="dep-pagination" class="pagination"></div>
        </div>`;
    }

    scorecardSection.innerHTML = html;
    show(scorecardSection);

    if (project.dependencies.length > 0) {
        renderDepPage();
    }
}

function signalItem(label, value, detail) {
    let icon, cls;
    if (value === true) { icon = '&#10003;'; cls = 'signal-ok'; }
    else if (value === false) { icon = '&#10007;'; cls = 'signal-fail'; }
    else { icon = '?'; cls = 'signal-unknown'; }

    return `<div class="signal-item ${cls}">
        <span class="signal-icon">${icon}</span>
        <span class="signal-label">${label}</span>
        ${detail ? `<span class="signal-detail">${escapeHtml(detail)}</span>` : ''}
    </div>`;
}

function getFilteredDeps() {
    if (_projectDepFilter === 'all') return _projectDeps;
    if (_projectDepFilter === 'vulnerable') return _projectDeps.filter(d => d.is_vulnerable);
    return _projectDeps.filter(d => !d.is_vulnerable);
}

function filterDeps(filter) {
    _projectDepFilter = filter;
    _projectDepPage = 1;
    document.querySelectorAll('.dep-list .filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    renderDepPage();
}

function renderDepPage() {
    const filtered = getFilteredDeps();
    const totalPages = Math.max(1, Math.ceil(filtered.length / PROJECT_DEPS_PER_PAGE));
    _projectDepPage = Math.min(_projectDepPage, totalPages);
    const start = (_projectDepPage - 1) * PROJECT_DEPS_PER_PAGE;
    const pageDeps = filtered.slice(start, start + PROJECT_DEPS_PER_PAGE);

    const countEl = document.getElementById('dep-shown-count');
    if (countEl) countEl.textContent = filtered.length;

    const container = document.getElementById('dep-items');
    if (container) {
        container.innerHTML = pageDeps.map(d => depItem(d)).join('');
    }

    const pagination = document.getElementById('dep-pagination');
    if (pagination) {
        if (totalPages <= 1) {
            pagination.innerHTML = '';
        } else {
            let pHtml = `<button class="page-btn" ${_projectDepPage <= 1 ? 'disabled' : ''} onclick="goToDepPage(${_projectDepPage - 1})">&laquo; Prev</button>`;
            const range = paginationRange(_projectDepPage, totalPages);
            for (const p of range) {
                if (p === '...') {
                    pHtml += `<span class="page-ellipsis">&hellip;</span>`;
                } else {
                    pHtml += `<button class="page-btn ${p === _projectDepPage ? 'active' : ''}" onclick="goToDepPage(${p})">${p}</button>`;
                }
            }
            pHtml += `<button class="page-btn" ${_projectDepPage >= totalPages ? 'disabled' : ''} onclick="goToDepPage(${_projectDepPage + 1})">Next &raquo;</button>`;
            pHtml += `<span class="page-info">${start + 1}&ndash;${Math.min(start + PROJECT_DEPS_PER_PAGE, filtered.length)} of ${filtered.length}</span>`;
            pagination.innerHTML = pHtml;
        }
    }
}

function goToDepPage(page) {
    const filtered = getFilteredDeps();
    const totalPages = Math.ceil(filtered.length / PROJECT_DEPS_PER_PAGE);
    if (page < 1 || page > totalPages) return;
    _projectDepPage = page;
    renderDepPage();
    const depList = document.querySelector('.dep-list');
    if (depList) depList.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function depItem(d) {
    const ecoColors = {
        'PyPI': '#3776ab', 'npm': '#cb3837', 'Go': '#00add8',
        'crates.io': '#dea584', 'Maven': '#c71a36', 'RubyGems': '#cc342d',
    };
    const ecoColor = ecoColors[d.ecosystem] || 'var(--text-muted)';

    let vulnHtml = '';
    if (d.vulnerabilities.length > 0) {
        vulnHtml = `<div class="dep-vulns">`;
        for (const v of d.vulnerabilities.slice(0, 5)) {
            const sevColor = {
                CRITICAL: 'var(--critical)', HIGH: 'var(--orange)',
                MEDIUM: 'var(--yellow)', LOW: 'var(--green)',
            }[v.severity] || 'var(--text-muted)';
            const cveId = v.aliases.find(a => a.startsWith('CVE-')) || v.vuln_id;
            const vulnUrl = cveId.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cveId}` : v.url;
            vulnHtml += `<div class="dep-vuln-entry">
                <a href="${vulnUrl}" target="_blank" rel="noopener" style="color:${sevColor}; font-family:var(--mono); font-size:0.8rem;">${cveId}</a>
                <span style="color:${sevColor}; font-size:0.75rem;">${v.severity}</span>
                ${v.fixed_version ? `<span class="tag tag-patched" style="font-size:0.65rem;">Fix: ${escapeHtml(v.fixed_version)}</span>` : ''}
            </div>`;
        }
        if (d.vulnerabilities.length > 5) {
            vulnHtml += `<div style="font-size:0.75rem; color:var(--text-muted)">+${d.vulnerabilities.length - 5} more</div>`;
        }
        vulnHtml += `</div>`;
    }

    return `
        <div class="dep-item ${d.is_vulnerable ? 'dep-vulnerable' : ''}">
            <div class="dep-header">
                <span class="dep-name">${escapeHtml(d.name)}</span>
                <span class="dep-version">${escapeHtml(d.version || 'unpinned')}</span>
                <span class="dep-eco" style="color:${ecoColor}">${d.ecosystem}</span>
                ${!d.is_direct ? '<span class="tag" style="font-size:0.65rem; background:var(--surface)">transitive</span>' : ''}
                ${d.is_vulnerable ? `<span class="tag tag-unpatched">${d.vuln_count} vuln${d.vuln_count !== 1 ? 's' : ''}</span>` : '<span class="tag tag-patched" style="font-size:0.65rem;">clean</span>'}
            </div>
            ${vulnHtml}
        </div>
    `;
}

function breakdownItem(label, value, hint) {
    const color = value >= 80 ? 'var(--green)' :
                  value >= 60 ? 'var(--yellow)' :
                  value >= 40 ? 'var(--orange)' : 'var(--red)';
    return `
        <div class="breakdown-item" title="${hint || ''}">
            <div class="label">${label}</div>
            <div style="font-family:var(--mono); font-weight:600;">${value.toFixed(1)}<span style="font-size:0.7em; color:var(--text-muted)">/100</span></div>
            <div class="bar"><div class="bar-fill" style="width:${value}%; background:${color}"></div></div>
            ${hint ? `<div class="breakdown-hint">${hint}</div>` : ''}
        </div>
    `;
}

function vulnItem(v) {
    const severityColor = {
        CRITICAL: 'var(--critical)', HIGH: 'var(--orange)',
        MEDIUM: 'var(--yellow)', LOW: 'var(--green)', NONE: 'var(--text-muted)'
    }[v.severity] || 'var(--text-muted)';

    let tags = '';
    if (v.in_kev) tags += '<span class="tag tag-kev">KEV</span>';
    if (v.is_patched) tags += '<span class="tag tag-patched">Patched</span>';
    else tags += '<span class="tag tag-unpatched">Unpatched</span>';
    if (v.epss_score) tags += `<span class="tag" style="background:var(--surface);color:var(--text-muted)">EPSS: ${(v.epss_score * 100).toFixed(1)}%</span>`;

    let patchLinks = '';
    if (v.patches && v.patches.length > 0) {
        const advisories = v.patches
            .filter(p => p.advisory_id && p.advisory_url)
            .slice(0, 3)
            .map(p => `<a href="${escapeHtml(p.advisory_url)}" target="_blank" rel="noopener" class="advisory-link">${escapeHtml(p.advisory_id)}</a>`);
        if (advisories.length > 0) {
            patchLinks = `<span class="advisory-links">${advisories.join(' ')}</span>`;
        }
    }

    return `
        <div class="vuln-item">
            <div class="vuln-header">
                <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve_id)}" target="_blank" rel="noopener" class="cve-id">${v.cve_id}</a>
                <span class="cvss" style="color:${severityColor}">${v.cvss_score.toFixed(1)} ${v.severity}</span>
            </div>
            <div class="vuln-desc">${escapeHtml(v.description)}</div>
            <div class="vuln-tags">${tags}${patchLinks}</div>
        </div>
    `;
}

function getFilteredVulns() {
    if (_currentVulnFilter === 'all') return _currentVulns;
    if (_currentVulnFilter === 'patched') return _currentVulns.filter(v => v.is_patched);
    if (_currentVulnFilter === 'unpatched') return _currentVulns.filter(v => !v.is_patched);
    return _currentVulns.filter(v => v.severity.toLowerCase() === _currentVulnFilter);
}

function filterVulns(filter) {
    _currentVulnFilter = filter;
    _currentVulnPage = 1;

    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });

    renderVulnPage();
}

function renderVulnPage() {
    const filtered = getFilteredVulns();
    const totalPages = Math.max(1, Math.ceil(filtered.length / VULNS_PER_PAGE));
    _currentVulnPage = Math.min(_currentVulnPage, totalPages);

    const start = (_currentVulnPage - 1) * VULNS_PER_PAGE;
    const pageVulns = filtered.slice(start, start + VULNS_PER_PAGE);

    const countEl = document.getElementById('vuln-shown-count');
    if (countEl) countEl.textContent = filtered.length;

    const container = document.getElementById('vuln-items');
    if (container) {
        container.innerHTML = pageVulns.map(v => vulnItem(v)).join('');
    }

    const pagination = document.getElementById('vuln-pagination');
    if (pagination) {
        if (totalPages <= 1) {
            pagination.innerHTML = '';
        } else {
            let pHtml = '';
            pHtml += `<button class="page-btn" ${_currentVulnPage <= 1 ? 'disabled' : ''} onclick="goToVulnPage(${_currentVulnPage - 1})">&laquo; Prev</button>`;

            const range = paginationRange(_currentVulnPage, totalPages);
            for (const p of range) {
                if (p === '...') {
                    pHtml += `<span class="page-ellipsis">&hellip;</span>`;
                } else {
                    pHtml += `<button class="page-btn ${p === _currentVulnPage ? 'active' : ''}" onclick="goToVulnPage(${p})">${p}</button>`;
                }
            }

            pHtml += `<button class="page-btn" ${_currentVulnPage >= totalPages ? 'disabled' : ''} onclick="goToVulnPage(${_currentVulnPage + 1})">Next &raquo;</button>`;
            pHtml += `<span class="page-info">${start + 1}&ndash;${Math.min(start + VULNS_PER_PAGE, filtered.length)} of ${filtered.length}</span>`;
            pagination.innerHTML = pHtml;
        }
    }
}

function paginationRange(current, total) {
    if (total <= 7) return Array.from({length: total}, (_, i) => i + 1);
    const pages = [];
    pages.push(1);
    if (current > 3) pages.push('...');
    for (let i = Math.max(2, current - 1); i <= Math.min(total - 1, current + 1); i++) {
        pages.push(i);
    }
    if (current < total - 2) pages.push('...');
    pages.push(total);
    return pages;
}

function goToVulnPage(page) {
    const filtered = getFilteredVulns();
    const totalPages = Math.ceil(filtered.length / VULNS_PER_PAGE);
    if (page < 1 || page > totalPages) return;
    _currentVulnPage = page;
    renderVulnPage();
    const vulnList = document.querySelector('.vuln-list');
    if (vulnList) vulnList.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function getGradeClass(grade) {
    if (!grade) return '';
    const letter = grade[0].toLowerCase();
    if (letter === 'a') return 'grade-a';
    if (letter === 'b') return 'grade-b';
    if (letter === 'c') return 'grade-c';
    return 'grade-d';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
}
