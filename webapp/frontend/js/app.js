/**
 * CodeShield AI — Frontend Application Logic
 * Handles scanning, rendering results, charts, and interactivity.
 */

const API_BASE = 'http://localhost:8000';

// ─── State ────────────────────────────────────────────────────────────────────
let currentData = null;
let currentFilter = 'ALL';
let doughnutChart = null;
let barChart = null;

const SEV_COLORS = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#10b981'
};

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  $('scan-btn').addEventListener('click', handleScan);
  $('repo-url-input').addEventListener('keydown', e => { if (e.key === 'Enter') handleScan(); });
  $('new-scan-btn').addEventListener('click', resetToHero);

  document.querySelectorAll('.example-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $('repo-url-input').value = btn.dataset.url;
      $('repo-url-input').focus();
    });
  });

  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.sev;
      renderVulnList(currentData.vulnerabilities);
    });
  });

  document.querySelectorAll('.chart-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.chart-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      if (btn.dataset.chart === 'doughnut') {
        $('chart-doughnut-wrap').classList.remove('hidden');
        $('chart-bar-wrap').classList.add('hidden');
      } else {
        $('chart-doughnut-wrap').classList.add('hidden');
        $('chart-bar-wrap').classList.remove('hidden');
      }
    });
  });
});

// ─── Scan ─────────────────────────────────────────────────────────────────────
async function handleScan() {
  const url = $('repo-url-input').value.trim();
  if (!url) { showError('Please enter a GitHub repository URL.'); return; }
  if (!url.startsWith('https://github.com/')) {
    showError('URL must start with https://github.com/');
    return;
  }
  clearError();
  showLoading();

  try {
    const data = await scanRepo(url);
    currentData = data;
    renderResults(data);
  } catch (err) {
    hideLoading();
    showError(err.message || 'Scan failed. Please try again.');
  }
}

async function scanRepo(url) {
  animateLoadingSteps();
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo_url: url }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Server error: ${res.status}`);
  }
  return res.json();
}

// ─── Loading Steps ────────────────────────────────────────────────────────────
function animateLoadingSteps() {
  const steps = ['step-clone', 'step-scan', 'step-analyze'];
  let i = 0;
  steps.forEach(id => {
    const el = $(id);
    el.classList.remove('active', 'done');
  });
  $(steps[0]).classList.add('active');

  const iv = setInterval(() => {
    if (i < steps.length - 1) {
      $(steps[i]).classList.remove('active');
      $(steps[i]).classList.add('done');
      i++;
      $(steps[i]).classList.add('active');
    } else {
      clearInterval(iv);
    }
  }, 1800);
}

// ─── Render Results ───────────────────────────────────────────────────────────
function renderResults(data) {
  hideLoading();
  $('results-section').classList.remove('hidden');
  $('scan-card').classList.add('hidden');

  // Repo info
  $('result-repo-name').textContent = data.repo_name;
  $('result-scan-time').textContent = data.stats.timestamp;

  // Score
  const s = data.score;
  $('score-value').textContent = s.score;
  $('score-value').style.color = scoreColor(s.score);
  $('score-grade').textContent = s.grade;
  $('score-grade').style.color = scoreColor(s.score);
  $('score-grade').style.borderColor = scoreColor(s.score) + '44';
  $('score-label').textContent = s.label;
  $('score-pass-badge').textContent = s.passed ? '✅ PASSED' : '❌ FAILED';
  $('score-pass-badge').style.background = s.passed ? 'rgba(16,185,129,.15)' : 'rgba(239,68,68,.15)';
  $('score-pass-badge').style.color = s.passed ? '#10b981' : '#ef4444';

  // Severity counts
  $('count-critical').textContent = data.summary.CRITICAL;
  $('count-high').textContent = data.summary.HIGH;
  $('count-medium').textContent = data.summary.MEDIUM;
  $('count-low').textContent = data.summary.LOW;

  // Stats strip
  $('stat-files').textContent = data.stats.files_scanned.toLocaleString();
  $('stat-lines').textContent = data.stats.lines_scanned.toLocaleString();
  $('stat-issues').textContent = data.vulnerabilities.length;
  $('stat-duration').textContent = data.stats.duration_ms + 'ms';
  $('stat-affected').textContent = data.affected_files.length;

  // Charts
  renderScoreGauge(s.score);
  renderDoughnut(data.summary);
  renderBarChart(data.vulnerabilities);

  // File tree
  renderFileTree(data.affected_files);

  // Vuln list
  renderVulnList(data.vulnerabilities);

  // Scroll to results
  $('results-section').scrollIntoView({ behavior: 'smooth' });
}

// ─── Score Gauge (doughnut) ───────────────────────────────────────────────────
function renderScoreGauge(score) {
  const ctx = $('score-gauge').getContext('2d');
  if (window._gaugeChart) window._gaugeChart.destroy();
  window._gaugeChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [score, 100 - score],
        backgroundColor: [scoreColor(score), 'rgba(255,255,255,.06)'],
        borderWidth: 0,
        hoverOffset: 0,
      }]
    },
    options: {
      cutout: '80%', responsive: false,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      animation: { animateRotate: true, duration: 800 },
    }
  });
}

function scoreColor(score) {
  if (score >= 75) return '#10b981';
  if (score >= 50) return '#eab308';
  return '#ef4444';
}

// ─── Severity Doughnut ────────────────────────────────────────────────────────
function renderDoughnut(summary) {
  const ctx = $('sev-doughnut').getContext('2d');
  if (doughnutChart) doughnutChart.destroy();
  const labels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const vals = labels.map(l => summary[l] || 0);
  const total = vals.reduce((a, b) => a + b, 0);
  if (total === 0) { vals[4] = 1; } // show INFO if empty

  doughnutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: vals,
        backgroundColor: labels.map(l => SEV_COLORS[l]),
        borderWidth: 0,
      }]
    },
    options: {
      responsive: false,
      plugins: {
        legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 11 }, padding: 8, boxWidth: 12 } },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}` } }
      },
      animation: { duration: 600 }
    }
  });
}

// ─── Bar Chart by Rule ────────────────────────────────────────────────────────
function renderBarChart(vulns) {
  const ctx = $('type-bar').getContext('2d');
  if (barChart) barChart.destroy();

  const ruleCount = {};
  vulns.forEach(v => { ruleCount[v.rule_id] = (ruleCount[v.rule_id] || 0) + 1; });
  const sorted = Object.entries(ruleCount).sort((a, b) => b[1] - a[1]).slice(0, 8);

  barChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: sorted.map(([id]) => id),
      datasets: [{
        label: 'Occurrences',
        data: sorted.map(([, c]) => c),
        backgroundColor: 'rgba(99,102,241,.7)',
        borderRadius: 6,
        borderSkipped: false,
      }]
    },
    options: {
      responsive: false, indexAxis: 'y',
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: ctx => ` ${ctx.parsed.x} occurrences` } } },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,.05)' }, ticks: { color: '#64748b' } },
        y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } } }
      },
      animation: { duration: 600 }
    }
  });
}

// ─── File Tree ────────────────────────────────────────────────────────────────
function renderFileTree(files) {
  const container = $('file-tree');
  if (!files.length) { container.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">No affected files</div>'; return; }
  container.innerHTML = files.map(f =>
    `<div class="file-item" title="${esc(f)}">📄 ${esc(f)}</div>`
  ).join('');
}

// ─── Vuln List ────────────────────────────────────────────────────────────────
function renderVulnList(vulns) {
  const container = $('vuln-list');
  const empty = $('vuln-empty');

  const filtered = currentFilter === 'ALL' ? vulns : vulns.filter(v => v.severity === currentFilter);
  const sorted = [...filtered].sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return order[a.severity] - order[b.severity];
  });

  if (!sorted.length) {
    container.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }
  empty.classList.add('hidden');
  container.innerHTML = sorted.map(v => vulnCardHtml(v)).join('');

  // Expand/collapse
  container.querySelectorAll('.vuln-card-header').forEach(header => {
    header.addEventListener('click', () => {
      header.parentElement.classList.toggle('expanded');
    });
  });
}

function vulnCardHtml(v) {
  const c = SEV_COLORS[v.severity] || '#fff';
  const fileShort = v.location.file.split('/').slice(-2).join('/');

  const metaChips = [
    v.cwe_id ? `<span class="vuln-meta-chip"><a href="https://cwe.mitre.org/data/definitions/${v.cwe_id.replace('CWE-','')}.html" target="_blank">${esc(v.cwe_id)}</a></span>` : '',
    v.owasp_category ? `<span class="vuln-meta-chip">${esc(v.owasp_category)}</span>` : '',
  ].filter(Boolean).join('');

  const diff = v.remediation_code ? `
    <div class="vuln-section-label" style="margin-top:12px">Code Fix</div>
    <div class="diff-wrap">
      <div class="diff-panel diff-before">
        <div class="diff-label">🔴 Vulnerable</div>
        <pre class="diff-code">${esc(v.location.snippet || '')}</pre>
      </div>
      <div class="diff-panel diff-after">
        <div class="diff-label">🟢 Fixed</div>
        <pre class="diff-code">${esc(v.remediation_code)}</pre>
      </div>
    </div>` : (v.location.snippet ? `
    <div class="vuln-section-label" style="margin-top:12px">Vulnerable Code</div>
    <div class="diff-panel diff-before"><div class="diff-label">🔴 Snippet</div><pre class="diff-code">${esc(v.location.snippet)}</pre></div>` : '');

  return `
  <div class="vuln-card" style="border-left-color:${c}">
    <div class="vuln-card-header">
      <span class="vuln-sev-badge" style="background:${c}22;color:${c};border:1px solid ${c}44">${v.severity}</span>
      <span class="vuln-rule-id">${esc(v.rule_id)}</span>
      <span class="vuln-title">${esc(v.rule_name)}</span>
      <span class="vuln-loc-chip">${esc(fileShort)}:${v.location.line}</span>
      <svg class="vuln-expand-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
    </div>
    <div class="vuln-card-body">
      <div class="vuln-msg">${esc(v.message)}</div>
      ${metaChips ? `<div class="vuln-meta-row">${metaChips}</div>` : ''}
      ${v.explain_why ? `<div class="why-box"><strong>⚠️ Why this matters:</strong> ${esc(v.explain_why)}</div>` : ''}
      <div class="vuln-section-label">Remediation</div>
      <div class="vuln-remediation">${esc(v.remediation)}</div>
      ${diff}
    </div>
  </div>`;
}

// ─── UI Helpers ───────────────────────────────────────────────────────────────
function showLoading() {
  $('scan-btn').disabled = true;
  $('scan-btn-text').classList.add('hidden');
  $('scan-btn-spinner').classList.remove('hidden');
  $('loading-state').classList.remove('hidden');
  $('results-section').classList.add('hidden');
}

function hideLoading() {
  $('scan-btn').disabled = false;
  $('scan-btn-text').classList.remove('hidden');
  $('scan-btn-spinner').classList.add('hidden');
  $('loading-state').classList.add('hidden');
}

function resetToHero() {
  $('results-section').classList.add('hidden');
  $('scan-card').classList.remove('hidden');
  $('repo-url-input').value = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function showError(msg) {
  const el = $('scan-error');
  el.textContent = '⚠️ ' + msg;
  el.classList.remove('hidden');
}

function clearError() { $('scan-error').classList.add('hidden'); }

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
