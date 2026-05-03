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
let currentLang = localStorage.getItem('codeshield_lang') || 'en';

const TRANSLATIONS = {
  en: {
    lang_btn: "العربية",
    nav_scanner: "Scanner",
    nav_features: "Features",
    nav_extension: "VS Code Extension",
    hero_badge: "AI-Powered Security Analysis",
    hero_title: "Scan GitHub Repos for<br/><span class='gradient-text'>Security Vulnerabilities</span>",
    hero_subtitle: "Detect SQL Injection, XSS, hardcoded secrets, command injection, and more across 10+ languages. Instantly. For free.",
    scan_placeholder: "https://github.com/owner/repository",
    scan_btn: "Scan Repository",
    scan_try: "Try:",
    step_clone: "Cloning repository...",
    step_scan: "Scanning files...",
    step_analyze: "Analyzing vulnerabilities...",
    stat_languages: "Languages",
    stat_types: "Vulnerability Types",
    stat_mapped: "Mapped",
    stat_free: "Free",
    stat_forever: "Forever",
    result_scan_time: "Just scanned",
    new_scan_btn: "← New Scan",
    metric_score: "Security Score",
    score_analyzing: "Analyzing...",
    sev_critical: "CRITICAL",
    sev_high: "HIGH",
    sev_medium: "MEDIUM",
    sev_low: "LOW",
    chart_distribution: "Distribution",
    chart_type: "By Type",
    stat_files: "Files Scanned",
    stat_lines: "Lines of Code",
    stat_issues: "Issues Found",
    stat_duration: "Scan Time",
    stat_affected: "Affected Files",
    findings_title: "Vulnerability Findings",
    filter_all: "All",
    filter_critical: "Critical",
    filter_high: "High",
    filter_medium: "Medium",
    filter_low: "Low",
    empty_title: "No vulnerabilities detected!",
    empty_sub: "Your repository passed all CodeShield security checks.",
    affected_files: "Affected Files",
    features_badge: "Capabilities",
    features_title: "Enterprise-Grade Security Analysis",
    feature1_title: "Static Analysis",
    feature1_desc: "AST-level pattern matching detects vulnerabilities other scanners miss, with near-zero false positives.",
    feature2_title: "10+ Languages",
    feature2_desc: "Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, C/C++, C# and more — one scan covers everything.",
    feature3_title: "Lightning Fast",
    feature3_desc: "Shallow clone + parallel scanning delivers results in seconds, not minutes, even for large repos.",
    feature4_title: "CWE/OWASP Mapped",
    feature4_desc: "Every finding is mapped to CWE IDs and OWASP Top 10 categories for compliance reporting.",
    feature5_title: "Secret Detection",
    feature5_desc: "Entropy-based and pattern matching catches hardcoded API keys, passwords, and tokens.",
    feature6_title: "VS Code Extension",
    feature6_desc: "Get inline vulnerability highlighting, AI-powered auto-fix, and real-time scanning as you code.",
    cta_badge: "VS Code Extension",
    cta_title: "Scan As You Code",
    cta_sub: "Get real-time vulnerability detection, inline red underlines, and AI-powered one-click fixes directly in your editor.",
    cta_btn: "Install VibeGuard for VS Code",
    footer_github: "GitHub",
    footer_vscode: "VS Code",
    footer_copy: "© 2025 CodeShield AI. Powered by VibeGuard Engine.",
    why_matters: "Why this matters:",
    remediation: "Remediation",
    code_fix: "Code Fix",
    vulnerable_code: "Vulnerable Code",
    vulnerable: "Vulnerable",
    fixed: "Fixed",
    snippet: "Snippet",
    scan_failed: "Scan failed. Please try again.",
    enter_url: "Please enter a GitHub repository URL.",
    invalid_url: "URL must start with https://github.com/",
    download_pdf: "Download PDF",
    pdf_modal_title: "Download Report (PDF)",
    pdf_modal_sub: "Select the language for your security report:",
    cancel: "Cancel",
    pdf_title_report: "Security Analysis Report",
    pdf_target: "Target:",
    pdf_date: "Date:",
    pdf_score: "Security Score:",
    pdf_total: "Total Issues:",
    pdf_summary: "Summary",
    pdf_findings: "Detailed Findings",
    generating_pdf: "Generating PDF..."
  },
  ar: {
    lang_btn: "English",
    nav_scanner: "الفاحص",
    nav_features: "المميزات",
    nav_extension: "إضافة VS Code",
    hero_badge: "تحليل أمني مدعوم بالذكاء الاصطناعي",
    hero_title: "افحص مستودعات GitHub بحثاً عن<br/><span class='gradient-text'>الثغرات الأمنية</span>",
    hero_subtitle: "اكتشف ثغرات SQL Injection و XSS والأسرار المسربة وحقن الأوامر وغيرها في أكثر من 10 لغات. فوراً وبشكل مجاني.",
    scan_placeholder: "https://github.com/owner/repository",
    scan_btn: "ابدأ الفحص",
    scan_try: "جرب:",
    step_clone: "جاري استنساخ المستودع...",
    step_scan: "جاري فحص الملفات...",
    step_analyze: "جاري تحليل الثغرات...",
    stat_languages: "لغات",
    stat_types: "أنواع الثغرات",
    stat_mapped: "موثقة",
    stat_free: "مجاني",
    stat_forever: "للأبد",
    result_scan_time: "تم الفحص الآن",
    new_scan_btn: "← فحص جديد",
    metric_score: "درجة الأمان",
    score_analyzing: "جاري التحليل...",
    sev_critical: "خطير جداً",
    sev_high: "خطورة عالية",
    sev_medium: "متوسط",
    sev_low: "منخفض",
    chart_distribution: "التوزيع",
    chart_type: "حسب النوع",
    stat_files: "ملفات مفحوصة",
    stat_lines: "أسطر الكود",
    stat_issues: "ثغرات مكتشفة",
    stat_duration: "وقت الفحص",
    stat_affected: "ملفات متأثرة",
    findings_title: "نتائج الفحص",
    filter_all: "الكل",
    filter_critical: "خطير جداً",
    filter_high: "عالي",
    filter_medium: "متوسط",
    filter_low: "منخفض",
    empty_title: "لم يتم اكتشاف أي ثغرات!",
    empty_sub: "مستودعك اجتاز جميع الاختبارات الأمنية بنجاح.",
    affected_files: "الملفات المتأثرة",
    features_badge: "الإمكانيات",
    features_title: "تحليل أمني بمستوى احترافي",
    feature1_title: "التحليل الساكن",
    feature1_desc: "مطابقة الأنماط على مستوى AST تكتشف الثغرات التي تغفل عنها الفواحص الأخرى، مع تقليل الإنذارات الخاطئة.",
    feature2_title: "أكثر من 10 لغات",
    feature2_desc: "Python و JS و TypeScript و Java و PHP و Ruby و Go و C/C++ و C# وغيرها — فحص واحد يغطي كل شيء.",
    feature3_title: "سرعة فائقة",
    feature3_desc: "الاستنساخ الضحل والفحص المتوازي يعطي نتائج في ثوانٍ معدودة حتى للمستودعات الكبيرة.",
    feature4_title: "موثق CWE/OWASP",
    feature4_desc: "كل نتيجة مرتبطة بمعرفات CWE وفئات OWASP Top 10 لتقارير الامتثال.",
    feature5_title: "اكتشاف الأسرار",
    feature5_desc: "اكتشاف مفاتيح API وكلمات المرور والرموز السرية المسربة باستخدام الأنماط والإنتروبيا.",
    feature6_title: "إضافة VS Code",
    feature6_desc: "احصل على تنبيهات فورية، وإصلاحات ذكية بالذكاء الاصطناعي أثناء كتابة الكود.",
    cta_badge: "إضافة VS Code",
    cta_title: "افحص أثناء البرمجة",
    cta_sub: "احصل على اكتشاف فوري للثغرات وإصلاحات بضغطة زر واحدة داخل محررك المفضل.",
    cta_btn: "تثبيت VibeGuard لـ VS Code",
    footer_github: "GitHub",
    footer_vscode: "VS Code",
    footer_copy: "© 2025 CodeShield AI. مدعوم بمحرك VibeGuard.",
    why_matters: "لماذا هذا مهم:",
    remediation: "طريقة الإصلاح",
    code_fix: "إصلاح الكود",
    vulnerable_code: "الكود المصاب",
    vulnerable: "مصاب",
    fixed: "مصلح",
    snippet: "مقتطف",
    scan_failed: "فشل الفحص. يرجى المحاولة مرة أخرى.",
    enter_url: "يرجى إدخال رابط مستودع GitHub.",
    invalid_url: "يجب أن يبدأ الرابط بـ https://github.com/",
    download_pdf: "تنزيل PDF",
    pdf_modal_title: "تنزيل التقرير (PDF)",
    pdf_modal_sub: "اختر لغة تقرير الفحص الأمني:",
    cancel: "إلغاء",
    pdf_title_report: "تقرير التحليل الأمني",
    pdf_target: "المستهدف:",
    pdf_date: "التاريخ:",
    pdf_score: "درجة الأمان:",
    pdf_total: "إجمالي الثغرات:",
    pdf_summary: "ملخص",
    pdf_findings: "النتائج التفصيلية",
    generating_pdf: "جاري إنشاء PDF..."
  }
};

const SEV_COLORS = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#10b981'
};

// ─── DOM Refs ─────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  updateUI();
  $('scan-btn').addEventListener('click', handleScan);
  $('repo-url-input').addEventListener('keydown', e => { if (e.key === 'Enter') handleScan(); });
  $('new-scan-btn').addEventListener('click', resetToHero);
  $('lang-toggle').addEventListener('click', toggleLanguage);
  
  // PDF Download Events
  $('download-pdf-btn').addEventListener('click', () => {
    $('pdf-modal').classList.remove('hidden');
  });
  $('pdf-close-btn').addEventListener('click', () => {
    $('pdf-modal').classList.add('hidden');
  });
  $('pdf-en-btn').addEventListener('click', () => {
    $('pdf-modal').classList.add('hidden');
    generatePdf('en');
  });
  $('pdf-ar-btn').addEventListener('click', () => {
    $('pdf-modal').classList.add('hidden');
    generatePdf('ar');
  });

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
  $('stat-duration').textContent = data.stats.duration_ms + (currentLang === 'ar' ? ' ملي ثانية' : 'ms');
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

// ─── i18n Logic ───────────────────────────────────────────────────────────────
function toggleLanguage() {
  currentLang = currentLang === 'en' ? 'ar' : 'en';
  localStorage.setItem('codeshield_lang', currentLang);
  updateUI();
  if (currentData) {
    renderResults(currentData);
  }
}

function updateUI() {
  const dict = TRANSLATIONS[currentLang];
  document.documentElement.dir = currentLang === 'ar' ? 'rtl' : 'ltr';
  document.documentElement.lang = currentLang;

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (dict[key]) {
      if (el.tagName === 'INPUT') {
        el.placeholder = dict[key];
      } else {
        el.innerHTML = dict[key];
      }
    }
  });

  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (dict[key]) el.placeholder = dict[key];
  });
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
        label: currentLang === 'ar' ? 'عدد المرات' : 'Occurrences',
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
      <span class="vuln-sev-badge" style="background:${c}22;color:${c};border:1px solid ${c}44">${translateSeverity(v.severity, currentLang)}</span>
      <span class="vuln-rule-id">${esc(v.rule_id)}</span>
      <span class="vuln-title">${esc(v.rule_name)}</span>
      <span class="vuln-loc-chip">${esc(fileShort)}:${v.location.line}</span>
      <svg class="vuln-expand-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
    </div>
    <div class="vuln-card-body">
      <div class="vuln-msg">${esc(v.message)}</div>
      ${metaChips ? `<div class="vuln-meta-row">${metaChips}</div>` : ''}
      ${v.explain_why ? `<div class="why-box"><strong>⚠️ ${TRANSLATIONS[currentLang].why_matters}</strong> ${esc(v.explain_why)}</div>` : ''}
      <div class="vuln-section-label">${TRANSLATIONS[currentLang].remediation}</div>
      <div class="vuln-remediation">${esc(v.remediation)}</div>
      ${diff}
    </div>
  </div>`;
}

function translateSeverity(sev, lang) {
  const l = lang || currentLang;
  if (l === 'en') return sev;
  const map = { CRITICAL: 'خطير جداً', HIGH: 'عالي', MEDIUM: 'متوسط', LOW: 'منخفض', INFO: 'معلومات' };
  return map[sev] || sev;
}

// ─── PDF Generation ───────────────────────────────────────────────────────────
function generatePdf(lang) {
  if (!currentData) return;
  const t = TRANSLATIONS[lang];
  const tpl = $('pdf-template');
  const d = currentData;
  
  // Setup Direction & Fonts
  tpl.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
  
  // Populate Header & Meta
  $('pdf-main-title').textContent = t.pdf_title_report;
  $('pdf-repo-name').textContent = d.repo_url;
  $('pdf-date').textContent = new Date().toLocaleString(lang === 'ar' ? 'ar-EG' : 'en-US');
  $('pdf-score').textContent = d.score ? d.score.score : '--';
  $('pdf-total-issues').textContent = d.vulnerabilities.length;
  
  // Update Meta Labels
  const metaItems = document.querySelectorAll('.pdf-meta-item strong');
  if (metaItems.length >= 4) {
    metaItems[0].textContent = t.pdf_target;
    metaItems[1].textContent = t.pdf_date;
    metaItems[2].textContent = t.pdf_score;
    metaItems[3].textContent = t.pdf_total;
  }

  // Populate Summary
  $('pdf-summary-title').textContent = t.pdf_summary;
  $('pdf-crit-count').textContent = d.summary.CRITICAL || 0;
  $('pdf-crit-label').textContent = translateSeverity('CRITICAL', lang);
  $('pdf-high-count').textContent = d.summary.HIGH || 0;
  $('pdf-high-label').textContent = translateSeverity('HIGH', lang);
  $('pdf-med-count').textContent = d.summary.MEDIUM || 0;
  $('pdf-med-label').textContent = translateSeverity('MEDIUM', lang);
  $('pdf-low-count').textContent = d.summary.LOW || 0;
  $('pdf-low-label').textContent = translateSeverity('LOW', lang);

  // Populate Findings
  $('pdf-findings-title').textContent = t.pdf_findings;
  const vulnList = $('pdf-vuln-list');
  vulnList.innerHTML = '';
  
  if (d.vulnerabilities.length === 0) {
    vulnList.innerHTML = `<p>${t.empty_sub}</p>`;
  } else {
    d.vulnerabilities.forEach(v => {
      const c = SEV_COLORS[v.severity] || '#aaa';
      const sevLabel = translateSeverity(v.severity, lang);
      const fileShort = v.location.file.split('/').pop();
      const div = document.createElement('div');
      div.className = 'pdf-vuln';
      div.innerHTML = `
        <div class="pdf-vuln-header">
          <span class="pdf-vuln-badge" style="color:${c}">${sevLabel}</span>
          <span class="pdf-vuln-title">${esc(v.rule_name)}</span>
          <span class="pdf-vuln-loc">${esc(v.location.file)}:${v.location.line}</span>
        </div>
        <div class="pdf-vuln-msg">${esc(v.message)}</div>
        <div class="pdf-section-title">${t.remediation}</div>
        <div class="pdf-remediation">${esc(v.remediation)}</div>
      `;
      vulnList.appendChild(div);
    });
  }

  // Generate with html2pdf
  const opt = {
    margin:       10,
    filename:     `CodeShield_Report_${d.repo_url.split('/').pop()}.pdf`,
    image:        { type: 'jpeg', quality: 0.98 },
    html2canvas:  { scale: 2, useCORS: true },
    jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' }
  };
  
  // Show temporary feedback on button
  const btnText = $('download-pdf-btn').querySelector('span');
  const origText = btnText.textContent;
  btnText.textContent = t.generating_pdf;
  
  $('pdf-template-wrapper').style.display = 'block';
  
  html2pdf().set(opt).from(tpl).save().then(() => {
    $('pdf-template-wrapper').style.display = 'none';
    btnText.textContent = origText;
  });
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
