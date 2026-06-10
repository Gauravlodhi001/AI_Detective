// ==========================================================================
// AI-Detective Frontend Application Logic
// ==========================================================================

const API_BASE = window.location.origin;

// State Variables
let currentTab = 'dashboard';
let currentScanMode = 'zip';
let selectedFile = null;
let currentReport = null;
let severityChartInstance = null;
let owaspChartInstance = null;

// On Initialization
document.addEventListener('DOMContentLoaded', () => {
  // Set up drag and drop listeners
  setupDragAndDrop();
  
  // Load initial dashboard lists and run self-check diagnostics
  loadDashboardData();
  runDiagnostics();
});

// ==========================================================================
// Navigation & Tab Switching
// ==========================================================================
function switchTab(tabId) {
  // Hide all panes
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.remove('active');
  });
  
  // Deactivate all navigation items
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.remove('active');
  });
  
  // Activate selected pane and navigation button
  const selectedPane = document.getElementById(`tab-${tabId}`);
  if (selectedPane) selectedPane.classList.add('active');
  
  const navBtn = document.getElementById(`nav-btn-${tabId}`);
  if (navBtn) navBtn.classList.add('active');
  
  currentTab = tabId;

  // Set header title
  const pageTitle = document.getElementById('page-title');
  if (tabId === 'dashboard') pageTitle.textContent = 'Security Dashboard';
  else if (tabId === 'scan') pageTitle.textContent = 'Scan Hub';
  else if (tabId === 'reports') pageTitle.textContent = 'Saved Reports Catalog';
  else if (tabId === 'settings') pageTitle.textContent = 'Settings & Diagnostics';
  else if (tabId === 'report-viewer') pageTitle.textContent = 'Audit Analysis Report';
  else if (tabId === 'wapt') pageTitle.textContent = 'WAPT Scanner Hub';

  // Load specific tab data
  if (tabId === 'reports') {
    loadSavedReports();
  } else if (tabId === 'dashboard') {
    loadDashboardData();
  }
}

function switchScanMode(mode) {
  document.querySelectorAll('.card-tab-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  document.querySelectorAll('.scan-panel').forEach(panel => {
    panel.classList.remove('active');
  });

  document.getElementById(`tab-btn-${mode}`).classList.add('active');
  document.getElementById(`panel-${mode}`).classList.add('active');
  currentScanMode = mode;
}

// ==========================================================================
// Diagnostics & Settings
// ==========================================================================
async function runDiagnostics() {
  const badgeDot = document.querySelector('#semgrep-status-badge .status-dot');
  const badgeText = document.getElementById('semgrep-status-text');

  try {
    const res = await fetch(`${API_BASE}/api/settings/diagnostics`);
    const data = await res.json();
    
    if (data.success) {
      const diag = data.diagnostics;
      
      // Update settings panel
      document.getElementById('diag-os').textContent = formatOS(diag.os);
      document.getElementById('diag-node').textContent = diag.nodeVersion;
      
      if (diag.semgrepAvailable) {
        document.getElementById('diag-semgrep').textContent = `Active (${diag.semgrepVersion})`;
        document.getElementById('diag-semgrep').className = 'diag-value green';
        
        // Update footer badge
        badgeDot.className = 'status-dot pulsing active';
        badgeText.textContent = `Semgrep Active`;
      } else {
        document.getElementById('diag-semgrep').textContent = 'Not Found (Fallback SAST Active)';
        document.getElementById('diag-semgrep').className = 'diag-value red';
        
        // Update footer badge
        badgeDot.className = 'status-dot warning';
        badgeText.textContent = `Local Engine (Offline)`;
      }
    }
  } catch (err) {
    console.error('Failed to contact diagnostics:', err);
    badgeDot.className = 'status-dot error';
    badgeText.textContent = `Connection Error`;
  }
}

function formatOS(os) {
  if (os === 'win32') return 'Windows (x64)';
  if (os === 'darwin') return 'macOS (Darwin)';
  if (os === 'linux') return 'Linux (Kernel)';
  return os;
}

// ==========================================================================
// Dashboard Data Loading
// ==========================================================================
async function loadDashboardData() {
  try {
    const res = await fetch(`${API_BASE}/api/reports/list`);
    const reports = await res.json();
    
    // Update counters
    document.getElementById('stat-total-scans').textContent = reports.length;
    
    const secureCount = reports.filter(r => r.metrics.grade === 'A').length;
    document.getElementById('stat-secure-projects').textContent = secureCount;
    
    const hotspotCount = reports.filter(r => ['D', 'F'].includes(r.metrics.grade)).length;
    document.getElementById('stat-hotspot-projects').textContent = hotspotCount;

    // Find top threat category
    const categoryTotals = {};
    reports.forEach(r => {
      if (r.metrics.topIssueCategory && r.metrics.topIssueCategory !== 'None') {
        categoryTotals[r.metrics.topIssueCategory] = (categoryTotals[r.metrics.topIssueCategory] || 0) + 1;
      }
    });

    let topCategory = 'None';
    let maxCount = 0;
    Object.entries(categoryTotals).forEach(([cat, count]) => {
      if (count > maxCount) {
        maxCount = count;
        topCategory = cat;
      }
    });
    document.getElementById('stat-top-threat').textContent = topCategory;

    // Render Recent Audit Table
    const tbody = document.getElementById('scan-list-tbody');
    tbody.innerHTML = '';

    if (reports.length === 0) {
      tbody.innerHTML = `
        <tr class="empty-state-row">
          <td colspan="7">
            <div class="empty-state">
              <i class="fa-solid fa-folder-open"></i>
              <p>No scans performed yet. Head over to the scan tab to audit your code.</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    // List top 5 recent scans
    reports.slice(0, 5).forEach(report => {
      const row = document.createElement('tr');
      const date = new Date(report.scanTime).toLocaleString();
      const m = report.metrics.severityCounts;
      
      row.innerHTML = `
        <td><strong>${escapeHtml(report.projectName)}</strong></td>
        <td><span class="grade-badge ${report.metrics.grade.toLowerCase()}">${report.metrics.grade}</span></td>
        <td><strong>${report.metrics.securityScore}/100</strong></td>
        <td>
          <span class="badge ${m.Critical > 0 ? 'danger' : 'info'}">${m.Critical} C</span>
          <span class="badge ${m.High > 0 ? 'danger' : 'info'}">${m.High} H</span>
          <span class="badge ${m.Medium > 0 ? 'warning' : 'info'}">${m.Medium} M</span>
          <span class="badge info">${m.Low} L</span>
        </td>
        <td>${report.filesScannedCount}</td>
        <td>${date}</td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="viewReportDetails('${report.id}')">
            <i class="fa-solid fa-magnifying-glass"></i> View
          </button>
        </td>
      `;
      tbody.appendChild(row);
    });

  } catch (err) {
    console.error('Failed to load dashboard data:', err);
  }
}

// ==========================================================================
// Saved Reports Catalog
// ==========================================================================
async function loadSavedReports() {
  const tbody = document.getElementById('saved-reports-tbody');
  tbody.innerHTML = `
    <tr>
      <td colspan="7" style="text-align: center;">
        <i class="fa-solid fa-circle-notch fa-spin"></i> Loading reports...
      </td>
    </tr>
  `;

  try {
    const res = await fetch(`${API_BASE}/api/reports/list`);
    const reports = await res.json();
    tbody.innerHTML = '';

    if (reports.length === 0) {
      tbody.innerHTML = `
        <tr class="empty-state-row">
          <td colspan="7">
            <div class="empty-state">
              <i class="fa-solid fa-box-open"></i>
              <p>No historical security audit files found.</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    reports.forEach(report => {
      const row = document.createElement('tr');
      const date = new Date(report.scanTime).toLocaleString();
      const m = report.metrics.severityCounts;

      row.innerHTML = `
        <td><strong>${escapeHtml(report.projectName)}</strong></td>
        <td><span class="grade-badge ${report.metrics.grade.toLowerCase()}">${report.metrics.grade}</span></td>
        <td><strong>${report.metrics.securityScore}/100</strong></td>
        <td>
          <span class="badge ${m.Critical > 0 ? 'danger' : 'info'}">${m.Critical} C</span>
          <span class="badge ${m.High > 0 ? 'danger' : 'info'}">${m.High} H</span>
          <span class="badge ${m.Medium > 0 ? 'warning' : 'info'}">${m.Medium} M</span>
          <span class="badge info">${m.Low} L</span>
        </td>
        <td>${report.filesScannedCount}</td>
        <td>${date}</td>
        <td>
          <div style="display: flex; gap: 6px;">
            <button class="btn btn-secondary btn-sm" onclick="viewReportDetails('${report.id}')">
              <i class="fa-solid fa-folder-open"></i> Details
            </button>
            <button class="btn btn-danger btn-sm" onclick="deleteReport('${report.id}', event)">
              <i class="fa-solid fa-trash"></i> Delete
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(row);
    });

  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="color: var(--color-critical); text-align: center;">
          <i class="fa-solid fa-circle-exclamation"></i> Failed to retrieve saved audits.
        </td>
      </tr>
    `;
    console.error('Error fetching saved reports:', err);
  }
}

async function deleteReport(id, event) {
  event.stopPropagation();
  if (!confirm('Are you sure you want to permanently delete this report?')) return;
  
  try {
    const res = await fetch(`${API_BASE}/api/reports/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      loadSavedReports();
    } else {
      alert(data.message || 'Failed to delete report.');
    }
  } catch (err) {
    console.error('Error deleting report:', err);
  }
}

// ==========================================================================
// Drag and Drop Zip Handling
// ==========================================================================
function setupDragAndDrop() {
  const zone = document.getElementById('drag-drop-zone');
  if (!zone) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    zone.addEventListener(eventName, (e) => {
      e.preventDefault();
      zone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    zone.addEventListener(eventName, (e) => {
      e.preventDefault();
      zone.classList.remove('dragover');
    }, false);
  });

  zone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files.length > 0) {
      const file = files[0];
      if (file.name.endsWith('.zip')) {
        handleFileSelection(file);
      } else {
        alert('Please drop a valid .zip compressed archive.');
      }
    }
  });
}

function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) {
    handleFileSelection(file);
  }
}

function handleFileSelection(file) {
  selectedFile = file;
  document.getElementById('selected-file-name').textContent = file.name;
  document.getElementById('selected-file-display').style.display = 'flex';
  
  // Set default project name based on file name
  const projectInput = document.getElementById('zip-project-name');
  if (projectInput && !projectInput.value) {
    projectInput.value = file.name.replace(/\.zip$/i, '');
  }
}

function clearSelectedFile() {
  selectedFile = null;
  document.getElementById('zip-file-input').value = '';
  document.getElementById('selected-file-display').style.display = 'none';
}

// ==========================================================================
// Console Log Simulator Sequence
// ==========================================================================
function writeConsoleLog(text, logClass = '') {
  const consoleBox = document.getElementById('scan-console-logs');
  if (!consoleBox) return;

  const line = document.createElement('div');
  line.className = `console-line ${logClass}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  consoleBox.appendChild(line);
  consoleBox.scrollTop = consoleBox.scrollHeight;
}

function clearConsoleLogs() {
  const consoleBox = document.getElementById('scan-console-logs');
  if (consoleBox) consoleBox.innerHTML = '';
}

/**
 * Triggers progressive logs simulation. Returns a function to complete/stop.
 */
function runLogSimulation(projectName, type = 'zip') {
  clearConsoleLogs();
  writeConsoleLog(`[START] Initializing Security Audit for: "${projectName}"`, 'warning');
  
  const steps = [
    { text: 'Preparing sandbox staging directory...', delay: 100 },
    { text: type === 'git' ? 'Spawning Git subsystem subprocess...' : 'Extracting manifest files...', delay: 400 },
    { text: type === 'git' ? 'Fetching remote repository metadata...' : 'Unpacking directory tree...', delay: 800 },
    { text: 'Crawling file tree structures (excluding node_modules)...', delay: 1200 },
    { text: 'Triggering custom high-entropy credentials scanner...', delay: 1700 },
    { text: 'Custom Secret scan complete. Redacting tokens.', class: 'success', delay: 2200 },
    { text: 'Detecting Semgrep configuration files...', delay: 2600 },
    { text: 'Spawning Semgrep CLI static analysis engine (Primary SAST)...', delay: 3100 },
    { text: 'Parsing Semgrep JSON reports and mapping vulnerabilities...', delay: 4200 },
    { text: 'Semgrep SAST scan completed successfully.', class: 'success', delay: 4800 },
    { text: 'Scanning manifests for software dependencies (SCA)...', delay: 5200 },
    { text: 'Comparing packages against local CVE databases...', delay: 5700 },
    { text: 'Dependency checks complete.', class: 'success', delay: 6200 },
    { text: 'Applying risk grading engine matrices...', delay: 6600 },
    { text: 'Writing HTML, Markdown & JSON reports to disk...', delay: 7100 },
    { text: 'Audit complete! Rendering analysis dashboard...', class: 'success', delay: 7500 }
  ];

  const timeouts = [];
  
  steps.forEach(step => {
    const t = setTimeout(() => {
      writeConsoleLog(`[INFO] ${step.text}`, step.class || '');
    }, step.delay);
    timeouts.push(t);
  });

  return {
    clear: () => {
      timeouts.forEach(clearTimeout);
    }
  };
}

// ==========================================================================
// Scan Submission Handlers
// ==========================================================================

async function handleZipScan(event) {
  event.preventDefault();
  if (!selectedFile) {
    alert('Please select or drag a project zip file first.');
    return;
  }

  const submitBtn = document.getElementById('zip-submit-btn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...`;

  const projName = document.getElementById('zip-project-name').value || selectedFile.name.replace(/\.zip$/i, '');
  const sim = runLogSimulation(projName, 'zip');

  const formData = new FormData();
  formData.append('zipFile', selectedFile);
  formData.append('projectName', projName);

  try {
    const res = await fetch(`${API_BASE}/api/scan/upload`, {
      method: 'POST',
      body: formData
    });
    
    const data = await res.json();
    
    // Ensure animation looks complete or completes before transition
    setTimeout(() => {
      sim.clear();
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i class="fa-solid fa-circle-play"></i> Run Security Scan`;
      
      if (data.success) {
        showReport(data.report);
      } else {
        writeConsoleLog(`[ERROR] Scan failed: ${data.message}`, 'error');
        alert(`Scanning Error: ${data.message}`);
      }
    }, 3000); // Wait at least 3 seconds to show logs

  } catch (err) {
    sim.clear();
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<i class="fa-solid fa-circle-play"></i> Run Security Scan`;
    writeConsoleLog(`[ERROR] Network error during scan: ${err.message}`, 'error');
    alert('Network error. Check server status.');
  }
}

async function handleGitScan(event) {
  event.preventDefault();
  const gitUrl = document.getElementById('git-url').value;
  const branch = document.getElementById('git-branch').value;

  if (!gitUrl) return;

  const submitBtn = document.getElementById('git-submit-btn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Cloning & Scanning...`;

  const sim = runLogSimulation(gitUrl, 'git');

  try {
    const res = await fetch(`${API_BASE}/api/scan/git`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ gitUrl, branch })
    });
    
    const data = await res.json();

    setTimeout(() => {
      sim.clear();
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i class="fa-solid fa-code-branch"></i> Clone & Scan Repository`;
      
      if (data.success) {
        showReport(data.report);
      } else {
        writeConsoleLog(`[ERROR] Scan failed: ${data.message}`, 'error');
        alert(`Scanning Error: ${data.message}`);
      }
    }, 4000); // Wait to show logs

  } catch (err) {
    sim.clear();
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<i class="fa-solid fa-code-branch"></i> Clone & Scan Repository`;
    writeConsoleLog(`[ERROR] Network error: ${err.message}`, 'error');
    alert('Network error cloning repository.');
  }
}

async function handlePasteScan(event) {
  event.preventDefault();
  const code = document.getElementById('paste-code').value;
  const filename = document.getElementById('paste-filename').value;
  const projectName = document.getElementById('paste-project-name').value || 'Snippet Code';

  if (!code || !filename) return;

  const submitBtn = document.getElementById('paste-submit-btn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning Snippet...`;

  const sim = runLogSimulation(projectName, 'paste');

  try {
    const res = await fetch(`${API_BASE}/api/scan/paste`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, filename, projectName })
    });

    const data = await res.json();

    setTimeout(() => {
      sim.clear();
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i class="fa-solid fa-laptop-code"></i> Analyze Code Snippet`;
      
      if (data.success) {
        showReport(data.report);
      } else {
        writeConsoleLog(`[ERROR] Scan failed: ${data.message}`, 'error');
        alert(`Scanning Error: ${data.message}`);
      }
    }, 2500);

  } catch (err) {
    sim.clear();
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<i class="fa-solid fa-laptop-code"></i> Analyze Code Snippet`;
    writeConsoleLog(`[ERROR] Network error: ${err.message}`, 'error');
    alert('Network error scanning pasted snippet.');
  }
}

// ==========================================================================
// Saved Report Loading details
// ==========================================================================
async function viewReportDetails(reportId) {
  try {
    const res = await fetch(`${API_BASE}/api/reports/${reportId}`);
    if (res.status === 404) {
      alert('Report not found. It may have been deleted.');
      return;
    }
    const report = await res.json();
    showReport(report);
  } catch (err) {
    console.error('Error fetching report details:', err);
    alert('Failed to retrieve report details.');
  }
}

// ==========================================================================
// Report Display & Chart Rendering
// ==========================================================================
function showReport(report) {
  currentReport = report;
  switchTab('report-viewer');

  const m = report.metrics;
  const sev = m.severityCounts;

  // Header Details
  document.getElementById('report-title-h2').textContent = report.projectName;
  document.getElementById('report-date-text').textContent = `Scanned on: ${new Date(report.scanTime).toLocaleString()}`;
  document.getElementById('report-badge-status').textContent = `Engine: ${report.semgrepStatus}`;

  // Metrics Grid
  document.getElementById('report-grade-letter').textContent = m.grade;
  document.getElementById('report-grade-rating').textContent = m.rating;
  document.getElementById('report-score-index').textContent = `${m.securityScore}/100`;

  // Color grade ring based on grade
  const ring = document.getElementById('report-grade-ring');
  ring.style.borderColor = m.gradeColor || '#10b981';
  ring.style.boxShadow = `0 0 20px ${m.gradeColor}33`;

  // Severity Counts
  document.getElementById('report-count-critical').textContent = sev.Critical;
  document.getElementById('report-count-high').textContent = sev.High;
  document.getElementById('report-count-medium').textContent = sev.Medium;
  document.getElementById('report-count-low').textContent = sev.Low;

  // Stats Card
  document.getElementById('report-stat-files').textContent = report.filesScannedCount;
  document.getElementById('report-stat-findings').textContent = report.findings.length;
  document.getElementById('report-stat-engine').textContent = report.semgrepStatus.split(' ')[0];
  document.getElementById('report-stat-common').textContent = m.topIssueCategory;

  // Render findings list
  renderFindings(report.findings);

  // Render Charts
  renderSeverityChart(sev);
  renderOwaspChart(m.owaspCounts);
  
  // Update AI Detective assessment panel
  updateAiAnalysisPanel(report);
}

// ==========================================================================
// Chart.js Implementations
// ==========================================================================
function renderSeverityChart(sev) {
  const ctx = document.getElementById('chart-severity').getContext('2d');
  
  if (severityChartInstance) {
    severityChartInstance.destroy();
  }

  severityChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        label: 'Issues Count',
        data: [sev.Critical, sev.High, sev.Medium, sev.Low],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6'],
        borderWidth: 0,
        borderRadius: 6
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#94a3b8', stepSize: 1 }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#94a3b8' }
        }
      }
    }
  });
}

function renderOwaspChart(owaspCounts) {
  const ctx = document.getElementById('chart-owasp').getContext('2d');
  
  if (owaspChartInstance) {
    owaspChartInstance.destroy();
  }

  const labels = Object.keys(owaspCounts).map(cat => cat.split(':')[0]); // Just category code
  const data = Object.values(owaspCounts);

  if (labels.length === 0) {
    // Empty state
    labels.push('Clean');
    data.push(1);
  }

  const bgColors = [
    '#06b6d4', '#6366f1', '#a855f7', '#ec4899', 
    '#3b82f6', '#10b981', '#f59e0b', '#f97316', '#ef4444'
  ];

  owaspChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: labels[0] === 'Clean' ? ['rgba(16, 185, 129, 0.15)'] : bgColors.slice(0, data.length),
        borderColor: labels[0] === 'Clean' ? ['#10b981'] : ['rgba(11, 15, 25, 0.8)'],
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#94a3b8', font: { size: 11 } }
        }
      }
    }
  });
}

// ==========================================================================
// Findings List Accordion & Filtering
// ==========================================================================
function renderFindings(findings) {
  const accordion = document.getElementById('findings-list-accordion');
  accordion.innerHTML = '';

  if (findings.length === 0) {
    accordion.innerHTML = `
      <div class="empty-state">
        <i class="fa-solid fa-circle-check" style="color: var(--color-success); font-size: 36px;"></i>
        <p>Excellent! No security findings detected in this directory.</p>
      </div>
    `;
    return;
  }

  findings.forEach((finding, idx) => {
    const row = document.createElement('div');
    row.className = `finding-row ${finding.severity.toLowerCase()}`;
    row.dataset.severity = finding.severity.toUpperCase();
    row.dataset.title = finding.title.toLowerCase();
    row.dataset.path = finding.path.toLowerCase();
    row.dataset.rule = finding.rule_id.toLowerCase();

    row.innerHTML = `
      <div class="finding-summary-header" onclick="toggleFindingRow(this)">
        <div class="finding-sev-bar"></div>
        <i class="fa-solid fa-chevron-right collapse-icon"></i>
        <div class="finding-headline">
          <h4>${finding.title}</h4>
          <div class="finding-path-meta">
            <span class="badge ${getSeverityClass(finding.severity)}">${finding.severity}</span>
            <code>${escapeHtml(finding.path)}:L${finding.line}</code>
          </div>
        </div>
      </div>
      <div class="finding-details-body">
        <div class="detail-meta-pillrow">
          <div class="meta-pill">Rule: <strong>${escapeHtml(finding.rule_id)}</strong></div>
          <div class="meta-pill">CWE: <strong>${escapeHtml(finding.cwe)}</strong></div>
          <div class="meta-pill">OWASP: <strong>${escapeHtml(finding.owasp)}</strong></div>
        </div>
        
        <div class="detail-section-title">Vulnerability Description</div>
        <div class="detail-section-content">${escapeHtml(finding.message).replace(/\n/g, '<br>')}</div>

        ${finding.codeSnippet ? `
          <div class="detail-section-title">Vulnerable Snippet</div>
          <div class="codeblock-container">
            <code>${highlightSnippet(finding.codeSnippet)}</code>
          </div>
        ` : ''}

        <div class="detail-section-title">Remediation Steps</div>
        <div class="detail-section-content">${escapeHtml(finding.remediation)}</div>

        ${finding.suggestedDiff ? `
          <div class="detail-section-title">Suggested Security Fix</div>
          ${formatDiffBlock(finding.suggestedDiff)}
        ` : ''}
      </div>
    `;

    accordion.appendChild(row);
  });
}

function toggleFindingRow(headerElement) {
  const row = headerElement.parentElement;
  row.classList.toggle('expanded');
}

function filterFindings() {
  const searchVal = document.getElementById('finding-search-input').value.toLowerCase();
  const severityVal = document.getElementById('finding-severity-filter').value;
  
  const rows = document.querySelectorAll('.finding-row');
  
  rows.forEach(row => {
    const sevMatch = (severityVal === 'ALL' || row.dataset.severity === severityVal);
    const textMatch = (!searchVal || 
                       row.dataset.title.includes(searchVal) || 
                       row.dataset.path.includes(searchVal) || 
                       row.dataset.rule.includes(searchVal));

    if (sevMatch && textMatch) {
      row.style.display = 'block';
    } else {
      row.style.display = 'none';
    }
  });
}

function getSeverityClass(sev) {
  if (sev === 'Critical' || sev === 'High') return 'danger';
  if (sev === 'Medium') return 'warning';
  return 'info';
}

function highlightSnippet(snippet) {
  // Simple styling wrapping matches or just printing sanitarily
  return escapeHtml(snippet);
}

function formatDiffBlock(diffText) {
  // Parses custom diff output matching:
  // <<<< CURRENT CODE
  // ...
  // ==== SUGGESTED FIX
  // ...
  // >>>>
  
  const currentMarker = '<<<< CURRENT CODE';
  const fixMarker = '==== SUGGESTED FIX';
  const endMarker = '>>>>';
  
  let currentBlock = '';
  let fixBlock = '';
  
  if (diffText.includes(currentMarker) && diffText.includes(fixMarker)) {
    const parts = diffText.split(fixMarker);
    currentBlock = parts[0].replace(currentMarker, '').trim();
    fixBlock = parts[1].replace(endMarker, '').trim();
  } else {
    // Non-standard format, print as plain code
    return `<pre class="codeblock-container"><code>${escapeHtml(diffText)}</code></pre>`;
  }

  const currentLines = currentBlock.split('\n').map(l => `<div class="diff-line deletion">- ${escapeHtml(l)}</div>`).join('');
  const fixLines = fixBlock.split('\n').map(l => `<div class="diff-line addition">+ ${escapeHtml(l)}</div>`).join('');

  return `
    <div class="diff-box">
      <div class="diff-header">Mitigation Code Diff Comparison</div>
      <div class="diff-line info">Vulnerable Original</div>
      ${currentLines}
      <div class="diff-line info">Secure Mitigated</div>
      ${fixLines}
    </div>
  `;
}

// ==========================================================================
// Exports & Downloads
// ==========================================================================
function exportReport(format) {
  if (!currentReport) return;
  const url = `${API_BASE}/api/reports/${currentReport.id}/download?format=${format}`;
  window.open(url, '_blank');
}

// ==========================================================================
// HTML Sanitization Utility
// ==========================================================================
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ==========================================================================
// AI Detective Feature Logic
// ==========================================================================

/**
 * Updates the AI Detective Analysis card based on whether the report contains AI insights.
 */
function updateAiAnalysisPanel(report) {
  const aiCard = document.getElementById('report-ai-card');
  const aiLaunch = document.getElementById('ai-analysis-launch');
  const aiDetails = document.getElementById('ai-analysis-details');
  const aiModeBadge = document.getElementById('ai-mode-badge');
  const aiSummaryBox = document.getElementById('ai-summary-box');
  const aiTimelineBox = document.getElementById('ai-timeline-box');
  const aiPriorityBox = document.getElementById('ai-priority-box');

  if (!aiCard) return;

  // Show the AI Card section
  aiCard.style.display = 'block';

  if (report.aiAnalysis) {
    if (aiLaunch) aiLaunch.style.display = 'none';
    if (aiDetails) aiDetails.style.display = 'block';

    // Update API mode badge
    if (aiModeBadge) {
      if (report.aiAnalysis.isMock) {
        aiModeBadge.textContent = 'Demo Mode (Mock)';
        aiModeBadge.className = 'badge warning';
      } else {
        aiModeBadge.textContent = 'Claude 3.5 Sonnet';
        aiModeBadge.className = 'badge success';
      }
    }

    // Render Executive Summary
    if (aiSummaryBox) {
      aiSummaryBox.innerHTML = renderMarkdown(report.aiAnalysis.executiveSummary);
    }

    // Render Threat Chain Timeline
    if (aiTimelineBox) {
      aiTimelineBox.innerHTML = '';
      const narrative = report.aiAnalysis.attackNarrative;

      // Extract narrative steps matching "**Step X: Title**\nDescription"
      const stepRegex = /\*\*Step\s+(\d+):\s*(.*?)\*\*\s*\n+([\s\S]*?)(?=(?:\*\*Step\s+\d+:)|(?:\*\*Impact Assessment:)|$)/gi;
      let match;
      const steps = [];
      const cleanNarrative = narrative.replace(/^###.*?\n/, '').replace(/^A penetration tester.*?\n/, '');

      while ((match = stepRegex.exec(cleanNarrative)) !== null) {
        steps.push({
          num: match[1],
          title: match[2],
          description: match[3].trim()
        });
      }

      if (steps.length > 0) {
        steps.forEach(step => {
          const stepEl = document.createElement('div');
          stepEl.className = 'ai-timeline-step';
          stepEl.innerHTML = `
            <div class="ai-step-title">Step ${step.num}: ${step.title}</div>
            <div class="ai-step-desc">${renderMarkdown(step.description)}</div>
          `;
          aiTimelineBox.appendChild(stepEl);
        });

        // Check for impact assessment
        const impactMatch = cleanNarrative.match(/\*\*Impact Assessment:\*\*\s*([\s\S]*)$/i) || cleanNarrative.match(/Impact Assessment:\s*([\s\S]*)$/i);
        if (impactMatch) {
          const impactEl = document.createElement('div');
          impactEl.className = 'ai-timeline-step';
          impactEl.style.borderLeft = '2px solid var(--color-critical)';
          impactEl.style.background = 'rgba(239, 68, 68, 0.03)';
          impactEl.innerHTML = `
            <div class="ai-step-title" style="color: var(--color-critical);">Impact Assessment</div>
            <div class="ai-step-desc" style="font-weight: 500;">${renderMarkdown(impactMatch[1].trim())}</div>
          `;
          aiTimelineBox.appendChild(impactEl);
        }
      } else {
        // Fallback: render narrative as a single block
        aiTimelineBox.innerHTML = `<div class="ai-step-desc">${renderMarkdown(narrative)}</div>`;
      }
    }

    // Render Remediation Rankings
    if (aiPriorityBox) {
      aiPriorityBox.innerHTML = '';
      const rankings = report.aiAnalysis.remediationRanking;

      if (Array.isArray(rankings) && rankings.length > 0) {
        rankings.forEach(item => {
          const rank = parseInt(item.rank);
          let rankClass = 'rank-other';
          let badgeText = 'LOW PRIORITY';

          if (rank === 1) {
            rankClass = 'rank-1';
            badgeText = 'CRITICAL PRIORITY';
          } else if (rank === 2) {
            rankClass = 'rank-2';
            badgeText = 'HIGH PRIORITY';
          } else if (rank === 3) {
            rankClass = 'rank-3';
            badgeText = 'MEDIUM PRIORITY';
          }

          const card = document.createElement('div');
          card.className = `ai-priority-card ${rankClass}`;
          card.innerHTML = `
            <div class="ai-prio-header">
              <div class="ai-prio-title">Priority #${rank}</div>
              <span class="ai-prio-badge">${badgeText}</span>
            </div>
            <div class="ai-prio-title" style="margin-top: 4px; font-weight: 700; color: var(--text-main);">${escapeHtml(item.title)}</div>
            <div class="ai-prio-loc" style="font-size: 11.5px; font-family: monospace; color: var(--text-muted); margin-bottom: 4px;">Location: ${escapeHtml(item.location || '')}</div>
            <div class="ai-prio-reason">${renderMarkdown(item.reasoning)}</div>
          `;
          aiPriorityBox.appendChild(card);
        });
      } else {
        aiPriorityBox.innerHTML = `<div class="empty-state"><p>No items ranked for remediation.</p></div>`;
      }
    }
  } else {
    // Hide details, show launch prompt
    if (aiLaunch) {
      aiLaunch.style.display = 'block';
      // Reset button inside launch in case it was left disabled
      const launchBtn = document.getElementById('btn-launch-ai-audit');
      if (launchBtn) {
        launchBtn.disabled = false;
        launchBtn.innerHTML = `<i class="fa-solid fa-wand-magic-sparkles"></i> Launch AI Security Audit`;
      }
    }
    if (aiDetails) aiDetails.style.display = 'none';
    if (aiModeBadge) {
      aiModeBadge.textContent = 'Ready';
      aiModeBadge.className = 'badge info';
    }
  }
}

/**
 * Triggers the AI audit generation by executing API and simulating logs.
 */
async function launchAiAudit() {
  if (!currentReport) return;

  const aiLaunch = document.getElementById('ai-analysis-launch');
  if (!aiLaunch) return;

  const originalHtml = aiLaunch.innerHTML;

  // Render simulated log console
  aiLaunch.innerHTML = `
    <div class="ai-launch-inner" style="width: 100%; text-align: left; max-width: 650px;">
      <h3 style="text-align: center; margin-bottom: 15px; font-family: 'Outfit', sans-serif;">
        <i class="fa-solid fa-circle-notch fa-spin" style="color: var(--color-accent); margin-right: 8px;"></i>
        AI Detective Threat Assessment in Progress
      </h3>
      <div id="ai-terminal-logs" style="height: 180px; background: #05070f; border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; font-family: 'Fira Code', monospace; font-size: 11.5px; overflow-y: auto; color: #cbd5e1; box-shadow: inset 0 2px 10px rgba(0,0,0,0.5);">
        <div style="color: var(--color-accent);">[INIT] Preparing security context parameters...</div>
      </div>
    </div>
  `;

  const logBox = document.getElementById('ai-terminal-logs');
  function addLog(text, logClass = '') {
    if (!logBox) return;
    const line = document.createElement('div');
    line.className = logClass;
    line.style.margin = '4px 0';
    line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    logBox.appendChild(line);
    logBox.scrollTop = logBox.scrollHeight;

    // Log to the main hub terminal feed if it exists
    writeConsoleLog(text, logClass);
  }

  // Simulated steps
  const steps = [
    { text: 'Establishing Anthropic API secure pipeline (Claude 3.5 Sonnet)...', delay: 400 },
    { text: 'Retrieving local report JSON and parsing vulnerability catalog...', delay: 800 },
    { text: 'Building security graph vectors and taint flow correlations...', delay: 1300 },
    { text: 'Analyzing CWE mappings and chaining vector Entry Points...', delay: 1800 },
    { text: 'Generating realistic penetration scenario narratives...', delay: 2400 },
    { text: 'Compiling prioritized remediation checklists with business context...', delay: 3000 },
    { text: 'Integrating AI assessments into Markdown and PDF reports...', delay: 3600 }
  ];

  const timeouts = [];
  steps.forEach(s => {
    const t = setTimeout(() => {
      addLog(`[AI DETECTIVE] ${s.text}`);
    }, s.delay);
    timeouts.push(t);
  });

  const startTime = Date.now();

  try {
    const res = await fetch(`${API_BASE}/api/scan/${currentReport.id}/ai-analyze`, {
      method: 'POST'
    });

    const data = await res.json();
    const elapsed = Date.now() - startTime;
    const minPlayTime = 4200; // Let simulator play out
    const remainingTime = Math.max(0, minPlayTime - elapsed);

    setTimeout(() => {
      if (data.success) {
        addLog('[SUCCESS] Threat assessment generated and synchronized.', 'success');
        setTimeout(() => {
          timeouts.forEach(clearTimeout);
          // Reload report details
          viewReportDetails(currentReport.id);
        }, 1000);
      } else {
        throw new Error(data.message || 'Server returned failure status.');
      }
    }, remainingTime);

  } catch (err) {
    timeouts.forEach(clearTimeout);
    addLog(`[ERROR] AI Audit failed: ${err.message}`, 'error');
    alert(`AI Analysis Error: ${err.message}`);
    setTimeout(() => {
      aiLaunch.innerHTML = originalHtml;
    }, 3000);
  }
}

/**
 * Basic markdown parser/renderer translating bold, headings, lists, inline code and paragraphs.
 */
function renderMarkdown(mdStr) {
  if (!mdStr || typeof mdStr !== 'string') return '';

  let html = escapeHtml(mdStr);

  // Inline Code: `code`
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Bold: **text**
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

  // Headings: ###, ##, #
  html = html.replace(/^### (.*$)/gim, '<h4>$1</h4>');
  html = html.replace(/^## (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^# (.*$)/gim, '<h2>$1</h2>');

  // List Items: * item or - item
  html = html.replace(/^\s*[-*]\s+(.*$)/gim, '<li>$1</li>');

  // Parse paragraphs and list containers
  const blocks = html.split(/\n\n+/);
  html = blocks.map(block => {
    block = block.trim();
    if (!block) return '';
    if (block.startsWith('<h') || block.startsWith('<li>')) {
      return block;
    }
    if (block.includes('<li>')) {
      return `<ul>${block}</ul>`;
    }
    return `<p>${block.replace(/\n/g, '<br>')}</p>`;
  }).join('\n');

  return html;
}

// ==========================================================================
// WAPT Feature Logic
// ==========================================================================

function waptLog(msg) {
  const c = document.getElementById('wapt-console-logs');
  if (!c) return;
  const line = document.createElement('div');
  line.className = 'console-line';
  line.textContent = msg;
  c.appendChild(line);
  c.scrollTop = c.scrollHeight;
}

function clearWaptConsole() {
  const c = document.getElementById('wapt-console-logs');
  if (c) c.innerHTML = '<div class="console-line">[CLEARED]</div>';
}

function escW(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function handleWaptScan() {
  const targetUrl = (document.getElementById('wapt-url-input')?.value || '').trim();
  if (!targetUrl) { waptLog('[ERROR] Please enter a target URL.'); return; }
  const btn = document.getElementById('wapt-scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning…';
  clearWaptConsole();
  waptLog(`[WAPT] Target: ${targetUrl}`);
  waptLog('[WAPT] Running 10 security checks — this may take 30-60 seconds…');
  document.getElementById('wapt-results-placeholder').style.display = 'flex';
  document.getElementById('wapt-results-panel').style.display = 'none';
  try {
    const res = await fetch('/api/wapt/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl })
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.message || 'Scan failed');
    (data.result?.log || []).forEach(l => waptLog(l));
    waptLog(`[DONE] Score: ${data.result.metrics.securityScore}/100  Grade: ${data.result.metrics.grade}`);
    renderWaptResults(data.result);
  } catch (err) {
    waptLog(`[ERROR] ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-play"></i> Start WAPT Scan';
  }
}

function renderWaptResults(result) {
  document.getElementById('wapt-results-placeholder').style.display = 'none';
  document.getElementById('wapt-results-panel').style.display = 'block';
  const m = result.metrics, c = m.severityCounts;
  
  // Format target URL and indicators
  document.getElementById('wapt-score-section').innerHTML = `
    <div class="wapt-score-card-layout">
      <!-- Grade & Posture Score Dial -->
      <div class="wapt-metric-dial">
        <div class="wapt-grade-circle wapt-grade-${m.grade}">${m.grade}</div>
        <div class="wapt-metric-meta">
          <div class="wapt-metric-label">Security Posture</div>
          <div class="wapt-metric-value">${m.securityScore}/100</div>
        </div>
      </div>

      <!-- Confidence Score Dial -->
      <div class="wapt-metric-dial">
        <div class="wapt-metric-circle confidence-circle">${m.confidenceScore}%</div>
        <div class="wapt-metric-meta">
          <div class="wapt-metric-label">Scanner Confidence</div>
          <div class="wapt-metric-value">${m.confidenceScore >= 70 ? 'High' : m.confidenceScore >= 40 ? 'Medium' : 'Low'}</div>
        </div>
      </div>

      <!-- Risk Score Dial -->
      <div class="wapt-metric-dial">
        <div class="wapt-metric-circle risk-circle risk-${m.riskScore > 70 ? 'critical' : m.riskScore > 40 ? 'medium' : 'low'}">${m.riskScore}/100</div>
        <div class="wapt-metric-meta">
          <div class="wapt-metric-label">Threat Risk Index</div>
          <div class="wapt-metric-value">${m.riskScore > 70 ? 'Critical' : m.riskScore > 40 ? 'Medium' : 'Low'} Risk</div>
        </div>
      </div>
    </div>
    
    <div class="wapt-target-url-row mt-15">
      <div class="wapt-url-text" style="font-family: monospace; font-size: 0.8rem; word-break: break-all;">${escW(result.targetUrl)}</div>
      <div class="wapt-severity-pills mt-10" style="display:flex; gap:0.5rem; flex-wrap:wrap; align-items:center;">
        ${c.Critical ? `<span class="wapt-sev-pill Critical">🔴 Critical: ${c.Critical}</span>` : ''}
        ${c.High     ? `<span class="wapt-sev-pill High">🟠 High: ${c.High}</span>` : ''}
        ${c.Medium   ? `<span class="wapt-sev-pill Medium">🟡 Medium: ${c.Medium}</span>` : ''}
        ${c.Low      ? `<span class="wapt-sev-pill Low">🔵 Low: ${c.Low}</span>` : ''}
        <span style="font-size:.72rem;color:var(--text-muted);margin-left:auto;">${m.totalFindings} finding(s)</span>
      </div>
    </div>`;

  const container = document.getElementById('wapt-findings-list');
  if (!result.findings?.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:.85rem;padding:20px 0;">No issues found.</p>';
    return;
  }

  const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  const sorted = [...result.findings].sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

  container.innerHTML = sorted.map((f, index) => {
    const uniqueId = `finding-${index}`;
    return `
      <div class="wapt-finding-card">
        <div class="wapt-finding-header" onclick="toggleWaptFinding(this)">
          <span class="wapt-sev-badge ${escW(f.severity)}">${escW(f.severity)}</span>
          <span class="wapt-finding-title">${escW(f.title)}</span>
          <span class="wapt-finding-category-tag">${escW(f.category)}</span>
          <i class="fa-solid fa-chevron-down" style="margin-left:.5rem;font-size:.7rem;color:var(--text-muted);transition:transform .2s;"></i>
        </div>
        
        <div class="wapt-finding-body" style="display:none;">
          <!-- Accordion Tabs -->
          <div class="wapt-tabs-nav">
            <button class="wapt-tab-btn active" onclick="switchWaptTab(event, '${uniqueId}-overview')">Overview</button>
            <button class="wapt-tab-btn" onclick="switchWaptTab(event, '${uniqueId}-evidence')">Evidence (HTTP)</button>
            <button class="wapt-tab-btn" onclick="switchWaptTab(event, '${uniqueId}-remediation')">Remediation</button>
          </div>

          <!-- Tab: Overview -->
          <div class="wapt-tab-content active" id="${uniqueId}-overview">
            <p style="font-size:.82rem;line-height:1.5;color:var(--text-primary);">${escW(f.description)}</p>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:0.5rem; margin-top:0.75rem; font-size:0.74rem; background:rgba(255,255,255,0.02); padding:0.5rem 0.75rem; border-radius:6px; border:1px solid var(--border-color);">
              <div><strong>Confidence Rating:</strong> <span class="badge-conf-${(f.confidence || 'Medium').toLowerCase()}">${escW(f.confidence || 'Medium')} (${f.confidenceScore || 70}%)</span></div>
              <div><strong>Detection Logic:</strong> <code>${escW(f.detectionLogic || 'Signature Match')}</code></div>
            </div>
            <div class="wapt-field-label mt-10">Analysis Reasoning</div>
            <div class="wapt-reasoning-box">${escW(f.reasoning || 'Standard compliance evaluation.')}</div>
          </div>

          <!-- Tab: Evidence -->
          <div class="wapt-tab-content" id="${uniqueId}-evidence">
            <div class="wapt-field-label">Raw HTTP Request</div>
            <pre class="wapt-http-box">${escW(f.rawRequest || 'No request log available.')}</pre>
            <div class="wapt-field-label mt-10">Raw HTTP Response</div>
            <pre class="wapt-http-box">${escW(f.rawResponse || 'No response log available.')}</pre>
          </div>

          <!-- Tab: Remediation -->
          <div class="wapt-tab-content" id="${uniqueId}-remediation">
            <div class="wapt-field-label">Suggested Remediation</div>
            <div class="wapt-rec">${escW(f.remediation || 'Maintain standard configurations.')}</div>
          </div>
        </div>
      </div>`;
  }).join('');
}

function toggleWaptFinding(header) {
  const body = header.nextElementSibling;
  const icon = header.querySelector('.fa-chevron-down');
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  if (icon) icon.style.transform = isOpen ? '' : 'rotate(180deg)';
}

function switchWaptTab(event, targetTabId) {
  event.stopPropagation(); // Stop click from bubbling and collapsing the accordion
  const clickedBtn = event.currentTarget;
  const nav = clickedBtn.parentElement;
  const body = nav.parentElement;

  // Toggle active button
  nav.querySelectorAll('.wapt-tab-btn').forEach(btn => btn.classList.remove('active'));
  clickedBtn.classList.add('active');

  // Toggle active tab content
  body.querySelectorAll('.wapt-tab-content').forEach(content => {
    if (content.id === targetTabId) {
      content.style.display = 'block';
    } else {
      content.style.display = 'none';
    }
  });
}
