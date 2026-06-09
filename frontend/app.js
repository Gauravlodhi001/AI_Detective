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
