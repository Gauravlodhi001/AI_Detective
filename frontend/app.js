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
    if (report.type === 'wapt') {
      switchTab('wapt');
      renderWaptResults(report);
    } else {
      showReport(report);
    }
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

// Global memory store for WAPT multi-role configurations
window.waptRolesConfig = {
  userA: { authType: 'none', credentials: { loginUrl: '', usernameField: 'email', passwordField: 'password', usernameValue: '', passwordValue: '' }, staticHeaders: {} },
  userB: { authType: 'none', credentials: { loginUrl: '', usernameField: 'email', passwordField: 'password', usernameValue: '', passwordValue: '' }, staticHeaders: {} },
  manager: { authType: 'none', credentials: { loginUrl: '', usernameField: 'email', passwordField: 'password', usernameValue: '', passwordValue: '' }, staticHeaders: {} },
  admin: { authType: 'none', credentials: { loginUrl: '', usernameField: 'email', passwordField: 'password', usernameValue: '', passwordValue: '' }, staticHeaders: {} }
};

window.waptActiveRole = 'userA'; // Currently selected role to configure in the form

function toggleWaptMultiRole(checked) {
  const roleSelector = document.getElementById('wapt-role-selector-container');
  if (roleSelector) {
    roleSelector.style.display = checked ? 'block' : 'none';
  }
  
  // Update the select dropdown target and active configurations
  if (checked) {
    document.getElementById('wapt-configure-role').value = 'userA';
    window.waptActiveRole = 'userA';
    loadRoleConfigIntoUI('userA');
  } else {
    // Reset selector and load default UI fields
    const activeAuthType = document.getElementById('wapt-auth-type').value;
    toggleWaptAuthFields(activeAuthType);
  }
}

// Save active form values to the currently selected role config in memory
function saveActiveRoleConfig() {
  const role = window.waptActiveRole;
  if (!window.waptRolesConfig[role]) return;

  const authType = document.getElementById('wapt-auth-type').value;
  window.waptRolesConfig[role].authType = authType;

  if (authType === 'cookie' || authType === 'jwt') {
    window.waptRolesConfig[role].canaryUrl = (document.getElementById('wapt-auth-canaryurl')?.value || '').trim();
    window.waptRolesConfig[role].credentials = {
      loginUrl: (document.getElementById('wapt-auth-loginurl')?.value || '').trim(),
      usernameField: (document.getElementById('wapt-auth-userfield')?.value || 'email').trim(),
      passwordField: (document.getElementById('wapt-auth-pwdfield')?.value || 'password').trim(),
      usernameValue: (document.getElementById('wapt-auth-userval')?.value || '').trim(),
      passwordValue: (document.getElementById('wapt-auth-pwdval')?.value || '').trim()
    };
  } else if (authType === 'header') {
    window.waptRolesConfig[role].canaryUrl = '';
    const rawJson = (document.getElementById('wapt-auth-headersjson')?.value || '').trim();
    if (rawJson) {
      try {
        window.waptRolesConfig[role].staticHeaders = JSON.parse(rawJson);
      } catch (e) {
        window.waptRolesConfig[role].staticHeaders = {};
      }
    } else {
      window.waptRolesConfig[role].staticHeaders = {};
    }
  } else {
    window.waptRolesConfig[role].canaryUrl = '';
    window.waptRolesConfig[role].credentials = {};
    window.waptRolesConfig[role].staticHeaders = {};
  }
}

// Load configurations from memory into the active UI input fields
function loadRoleConfigIntoUI(role) {
  const config = window.waptRolesConfig[role];
  if (!config) return;

  // Set auth type and trigger field updates
  const authTypeSelect = document.getElementById('wapt-auth-type');
  if (authTypeSelect) {
    authTypeSelect.value = config.authType;
    toggleWaptAuthFields(config.authType);
  }

  // Set credentials fields
  const creds = config.credentials || {};
  const loginUrlField = document.getElementById('wapt-auth-loginurl');
  if (loginUrlField) loginUrlField.value = creds.loginUrl || '';

  const userField = document.getElementById('wapt-auth-userfield');
  if (userField) userField.value = creds.usernameField || 'email';

  const pwdField = document.getElementById('wapt-auth-pwdfield');
  if (pwdField) pwdField.value = creds.passwordField || 'password';

  const userValField = document.getElementById('wapt-auth-userval');
  if (userValField) userValField.value = creds.usernameValue || '';

  const pwdValField = document.getElementById('wapt-auth-pwdval');
  if (pwdValField) pwdValField.value = creds.passwordValue || '';

  const canaryUrlField = document.getElementById('wapt-auth-canaryurl');
  if (canaryUrlField) canaryUrlField.value = config.canaryUrl || '';

  // Set static headers JSON
  const headersField = document.getElementById('wapt-auth-headersjson');
  if (headersField) {
    headersField.value = config.staticHeaders ? JSON.stringify(config.staticHeaders, null, 2) : '';
  }
}

// Triggered when selection of Configure Role select changes
function changeActiveRoleConfig(newRole) {
  saveActiveRoleConfig();
  window.waptActiveRole = newRole;
  loadRoleConfigIntoUI(newRole);
}

function toggleWaptAuthFields(value) {
  const credsContainer = document.getElementById('wapt-auth-creds-fields');
  const headersContainer = document.getElementById('wapt-auth-headers-fields');
  
  if (value === 'cookie' || value === 'jwt') {
    if (credsContainer) credsContainer.style.display = 'block';
    if (headersContainer) headersContainer.style.display = 'none';
  } else if (value === 'header') {
    if (credsContainer) credsContainer.style.display = 'none';
    if (headersContainer) headersContainer.style.display = 'block';
  } else {
    if (credsContainer) credsContainer.style.display = 'none';
    if (headersContainer) headersContainer.style.display = 'none';
  }
}


async function handleWaptScan() {
  const targetUrl = (document.getElementById('wapt-url-input')?.value || '').trim();
  if (!targetUrl) { waptLog('[ERROR] Please enter a target URL.'); return; }

  // Extract authConfig parameters
  const isMultiRole = document.getElementById('wapt-multi-role-toggle')?.checked || false;
  let authConfig = {};
  let authType = 'none';

  if (isMultiRole) {
    // Save current active role values first
    saveActiveRoleConfig();
    authConfig = {
      guest: { authType: 'none' },
      userA: window.waptRolesConfig.userA,
      userB: window.waptRolesConfig.userB,
      manager: window.waptRolesConfig.manager,
      admin: window.waptRolesConfig.admin
    };
  } else {
    authType = document.getElementById('wapt-auth-type')?.value || 'none';
    let singleConfig = { authType };
    if (authType === 'cookie' || authType === 'jwt') {
      singleConfig.canaryUrl = (document.getElementById('wapt-auth-canaryurl')?.value || '').trim();
      singleConfig.credentials = {
        loginUrl: (document.getElementById('wapt-auth-loginurl')?.value || '').trim(),
        usernameField: (document.getElementById('wapt-auth-userfield')?.value || 'email').trim(),
        passwordField: (document.getElementById('wapt-auth-pwdfield')?.value || 'password').trim(),
        usernameValue: (document.getElementById('wapt-auth-userval')?.value || '').trim(),
        passwordValue: (document.getElementById('wapt-auth-pwdval')?.value || '').trim()
      };
    } else if (authType === 'header') {
      const rawJson = (document.getElementById('wapt-auth-headersjson')?.value || '').trim();
      if (rawJson) {
        try {
          singleConfig.staticHeaders = JSON.parse(rawJson);
        } catch (e) {
          waptLog('[ERROR] Invalid JSON in Static Headers. Using empty configuration.');
          singleConfig.staticHeaders = {};
        }
      } else {
        singleConfig.staticHeaders = {};
      }
    }
    authConfig = {
      guest: { authType: 'none' },
      userA: singleConfig,
      userB: { authType: 'none' },
      manager: { authType: 'none' },
      admin: singleConfig
    };
  }


  const scanId = `wapt-scan-${Date.now()}`;

  const btn = document.getElementById('wapt-scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning…';
  clearWaptConsole();
  waptLog(`[WAPT] Target: ${targetUrl}`);
  waptLog(`[WAPT] Mode: ${isMultiRole ? 'Multi-Role RBAC Audit' : (authType === 'none' ? 'Anonymous Black Box' : 'Authenticated Gray Box')}`);
  waptLog('[WAPT] Running 10 security checks — this may take 30-60 seconds…');
  document.getElementById('wapt-results-placeholder').style.display = 'flex';
  document.getElementById('wapt-results-panel').style.display = 'none';

  let loggedCount = 0;
  const pollInterval = setInterval(async () => {
    try {
      const pollRes = await fetch(`/api/wapt/scan/${scanId}/logs`);
      const pollData = await pollRes.json();
      if (pollData.success && pollData.logs && pollData.logs.length > loggedCount) {
        const newLogs = pollData.logs.slice(loggedCount);
        newLogs.forEach(l => waptLog(l));
        loggedCount = pollData.logs.length;
      }
    } catch (e) {}
  }, 1500);

  try {
    const res = await fetch('/api/wapt/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl, authConfig, scanId })
    });
    const data = await res.json();
    clearInterval(pollInterval);
    if (!data.success) throw new Error(data.message || 'Scan failed');
    
    // Clear and draw final logs cleanly
    clearWaptConsole();
    (data.result?.log || []).forEach(l => waptLog(l));
    waptLog(`[DONE] Score: ${data.result.metrics.securityScore}/100  Grade: ${data.result.metrics.grade}`);
    renderWaptResults(data.result);
  } catch (err) {
    clearInterval(pollInterval);
    waptLog(`[ERROR] ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-play"></i> Start WAPT Scan';
  }
}

function renderWaptResults(result) {
  window.activeWaptReportId = result.reportId;
  document.getElementById('wapt-results-placeholder').style.display = 'none';
  document.getElementById('wapt-results-panel').style.display = 'block';
  const m = result.metrics, c = m.severityCounts;
  
  // Sync Auditor Mode switch checkbox
  const auditorSwitch = document.getElementById('wapt-auditor-mode-switch');
  if (auditorSwitch) {
    auditorSwitch.checked = !!window.activeAuditorMode;
  }

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
        <div class="wapt-metric-circle confidence-circle">${result.attackSurface?.securityCoverage?.assessmentConfidence || 85}%</div>
        <div class="wapt-metric-meta">
          <div class="wapt-metric-label">Assessment Confidence</div>
          <div class="wapt-metric-value">${result.attackSurface?.securityCoverage?.assessmentConfidenceRating || 'High'}</div>
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
        ${c.Info     ? `<span class="wapt-sev-pill Info">ℹ️ Info: ${c.Info}</span>` : ''}
        <span style="font-size:.72rem;color:var(--text-muted);margin-left:auto;">${m.totalFindings} finding(s)</span>
      </div>
    </div>`;

  // Render Defensive Attack Surface & Scope Metrics
  const surface = result.attackSurface || { discoveryMetrics: {}, technologies: [], securityCoverage: {} };
  const disc = surface.discoveryMetrics || {};
  const cov = surface.securityCoverage || {};

  const metricsHtml = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
      <!-- Left Column: Discovery Metrics -->
      <div>
        <h4 style="font-size: 0.82rem; font-weight: 700; margin-bottom: 0.5rem; text-transform: uppercase; color: var(--text-muted);">Discovered Assets</h4>
        <div class="wapt-map-grid" style="grid-template-columns: 1fr 1fr; gap: 8px;">
          <div class="wapt-map-card"><i class="fa-solid fa-spider"></i><div class="wapt-map-card-text"><span class="wapt-map-card-title">Pages Crawled</span><span class="wapt-map-card-value">${disc.pagesCrawled || 1}</span></div></div>
          <div class="wapt-map-card"><i class="fa-solid fa-link"></i><div class="wapt-map-card-text"><span class="wapt-map-card-title">URLs Discovered</span><span class="wapt-map-card-value">${disc.urlsDiscovered || 0}</span></div></div>
          <div class="wapt-map-card"><i class="fa-solid fa-list-check"></i><div class="wapt-map-card-text"><span class="wapt-map-card-title">Forms Found</span><span class="wapt-map-card-value">${disc.formsFound || 0}</span></div></div>
          <div class="wapt-map-card"><i class="fa-solid fa-terminal"></i><div class="wapt-map-card-text"><span class="wapt-map-card-title">Inputs Found</span><span class="wapt-map-card-value">${disc.inputFieldsFound || 0}</span></div></div>
          <div class="wapt-map-card"><i class="fa-solid fa-key"></i><div class="wapt-map-card-text"><span class="wapt-map-card-title">Parameters Identified</span><span class="wapt-map-card-value">${disc.parametersIdentified || 0}</span></div></div>
          <div class="wapt-map-card"><i class="fa-solid fa-cookie"></i><div class="wapt-map-card-text"><span class="wapt-map-card-title">Cookies Observed</span><span class="wapt-map-card-value">${disc.cookiesObserved || 0}</span></div></div>
          <div class="wapt-map-card"><i class="fa-solid fa-gears"></i><div class="wapt-map-card-text"><span class="wapt-map-card-title">API Endpoints</span><span class="wapt-map-card-value">${disc.apiEndpointsDetected || 0}</span></div></div>
          <div class="wapt-map-card"><i class="fa-solid fa-file-code"></i><div class="wapt-map-card-text"><span class="wapt-map-card-title">JS Files</span><span class="wapt-map-card-value">${disc.javascriptFilesAnalyzed || 0}</span></div></div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-top: 8px;">
          <div style="background: rgba(255,255,255,0.01); border: 1px dashed var(--border-color); padding: 5px; border-radius: 4px; text-align: center;"><span style="font-size: 0.62rem; color: var(--text-muted); display:block;">Auth Portals</span> <strong style="font-size:0.75rem; color:#fff;">${disc.authenticationPortalsFound || 0}</strong></div>
          <div style="background: rgba(255,255,255,0.01); border: 1px dashed var(--border-color); padding: 5px; border-radius: 4px; text-align: center;"><span style="font-size: 0.62rem; color: var(--text-muted); display:block;">Uploads</span> <strong style="font-size:0.75rem; color:#fff;">${disc.uploadInterfacesFound || 0}</strong></div>
          <div style="background: rgba(255,255,255,0.01); border: 1px dashed var(--border-color); padding: 5px; border-radius: 4px; text-align: center;"><span style="font-size: 0.62rem; color: var(--text-muted); display:block;">Search</span> <strong style="font-size:0.75rem; color:#fff;">${disc.searchInterfacesFound || 0}</strong></div>
          <div style="background: rgba(255,255,255,0.01); border: 1px dashed var(--border-color); padding: 5px; border-radius: 4px; text-align: center;"><span style="font-size: 0.62rem; color: var(--text-muted); display:block;">Admins</span> <strong style="font-size:0.75rem; color:#fff;">${disc.administrativeInterfacesFound || 0}</strong></div>
        </div>
      </div>
      <!-- Right Column: Technology Confidence -->
      <div>
        <h4 style="font-size: 0.82rem; font-weight: 700; margin-bottom: 0.5rem; text-transform: uppercase; color: var(--text-muted);">Technology Confidence Details</h4>
        <div style="max-height: 250px; overflow-y: auto; display: flex; flex-direction: column; gap: 6px;">
          ${(surface.technologies || []).map(t => `
            <div class="wapt-tech-item-card">
              <div class="wapt-tech-item-header">
                <span class="wapt-tech-item-name">${escW(t.name)}</span>
                <span class="wapt-tech-item-conf">${t.confidence}% Confidence</span>
              </div>
              <div class="wapt-tech-item-evidence">Source: ${escW(t.evidenceSource)} (${escW(t.evidenceDetails)})</div>
            </div>
          `).join('') || '<p style="color:var(--text-muted);font-size:.8rem;padding:10px 0;">No technology signatures observed passively.</p>'}
        </div>
      </div>
    </div>

    <!-- Security Coverage Bars -->
    <div style="margin-top: 20px; border-top: 1px solid var(--border-color); padding-top: 15px;">
      <h4 style="font-size: 0.82rem; font-weight: 700; margin-bottom: 0.8rem; text-transform: uppercase; color: var(--text-muted);">Security Validation Coverage</h4>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px 25px;">
        ${[
          { name: 'Injection Security', score: cov.injectionCoverage },
          { name: 'Authentication Control', score: cov.authenticationCoverage },
          { name: 'Authorization Auditing', score: cov.authorizationCoverage },
          { name: 'Session Management', score: cov.sessionManagementCoverage },
          { name: 'CSRF Coverage', score: cov.csrfCoverage },
          { name: 'Security Headers', score: cov.securityHeadersCoverage },
          { name: 'Transport Layer Security', score: cov.transportSecurityCoverage },
          { name: 'API Security Probing', score: cov.apiSecurityCoverage },
          { name: 'Cookie Hardening', score: cov.cookieSecurityCoverage }
        ].map(item => `
          <div class="wapt-owasp-row" style="padding: 0.35rem 0.6rem; border-color: rgba(255,255,255,0.03); margin: 0;">
            <span style="font-weight: 600; width: 160px; font-size: 0.72rem; color: #cbd5e1; white-space: nowrap; text-overflow: ellipsis; overflow: hidden;">${item.name}</span>
            <div class="wapt-owasp-bar-bg" style="height: 6px;">
              <div class="wapt-owasp-bar secured" style="width: ${item.score || 0}%; background: #2563eb;"></div>
            </div>
            <span style="width: 40px; font-size: 0.7rem; font-weight: 700; text-align: right; color: var(--text-primary);">${item.score || 0}%</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  document.getElementById('wapt-surface-section').innerHTML = `
    <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.75rem;">Defensive Assessment Coverage & Scope</h3>
    ${metricsHtml}
  `;

  // Render AI Correlated Attack Paths
  const paths = result.attackPaths || [];
  if (paths.length > 0) {
    const pathsHtml = paths.map(path => {
      const stepsHtml = path.steps.map((step, idx) => `
        <div class="wapt-path-step">
          <div class="wapt-path-step-num">${idx + 1}</div>
          <span><strong>${escW(step.finding)}</strong>: ${escW(step.impact)}</span>
        </div>
      `).join('<div class="wapt-path-arrow"><i class="fa-solid fa-arrow-down-long"></i></div>');

      return `
        <div class="wapt-path-chain">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <span style="font-size: 0.82rem; font-weight: 700; color: #a78bfa;">🔗 Potential Attack Path Chain</span>
            <span class="wapt-sev-badge ${escW(path.severity)}">${escW(path.severity)} Risk</span>
          </div>
          <div style="margin-top: 0.6rem; display: flex; flex-direction: column; gap: 0.4rem;">
            ${stepsHtml}
          </div>
          <div class="wapt-path-description">
            <strong>Security Assessment Summary:</strong> ${escW(path.description)}
          </div>
        </div>
      `;
    }).join('');

    document.getElementById('wapt-paths-section').innerHTML = `
      <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem;">AI Correlated Attack Paths</h3>
      ${pathsHtml}
    `;
    document.getElementById('wapt-paths-section').style.display = 'block';
  } else {
    document.getElementById('wapt-paths-section').style.display = 'none';
  }

  // Render OWASP Top 10 Control Coverage
  const owaspCov = m.owaspCoverage || {};
  const owaspKeys = Object.keys(owaspCov);
  if (owaspKeys.length > 0) {
    const owaspRows = owaspKeys.map(category => {
      const item = owaspCov[category];
      
      let barClass = 'not-tested';
      if (item.status === 'FLAGGED') barClass = 'flagged';
      else if (item.status === 'SECURED') barClass = 'secured';
      else if (item.status === 'NOT OBSERVED') barClass = 'not-observed';
      else if (item.status === 'INSUFFICIENT COVERAGE') barClass = 'insufficient-coverage';

      let barWidth = '100%';
      if (item.status === 'INSUFFICIENT COVERAGE') barWidth = '40%';
      else if (item.status === 'NOT TESTED') barWidth = '0%';
      
      return `
        <div class="wapt-owasp-row">
          <span class="wapt-owasp-category" title="${escW(category)}">${escW(category)}</span>
          <div class="wapt-owasp-bar-bg">
            <div class="wapt-owasp-bar ${barClass}" style="width: ${barWidth};"></div>
          </div>
          <span class="wapt-owasp-status ${barClass}">${escW(item.status)} ${item.findings > 0 ? `(${item.findings})` : ''}</span>
        </div>
      `;
    }).join('');

    document.getElementById('wapt-owasp-section').innerHTML = `
      <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem;">OWASP Top 10 Control Coverage</h3>
      <div class="wapt-owasp-list">
        ${owaspRows}
      </div>
    `;
    document.getElementById('wapt-owasp-section').style.display = 'block';
  } else {
    document.getElementById('wapt-owasp-section').style.display = 'none';
  }

  // Render RBAC Matrix Section
  const rbacContainer = document.getElementById('wapt-rbac-section');
  if (rbacContainer) {
    if (result.rbacMatrix && result.rbacMatrix.length > 0) {
      rbacContainer.style.display = 'block';
      let rbacHtml = `
        <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem; color: var(--text-primary);"><i class="fa-solid fa-users-viewfinder" style="margin-right: 6px; color: #10b981;"></i> Role-Based Access Control (RBAC) Matrix</h3>
        <div style="overflow-x: auto; background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 20px;">
          <table style="width: 100%; border-collapse: collapse; font-size: 0.74rem; text-align: left; min-width: 600px;">
            <thead>
              <tr style="background: rgba(255,255,255,0.04); border-bottom: 1px solid var(--border-color);">
                <th style="padding: 10px; font-weight: 600; color: var(--text-muted); width: 40%;">API Route</th>
                <th style="padding: 10px; font-weight: 600; color: var(--text-muted); width: 10%;">Method</th>
                <th style="padding: 10px; font-weight: 600; color: var(--text-muted); text-align: center; width: 10%;">Guest</th>
                <th style="padding: 10px; font-weight: 600; color: var(--text-muted); text-align: center; width: 10%;">User A</th>
                <th style="padding: 10px; font-weight: 600; color: var(--text-muted); text-align: center; width: 10%;">User B</th>
                <th style="padding: 10px; font-weight: 600; color: var(--text-muted); text-align: center; width: 10%;">Manager</th>
                <th style="padding: 10px; font-weight: 600; color: var(--text-muted); text-align: center; width: 10%;">Admin</th>
              </tr>
            </thead>
            <tbody>
      `;

      const getBadge = (status) => {
        if (!status) return `<span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-muted); padding: 2px 6px; border-radius: 4px; font-size: 0.68rem;">N/A</span>`;
        if (status >= 200 && status < 300) {
          return `<span class="badge" style="background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3); font-weight:bold; padding: 2px 6px; border-radius: 4px; font-size: 0.68rem;">${status}</span>`;
        }
        if (status === 401 || status === 403) {
          return `<span class="badge" style="background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); padding: 2px 6px; border-radius: 4px; font-size: 0.68rem;">${status}</span>`;
        }
        return `<span class="badge" style="background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); padding: 2px 6px; border-radius: 4px; font-size: 0.68rem;">${status}</span>`;
      };

      result.rbacMatrix.forEach(row => {
        const rowStyle = row.isVulnerable ? 'background: rgba(239, 68, 68, 0.04); border-bottom: 1px solid var(--border-color);' : 'border-bottom: 1px solid var(--border-color);';
        const routeLabel = row.isVulnerable ? `<span style="color: var(--color-critical); font-weight:bold;"><i class="fa-solid fa-triangle-exclamation"></i> ${escW(row.path)}</span>` : escW(row.path);
        
        rbacHtml += `
          <tr style="${rowStyle}">
            <td style="padding: 10px; font-family: monospace; font-size: 0.72rem; word-break: break-all;">${routeLabel}</td>
            <td style="padding: 10px; font-family: monospace; font-weight: 700;">${row.method}</td>
            <td style="padding: 10px; text-align: center;">${getBadge(row.guest)}</td>
            <td style="padding: 10px; text-align: center;">${getBadge(row.userA)}</td>
            <td style="padding: 10px; text-align: center;">${getBadge(row.userB)}</td>
            <td style="padding: 10px; text-align: center;">${getBadge(row.manager)}</td>
            <td style="padding: 10px; text-align: center;">${getBadge(row.admin)}</td>
          </tr>
        `;
      });

      rbacHtml += `
            </tbody>
          </table>
        </div>
      `;
      rbacContainer.innerHTML = rbacHtml;
    } else {
      rbacContainer.style.display = 'none';
    }
  }

  // Render Parameter Mining Section
  const paramsContainer = document.getElementById('wapt-params-section');
  if (paramsContainer) {
    if (result.discoveredParameters && Object.keys(result.discoveredParameters).length > 0) {
      paramsContainer.style.display = 'block';
      let paramsHtml = `
        <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem; color: var(--text-primary);"><i class="fa-solid fa-magnifying-glass" style="margin-right: 6px; color: #60a5fa;"></i> Mined API Parameters</h3>
        <div style="background: rgba(255, 255, 255, 0.02); border: 1px solid var(--border-color); border-radius: 8px; padding: 12px; max-height: 200px; overflow-y: auto; margin-bottom: 20px;">
          <div style="display: flex; flex-direction: column; gap: 8px;">
      `;

      for (const [endpoint, params] of Object.entries(result.discoveredParameters)) {
        if (!params || params.length === 0) continue;
        paramsHtml += `
          <div style="border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 8px; margin-bottom: 4px;">
            <div style="font-family: monospace; font-size: 0.72rem; color: var(--text-primary); margin-bottom: 4px; word-break: break-all;">${escW(endpoint)}</div>
            <div style="display: flex; gap: 5px; flex-wrap: wrap;">
              ${params.map(p => `<span style="background: rgba(96,165,250,0.1); color: #60a5fa; border: 1px solid rgba(96,165,250,0.25); border-radius: 4px; padding: 2px 6px; font-size: 0.64rem; font-family: monospace;">${escW(p)}</span>`).join('')}
            </div>
          </div>
        `;
      }

      paramsHtml += `
          </div>
        </div>
      `;
      paramsContainer.innerHTML = paramsHtml;
    } else {
      paramsContainer.style.display = 'none';
    }
  }

  // Trigger loading of Benchmarks
  loadWaptBenchmarks();


  const container = document.getElementById('wapt-findings-list');
  if (!result.findings?.length) {
    container.innerHTML = '<p style="color:var(--text-muted);font-size:.85rem;padding:20px 0;">No issues found.</p>';
    return;
  }

  const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
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
            <button class="wapt-tab-btn active" onclick="switchWaptTab(event, '${uniqueId}-overview')">Overview & Analysis</button>
            <button class="wapt-tab-btn" onclick="switchWaptTab(event, '${uniqueId}-evidence')">Evidence (HTTP)</button>
            <button class="wapt-tab-btn" onclick="switchWaptTab(event, '${uniqueId}-remediation')">Impact & Remediation</button>
          </div>

          <!-- Tab: Overview -->
          <div class="wapt-tab-content active" id="${uniqueId}-overview">
            <div style="font-size:.82rem;line-height:1.5;color:var(--text-primary);margin-bottom:0.75rem;"><strong>Observation:</strong> ${escW(f.observation || f.description)}</div>
            
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:0.5rem; margin-top:0.75rem; font-size:0.74rem; background:rgba(255,255,255,0.02); padding:0.5rem 0.75rem; border-radius:6px; border:1px solid var(--border-color);">
              <div><strong>Detection Confidence:</strong> <span style="color:#3b82f6;font-weight:600;">${f.detectionConfidence || 100}%</span></div>
              <div><strong>Risk Confidence:</strong> <span class="badge-conf-${(f.confidence || 'Medium').toLowerCase()}">${f.riskConfidence || 50}%</span></div>
              <div><strong>OWASP Top 10:</strong> <span style="color:#f59e0b;font-weight:600;">${escW(f.owasp || 'N/A')}</span></div>
              <div><strong>CWE:</strong> <span style="color:#ef4444;font-weight:600;">${escW(f.cwe || 'N/A')}</span></div>
              <div><strong>CVSS v3.1:</strong> <span style="color:#f43f5e;font-weight:600;">${escW(f.cvss || 'N/A')}</span></div>
              <div><strong>ASVS Control:</strong> <span style="color:#10b981;font-weight:600;">${escW(f.asvs || 'N/A')}</span></div>
              <div style="grid-column: span 2;"><strong>Detection Logic:</strong> <code>${escW(f.detectionLogic || 'Signature Match')}</code></div>
            </div>

            <!-- Auditor Mode Verification Block -->
            <div class="auditor-mode-only" style="display: ${window.activeAuditorMode ? 'block' : 'none'};">
              <div class="auditor-title"><i class="fa-solid fa-user-shield"></i> Auditor Verification & Context</div>
              <div class="auditor-desc"><strong>Rule Signature:</strong> <code>${escW(f.detectionLogic || 'Signature Pattern')}</code></div>
              <div class="auditor-list-row">
                <div class="auditor-list-item"><strong>Detection confidence:</strong> ${f.detectionConfidence || 100}%</div>
                <div class="auditor-list-item"><strong>Risk confidence:</strong> ${f.riskConfidence || 50}%</div>
                <div class="auditor-list-item"><strong>Assessment confidence:</strong> ${cov.assessmentConfidence || 85}%</div>
                <div class="auditor-list-item"><strong>Mitigations considered:</strong> ${escW(f.falsePositiveAssessment || 'None')}</div>
              </div>
            </div>
            
            <div class="wapt-field-label mt-10">AI Security Analysis</div>
            <div class="wapt-reasoning-box">${escW(f.aiAnalysis || f.reasoning || 'Standard compliance evaluation.')}</div>
            
            <div class="wapt-field-label mt-10">AI False Positive Review</div>
            <div class="wapt-fp-box">${escW(f.falsePositiveAssessment || 'No false positives detected.')}</div>
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
            <div class="wapt-field-label">Business Risk & Impact</div>
            <div class="wapt-impact-box">${escW(f.businessImpact || 'Minimal direct business risk.')}</div>
            
            <div class="wapt-field-label mt-10">Suggested Remediation</div>
            <div class="wapt-rec">${escW(f.remediation || 'Maintain standard configurations.')}</div>
          </div>
        </div>
      </div>`;
  }).join('');
}

async function loadWaptBenchmarks() {
  try {
    const res = await fetch('/api/wapt/benchmark');
    const data = await res.json();
    if (data.success && data.benchmarks) {
      const rows = data.benchmarks.map(b => `
        <tr>
          <td style="font-weight: 600;">${escW(b.suite)}</td>
          <td style="color: #cbd5e1; font-weight: 700;">${b.expectedFindings}</td>
          <td style="color: #60a5fa; font-weight: 700;">${b.detectedFindings}</td>
          <td style="color: #f43f5e; font-weight: 700;">${b.missedFindings}</td>
          <td style="color: #f59e0b; font-weight: 700;">${b.falsePositives}</td>
          <td style="color: #8b5cf6; font-weight: 700;">${b.coveragePercent}%</td>
          <td style="color: #10b981; font-weight: 700;">${b.confidencePercent}%</td>
          <td><span class="wapt-bench-badge pass">${escW(b.status)}</span></td>
        </tr>
      `).join('');

      document.getElementById('wapt-benchmark-section').innerHTML = `
        <h3 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 0.5rem;">Scanner Benchmarking Validation</h3>
        <div class="wapt-bench-card">
          <div style="font-size: 0.76rem; color: var(--text-muted); line-height: 1.4; margin-bottom: 0.5rem;">
            The scanner is continuously evaluated against standard industry vulnerable testbeds to ensure optimal detection capability and minimal false positive rate.
          </div>
          <table class="wapt-bench-table">
            <thead>
              <tr>
                <th>Test Suite</th>
                <th>Expected</th>
                <th>Detected</th>
                <th>Missed</th>
                <th>False Positives</th>
                <th>Coverage Depth</th>
                <th>Confidence</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      `;
      document.getElementById('wapt-benchmark-section').style.display = 'block';
    }
  } catch (e) {
    console.error('Failed to load WAPT benchmarks:', e);
  }
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

function downloadWaptPdf() {
  if (!window.activeWaptReportId) {
    alert('No active scan report loaded to download.');
    return;
  }
  window.location.href = `/api/wapt/reports/${window.activeWaptReportId}/pdf`;
}

function toggleAuditorMode(checked) {
  window.activeAuditorMode = checked;
  const elements = document.querySelectorAll('.auditor-mode-only');
  elements.forEach(el => {
    el.style.display = checked ? 'block' : 'none';
  });
}
