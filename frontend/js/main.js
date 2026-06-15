/* ==========================================================================
   AI-Detective Corporate Redesign - Application Main Bootstrapper
   ========================================================================== */

import { api } from './api.js';
import { store } from './state.js';
import { 
  renderSeverityChart, 
  renderOwaspChart,
  renderPrivilegeAuditMatrix,
  renderFindingsHistoryTrend
} from './charts.js';
import { 
  setupDragAndDrop, 
  handleFileSelect, 
  clearSelectedFile, 
  handleZipScan, 
  handleGitScan, 
  handlePasteScan 
} from './scan-panel.js';
import { renderWaptResults } from './wapt-panel.js';
import { 
  renderFindings, 
  updateAiAnalysisPanel, 
  escapeHtml,
  renderCockpitLeftSidebar
} from './components.js';
import { initUniverse, buildGraph } from './universe.js';

export async function checkAuth() {
  const authModal = document.getElementById('auth-modal');
  const userProfile = document.getElementById('user-profile-info');
  const logoutBtn = document.getElementById('logout-btn');
  
  try {
    const data = await api.getDiagnostics();
    if (data.success) {
      if (authModal) authModal.style.display = 'none';
      
      const savedUser = localStorage.getItem('user');
      if (savedUser) {
        const user = JSON.parse(savedUser);
        if (userProfile) {
          userProfile.textContent = `[USER: ${user.username.toUpperCase()} (${user.role.toUpperCase()})]`;
          userProfile.style.display = 'inline-block';
        }
        if (logoutBtn) logoutBtn.style.display = 'inline-block';
      }
      return true;
    }
  } catch (e) {
    // Unauthenticated
  }

  if (authModal) authModal.style.display = 'flex';
  if (userProfile) userProfile.style.display = 'none';
  if (logoutBtn) logoutBtn.style.display = 'none';
  return false;
}

export async function handleLoginSubmit() {
  const usernameInput = document.getElementById('auth-username');
  const passwordInput = document.getElementById('auth-password');
  const errorMsg = document.getElementById('auth-error-msg');
  
  const username = usernameInput?.value || '';
  const password = passwordInput?.value || '';
  
  if (!username || !password) {
    if (errorMsg) {
      errorMsg.textContent = 'Please enter both username and password.';
      errorMsg.style.display = 'block';
    }
    return;
  }
  
  try {
    const res = await api.login(username, password);
    if (res.success) {
      localStorage.setItem('user', JSON.stringify(res.user));
      window.location.reload();
    } else {
      if (errorMsg) {
        errorMsg.textContent = res.message || 'Login failed.';
        errorMsg.style.display = 'block';
      }
    }
  } catch (err) {
    if (errorMsg) {
      errorMsg.textContent = 'Connection error or lockout. Please try again.';
      errorMsg.style.display = 'block';
    }
  }
}

export async function handleRegisterSubmit() {
  const usernameInput = document.getElementById('auth-username');
  const passwordInput = document.getElementById('auth-password');
  const errorMsg = document.getElementById('auth-error-msg');
  
  const username = usernameInput?.value || '';
  const password = passwordInput?.value || '';
  
  if (!username || !password) {
    if (errorMsg) {
      errorMsg.textContent = 'Please enter both username and password.';
      errorMsg.style.display = 'block';
    }
    return;
  }
  
  try {
    const res = await api.register(username, password);
    if (res.success) {
      localStorage.setItem('user', JSON.stringify(res.user));
      window.location.reload();
    } else {
      if (errorMsg) {
        errorMsg.textContent = res.message || 'Registration failed.';
        errorMsg.style.display = 'block';
      }
    }
  } catch (err) {
    if (errorMsg) {
      errorMsg.textContent = 'Connection error. Please try again.';
      errorMsg.style.display = 'block';
    }
  }
}

export async function handleLogoutSubmit() {
  try {
    await api.logout();
    localStorage.removeItem('user');
    window.location.reload();
  } catch (err) {
    console.error('Logout error:', err);
    localStorage.removeItem('user');
    window.location.reload();
  }
}

/**
 * Tab routing/switching handler.
 */
export function switchTab(tabId) {
  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.remove('active');
  });
  
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.remove('active');
  });
  
  const selectedPane = document.getElementById(`tab-${tabId}`);
  if (selectedPane) selectedPane.classList.add('active');
  
  const navBtn = document.getElementById(`nav-btn-${tabId}`);
  if (navBtn) navBtn.classList.add('active');
  
  store.set('activeTab', tabId);

  const pageTitle = document.getElementById('page-title');
  if (pageTitle) {
    if (tabId === 'scan') pageTitle.textContent = 'Scan Hub';
    else if (tabId === 'reports') pageTitle.textContent = 'Saved Reports Catalog';
    else if (tabId === 'settings') pageTitle.textContent = 'Settings & Diagnostics';
    else if (tabId === 'report-viewer') pageTitle.textContent = 'Audit Analysis Report';
    else if (tabId === 'wapt') pageTitle.textContent = 'WAPT Scanner Hub';
  }

  if (tabId === 'reports') {
    loadSavedReports();
  }

  // Force recalculation of container widths for Chart.js and Three.js
  setTimeout(() => {
    window.dispatchEvent(new Event('resize'));
  }, 50);
}

/**
 * Switch scanning mode panel.
 */
export function switchScanMode(mode) {
  document.querySelectorAll('.card-tab-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  document.querySelectorAll('.scan-panel').forEach(panel => {
    panel.classList.remove('active');
  });

  const btn = document.getElementById(`tab-btn-${mode}`);
  if (btn) btn.classList.add('active');
  
  const panel = document.getElementById(`panel-${mode}`);
  if (panel) panel.classList.add('active');
  
  store.set('currentScanMode', mode);
}

/**
 * OS formatting helper.
 */
function formatOS(os) {
  if (os === 'win32') return 'Windows (x64)';
  if (os === 'darwin') return 'macOS (Darwin)';
  if (os === 'linux') return 'Linux (Kernel)';
  return os;
}

/**
 * Runs diagnostics / environment checks.
 */
export async function runDiagnostics() {
  const badgeDot = document.querySelector('#semgrep-status-badge .status-dot');
  const badgeText = document.getElementById('semgrep-status-text');

  try {
    const data = await api.getDiagnostics();
    if (data.success) {
      const diag = data.diagnostics;
      
      const diagOs = document.getElementById('diag-os');
      if (diagOs) diagOs.textContent = formatOS(diag.os);
      
      const diagNode = document.getElementById('diag-node');
      if (diagNode) diagNode.textContent = diag.nodeVersion;
      
      const diagSemgrep = document.getElementById('diag-semgrep');
      if (diagSemgrep) {
        if (diag.semgrepAvailable) {
          diagSemgrep.textContent = `Active (${diag.semgrepVersion})`;
          diagSemgrep.className = 'diag-value green';
          if (badgeDot) badgeDot.className = 'status-dot pulsing active';
          if (badgeText) badgeText.textContent = `Semgrep Active`;
        } else {
          diagSemgrep.textContent = 'Not Found (Fallback SAST Active)';
          diagSemgrep.className = 'diag-value red';
          if (badgeDot) badgeDot.className = 'status-dot warning';
          if (badgeText) badgeText.textContent = `Local Engine (Offline)`;
        }
      }
    }
  } catch (err) {
    console.error('Failed to contact diagnostics:', err);
    if (badgeDot) badgeDot.className = 'status-dot error';
    if (badgeText) badgeText.textContent = `Connection Error`;
  }
}

/**
 * Update the dashboard circular radar score gauge.
 */
export function updateRadarGauge(score) {
  const scoreArc = document.getElementById('dashboard-score-arc');
  const scoreNeedle = document.getElementById('dashboard-score-needle');
  const scoreValue = document.getElementById('dashboard-score-value');
  const postureText = document.getElementById('dashboard-posture-text');

  if (scoreValue) {
    scoreValue.textContent = score;
  }

  if (scoreArc) {
    // Circumference = 2 * Math.PI * 40 = 251.2
    const circumference = 251.2;
    const offset = circumference - (score / 100) * circumference;
    scoreArc.style.strokeDashoffset = offset;
  }

  if (scoreNeedle) {
    // Sweep needle from -135deg (0 score) to +135deg (100 score)
    const angle = -135 + (score / 100) * 270;
    scoreNeedle.style.transform = `rotate(${angle}deg)`;
  }

  if (postureText) {
    if (score >= 75) {
      postureText.textContent = 'POSTURE: STABLE';
      postureText.className = 'radar-posture-status';
    } else if (score >= 50) {
      postureText.textContent = 'POSTURE: WARNING';
      postureText.className = 'radar-posture-status';
    } else {
      postureText.textContent = 'POSTURE: COMPROMISED';
      postureText.className = 'radar-posture-status compromised';
    }
  }
}

/**
 * Loads recent audit table on dashboard view.
 */
export async function loadDashboardData() {
  try {
    const reports = await api.getReportsList();
    
    // Sort reports by scanTime descending
    const sortedReports = reports.sort((a, b) => new Date(b.scanTime) - new Date(a.scanTime));

    const totalFindings = document.getElementById('stat-total-findings');
    const criticalFindings = document.getElementById('stat-critical-findings');
    const dependenciesFindings = document.getElementById('stat-dependencies-findings');
    const lastScanAge = document.getElementById('stat-last-scan-age');
    const signalList = document.getElementById('dashboard-signals-list');
    const consoleLogs = document.getElementById('dashboard-console-logs');

    if (reports.length === 0) {
      if (totalFindings) totalFindings.textContent = '00';
      if (criticalFindings) criticalFindings.textContent = '00';
      if (dependenciesFindings) dependenciesFindings.textContent = '00';
      if (lastScanAge) lastScanAge.textContent = 'N/A';
      updateRadarGauge(0);
      
      if (signalList) {
        signalList.innerHTML = '<div class="empty-state-text">NO ACTIVE SIGNALS. HEAD TO SCAN TO AUDIT CODE.</div>';
      }
      if (consoleLogs) {
        consoleLogs.innerHTML = '<div class="console-line success">> system initialized. standing by for security audit scans.</div>';
      }
      
      buildGraph(null);
      renderCockpitLeftSidebar(null);
      return;
    }

    const latestReport = sortedReports[0];
    if (latestReport && latestReport.findings) {
      latestReport.findings = latestReport.findings.filter(f => {
        const sevName = String(f.severity || f.finalSeverity || '').toLowerCase();
        return sevName !== 'low' && sevName !== 'info';
      });
    }
    store.set('currentReport', latestReport);
    const score = latestReport.metrics?.securityScore || 0;
    const findingsCount = latestReport.findings ? latestReport.findings.length : 0;
    const critCount = latestReport.findings?.filter(f => (f.severity || f.finalSeverity) === 'Critical').length || 0;
    
    // Count dependencies findings
    const depCount = latestReport.findings?.filter(f => f.rule_id && f.rule_id.startsWith('outdated-package-')).length || 0;
    const sastCount = findingsCount - depCount;

    // Calculate age of last scan
    const scanTime = new Date(latestReport.scanTime);
    const diffMs = new Date() - scanTime;
    const diffMins = Math.floor(diffMs / 60000);
    let ageStr = '0m';
    if (diffMins < 60) {
      ageStr = `${diffMins}m`;
    } else if (diffMins < 1440) {
      ageStr = `${Math.floor(diffMins / 60)}h`;
    } else {
      ageStr = `${Math.floor(diffMins / 1440)}d`;
    }

    if (totalFindings) totalFindings.textContent = findingsCount.toString().padStart(2, '0');
    if (criticalFindings) criticalFindings.textContent = critCount.toString().padStart(2, '0');
    if (dependenciesFindings) dependenciesFindings.textContent = depCount.toString().padStart(2, '0');
    if (lastScanAge) lastScanAge.textContent = ageStr;

    // Update gauge
    updateRadarGauge(score);

    // Update Speedometer & Counts
    const speedometerArc = document.getElementById('cockpit-speedometer-arc');
    const speedometerVal = document.getElementById('cockpit-speedometer-value');
    const riskPercent = Math.max(0, 100 - score);
    if (speedometerVal) speedometerVal.textContent = `${riskPercent}%`;
    if (speedometerArc) {
      const circ = 251.2;
      const offset = circ - (riskPercent / 100) * circ;
      speedometerArc.style.strokeDashoffset = offset;
    }
    const sastCountEl = document.getElementById('cockpit-sast-count');
    const scaCountEl = document.getElementById('cockpit-sca-count');
    if (sastCountEl) sastCountEl.textContent = sastCount;
    if (scaCountEl) scaCountEl.textContent = depCount;

    // Build 3D Graph
    buildGraph(latestReport);

    // Render Privilege Matrix & Trend Chart
    renderPrivilegeAuditMatrix(latestReport.metrics?.cweCounts || {});
    renderFindingsHistoryTrend(reports);

    // Populate Left Sidebar with the first high/critical finding
    const firstFinding = latestReport.findings?.find(f => f.severity === 'Critical' || f.severity === 'High') || latestReport.findings?.[0] || null;
    renderCockpitLeftSidebar(firstFinding);

    // Populate signals list
    if (signalList) {
      signalList.innerHTML = '';
      if (!latestReport.findings || latestReport.findings.length === 0) {
        signalList.innerHTML = '<div class="empty-state-text">NO ACTIVE SIGNALS. HEAD TO SCAN TO AUDIT CODE.</div>';
      } else {
        latestReport.findings.slice(0, 8).forEach(f => {
          const div = document.createElement('div');
          div.className = 'signal-item';
          
          let sevTag = 'INFO';
          let sevClass = 'info';
          if (f.severity === 'Critical') { sevTag = 'CRIT'; sevClass = 'crit'; }
          else if (f.severity === 'High') { sevTag = 'HIGH'; sevClass = 'high'; }
          else if (f.severity === 'Medium') { sevTag = 'MED'; sevClass = 'med'; }
          else if (f.severity === 'Low') { sevTag = 'LOW'; sevClass = 'low'; }
          
          const fileLoc = `${f.path}:${f.line}`;
          const title = f.title || f.message || 'Unknown finding';
          
          div.innerHTML = `
            <span class="signal-tag ${sevClass}">[${sevTag}]</span>
            <div class="signal-details">
              <span>${escapeHtml(title)}</span>
              <div class="signal-meta">${escapeHtml(fileLoc)}${f.isCorrelated && f.route ? ` ➔ ${escapeHtml(f.route)}` : ''}</div>
            </div>
          `;
          div.style.cursor = 'pointer';
          div.onclick = () => viewReportDetails(latestReport.id);
          signalList.appendChild(div);
        });
      }
    }

    // Populate console logs
    if (consoleLogs) {
      consoleLogs.innerHTML = '';
      const logs = [
        `> console initialization complete.`,
        `> database connected. profiles active.`,
        `> loaded report: "${latestReport.projectName}" (${latestReport.id})`,
        `> scan time: ${scanTime.toLocaleString()}`,
        `> severity counts: ${latestReport.metrics?.severityCounts?.Critical || 0} critical, ${latestReport.metrics?.severityCounts?.High || 0} high, ${latestReport.metrics?.severityCounts?.Medium || 0} medium, ${latestReport.metrics?.severityCounts?.Low || 0} low.`,
        `> posture signal: ${score}% | grade: ${latestReport.metrics?.grade || 'N/A'}`,
        `> monitoring security state... standing by.`
      ];
      
      logs.forEach(line => {
        const p = document.createElement('div');
        p.className = 'console-line';
        if (line.includes('critical') && (latestReport.metrics?.severityCounts?.Critical > 0 || latestReport.metrics?.severityCounts?.High > 0)) {
          p.className = 'console-line error';
        } else if (line.includes('monitoring') || line.includes('complete')) {
          p.className = 'console-line success';
        }
        p.textContent = line;
        consoleLogs.appendChild(p);
      });
    }
  } catch (err) {
    console.error('Failed to load dashboard data:', err);
  }
}

/**
 * Loads the saved reports catalog view.
 */
export async function loadSavedReports() {
  const tbody = document.getElementById('saved-reports-tbody');
  if (!tbody) return;
  tbody.innerHTML = `
    <tr>
      <td colspan="7" style="text-align: center;">
        <i class="fa-solid fa-circle-notch fa-spin"></i> Loading reports...
      </td>
    </tr>
  `;

  try {
    const reports = await api.getReportsList();
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
      const m = report.metrics?.severityCounts || { Critical: 0, High: 0, Medium: 0, Low: 0 };

      row.innerHTML = `
        <td><strong>${escapeHtml(report.projectName)}</strong></td>
        <td><span class="grade-badge ${report.metrics?.grade?.toLowerCase()}">${report.metrics?.grade || 'N/A'}</span></td>
        <td><strong>${report.metrics?.securityScore || 0}/100</strong></td>
        <td>
          <span class="badge ${m.Critical > 0 ? 'danger' : 'info'}">${m.Critical} C</span>
          <span class="badge ${m.High > 0 ? 'danger' : 'info'}">${m.High} H</span>
          <span class="badge ${m.Medium > 0 ? 'warning' : 'info'}">${m.Medium} M</span>
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

/**
 * Deletes a report from the database.
 */
export async function deleteReport(id, event) {
  event.stopPropagation();
  if (!confirm('Are you sure you want to permanently delete this report?')) return;
  
  try {
    const data = await api.deleteReport(id);
    if (data.success) {
      loadSavedReports();
    } else {
      alert(data.message || 'Failed to delete report.');
    }
  } catch (err) {
    console.error('Error deleting report:', err);
  }
}

/**
 * Fetch and load report details into viewer or WAPT results depending on type.
 */
export async function viewReportDetails(reportId) {
  try {
    const report = await api.getReport(reportId);
    if (report.type === 'wapt') {
      switchTab('wapt');
      renderWaptResults(report);
    } else {
      showReport(report);
    }
  } catch (err) {
    console.error('Error fetching report details:', err);
    alert('Failed to retrieve report details. It may have been deleted.');
  }
}

/**
 * Displays SAST reports inside viewer panel.
 */
export function showReport(report) {
  if (report && report.findings) {
    report.findings = report.findings.filter(f => {
      const sevName = String(f.severity || f.finalSeverity || '').toLowerCase();
      return sevName !== 'low' && sevName !== 'info';
    });
  }
  store.set('currentReport', report);
  
  // Make the [REPORT] button visible
  const reportBtn = document.getElementById('nav-btn-report-viewer');
  if (reportBtn) {
    reportBtn.style.display = 'inline-block';
  }
  
  switchTab('report-viewer');

  // Default to 3D Cockpit sub-tab
  switchReportSubTab('cockpit');

  const m = report.metrics || {};
  
  // Update report metrics toolbar
  const toolbarProjectName = document.getElementById('report-toolbar-project-name');
  if (toolbarProjectName) toolbarProjectName.textContent = report.projectName;

  const toolbarGrade = document.getElementById('report-toolbar-grade');
  if (toolbarGrade) {
    toolbarGrade.textContent = m.grade || 'N/A';
    toolbarGrade.className = `grade-badge ${m.grade?.toLowerCase() || ''}`;
  }

  const toolbarScore = document.getElementById('report-toolbar-score');
  if (toolbarScore) {
    toolbarScore.textContent = m.securityScore || 0;
  }

  const toolbarDate = document.getElementById('report-toolbar-date');
  if (toolbarDate) {
    let dateStr = '-';
    if (report.scanTime) {
      try {
        dateStr = new Date(report.scanTime).toISOString().slice(0, 10);
      } catch(e) {
        dateStr = '-';
      }
    }
    toolbarDate.textContent = dateStr;
  }
  const sev = {
    Critical: (report.findings || []).filter(f => (f.severity || f.finalSeverity) === 'Critical').length,
    High: (report.findings || []).filter(f => (f.severity || f.finalSeverity) === 'High').length,
    Medium: (report.findings || []).filter(f => (f.severity || f.finalSeverity) === 'Medium').length,
    Low: 0
  };

  // Update cockpit badges & totals
  const totalFindings = document.getElementById('stat-total-findings');
  const criticalFindings = document.getElementById('stat-critical-findings');
  const dependenciesFindings = document.getElementById('stat-dependencies-findings');

  const findingsCount = report.findings ? report.findings.length : 0;
  const critCount = sev.Critical || 0;
  const depCount = report.findings?.filter(f => f.rule_id && f.rule_id.startsWith('outdated-package-')).length || 0;
  const sastCount = findingsCount - depCount;

  if (totalFindings) totalFindings.textContent = findingsCount.toString().padStart(2, '0');
  if (criticalFindings) criticalFindings.textContent = critCount.toString().padStart(2, '0');
  if (dependenciesFindings) dependenciesFindings.textContent = depCount.toString().padStart(2, '0');

  // Sync the dashboard gauge variables
  updateRadarGauge(m.securityScore || 0);

  // Update Speedometer & Counts
  const speedometerArc = document.getElementById('cockpit-speedometer-arc');
  const speedometerVal = document.getElementById('cockpit-speedometer-value');
  const riskPercent = Math.max(0, 100 - (m.securityScore || 0));
  if (speedometerVal) speedometerVal.textContent = `${riskPercent}%`;
  if (speedometerArc) {
    const circ = 251.2;
    const offset = circ - (riskPercent / 100) * circ;
    speedometerArc.style.strokeDashoffset = offset;
  }
  const sastCountEl = document.getElementById('cockpit-sast-count');
  const scaCountEl = document.getElementById('cockpit-sca-count');
  if (sastCountEl) sastCountEl.textContent = sastCount;
  if (scaCountEl) scaCountEl.textContent = depCount;

  // Build 3D Graph
  buildGraph(report);

  // Render Privilege Matrix
  renderPrivilegeAuditMatrix(m.cweCounts || {});

  // Populate Left Sidebar with the first high/critical finding
  const firstFinding = report.findings?.find(f => f.severity === 'Critical' || f.severity === 'High') || report.findings?.[0] || null;
  renderCockpitLeftSidebar(firstFinding);

  // Also update standard report viewer panels just in case the user switches tabs manually later
  const reportTitleH2 = document.getElementById('report-title-h2');
  if (reportTitleH2) reportTitleH2.textContent = report.projectName;
  
  const reportDateText = document.getElementById('report-date-text');
  if (reportDateText) reportDateText.textContent = `Scanned on: ${new Date(report.scanTime).toLocaleString()}`;
  
  const reportBadgeStatus = document.getElementById('report-badge-status');
  if (reportBadgeStatus) reportBadgeStatus.textContent = `Engine: ${report.semgrepStatus}`;

  const reportGradeLetter = document.getElementById('report-grade-letter');
  if (reportGradeLetter) reportGradeLetter.textContent = m.grade || 'N/A';
  
  const reportGradeRating = document.getElementById('report-grade-rating');
  if (reportGradeRating) reportGradeRating.textContent = m.rating || 'No Rating';
  
  const reportScoreIndex = document.getElementById('report-score-index');
  if (reportScoreIndex) reportScoreIndex.textContent = `${m.securityScore || 0}/100`;

  const ring = document.getElementById('report-grade-ring');
  if (ring) {
    ring.style.borderColor = m.gradeColor || '#10b981';
    ring.style.boxShadow = `0 0 20px ${m.gradeColor || '#10b981'}33`;
  }

  const reportCountCritical = document.getElementById('report-count-critical');
  if (reportCountCritical) reportCountCritical.textContent = sev.Critical;
  
  const reportCountHigh = document.getElementById('report-count-high');
  if (reportCountHigh) reportCountHigh.textContent = sev.High;
  
  const reportCountMedium = document.getElementById('report-count-medium');
  if (reportCountMedium) reportCountMedium.textContent = sev.Medium;
  
  const reportCountLow = document.getElementById('report-count-low');
  if (reportCountLow) reportCountLow.textContent = sev.Low;

  const reportStatFiles = document.getElementById('report-stat-files');
  if (reportStatFiles) reportStatFiles.textContent = report.filesScannedCount;
  
  const reportStatFindings = document.getElementById('report-stat-findings');
  if (reportStatFindings) reportStatFindings.textContent = findingsCount;
  
  const correlatedCount = report.findings?.filter(f => f.isCorrelated).length || 0;
  const reportStatCorrelated = document.getElementById('report-stat-correlated');
  if (reportStatCorrelated) reportStatCorrelated.textContent = correlatedCount;

  const reportStatEngine = document.getElementById('report-stat-engine');
  if (reportStatEngine) reportStatEngine.textContent = (report.semgrepStatus || '').split(' ')[0] || 'SAST';
  
  const reportStatCommon = document.getElementById('report-stat-common');
  if (reportStatCommon) reportStatCommon.textContent = m.topIssueCategory || 'None';

  renderFindings(report.findings || []);
  renderSeverityChart(sev);
  renderOwaspChart(m.owaspCounts || {});
  updateAiAnalysisPanel(report);
}

/**
 * Downloads report in requested formats.
 */
export async function exportReport(format) {
  const currentReport = store.state.currentReport;
  if (!currentReport) return;
  
  try {
    let url;
    let defaultFilename = `security-report-${currentReport.id}.${format === 'docx' || format === 'doc' ? 'docx' : format}`;
    if (currentReport.type === 'wapt' && format === 'pdf') {
      url = api.getWaptPdfUrl(currentReport.id);
      defaultFilename = `${currentReport.projectName || 'wapt'}-security-report-${currentReport.id}.pdf`;
    } else {
      url = api.getDownloadUrl(currentReport.id, format);
      const ext = format === 'docx' || format === 'doc' ? 'docx' : (format === 'markdown' || format === 'md' ? 'md' : format);
      defaultFilename = `${currentReport.projectName || 'sast'}-security-report.${ext}`;
    }

    const headers = {
      'X-Requested-With': 'XMLHttpRequest'
    };
    const response = await fetch(url, { headers, credentials: 'include' });
    if (!response.ok) {
      throw new Error(`Failed to download report: ${response.statusText}`);
    }
    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = downloadUrl;
    
    const contentDisposition = response.headers.get('Content-Disposition');
    let filename = defaultFilename;
    if (contentDisposition) {
      const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
      if (filenameMatch && filenameMatch[1]) {
        filename = filenameMatch[1];
      }
    }
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(downloadUrl);
  } catch (err) {
    console.error('Export error:', err);
    alert('Failed to download report: ' + err.message);
  }
}

// AI insights helpers
function renderMarkdown(text) {
  if (!text) return '';
  return text
    .replace(/### (.*)/g, '<h4 style="color: var(--color-accent); margin: 12px 0 6px 0; font-size: 12px; font-weight: bold;">$1</h4>')
    .replace(/\*\*(.*?)\*\*/g, '<strong style="color: var(--text-main); font-weight: bold;">$1</strong>')
    .replace(/\n/g, '<br>');
}

export async function triggerCockpitAiAudit() {
  const currentReport = store.state.currentReport;
  if (!currentReport) {
    alert('No active report loaded to analyze.');
    return;
  }

  const aiBtn = document.getElementById('cockpit-ai-btn') || document.getElementById('toolbar-ai-btn');
  if (aiBtn) {
    aiBtn.disabled = true;
    aiBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Running Threat Model...`;
  }

  // Clear previous modal contents
  const summaryEl = document.getElementById('modal-ai-summary');
  const timelineEl = document.getElementById('modal-ai-timeline');
  const priorityEl = document.getElementById('modal-ai-priority');
  if (summaryEl) summaryEl.innerHTML = '';
  if (timelineEl) timelineEl.innerHTML = '';
  if (priorityEl) priorityEl.innerHTML = '';

  // Stream logs to console
  const consoleLogs = document.getElementById('dashboard-console-logs');
  const addLog = (text, isError = false) => {
    if (consoleLogs) {
      const line = document.createElement('div');
      line.className = isError ? 'console-line error' : 'console-line success';
      line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
      consoleLogs.appendChild(line);
      consoleLogs.scrollTop = consoleLogs.scrollHeight;
    }
  };

  addLog('> Spawning Claude 3.5 Sonnet Threat Modeling Engine...');
  addLog('> Assembling security vulnerability context nodes...');
  
  try {
    const data = await api.launchAiAudit(currentReport.id);
    if (data.success && data.aiAnalysis) {
      addLog('> AI threat analysis completed successfully.');
      currentReport.aiAnalysis = data.aiAnalysis;
      openAiInsightsModal(currentReport);
    } else {
      addLog(`> ERROR: AI audit failed: ${data.message || 'Unknown error'}`, true);
      alert(`AI Audit Failed: ${data.message || 'Unknown error'}`);
    }
  } catch (err) {
    addLog(`> ERROR: Failed to call Claude API: ${err.message}`, true);
    alert(`AI Audit Failed: ${err.message}`);
  } finally {
    if (aiBtn) {
      aiBtn.disabled = false;
      if (aiBtn.id === 'toolbar-ai-btn') {
        aiBtn.innerHTML = `<i class="fa-solid fa-wand-magic-sparkles"></i> Launch AI Audit`;
      } else {
        aiBtn.innerHTML = `[LAUNCH AI AUDIT]`;
      }
    }
  }
}

export function openAiInsightsModal(report) {
  const modal = document.getElementById('ai-insights-modal');
  if (!modal) return;

  const summaryEl = document.getElementById('modal-ai-summary');
  const timelineEl = document.getElementById('modal-ai-timeline');
  const priorityEl = document.getElementById('modal-ai-priority');

  const analysis = report.aiAnalysis;
  if (!analysis) {
    triggerCockpitAiAudit();
    return;
  }

  if (summaryEl) {
    summaryEl.innerHTML = renderMarkdown(analysis.executiveSummary || '');
  }

  if (timelineEl) {
    timelineEl.innerHTML = renderMarkdown(analysis.attackNarrative || '');
  }

  if (priorityEl) {
    priorityEl.innerHTML = '';
    const rankings = analysis.remediationRanking || [];
    if (rankings.length === 0) {
      priorityEl.innerHTML = '<div class="empty-state-text">NO ACTIONABLE MITIGATION RANKINGS.</div>';
    } else {
      rankings.forEach(rankObj => {
        const finding = report.findings?.find(f => f.id === rankObj.id);
        const title = finding ? (finding.title || finding.message) : (rankObj.title || 'Vulnerability');
        const location = finding ? `${finding.path}:${finding.line}` : (rankObj.location || '');
        
        const card = document.createElement('div');
        card.className = 'glass-hud';
        card.style.padding = '12px';
        card.style.border = '1px solid var(--border-color)';
        card.style.borderLeft = '3px solid var(--color-accent)';
        card.style.borderRadius = '4px';
        card.style.background = 'rgba(255,255,255,0.01)';
        card.style.marginBottom = '10px';
        
        card.innerHTML = `
          <div style="display:flex; justify-content:space-between; margin-bottom:6px; font-weight:bold; font-size:11px;">
            <span style="color:var(--color-accent);">#${rankObj.rank} - PRIORITY KEY</span>
            <span style="color:var(--text-muted); font-size:10.5px;">${escapeHtml(location)}</span>
          </div>
          <div style="font-weight:bold; color:var(--text-main); font-size:11.5px; margin-bottom:6px; text-transform:uppercase;">${escapeHtml(title)}</div>
          <div style="color:var(--text-muted); font-size:11px; line-height:1.5;">${escapeHtml(rankObj.reasoning)}</div>
        `;
        priorityEl.appendChild(card);
      });
    }
  }

  modal.style.display = 'flex';
}

export function closeAiInsightsModal() {
  const modal = document.getElementById('ai-insights-modal');
  if (modal) {
    modal.style.display = 'none';
  }
}

export function switchReportSubTab(tab) {
  document.querySelectorAll('.report-subtab-pane').forEach(pane => {
    pane.classList.remove('active');
    pane.style.display = 'none';
  });
  document.querySelectorAll('.subtab-btn').forEach(btn => {
    btn.classList.remove('active');
  });

  const selectedPane = document.getElementById(`report-subtab-${tab}`);
  if (selectedPane) {
    selectedPane.classList.add('active');
    selectedPane.style.display = tab === 'cockpit' ? 'flex' : 'block';
  }

  const selectedBtn = document.getElementById(`subtab-btn-${tab}`);
  if (selectedBtn) {
    selectedBtn.classList.add('active');
  }

  // Force chart/Three.js recalculation when switching to cockpit
  if (tab === 'cockpit') {
    setTimeout(() => {
      window.dispatchEvent(new Event('resize'));
    }, 50);
  }
}

export function toggleDownloadDropdown(event) {
  if (event) event.stopPropagation();
  const menu = document.getElementById('download-dropdown-menu');
  if (menu) {
    const isVisible = menu.style.display === 'block';
    menu.style.display = isVisible ? 'none' : 'block';
  }
}

// Close dropdown on click outside
document.addEventListener('click', () => {
  const menu = document.getElementById('download-dropdown-menu');
  if (menu) {
    menu.style.display = 'none';
  }
});

// Bind methods to global scope for HTML event attributes
window.switchTab = switchTab;
window.switchScanMode = switchScanMode;
window.runDiagnostics = runDiagnostics;
window.loadSavedReports = loadSavedReports;
window.deleteReport = deleteReport;
window.viewReportDetails = viewReportDetails;
window.exportReport = exportReport;
window.handleFileSelect = handleFileSelect;
window.clearSelectedFile = clearSelectedFile;
window.handleZipScan = handleZipScan;
window.handleGitScan = handleGitScan;
window.handlePasteScan = handlePasteScan;
window.triggerCockpitAiAudit = triggerCockpitAiAudit;
window.openAiInsightsModal = openAiInsightsModal;
window.closeAiInsightsModal = closeAiInsightsModal;
window.switchReportSubTab = switchReportSubTab;
window.handleLoginSubmit = handleLoginSubmit;
window.handleRegisterSubmit = handleRegisterSubmit;
window.handleLogoutSubmit = handleLogoutSubmit;

// Document Ready Initialization
document.addEventListener('DOMContentLoaded', async () => {
  setupDragAndDrop();
  initUniverse('threejs-universe-container');
  
  const authenticated = await checkAuth();
  if (authenticated) {
    loadDashboardData();
    runDiagnostics();
  }

  // Listen for raycaster clicks on 3D nodes
  window.addEventListener('nodeSelected', (e) => {
    const data = e.detail;
    if (data.findings && data.findings.length > 0) {
      renderCockpitLeftSidebar(data.findings[0]);
    } else {
      // Clicked on a secure/clean node
      let title = 'SECURE COMPONENT';
      let message = 'This component was scanned and verified secure. No vulnerabilities were detected.';
      let codeSnippet = '';
      let path = data.path || 'Codebase';
      let cwe = 'N/A';
      
      if (data.type === 'sast_file') {
        title = `CLEAN FILE: ${data.path.split(/[\\/]/).pop()}`;
        message = `The static analyzer scanned all lines of code in this file (${data.path}) and found no command injections, secret leakages, or path traversals.`;
        codeSnippet = `// All security checks passed for ${data.path}`;
      } else if (data.type === 'sca') {
        title = `SECURE PACKAGE: ${data.name}`;
        message = `The dependency composition analysis verified that the package version used is fully up-to-date and does not contain any known CVE disclosures.`;
        cwe = 'CWE-1395 (Verified Clean)';
        path = 'package.json';
      } else if (data.type === 'wapt') {
        title = `SECURED ROUTE: ${data.endpoint}`;
        message = `The dynamic penetration testing fuzzer scanned this route with reflected XSS payloads, SQL injection sequences, and directory traversals. No flaws were detected.`;
        codeSnippet = `// Audited and verified endpoint\nGET ${data.endpoint.split(' ').slice(1).join(' ') || '/'}`;
        path = 'routes.js';
      }

      renderCockpitLeftSidebar({
        title,
        severity: 'Info',
        rule_id: 'secured-component-audit',
        cwe,
        path,
        line: 1,
        message,
        codeSnippet,
        isSecureCheck: true
      });
    }
  });
});
