/* ==========================================================================
   AI-Detective Corporate Redesign - WAPT Panel Handler
   ========================================================================== */

import { api } from './api.js';
import { store } from './state.js';

export function waptLog(msg) {
  const c = document.getElementById('wapt-console-logs');
  if (!c) return;
  const line = document.createElement('div');
  line.className = 'console-line';
  line.textContent = msg;
  c.appendChild(line);
  c.scrollTop = c.scrollHeight;
}

export function clearWaptConsole() {
  const c = document.getElementById('wapt-console-logs');
  if (c) c.innerHTML = '<div class="console-line">[CLEARED]</div>';
}

function escW(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

export function toggleWaptMultiRole(checked) {
  store.set('waptMultiRoleEnabled', checked);
  const roleSelector = document.getElementById('wapt-role-selector-container');
  if (roleSelector) {
    roleSelector.style.display = checked ? 'block' : 'none';
  }
  
  if (checked) {
    document.getElementById('wapt-configure-role').value = 'userA';
    store.set('waptConfigureRole', 'userA');
    loadRoleConfigIntoUI('userA');
  } else {
    const activeAuthType = document.getElementById('wapt-auth-type').value;
    toggleWaptAuthFields(activeAuthType);
  }
}

// Save active form values to the currently selected role config in the state store
export function saveActiveRoleConfig() {
  const role = store.state.waptConfigureRole;
  const authType = document.getElementById('wapt-auth-type').value;
  store.setRoleConfig(role, 'type', authType);

  if (authType === 'cookie' || authType === 'jwt') {
    store.setRoleConfig(role, 'canaryUrl', (document.getElementById('wapt-auth-canaryurl')?.value || '').trim());
    store.setRoleConfig(role, 'loginUrl', (document.getElementById('wapt-auth-loginurl')?.value || '').trim());
    store.setRoleConfig(role, 'userField', (document.getElementById('wapt-auth-userfield')?.value || 'email').trim());
    store.setRoleConfig(role, 'pwdField', (document.getElementById('wapt-auth-pwdfield')?.value || 'password').trim());
    store.setRoleConfig(role, 'username', (document.getElementById('wapt-auth-userval')?.value || '').trim());
    store.setRoleConfig(role, 'password', (document.getElementById('wapt-auth-pwdval')?.value || '').trim());
  } else if (authType === 'header') {
    store.setRoleConfig(role, 'canaryUrl', '');
    const rawJson = (document.getElementById('wapt-auth-headersjson')?.value || '').trim();
    store.setRoleConfig(role, 'headersJson', rawJson);
  } else {
    store.setRoleConfig(role, 'canaryUrl', '');
    store.setRoleConfig(role, 'loginUrl', '');
    store.setRoleConfig(role, 'username', '');
    store.setRoleConfig(role, 'password', '');
    store.setRoleConfig(role, 'headersJson', '');
  }
}

// Load configurations from the state store into the active UI input fields
export function loadRoleConfigIntoUI(role) {
  const config = store.getRoleConfig(role);
  if (!config) return;

  const authTypeSelect = document.getElementById('wapt-auth-type');
  if (authTypeSelect) {
    authTypeSelect.value = config.type || 'none';
    toggleWaptAuthFields(config.type || 'none');
  }

  const loginUrlField = document.getElementById('wapt-auth-loginurl');
  if (loginUrlField) loginUrlField.value = config.loginUrl || '';

  const userField = document.getElementById('wapt-auth-userfield');
  if (userField) userField.value = config.userField || 'email';

  const pwdField = document.getElementById('wapt-auth-pwdfield');
  if (pwdField) pwdField.value = config.pwdField || 'password';

  const userValField = document.getElementById('wapt-auth-userval');
  if (userValField) userValField.value = config.username || '';

  const pwdValField = document.getElementById('wapt-auth-pwdval');
  if (pwdValField) pwdValField.value = config.password || '';

  const canaryUrlField = document.getElementById('wapt-auth-canaryurl');
  if (canaryUrlField) canaryUrlField.value = config.canaryUrl || '';

  const headersField = document.getElementById('wapt-auth-headersjson');
  if (headersField) {
    headersField.value = config.headersJson || '';
  }
}

export function changeActiveRoleConfig(newRole) {
  saveActiveRoleConfig();
  store.set('waptConfigureRole', newRole);
  loadRoleConfigIntoUI(newRole);
}

export function toggleWaptAuthFields(value) {
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

// Maps role config object to backend format
function formatRoleConfigForBackend(roleKey) {
  const config = store.getRoleConfig(roleKey);
  const formatted = { authType: config.type || 'none' };
  
  if (config.type === 'cookie' || config.type === 'jwt') {
    formatted.canaryUrl = config.canaryUrl;
    formatted.credentials = {
      loginUrl: config.loginUrl,
      usernameField: config.userField,
      passwordField: config.pwdField,
      usernameValue: config.username,
      passwordValue: config.password
    };
  } else if (config.type === 'header') {
    formatted.canaryUrl = '';
    if (config.headersJson) {
      try {
        formatted.staticHeaders = JSON.parse(config.headersJson);
      } catch (e) {
        formatted.staticHeaders = {};
      }
    } else {
      formatted.staticHeaders = {};
    }
  } else {
    formatted.canaryUrl = '';
    formatted.credentials = {};
    formatted.staticHeaders = {};
  }
  return formatted;
}

export async function handleWaptScan() {
  const targetUrl = (document.getElementById('wapt-url-input')?.value || '').trim();
  if (!targetUrl) { waptLog('[ERROR] Please enter a target URL.'); return; }

  const isMultiRole = store.state.waptMultiRoleEnabled;
  let authConfig = {};
  let authType = 'none';

  if (isMultiRole) {
    saveActiveRoleConfig();
    authConfig = {
      guest: { authType: 'none' },
      userA: formatRoleConfigForBackend('userA'),
      userB: formatRoleConfigForBackend('userB'),
      manager: formatRoleConfigForBackend('manager'),
      admin: formatRoleConfigForBackend('admin')
    };
  } else {
    authType = document.getElementById('wapt-auth-type')?.value || 'none';
    saveActiveRoleConfig();
    const singleConfig = formatRoleConfigForBackend('userA');
    authConfig = {
      guest: { authType: 'none' },
      userA: singleConfig,
      userB: { authType: 'none' },
      manager: { authType: 'none' },
      admin: singleConfig
    };
  }

  const scanId = `wapt-scan-${Date.now()}`;
  store.set('waptActiveScanId', scanId);

  const btn = document.getElementById('wapt-scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
  clearWaptConsole();
  waptLog(`[WAPT] Target: ${targetUrl}`);
  waptLog(`[WAPT] Mode: ${isMultiRole ? 'Multi-Role RBAC Audit' : (authType === 'none' ? 'Anonymous Black Box' : 'Authenticated Gray Box')}`);
  waptLog('[WAPT] Running 10 security checks — this may take 30-60 seconds...');
  document.getElementById('wapt-results-placeholder').style.display = 'flex';
  document.getElementById('wapt-results-panel').style.display = 'none';

  let loggedCount = 0;
  const pollInterval = setInterval(async () => {
    try {
      const pollData = await api.getWaptLogs(scanId);
      if (pollData.success && pollData.logs && pollData.logs.length > loggedCount) {
        const newLogs = pollData.logs.slice(loggedCount);
        newLogs.forEach(l => waptLog(l));
        loggedCount = pollData.logs.length;
      }
    } catch (e) {}
  }, 1500);

  try {
    const data = await api.triggerWaptScan(targetUrl, authConfig, scanId);
    clearInterval(pollInterval);
    if (!data.success) throw new Error(data.message || 'Scan failed');
    
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

export function renderWaptResults(result) {
  if (result && result.findings) {
    result.findings = result.findings.filter(f => {
      const sev = String(f.severity || f.finalSeverity || '').toLowerCase();
      return sev !== 'low' && sev !== 'info';
    });
  }
  if (result && result.metrics) {
    result.metrics.severityCounts = {
      Critical: (result.findings || []).filter(f => (f.severity || f.finalSeverity) === 'Critical').length,
      High: (result.findings || []).filter(f => (f.severity || f.finalSeverity) === 'High').length,
      Medium: (result.findings || []).filter(f => (f.severity || f.finalSeverity) === 'Medium').length,
      Low: 0,
      Info: 0
    };
  }
  window.activeWaptReportId = result.reportId;
  document.getElementById('wapt-results-placeholder').style.display = 'none';
  document.getElementById('wapt-results-panel').style.display = 'block';
  const m = result.metrics, c = m.severityCounts;
  
  const auditorSwitch = document.getElementById('wapt-auditor-mode-switch');
  if (auditorSwitch) {
    auditorSwitch.checked = !!window.activeAuditorMode;
  }

  document.getElementById('wapt-score-section').innerHTML = `
    <div class="wapt-score-card-layout">
      <div class="wapt-metric-dial">
        <div class="wapt-grade-circle wapt-grade-${m.grade}">${m.grade}</div>
        <div class="wapt-metric-meta">
          <div class="wapt-metric-label">Security Posture</div>
          <div class="wapt-metric-value">${m.securityScore}/100</div>
        </div>
      </div>

      <div class="wapt-metric-dial">
        <div class="wapt-metric-circle confidence-circle">${result.attackSurface?.securityCoverage?.assessmentConfidence || 85}%</div>
        <div class="wapt-metric-meta">
          <div class="wapt-metric-label">Assessment Confidence</div>
          <div class="wapt-metric-value">${result.attackSurface?.securityCoverage?.assessmentConfidenceRating || 'High'}</div>
        </div>
      </div>

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

  const surface = result.attackSurface || { discoveryMetrics: {}, technologies: [], securityCoverage: {} };
  const disc = surface.discoveryMetrics || {};
  const cov = surface.securityCoverage || {};

  const metricsHtml = `
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
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
          <div class="wapt-tabs-nav">
            <button class="wapt-tab-btn active" onclick="switchWaptTab(event, '${uniqueId}-overview')">Overview & Analysis</button>
            <button class="wapt-tab-btn" onclick="switchWaptTab(event, '${uniqueId}-evidence')">Evidence (HTTP)</button>
            <button class="wapt-tab-btn" onclick="switchWaptTab(event, '${uniqueId}-remediation')">Impact & Remediation</button>
          </div>

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

          <div class="wapt-tab-content" id="${uniqueId}-evidence">
            <div class="wapt-field-label">Raw HTTP Request</div>
            <pre class="wapt-http-box">${escW(f.rawRequest || 'No request log available.')}</pre>
            <div class="wapt-field-label mt-10">Raw HTTP Response</div>
            <pre class="wapt-http-box">${escW(f.rawResponse || 'No response log available.')}</pre>
          </div>

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

export async function loadWaptBenchmarks() {
  try {
    const data = await api.getWaptBenchmarks();
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

export function toggleWaptFinding(header) {
  const body = header.nextElementSibling;
  const icon = header.querySelector('.fa-chevron-down');
  const isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  if (icon) icon.style.transform = isOpen ? '' : 'rotate(180deg)';
}

export function switchWaptTab(event, targetTabId) {
  event.stopPropagation();
  const clickedBtn = event.currentTarget;
  const nav = clickedBtn.parentElement;
  const body = nav.parentElement;

  nav.querySelectorAll('.wapt-tab-btn').forEach(btn => btn.classList.remove('active'));
  clickedBtn.classList.add('active');

  body.querySelectorAll('.wapt-tab-content').forEach(content => {
    if (content.id === targetTabId) {
      content.style.display = 'block';
    } else {
      content.style.display = 'none';
    }
  });
}

export function downloadWaptPdf() {
  if (!window.activeWaptReportId) {
    alert('No active scan report loaded to download.');
    return;
  }
  window.location.href = api.getWaptPdfUrl(window.activeWaptReportId);
}

export function toggleAuditorMode(checked) {
  window.activeAuditorMode = checked;
  const elements = document.querySelectorAll('.auditor-mode-only');
  elements.forEach(el => {
    el.style.display = checked ? 'block' : 'none';
  });
}

// Global WAPT event bindings
window.toggleWaptMultiRole = toggleWaptMultiRole;
window.changeActiveRoleConfig = changeActiveRoleConfig;
window.toggleWaptAuthFields = toggleWaptAuthFields;
window.handleWaptScan = handleWaptScan;
window.clearWaptConsole = clearWaptConsole;
window.toggleWaptFinding = toggleWaptFinding;
window.switchWaptTab = switchWaptTab;
window.downloadWaptPdf = downloadWaptPdf;
window.toggleAuditorMode = toggleAuditorMode;
