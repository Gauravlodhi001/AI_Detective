/* ==========================================================================
   AI-Detective Corporate Redesign - Components & Renderers
   ========================================================================== */

import { api } from './api.js';
import { store } from './state.js';
import { writeConsoleLog } from './scan-panel.js';
import { viewReportDetails } from './main.js';

/**
 * Basic HTML escaping utility.
 */
export function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Returns a bootstrap-styled class for severity badges.
 */
export function getSeverityClass(sev) {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  return 'info';
}

/**
 * Sanitizes and highlights code snippets (simple escape).
 */
export function highlightSnippet(snippet) {
  return escapeHtml(snippet);
}

/**
 * Formats custom source-to-sink code diff blocks.
 */
export function formatDiffBlock(diffText) {
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

/**
 * Renders the list of vulnerability findings inside the details accordion.
 */
export function renderFindings(findings) {
  const accordion = document.getElementById('findings-list-accordion');
  if (!accordion) return;
  accordion.innerHTML = '';

  const filtered = (findings || []).filter(f => {
    const sev = String(f.severity || f.finalSeverity || '').toLowerCase();
    return sev !== 'low' && sev !== 'info';
  });

  if (filtered.length === 0) {
    accordion.innerHTML = `
      <div class="empty-state">
        <i class="fa-solid fa-circle-check" style="color: var(--color-success); font-size: 36px;"></i>
        <p>Excellent! No security findings detected in this directory.</p>
      </div>
    `;
    return;
  }

  filtered.forEach((finding) => {
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
          <h4>${escapeHtml(finding.title)}</h4>
          <div class="finding-path-meta">
            <span class="badge ${getSeverityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
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
        
        ${finding.isCorrelated ? `
          <div class="detail-section-title" style="color: var(--color-accent); font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; margin-top: 15px; margin-bottom: 6px;">Exposed Endpoint (White Box Correlation)</div>
          <div class="detail-section-content" style="font-size: 14px; color: #cbd5e1; line-height: 1.6; margin-bottom: 12px;">
            <span style="background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: var(--color-accent); padding: 2px 6px; border-radius: 4px; font-weight: 600; font-size: 11.5px; margin-right: 8px;">
              ${escapeHtml(finding.endpointMethod)} ${escapeHtml(finding.endpointPath)}
            </span>
            Exposed via controller handler <code>${escapeHtml(finding.handler)}()</code> (lines ${finding.codeLocation.lineStart}-${finding.codeLocation.lineEnd})
          </div>
        ` : ''}

        ${finding.taintFlow ? `
          <div class="detail-section-title" style="color: var(--color-success); font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; font-size: 11px; margin-top: 12px; margin-bottom: 6px;">Data Flow Analysis (White Box Source-to-Sink Path)</div>
          <div class="detail-section-content" style="margin-bottom: 15px; background: rgba(16, 185, 129, 0.03); border: 1px dashed rgba(16, 185, 129, 0.25); padding: 12px; border-radius: 6px;">
            <div style="font-size: 13px; margin-bottom: 8px; color: #94a3b8;">
              <strong style="color: var(--color-accent);">Source:</strong> <code>${escapeHtml(finding.taintFlow.source)}</code>
            </div>
            <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 6px; font-size: 13px; margin-bottom: 8px;">
              ${finding.taintFlow.flow.map((step, sIdx) => `
                <span style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 4px; font-family: monospace;">${escapeHtml(step)}</span>
                ${sIdx < finding.taintFlow.flow.length - 1 ? '<span style="color: var(--color-success); font-weight: bold;">➔</span>' : ''}
              `).join('')}
            </div>
            <div style="font-size: 13px; color: #94a3b8;">
              <strong style="color: var(--color-critical);">Sink:</strong> <code>${escapeHtml(finding.taintFlow.sink)}()</code> (Line ${finding.taintFlow.line})
            </div>
          </div>
        ` : ''}

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

/**
 * Toggle the findings detail accordion row.
 */
export function toggleFindingRow(headerElement) {
  const row = headerElement.parentElement;
  if (row) {
    row.classList.toggle('expanded');
  }
}

/**
 * Search and filter findings in the catalog.
 */
export function filterFindings() {
  const searchVal = (document.getElementById('finding-search-input')?.value || '').toLowerCase();
  const severityVal = document.getElementById('finding-severity-filter')?.value || 'ALL';
  
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

/**
 * Markdown rendering utility for AI logs.
 */
export function renderMarkdown(mdStr) {
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

/**
 * Updates the AI Detective Insights card.
 */
export function updateAiAnalysisPanel(report) {
  const aiCard = document.getElementById('report-ai-card');
  const aiLaunch = document.getElementById('ai-analysis-launch');
  const aiDetails = document.getElementById('ai-analysis-details');
  const aiModeBadge = document.getElementById('ai-mode-badge');
  const aiSummaryBox = document.getElementById('ai-summary-box');
  const aiTimelineBox = document.getElementById('ai-timeline-box');
  const aiPriorityBox = document.getElementById('ai-priority-box');

  if (!aiCard) return;

  aiCard.style.display = 'block';

  if (report.aiAnalysis) {
    if (aiLaunch) aiLaunch.style.display = 'none';
    if (aiDetails) aiDetails.style.display = 'block';

    if (aiModeBadge) {
      if (report.aiAnalysis.isMock) {
        aiModeBadge.textContent = 'Demo Mode (Mock)';
        aiModeBadge.className = 'badge warning';
      } else {
        aiModeBadge.textContent = 'Claude 3.5 Sonnet';
        aiModeBadge.className = 'badge success';
      }
    }

    if (aiSummaryBox) {
      aiSummaryBox.innerHTML = renderMarkdown(report.aiAnalysis.executiveSummary);
    }

    if (aiTimelineBox) {
      aiTimelineBox.innerHTML = '';
      const narrative = report.aiAnalysis.attackNarrative;

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
        aiTimelineBox.innerHTML = `<div class="ai-step-desc">${renderMarkdown(narrative)}</div>`;
      }
    }

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
    if (aiLaunch) {
      aiLaunch.style.display = 'block';
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
 * Triggers AI Detective auditing pipeline.
 */
export async function launchAiAudit() {
  const currentReport = store.state.currentReport;
  if (!currentReport) return;

  const aiLaunch = document.getElementById('ai-analysis-launch');
  if (!aiLaunch) return;

  const originalHtml = aiLaunch.innerHTML;

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
    writeConsoleLog(text, logClass);
  }

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
    const data = await api.launchAiAudit(currentReport.id);
    const elapsed = Date.now() - startTime;
    const minPlayTime = 4200;
    const remainingTime = Math.max(0, minPlayTime - elapsed);

    setTimeout(() => {
      if (data.success) {
        addLog('[SUCCESS] Threat assessment generated and synchronized.', 'success');
        setTimeout(() => {
          timeouts.forEach(clearTimeout);
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
 * Renders the selected finding details, attack path, and mitigation diff in the left sidebar cards.
 */
export function renderCockpitLeftSidebar(finding) {
  const titleEl = document.getElementById('cockpit-risk-title');
  const bodyEl = document.getElementById('cockpit-risk-body');
  const pathEl = document.getElementById('cockpit-attack-path-body');
  const diffEl = document.getElementById('cockpit-diff-body');

  if (!titleEl || !bodyEl || !pathEl || !diffEl) return;

  if (!finding) {
    const activeReport = store.state.currentReport;
    if (activeReport && (!activeReport.findings || activeReport.findings.length === 0)) {
      titleEl.textContent = 'SYSTEM_STATUS: SECURE';
      titleEl.style.color = 'var(--color-success)';
      bodyEl.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 8px; color: var(--text-main); font-family: monospace; font-size: 11.5px; line-height: 1.45;">
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 4px;">
            <span>Audit Posture:</span><strong style="color: var(--color-success); font-weight: bold; text-shadow: 0 0 6px var(--color-success);">GRADE A / STABLE</strong>
          </div>
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 4px;">
            <span>Security Index:</span><strong>100/100</strong>
          </div>
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 4px;">
            <span>SAST Vulnerabilities:</span><span style="color: var(--color-success); font-weight: bold;">0 DETECTED</span>
          </div>
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 4px;">
            <span>SCA Outdated Packages:</span><span style="color: var(--color-success); font-weight: bold;">0 DETECTED</span>
          </div>
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 4px;">
            <span>Exposed Secrets:</span><span style="color: var(--color-success); font-weight: bold;">0 DETECTED</span>
          </div>
        </div>
        <p style="margin-top: 12px; color: var(--text-muted); font-size: 11px; line-height: 1.5; font-family: sans-serif;">The static analysis scanner, custom entropy checks, and composition analyzers crawled the repository and did not identify any active vulnerabilities or security hotspots.</p>
      `;
      pathEl.innerHTML = `
        <div class="attack-step-line" style="border-left: 2px solid var(--color-success);">
          <span style="color: var(--color-success); font-weight: bold; margin-right: 4px;">[SECURE]</span> All code inputs and router parameters verified clean.
        </div>
      `;
      diffEl.innerHTML = `
        <div class="diff-header" style="font-size: 10px; color: var(--color-success); text-transform: uppercase; margin-bottom: 4px;">Compliance Validation</div>
        <div style="padding: 10px; background: rgba(16, 185, 129, 0.04); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 4px; color: #cbd5e1; font-size: 11px; line-height: 1.45; font-family: sans-serif;">
          <i class="fa-solid fa-circle-check" style="color: var(--color-success); margin-right: 4px;"></i> 
          100% compliance with OWASP Top 10 code security rules. Standing by for future codebase audits.
        </div>
      `;
    } else {
      titleEl.textContent = 'AWAITING SELECTION';
      titleEl.style.color = 'var(--text-muted)';
      bodyEl.innerHTML = '<div class="empty-state-text">SELECT A NODE IN THE UNIVERSE TO INSPECT FINDINGS.</div>';
      pathEl.innerHTML = '<div class="empty-state-text">NO ACTIVE PATH TRACE.</div>';
      diffEl.innerHTML = '<div class="empty-state-text">NO MITIGATION DIFF LOADED.</div>';
    }
    return;
  }

  // Set Title & Severity Color
  titleEl.textContent = (finding.title || finding.message || 'SECURITY FINDING').toUpperCase();
  const sev = (finding.severity || 'info').toLowerCase();
  if (finding.isSecureCheck) {
    titleEl.style.color = 'var(--color-success)';
  } else if (sev === 'critical') {
    titleEl.style.color = 'var(--color-critical)';
  } else if (sev === 'high') {
    titleEl.style.color = 'var(--color-high)';
  } else if (sev === 'medium') {
    titleEl.style.color = 'var(--color-medium)';
  } else {
    titleEl.style.color = 'var(--color-low)';
  }

  // Set Body content
  bodyEl.innerHTML = `
    <div style="margin-bottom: 8px;"><strong>File:</strong> <code>${escapeHtml(finding.path)}:L${finding.line}</code></div>
    <div style="margin-bottom: 8px;"><strong>Rule ID:</strong> <code>${escapeHtml(finding.rule_id)}</code></div>
    <div style="margin-bottom: 8px;"><strong>CWE:</strong> <code>${escapeHtml(finding.cwe)}</code></div>
    <div style="color: var(--text-main); margin-top: 10px; font-family: sans-serif; font-size: 12.5px; line-height: 1.5;">${escapeHtml(finding.message).replace(/\n/g, '<br>')}</div>
  `;

  // Set Attack Path content
  if (finding.taintFlow) {
    const taint = finding.taintFlow;
    let pathHtml = `
      <div class="attack-step-line">
        <span class="text-secondary" style="color: var(--color-low); font-weight: bold; margin-right: 4px;">[SOURCE]</span> <code>${escapeHtml(taint.source)}</code>
      </div>
    `;
    if (taint.flow && Array.isArray(taint.flow)) {
      taint.flow.forEach(step => {
        pathHtml += `
          <div class="attack-step-arrow" style="text-align: center; margin: 2px 0; color: var(--color-accent);"><i class="fa-solid fa-down-long"></i></div>
          <div class="attack-step-line">
            <span class="text-muted" style="color: var(--text-muted); margin-right: 4px;">[FLOW]</span> <code>${escapeHtml(step)}</code>
          </div>
        `;
      });
    }
    pathHtml += `
      <div class="attack-step-arrow" style="text-align: center; margin: 2px 0; color: var(--color-accent);"><i class="fa-solid fa-down-long"></i></div>
      <div class="attack-step-line" style="border-left: 2px solid var(--color-critical);">
        <span class="text-vulnerability-red" style="color: var(--color-critical); font-weight: bold; margin-right: 4px;">[SINK]</span> <code>${escapeHtml(taint.sink)}()</code> (Line ${taint.line})
      </div>
    `;
    pathEl.innerHTML = pathHtml;
  } else if (finding.isCorrelated && finding.endpoint) {
    pathEl.innerHTML = `
      <div class="attack-step-line">
        <span style="color: var(--color-critical); font-weight: bold; margin-right: 4px;">[ENDPOINT]</span> <code>${escapeHtml(finding.endpoint)}</code>
      </div>
      <div class="attack-step-arrow" style="text-align: center; margin: 2px 0; color: var(--color-accent);"><i class="fa-solid fa-down-long"></i></div>
      <div class="attack-step-line">
        <span style="color: var(--color-accent); margin-right: 4px;">[CONTROLLER]</span> <code>${escapeHtml(finding.handler)}()</code>
      </div>
      <div class="attack-step-arrow" style="text-align: center; margin: 2px 0; color: var(--color-accent);"><i class="fa-solid fa-down-long"></i></div>
      <div class="attack-step-line" style="border-left: 2px solid var(--color-low);">
        <span style="color: var(--color-low); font-weight: bold; margin-right: 4px;">[CODE]</span> <code>${escapeHtml(finding.path)}:L${finding.line}</code>
      </div>
    `;
  } else {
    pathEl.innerHTML = '<div class="empty-state-text">NO TAINT PATH AVAILABLE FOR THIS FINDING.</div>';
  }

  // Set Mitigation Diff / Code Snippet
  if (finding.suggestedDiff) {
    diffEl.innerHTML = formatDiffBlock(finding.suggestedDiff);
  } else if (finding.codeSnippet) {
    diffEl.innerHTML = `
      <div class="diff-header" style="font-size: 10px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">Vulnerable Code Snippet</div>
      <pre class="codeblock-container" style="margin: 0; padding: 8px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-color); border-radius: 4px; overflow-x: auto; max-height: 200px;"><code>${escapeHtml(finding.codeSnippet)}</code></pre>
    `;
  } else {
    diffEl.innerHTML = '<div class="empty-state-text">NO MITIGATION CODE SNIPPET AVAILABLE.</div>';
  }
}

// Bind to window for inline HTML access
window.toggleFindingRow = toggleFindingRow;
window.filterFindings = filterFindings;
window.launchAiAudit = launchAiAudit;
window.renderCockpitLeftSidebar = renderCockpitLeftSidebar;

