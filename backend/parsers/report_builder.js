const fs = require('fs');
const path = require('path');
const docx = require('docx');
const { walkDir } = require('../utils/fileWalker');
const { checkSemgrepInstalled, runSemgrepScan } = require('../scanners/semgrep_scanner');
const { parseSemgrepResults } = require('./semgrep_parser');
const { scanSecrets } = require('../scanners/secret_scanner');
const { scanCustomRules } = require('../scanners/custom_scanner');
const { scanDependencies } = require('../scanners/dependency_scanner');
const { evaluateRisk } = require('../utils/riskEngine');
const { RouteMapper } = require('../utils/routeMapper');
const { CorrelationEngine } = require('../utils/correlationEngine');
const { encrypt } = require('../utils/crypto');

/**
 * Builds a markdown content representing the executive/developer vulnerability report.
 */
function buildMarkdownReport(report) {
  const m = report.metrics;
  const sev = m.severityCounts;

  let md = `# AI-Detective Security Assessment Report\n\n`;
  md += `## Executive Summary\n\n`;
  md += `* **Project Name:** ${report.projectName}\n`;
  md += `* **Scan Date:** ${new Date(report.scanTime).toUTCString()}\n`;
  md += `* **Files Scanned:** ${report.filesScannedCount}\n`;
  md += `* **Security Grade:** **${m.grade}** (${m.rating})\n`;
  md += `* **Security Posture Score:** ${m.securityScore} / 100\n`;
  md += `* **Semgrep Engine Status:** ${report.semgrepStatus}\n\n`;

  md += `### Vulnerability Summary\n\n`;
  md += `| Severity | Count |\n`;
  md += `| :--- | :--- |\n`;
  md += `| 🔴 Critical | ${sev.Critical} |\n`;
  md += `| 🟠 High | ${sev.High} |\n`;
  md += `| 🟡 Medium | ${sev.Medium} |\n`;
  md += `| **Total** | **${report.findings.length}** |\n\n`;

  md += `### Primary OWASP Theme: ${m.topIssueCategory}\n\n`;

  if (report.aiAnalysis) {
    const ai = report.aiAnalysis;
    md += `## 🔍 AI Detective Audit Insights\n\n`;
    md += `### Executive Posture Summary\n${ai.executiveSummary}\n\n`;
    md += `### Threat Vector & Attack Chain Scenario\n${ai.attackNarrative}\n\n`;
    md += `### AI Remediation Priority Checklist\n`;
    if (Array.isArray(ai.remediationRanking)) {
      ai.remediationRanking.forEach(item => {
        md += `* **Rank #${item.rank}**: ${item.title} (\`${item.location}\`)\n  *Reasoning:* ${item.reasoning}\n`;
      });
    }
    md += `\n---\n\n`;
  }

  md += `## Detailed Findings\n\n`;

  if (report.findings.length === 0) {
    md += `*No vulnerabilities were detected in this codebase. Good job!*\n`;
    return md;
  }

  report.findings.forEach((finding, idx) => {
    md += `### ${idx + 1}. [${finding.severity}] ${finding.title}\n\n`;
    md += `* **Rule ID:** \`${finding.rule_id}\`\n`;
    md += `* **File:** \`${finding.path}\` (Line ${finding.line})\n`;
    md += `* **CWE:** [${finding.cwe}](https://cwe.mitre.org/data/definitions/${finding.cwe.split('-')[1]}.html)\n`;
    if (finding.cve) {
      md += `* **CVE:** \`${finding.cve}\`\n`;
    }
    md += `* **OWASP Category:** ${finding.owasp}\n`;
    if (finding.isCorrelated) {
      if (finding.endpoint) {
        md += `* **Exposed URL:** \`${finding.endpointMethod} ${finding.endpointPath}\`\n`;
        md += `* **Controller Handler:** \`${finding.handler || 'inline'}()\` (lines ${finding.codeLocation ? (finding.codeLocation.lineStart + '-' + finding.codeLocation.lineEnd) : 'N/A'})\n`;
      } else if (finding.codeLocation) {
        md += `* **Controller File:** \`${finding.codeLocation.file}\` (lines ${finding.codeLocation.lineStart || 'N/A'}-${finding.codeLocation.lineEnd || 'N/A'})\n`;
        md += `* **Exposed Handler:** \`${finding.codeLocation.handler || 'inline'}()\`\n`;
      }
    }
    md += `\n`;
    md += `**Description:**\n${finding.message}\n\n`;
    
    if (finding.codeSnippet) {
      md += `**Vulnerable Snippet:**\n\`\`\`\n${finding.codeSnippet}\n\`\`\`\n\n`;
    }

    if (finding.taintFlow) {
      md += `**Data Flow Analysis:**\n`;
      md += `* **Source:** \`${finding.taintFlow.source}\`\n`;
      md += `* **Sink:** \`${finding.taintFlow.sink}()\`\n`;
      md += `* **Flow Path:** ${finding.taintFlow.flow.map(f => `\`${f}\``).join(' ➔ ')}\n\n`;
    }

    md += `**Remediation Suggestion:**\n${finding.remediation}\n\n`;

    if (finding.suggestedDiff) {
      md += `**Remediation Diff:**\n\`\`\`diff\n${finding.suggestedDiff}\n\`\`\`\n\n`;
    }

    md += `---\n\n`;
  });

  return md;
}

/**
 * Builds a complete HTML report for direct downloading.
 */
/**
 * Sanitizes strings for safe HTML rendering.
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Formats suggested diff comparisons into visual HTML blocks.
 */
function formatDiffHtml(diffText) {
  if (!diffText) return '';
  const currentMarker = '<<<< CURRENT CODE';
  const fixMarker = '==== SUGGESTED FIX';
  const endMarker = '>>>>';
  
  if (diffText.includes(currentMarker) && diffText.includes(fixMarker)) {
    const parts = diffText.split(fixMarker);
    const currentBlock = parts[0].replace(currentMarker, '').trim();
    const fixBlock = parts[1].replace(endMarker, '').trim();
    
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
  return `<pre class="codeblock-container"><code>${escapeHtml(diffText)}</code></pre>`;
}

/**
 * Builds a complete HTML report for direct downloading.
 */
function buildHtmlReport(report) {
  const m = report.metrics;
  const sev = m.severityCounts;

  const listItems = report.findings.map((finding, idx) => {
    return `
      <div class="finding-row ${finding.severity.toLowerCase()}">
        <div class="finding-header">
          <div class="finding-title-row">
            <span class="sev-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
            <h3 class="finding-title">${idx + 1}. ${escapeHtml(finding.title)}</h3>
          </div>
          <div class="finding-meta">
            <code>${escapeHtml(finding.path)}:L${finding.line}</code>
          </div>
        </div>
        <div class="finding-body">
          <div class="meta-pill-row">
            <span class="meta-pill">Rule: <strong>${escapeHtml(finding.rule_id)}</strong></span>
            <span class="meta-pill">CWE: <strong>${escapeHtml(finding.cwe)}</strong></span>
            ${finding.cve ? `<span class="meta-pill">CVE: <strong>${escapeHtml(finding.cve)}</strong></span>` : ''}
            <span class="meta-pill">OWASP: <strong>${escapeHtml(finding.owasp)}</strong></span>
          </div>
          
          ${finding.isCorrelated ? `
            <div class="whitebox-correlation-block" style="background: rgba(6, 182, 212, 0.05); border: 1px solid rgba(6, 182, 212, 0.2); border-radius: 6px; padding: 10px; margin: 15px 0; font-size: 13px;">
              <div style="font-weight: bold; color: var(--color-accent); margin-bottom: 4px; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px;">White Box Correlation Details</div>
              ${finding.endpoint ? `
                <strong>Exposed Endpoint:</strong> <span style="background: rgba(6, 182, 212, 0.1); border: 1px solid rgba(6, 182, 212, 0.3); color: var(--color-accent); padding: 1px 5px; border-radius: 3px; font-weight: 600; font-size: 11.5px;">${escapeHtml(finding.endpointMethod)} ${escapeHtml(finding.endpointPath)}</span>
                via handler <code>${escapeHtml(finding.handler)}()</code> (lines ${finding.codeLocation ? (finding.codeLocation.lineStart + '-' + finding.codeLocation.lineEnd) : 'N/A'})
              ` : `
                <strong>Controller File:</strong> <code>${escapeHtml(finding.codeLocation.file)}</code> (lines ${finding.codeLocation.lineStart || 'N/A'}-${finding.codeLocation.lineEnd || 'N/A'})
                handling endpoint via <code>${escapeHtml(finding.codeLocation.handler || 'inline')}()</code>
              `}
            </div>
          ` : ''}
          
          <div class="section-title">Vulnerability Description</div>
          <div class="section-content">${escapeHtml(finding.message).replace(/\n/g, '<br>')}</div>
          
          ${finding.codeSnippet ? `
            <div class="section-title">Vulnerable Snippet</div>
            <pre class="codeblock-container"><code>${escapeHtml(finding.codeSnippet)}</code></pre>
          ` : ''}

          ${finding.taintFlow ? `
            <div class="section-title">Data Flow Analysis</div>
            <div class="taint-timeline" style="margin: 15px 0; border-left: 2px dashed rgba(6, 182, 212, 0.4); padding-left: 15px; display: flex; flex-direction: column; gap: 8px;">
              <div style="font-size: 12px; color: var(--text-muted);">
                <strong style="color: var(--color-accent);">Source:</strong> <code>${escapeHtml(finding.taintFlow.source)}</code>
              </div>
              <div style="display: flex; flex-wrap: wrap; align-items: center; gap: 6px; font-size: 11.5px;">
                ${finding.taintFlow.flow.map((step, sIdx) => `
                  <span><code>${escapeHtml(step)}</code></span>
                  ${sIdx < finding.taintFlow.flow.length - 1 ? '<span style="color: var(--color-accent); font-weight: bold;">➔</span>' : ''}
                `).join('')}
              </div>
              <div style="font-size: 12px; color: var(--text-muted);">
                <strong style="color: var(--color-critical);">Sink:</strong> <code>${escapeHtml(finding.taintFlow.sink)}()</code> (Line ${finding.taintFlow.line})
              </div>
            </div>
          ` : ''}
          
          <div class="section-title">Remediation Steps</div>
          <div class="section-content">${escapeHtml(finding.remediation)}</div>
          
          ${finding.suggestedDiff ? `
            <div class="section-title">Suggested Security Fix</div>
            ${formatDiffHtml(finding.suggestedDiff)}
          ` : ''}
        </div>
      </div>
    `;
  }).join('');

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>AI-Detective Security Report - ${report.projectName}</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;500;600;700;800&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
      <style>
        :root {
          --bg-primary: #0b0f19;
          --bg-panel: rgba(20, 28, 47, 0.45);
          --border-color: rgba(255, 255, 255, 0.08);
          --text-main: #f8fafc;
          --text-muted: #94a3b8;
          --color-accent: #06b6d4;
          --color-critical: #ef4444;
          --color-high: #f97316;
          --color-medium: #eab308;
          --color-low: #3b82f6;
          --color-success: #10b981;
        }
        
        body {
          font-family: 'Inter', -apple-system, sans-serif;
          background-color: var(--bg-primary);
          color: var(--text-main);
          margin: 0;
          padding: 40px;
          line-height: 1.5;
        }

        .report-container {
          max-width: 1000px;
          margin: 0 auto;
          display: flex;
          flex-direction: column;
          gap: 30px;
        }

        header {
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 25px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        header h1 {
          font-family: 'Outfit', sans-serif;
          font-weight: 700;
          font-size: 28px;
          margin: 0;
        }

        .engine-badge {
          background: rgba(6, 182, 212, 0.1);
          border: 1px solid rgba(6, 182, 212, 0.3);
          color: var(--color-accent);
          padding: 6px 12px;
          border-radius: 6px;
          font-size: 13px;
          font-weight: 600;
        }

        /* Overview Grid */
        .overview-grid {
          display: grid;
          grid-template-columns: 1fr 1.2fr 1fr;
          gap: 24px;
        }

        .overview-card {
          background: var(--bg-panel);
          border: 1px solid var(--border-color);
          border-radius: 16px;
          padding: 24px;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }

        .overview-card h3 {
          margin-top: 0;
          margin-bottom: 15px;
          font-family: 'Outfit', sans-serif;
          font-size: 16px;
          font-weight: 600;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .grade-card-body {
          display: flex;
          align-items: center;
          gap: 20px;
        }

        .grade-ring {
          width: 80px;
          height: 80px;
          border-radius: 50%;
          border: 5px solid ${m.gradeColor || 'var(--color-success)'};
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: 'Outfit', sans-serif;
          font-weight: 800;
          font-size: 36px;
          color: var(--text-main);
          box-shadow: 0 0 15px ${m.gradeColor || 'var(--color-success)'}33;
        }

        .grade-text h4 {
          margin: 0;
          font-family: 'Outfit', sans-serif;
          font-size: 18px;
          font-weight: 700;
        }

        .grade-text p {
          margin: 4px 0 0 0;
          font-size: 13px;
          color: var(--text-muted);
        }

        /* Severity Counts */
        .severity-counts {
          display: flex;
          gap: 10px;
        }

        .sev-box {
          flex: 1;
          border-radius: 8px;
          padding: 12px 6px;
          text-align: center;
          border: 1px solid var(--border-color);
        }

        .sev-box.critical { background: rgba(239, 68, 68, 0.08); border-color: rgba(239, 68, 68, 0.15); color: var(--color-critical); }
        .sev-box.high { background: rgba(249, 115, 22, 0.08); border-color: rgba(249, 115, 22, 0.15); color: var(--color-high); }
        .sev-box.medium { background: rgba(234, 179, 8, 0.08); border-color: rgba(234, 179, 8, 0.15); color: var(--color-medium); }
        .sev-box.low { background: rgba(59, 130, 246, 0.08); border-color: rgba(59, 130, 246, 0.15); color: var(--color-low); }

        .sev-num {
          font-family: 'Outfit', sans-serif;
          font-size: 20px;
          font-weight: 700;
          display: block;
        }

        .sev-lbl {
          font-size: 11px;
          font-weight: 500;
          opacity: 0.8;
        }

        /* Stats List */
        .stats-list {
          list-style: none;
          padding: 0;
          margin: 0;
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .stats-list li {
          display: flex;
          justify-content: space-between;
          font-size: 13px;
          border-bottom: 1px solid rgba(255, 255, 255, 0.03);
          padding-bottom: 4px;
        }

        .stats-list li span { color: var(--text-muted); }
        .stats-list li strong { color: var(--text-main); }

        /* Findings Layout */
        .section-header-title {
          font-family: 'Outfit', sans-serif;
          font-size: 22px;
          margin-top: 15px;
          margin-bottom: 5px;
        }

        .finding-row {
          background: var(--bg-panel);
          border: 1px solid var(--border-color);
          border-radius: 12px;
          margin-bottom: 20px;
          padding: 24px;
          box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }

        .finding-row.critical { border-left: 6px solid var(--color-critical); }
        .finding-row.high { border-left: 6px solid var(--color-high); }
        .finding-row.medium { border-left: 6px solid var(--color-medium); }
        .finding-row.low { border-left: 6px solid var(--color-low); }

        .finding-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          border-bottom: 1px solid var(--border-color);
          padding-bottom: 15px;
          margin-bottom: 15px;
        }

        .finding-title-row {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .sev-badge {
          font-size: 11px;
          font-weight: 700;
          padding: 3px 8px;
          border-radius: 4px;
          text-transform: uppercase;
        }

        .sev-badge.critical { background: rgba(239, 68, 68, 0.15); color: var(--color-critical); border: 1px solid rgba(239, 68, 68, 0.3); }
        .sev-badge.high { background: rgba(249, 115, 22, 0.15); color: var(--color-high); border: 1px solid rgba(249, 115, 22, 0.3); }
        .sev-badge.medium { background: rgba(234, 179, 8, 0.15); color: var(--color-medium); border: 1px solid rgba(234, 179, 8, 0.3); }
        .sev-badge.low { background: rgba(59, 130, 246, 0.15); color: var(--color-low); border: 1px solid rgba(59, 130, 246, 0.3); }

        .finding-title {
          margin: 0;
          font-size: 16px;
          font-weight: 600;
        }

        .finding-meta code {
          background: rgba(0, 0, 0, 0.3);
          padding: 4px 8px;
          border-radius: 4px;
          font-size: 13px;
        }

        .meta-pill-row {
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          margin-bottom: 15px;
        }

        .meta-pill {
          background: rgba(255, 255, 255, 0.04);
          border: 1px solid var(--border-color);
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 11px;
          color: var(--text-muted);
        }

        .meta-pill strong {
          color: var(--text-main);
        }

        .section-title {
          font-size: 11px;
          font-weight: 700;
          text-transform: uppercase;
          color: var(--text-muted);
          letter-spacing: 0.5px;
          margin-top: 15px;
          margin-bottom: 6px;
        }

        .section-content {
          font-size: 14px;
          color: #cbd5e1;
          line-height: 1.6;
        }

        /* Code Block & Diff */
        .codeblock-container {
          background: #05070f;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          padding: 14px;
          font-family: 'Fira Code', Courier, monospace;
          font-size: 13px;
          overflow-x: auto;
          margin: 6px 0;
          color: #e2e8f0;
        }

        .diff-box {
          background: #010409;
          border: 1px solid var(--border-color);
          border-radius: 8px;
          font-family: 'Fira Code', Courier, monospace;
          font-size: 12px;
          overflow: hidden;
          margin: 6px 0;
        }

        .diff-header {
          background: #0d1117;
          padding: 6px 12px;
          border-bottom: 1px solid var(--border-color);
          color: var(--text-muted);
          font-size: 11px;
        }

        .diff-line {
          padding: 4px 12px;
          white-space: pre-wrap;
        }

        .diff-line.deletion { background: rgba(239, 68, 68, 0.15); color: #f87171; }
        .diff-line.addition { background: rgba(46, 160, 67, 0.15); color: #4ade80; }
        .diff-line.info { background: rgba(255,255,255,0.02); color: var(--text-muted); text-align: center; }

        /* Print styles */
        @media print {
          body {
            background: white !important;
            color: black !important;
            padding: 0;
          }
          .overview-card, .finding-row, .meta-pill {
            background: white !important;
            border: 1px solid #ddd !important;
            box-shadow: none !important;
            color: black !important;
            page-break-inside: avoid;
          }
          .grade-ring {
            border-color: #333 !important;
            box-shadow: none !important;
            color: black !important;
          }
          .sev-box {
            background: transparent !important;
            border: 1px solid #ddd !important;
            color: black !important;
          }
          .section-content, .finding-meta code, .meta-pill strong {
            color: #111827 !important;
          }
          .codeblock-container {
            background: #f8fafc !important;
            color: #0f172a !important;
            border: 1px solid #cbd5e1 !important;
          }
          .diff-box {
            background: #f8fafc !important;
            border: 1px solid #cbd5e1 !important;
            color: #0f172a !important;
          }
          .diff-header {
            background: #f1f5f9 !important;
            color: #475569 !important;
          }
          .diff-line.deletion { background: #fee2e2 !important; color: #991b1b !important; }
          .diff-line.addition { background: #dcfce7 !important; color: #166534 !important; }
          .diff-line.info { background: #f1f5f9 !important; color: #475569 !important; }
        }
      </style>
    </head>
    <body>
      <div class="report-container">
        <header>
          <div>
            <h1>Security Assessment Report</h1>
            <p style="margin:5px 0 0 0; font-size:14px; color:var(--text-muted);">Project: <strong>${escapeHtml(report.projectName)}</strong> | Date: ${new Date(report.scanTime).toUTCString()}</p>
          </div>
          <span class="engine-badge">Engine: ${escapeHtml(report.semgrepStatus)}</span>
        </header>

        <div class="overview-grid">
          <div class="overview-card">
            <h3>Posture Grade</h3>
            <div class="grade-card-body">
              <div class="grade-ring">${m.grade}</div>
              <div class="grade-text">
                <h4>${m.rating}</h4>
                <p>Score Index: ${m.securityScore}/100</p>
              </div>
            </div>
          </div>

          <div class="overview-card">
            <h3>Threat Breakdown</h3>
            <div class="severity-counts">
              <div class="sev-box critical">
                <span class="sev-num">${sev.Critical}</span>
                <span class="sev-lbl">Critical</span>
              </div>
              <div class="sev-box high">
                <span class="sev-num">${sev.High}</span>
                <span class="sev-lbl">High</span>
              </div>
              <div class="sev-box medium">
                <span class="sev-num">${sev.Medium}</span>
                <span class="sev-lbl">Medium</span>
              </div>
            </div>
          </div>

          <div class="overview-card">
            <h3>Audit Statistics</h3>
            <ul class="stats-list">
              <li><span>Files Audited:</span><strong>${report.filesScannedCount}</strong></li>
              <li><span>Total Issues:</span><strong>${report.findings.length}</strong></li>
              <li><span>Primary Threat:</span><strong>${escapeHtml(m.topIssueCategory)}</strong></li>
            </ul>
          </div>
        </div>

        <h2 class="section-header-title">Detailed Vulnerability Catalog</h2>
        ${listItems.length > 0 ? listItems : '<p>No vulnerabilities found.</p>'}
      </div>
    </body>
    </html>
  `;
}

/**
 * Runs the complete vulnerability scanner pipeline.
 * @param {string} scanDirectory - Directory containing the code target.


/**
 * Runs the complete vulnerability scanner pipeline.
 * @param {string} scanDirectory - Directory containing the code target.
 * @param {string} projectName - Display name of the project.
 * @returns {Promise<any>} Completed report object.
 */
async function buildReport(scanDirectory, projectName) {
  const reportId = `report-${Date.now()}`;
  const scanTime = new Date().toISOString();

  // Phase 1: Retrieve and filter files to scan
  const allFiles = walkDir(scanDirectory);
  const filesScannedCount = allFiles.length;

  console.log(`Scan initiated for project: ${projectName}. Scanning ${filesScannedCount} code/configuration files.`);

  // Phase 2: Run Custom Secret Scanner
  const secretFindings = scanSecrets(allFiles);

  // Phase 3: Run Semgrep scan (primary SAST)
  let semgrepFindings = [];
  let semgrepStatus = 'Inactive (Not Installed)';

  const isSemgrepInstalled = await checkSemgrepInstalled();
  if (isSemgrepInstalled) {
    semgrepStatus = 'Active (Global Scanner)';
    console.log('Semgrep is available. Launching Semgrep SAST scan...');
    
    const semgrepRes = await runSemgrepScan(scanDirectory);
    if (semgrepRes.success && semgrepRes.data) {
      semgrepFindings = parseSemgrepResults(semgrepRes.data, scanDirectory);
      console.log(`Semgrep scan completed. Identified ${semgrepFindings.length} findings.`);
    } else {
      semgrepStatus = 'Active (Execution Error - Fallback Used)';
      console.warn('Semgrep executed with errors. Falling back to local scanner engine.');
    }
  } else {
    console.log('Semgrep is not installed or not in local PATH. Running with custom SAST fallback engine.');
  }

  // Phase 4: Run Supplemental Custom SAST rules
  const customFindings = scanCustomRules(allFiles);

  // Phase 5: Run Dependency Analysis (SCA)
  const dependencyFindings = scanDependencies(allFiles);

  // Phase 6: Aggregate and combine findings (de-duplicate issues by path & line & rule)
  const combinedFindings = [];
  const findingKeys = new Set();

  // Helper to add findings avoiding duplicates
  const addFinding = (finding) => {
    const key = `${finding.path}:${finding.line}:${finding.rule_id}`;
    if (!findingKeys.has(key)) {
      findingKeys.add(key);
      combinedFindings.push(finding);
    }
  };

  secretFindings.forEach(addFinding);
  semgrepFindings.forEach(addFinding);
  customFindings.forEach(addFinding);
  dependencyFindings.forEach(addFinding);

  // Phase 7: Statically map routes and correlate findings (White Box)
  const routeMapper = new RouteMapper();
  const routes = routeMapper.mapRoutes(scanDirectory);

  const correlationEngine = new CorrelationEngine();
  const correlationResult = correlationEngine.correlate(combinedFindings, [], routes, scanDirectory);

  // Save both correlated and unmatched findings in the final list, excluding Low and Info findings
  const finalFindings = [
    ...correlationResult.correlatedFindings,
    ...correlationResult.unmatchedSast
  ].filter(f => {
    const sev = String(f.severity || '').toLowerCase();
    return sev !== 'low' && sev !== 'info';
  });

  // Run Risk Engine
  const metrics = evaluateRisk(finalFindings);

  const report = {
    id: reportId,
    projectName,
    scanTime,
    filesScannedCount,
    semgrepStatus,
    metrics,
    findings: finalFindings,
    routes
  };

  // Save JSON report
  const reportsDir = path.join(__dirname, '../../reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }
  const reportPathJson = path.join(reportsDir, `${reportId}.json`);
  fs.writeFileSync(reportPathJson, encrypt(JSON.stringify(report)), 'utf8');

  // Save Markdown executive summary
  const reportPathMd = path.join(reportsDir, `${reportId}.md`);
  const markdownContent = buildMarkdownReport(report);
  fs.writeFileSync(reportPathMd, markdownContent, 'utf8');

  console.log(`Scan complete! Report ${reportId} saved successfully.`);
  return report;
}

/**
 * Builds a complete Word DOCX report using the docx library.
 * Returns a Promise resolving to a binary buffer.
 */
async function buildDocReport(report) {
  const m = report.metrics;
  const sev = m.severityCounts;

  const COLOR_ACCENT = "06B6D4"; // Cyan
  const COLOR_TEXT_MAIN = "1E293B"; // Dark Slate
  const COLOR_TEXT_MUTED = "64748B"; // Muted Slate
  const COLOR_CRITICAL = "EF4444"; // Red
  const COLOR_HIGH = "F97316"; // Orange
  const COLOR_MEDIUM = "EAB308"; // Yellow
  const COLOR_LOW = "3B82F6"; // Blue
  const COLOR_BG_LIGHT = "F8FAFC"; // Very Light Slate
  const COLOR_BORDER = "E2E8F0"; // Border Slate

  // Helpers for text structures
  function createHeading2(text) {
    return new docx.Paragraph({
      heading: docx.HeadingLevel.HEADING_2,
      spacing: { before: 240, after: 120 },
      children: [
        new docx.TextRun({
          text: text,
          font: "Arial",
          bold: true,
          size: 28, // 14pt
          color: "0F172A",
        })
      ]
    });
  }

  function createHeading3(text) {
    return new docx.Paragraph({
      heading: docx.HeadingLevel.HEADING_3,
      spacing: { before: 180, after: 80 },
      children: [
        new docx.TextRun({
          text: text,
          font: "Arial",
          bold: true,
          size: 22, // 11pt
          color: "1E293B",
        })
      ]
    });
  }

  function createMetaTable(rowsData) {
    return new docx.Table({
      width: { size: 100, type: docx.WidthType.PERCENTAGE },
      rows: rowsData.map(row => new docx.TableRow({
        children: row.map(cell => new docx.TableCell({
          children: [
            new docx.Paragraph({
              children: [
                new docx.TextRun({
                  text: cell.text || "",
                  bold: cell.bold || false,
                  color: cell.color || COLOR_TEXT_MAIN,
                  font: cell.font || "Arial",
                  size: cell.size || 20, // 10pt
                })
              ],
              spacing: { before: 80, after: 80 }
            })
          ],
          shading: cell.fill ? { fill: cell.fill } : undefined,
          borders: {
            top: { style: docx.BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
            bottom: { style: docx.BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
            left: { style: docx.BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
            right: { style: docx.BorderStyle.SINGLE, size: 4, color: COLOR_BORDER }
          },
          padding: { top: 100, bottom: 100, left: 150, right: 150 }
        }))
      }))
    });
  }

  function createCodeBlock(codeText) {
    if (!codeText) return null;
    const lines = codeText.split('\n');
    return new docx.Table({
      width: { size: 100, type: docx.WidthType.PERCENTAGE },
      rows: [
        new docx.TableRow({
          children: [
            new docx.TableCell({
              children: lines.map(line => new docx.Paragraph({
                children: [
                  new docx.TextRun({
                    text: line,
                    font: "Consolas",
                    size: 18, // 9pt
                    color: "0F172A",
                  })
                ],
                spacing: { before: 40, after: 40 }
              })),
              shading: { fill: "F8FAFC" },
              borders: {
                top: { style: docx.BorderStyle.SINGLE, size: 4, color: "CBD5E1" },
                bottom: { style: docx.BorderStyle.SINGLE, size: 4, color: "CBD5E1" },
                left: { style: docx.BorderStyle.SINGLE, size: 4, color: "CBD5E1" },
                right: { style: docx.BorderStyle.SINGLE, size: 4, color: "CBD5E1" }
              },
              padding: { top: 120, bottom: 120, left: 150, right: 150 }
            })
          ]
        })
      ]
    });
  }

  function createDiffBlock(diffText) {
    if (!diffText) return null;

    const currentMarker = '<<<< CURRENT CODE';
    const fixMarker = '==== SUGGESTED FIX';
    const endMarker = '>>>>';

    let currentBlock = '';
    let fixBlock = '';
    let lines = [];

    if (diffText.includes(currentMarker) && diffText.includes(fixMarker)) {
      const parts = diffText.split(fixMarker);
      currentBlock = parts[0].replace(currentMarker, '').trim();
      fixBlock = parts[1].replace(endMarker, '').trim();

      lines.push({ text: "Vulnerable Original", isHeader: true });
      currentBlock.split('\n').forEach(l => lines.push({ text: `- ${l}`, isDeletion: true }));
      lines.push({ text: "Secure Mitigated", isHeader: true });
      fixBlock.split('\n').forEach(l => lines.push({ text: `+ ${l}`, isAddition: true }));
    } else {
      return createCodeBlock(diffText);
    }

    return new docx.Table({
      width: { size: 100, type: docx.WidthType.PERCENTAGE },
      rows: [
        new docx.TableRow({
          children: [
            new docx.TableCell({
              children: lines.map(line => {
                let color = "0F172A";
                let shading = undefined;
                let bold = false;

                if (line.isHeader) {
                  color = "475569";
                  bold = true;
                  shading = "F1F5F9";
                } else if (line.isDeletion) {
                  color = "991B1B";
                  shading = "FEE2E2";
                } else if (line.isAddition) {
                  color = "166534";
                  shading = "DCFCE7";
                }

                return new docx.Paragraph({
                  children: [
                    new docx.TextRun({
                      text: line.text,
                      font: "Consolas",
                      size: 18, // 9pt
                      color: color,
                      bold: bold
                    })
                  ],
                  spacing: { before: 60, after: 60 },
                  shading: shading ? { fill: shading } : undefined
                });
              }),
              shading: { fill: "FFFFFF" },
              borders: {
                top: { style: docx.BorderStyle.SINGLE, size: 4, color: "CBD5E1" },
                bottom: { style: docx.BorderStyle.SINGLE, size: 4, color: "CBD5E1" },
                left: { style: docx.BorderStyle.SINGLE, size: 4, color: "CBD5E1" },
                right: { style: docx.BorderStyle.SINGLE, size: 4, color: "CBD5E1" }
              },
              padding: { top: 120, bottom: 120, left: 150, right: 150 }
            })
          ]
        })
      ]
    });
  }

  const children = [];

  // Title Header
  children.push(new docx.Paragraph({
    spacing: { before: 200, after: 100 },
    children: [
      new docx.TextRun({
        text: "AI-Detective Security Assessment Report",
        font: "Arial",
        bold: true,
        size: 44, // 22pt
        color: "0F172A",
      })
    ]
  }));

  children.push(new docx.Paragraph({
    spacing: { before: 0, after: 360 },
    children: [
      new docx.TextRun({
        text: "Secure code analysis, hybrid vulnerability scanning, and AI-powered mitigation guidelines.",
        font: "Arial",
        size: 20, // 10pt
        color: COLOR_TEXT_MUTED,
        italic: true
      })
    ]
  }));

  // Executive Summary
  children.push(createHeading2("Executive Summary"));

  let gradeColor = COLOR_LOW;
  if (m.grade === "F") gradeColor = COLOR_CRITICAL;
  else if (m.grade === "D" || m.grade === "C") gradeColor = COLOR_HIGH;
  else if (m.grade === "B") gradeColor = COLOR_MEDIUM;

  const summaryRows = [
    [
      { text: "Project Name:", bold: true, fill: "F1F5F9" },
      { text: report.projectName },
      { text: "Scan Date:", bold: true, fill: "F1F5F9" },
      { text: new Date(report.scanTime).toUTCString() }
    ],
    [
      { text: "Security Grade:", bold: true, fill: "F1F5F9" },
      { text: `${m.grade} (${m.rating})`, bold: true, color: gradeColor },
      { text: "Security Score:", bold: true, fill: "F1F5F9" },
      { text: `${m.securityScore} / 100`, bold: true }
    ],
    [
      { text: "Files Scanned:", bold: true, fill: "F1F5F9" },
      { text: String(report.filesScannedCount) },
      { text: "Semgrep Status:", bold: true, fill: "F1F5F9" },
      { text: report.semgrepStatus }
    ]
  ];
  children.push(createMetaTable(summaryRows));

  children.push(new docx.Paragraph({ spacing: { before: 120, after: 120 } }));

  // Threat Severity Counts
  children.push(createHeading3("Vulnerability Severity Breakdown"));
  const threatRows = [
    [
      { text: "Severity", bold: true, fill: "F1F5F9" },
      { text: "Count", bold: true, fill: "F1F5F9" }
    ],
    [
      { text: "Critical Risk (🔴)", bold: true, color: COLOR_CRITICAL },
      { text: String(sev.Critical), bold: true }
    ],
    [
      { text: "High Risk (🟠)", bold: true, color: COLOR_HIGH },
      { text: String(sev.High), bold: true }
    ],
    [
      { text: "Medium Risk (🟡)", bold: true, color: COLOR_MEDIUM },
      { text: String(sev.Medium), bold: true }
    ]
  ];
  children.push(new docx.Table({
    width: { size: 50, type: docx.WidthType.PERCENTAGE },
    rows: threatRows.map(row => new docx.TableRow({
      children: row.map(cell => new docx.TableCell({
        children: [
          new docx.Paragraph({
            children: [
              new docx.TextRun({
                text: cell.text,
                bold: cell.bold || false,
                color: cell.color || COLOR_TEXT_MAIN,
                size: 20
              })
            ],
            spacing: { before: 60, after: 60 }
          })
        ],
        shading: cell.fill ? { fill: cell.fill } : undefined,
        borders: {
          top: { style: docx.BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
          bottom: { style: docx.BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
          left: { style: docx.BorderStyle.SINGLE, size: 4, color: COLOR_BORDER },
          right: { style: docx.BorderStyle.SINGLE, size: 4, color: COLOR_BORDER }
        },
        padding: { top: 80, bottom: 80, left: 120, right: 120 }
      }))
    }))
  }));

  children.push(new docx.Paragraph({ spacing: { before: 200, after: 200 } }));

  // AI Detective Insights
  if (report.aiAnalysis) {
    const ai = report.aiAnalysis;
    children.push(createHeading2("🔍 AI Detective Threat Assessment"));

    children.push(createHeading3("Executive Posture Summary"));
    ai.executiveSummary.split('\n\n').forEach(para => {
      if (para.trim()) {
        children.push(new docx.Paragraph({
          children: [new docx.TextRun({ text: para.replace(/###/g, '').replace(/\*\*/g, '').trim() })],
          spacing: { before: 80, after: 80 }
        }));
      }
    });

    children.push(createHeading3("Chained Threat Vectors (Attack Chain)"));
    ai.attackNarrative.split('\n\n').forEach(para => {
      if (para.trim()) {
        const isStep = para.startsWith('**Step');
        const isImpact = para.startsWith('**Impact') || para.startsWith('Impact');

        let text = para.replace(/\*\*/g, '').trim();
        let color = COLOR_TEXT_MAIN;
        let bold = false;

        if (isStep) {
          color = COLOR_ACCENT;
          bold = true;
        } else if (isImpact) {
          color = COLOR_CRITICAL;
          bold = true;
        }

        children.push(new docx.Paragraph({
          children: [new docx.TextRun({ text: text, color: color, bold: bold })],
          spacing: { before: 80, after: 80 }
        }));
      }
    });

    children.push(createHeading3("AI Prioritized Remediation Checklist"));
    if (Array.isArray(ai.remediationRanking)) {
      ai.remediationRanking.forEach(item => {
        children.push(new docx.Paragraph({
          bullet: { level: 0 },
          children: [
            new docx.TextRun({ text: `Rank #${item.rank}: `, bold: true, color: item.rank <= 2 ? COLOR_CRITICAL : COLOR_TEXT_MAIN }),
            new docx.TextRun({ text: `${item.title} (`, bold: true }),
            new docx.TextRun({ text: item.location, font: "Consolas" }),
            new docx.TextRun({ text: `)\n` }),
            new docx.TextRun({ text: `Reasoning: `, italic: true, color: COLOR_TEXT_MUTED }),
            new docx.TextRun({ text: item.reasoning, italic: true })
          ],
          spacing: { before: 60, after: 60 }
        }));
      });
    }

    children.push(new docx.Paragraph({ spacing: { before: 200, after: 200 } }));
  }

  // Detailed Findings
  children.push(createHeading2("Detailed Findings Catalog"));

  if (report.findings.length === 0) {
    children.push(new docx.Paragraph({
      children: [new docx.TextRun({ text: "No vulnerabilities were detected in this codebase. Good job!", italic: true })],
      spacing: { before: 100, after: 100 }
    }));
  } else {
    report.findings.forEach((finding, idx) => {
      let sevColor = COLOR_LOW;
      if (finding.severity === "Critical") sevColor = COLOR_CRITICAL;
      else if (finding.severity === "High") sevColor = COLOR_HIGH;
      else if (finding.severity === "Medium") sevColor = COLOR_MEDIUM;

      children.push(new docx.Paragraph({
        heading: docx.HeadingLevel.HEADING_3,
        spacing: { before: 200, after: 80 },
        children: [
          new docx.TextRun({
            text: `${idx + 1}. [${finding.severity.toUpperCase()}] ${finding.title}`,
            bold: true,
            color: sevColor,
            size: 24
          })
        ]
      }));

      const findingMetaRows = [
        [
          { text: "Rule ID:", bold: true, fill: "F1F5F9" },
          { text: finding.rule_id },
          { text: "File / Line:", bold: true, fill: "F1F5F9" },
          { text: `${finding.path}:L${finding.line}` }
        ],
        [
          { text: "CWE Mappings:", bold: true, fill: "F1F5F9" },
          { text: finding.cwe },
          { text: "OWASP Category:", bold: true, fill: "F1F5F9" },
          { text: finding.owasp }
        ]
      ];

      if (finding.cve) {
        findingMetaRows.push([
          { text: "CVE ID:", bold: true, fill: "F1F5F9" },
          { text: finding.cve },
          { text: "", fill: "F1F5F9" },
          { text: "" }
        ]);
      }

      if (finding.isCorrelated) {
        if (finding.endpoint) {
          findingMetaRows.push([
            { text: "Exposed URL:", bold: true, fill: "E6F7FF" },
            { text: `${finding.endpointMethod || ''} ${finding.endpointPath || ''}`, bold: true, color: "0050B3" },
            { text: "Controller Handler:", bold: true, fill: "E6F7FF" },
            { text: `${finding.handler || 'inline'}() (lines ${finding.codeLocation ? (finding.codeLocation.lineStart + '-' + finding.codeLocation.lineEnd) : 'N/A'})` }
          ]);
        } else if (finding.codeLocation) {
          findingMetaRows.push([
            { text: "Controller File:", bold: true, fill: "E6F7FF" },
            { text: `${finding.codeLocation.file}`, font: "Consolas" },
            { text: "Controller Handler:", bold: true, fill: "E6F7FF" },
            { text: `${finding.codeLocation.handler || 'inline'}() (lines ${finding.codeLocation.lineStart || 'N/A'}-${finding.codeLocation.lineEnd || 'N/A'})` }
          ]);
        }
      }

      children.push(createMetaTable(findingMetaRows));

      children.push(new docx.Paragraph({
        children: [new docx.TextRun({ text: "Vulnerability Description", bold: true, color: "475569" })],
        spacing: { before: 100, after: 40 }
      }));
      children.push(new docx.Paragraph({
        children: [new docx.TextRun({ text: finding.message })],
        spacing: { before: 40, after: 100 }
      }));

      if (finding.codeSnippet) {
        children.push(new docx.Paragraph({
          children: [new docx.TextRun({ text: "Vulnerable Code Snippet", bold: true, color: "475569" })],
          spacing: { before: 100, after: 40 }
        }));
        const codeBlock = createCodeBlock(finding.codeSnippet);
        if (codeBlock) children.push(codeBlock);
      }

      if (finding.taintFlow) {
        children.push(new docx.Paragraph({
          children: [new docx.TextRun({ text: "Data Flow Analysis (White Box Source-to-Sink Path)", bold: true, color: "0050B3" })],
          spacing: { before: 100, after: 40 }
        }));
        const flowText = `Source: ${finding.taintFlow.source}\nSink: ${finding.taintFlow.sink}()\nFlow: ${finding.taintFlow.flow.join(' ➔ ')}`;
        const flowBlock = createCodeBlock(flowText);
        if (flowBlock) children.push(flowBlock);
      }

      children.push(new docx.Paragraph({
        children: [new docx.TextRun({ text: "Remediation Steps", bold: true, color: "475569" })],
        spacing: { before: 100, after: 40 }
      }));
      children.push(new docx.Paragraph({
        children: [new docx.TextRun({ text: finding.remediation })],
        spacing: { before: 40, after: 100 }
      }));

      if (finding.suggestedDiff) {
        children.push(new docx.Paragraph({
          children: [new docx.TextRun({ text: "Suggested Mitigation Fix Comparison", bold: true, color: "475569" })],
          spacing: { before: 100, after: 40 }
        }));
        const diffBlock = createDiffBlock(finding.suggestedDiff);
        if (diffBlock) children.push(diffBlock);
      }

      children.push(new docx.Paragraph({
        spacing: { before: 150, after: 150 },
        border: {
          bottom: { style: docx.BorderStyle.SINGLE, size: 6, color: "CBD5E1" }
        }
      }));
    });
  }

  const doc = new docx.Document({
    styles: {
      default: {
        document: {
          run: {
            font: "Arial",
            size: 21, // ~10.5pt
            color: COLOR_TEXT_MAIN
          }
        }
      }
    },
    sections: [{
      properties: {},
      children: children
    }]
  });

  return await docx.Packer.toBuffer(doc);
}

module.exports = {
  buildReport,
  buildMarkdownReport,
  buildHtmlReport,
  buildDocReport
};
