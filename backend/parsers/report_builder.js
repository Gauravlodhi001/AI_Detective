const fs = require('fs');
const path = require('path');
const { walkDir } = require('../utils/fileWalker');
const { checkSemgrepInstalled, runSemgrepScan } = require('../scanners/semgrep_scanner');
const { parseSemgrepResults } = require('./semgrep_parser');
const { scanSecrets } = require('../scanners/secret_scanner');
const { scanCustomRules } = require('../scanners/custom_scanner');
const { scanDependencies } = require('../scanners/dependency_scanner');
const { evaluateRisk } = require('../utils/riskEngine');

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
  md += `| 🔵 Low | ${sev.Low} |\n`;
  md += `| **Total** | **${report.findings.length}** |\n\n`;

  md += `### Primary OWASP Theme: ${m.topIssueCategory}\n\n`;

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
    md += `* **OWASP Category:** ${finding.owasp}\n\n`;
    md += `**Description:**\n${finding.message}\n\n`;
    
    if (finding.codeSnippet) {
      md += `**Vulnerable Snippet:**\n\`\`\`\n${finding.codeSnippet}\n\`\`\`\n\n`;
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
            <span class="meta-pill">OWASP: <strong>${escapeHtml(finding.owasp)}</strong></span>
          </div>
          
          <div class="section-title">Vulnerability Description</div>
          <div class="section-content">${escapeHtml(finding.message).replace(/\n/g, '<br>')}</div>
          
          ${finding.codeSnippet ? `
            <div class="section-title">Vulnerable Snippet</div>
            <pre class="codeblock-container"><code>${escapeHtml(finding.codeSnippet)}</code></pre>
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
              <div class="sev-box low">
                <span class="sev-num">${sev.Low}</span>
                <span class="sev-lbl">Low</span>
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

  // Run Risk Engine
  const metrics = evaluateRisk(combinedFindings);

  const report = {
    id: reportId,
    projectName,
    scanTime,
    filesScannedCount,
    semgrepStatus,
    metrics,
    findings: combinedFindings
  };

  // Save JSON report
  const reportsDir = path.join(__dirname, '../../reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }
  const reportPathJson = path.join(reportsDir, `${reportId}.json`);
  fs.writeFileSync(reportPathJson, JSON.stringify(report, null, 2), 'utf8');

  // Save Markdown executive summary
  const reportPathMd = path.join(reportsDir, `${reportId}.md`);
  const markdownContent = buildMarkdownReport(report);
  fs.writeFileSync(reportPathMd, markdownContent, 'utf8');

  console.log(`Scan complete! Report ${reportId} saved successfully.`);
  return report;
}

/**
 * Builds a complete Word DOC report using HTML representation.
 */
function buildDocReport(report) {
  const m = report.metrics;
  const sev = m.severityCounts;

  const listItems = report.findings.map((finding, idx) => {
    return `
      <div class="finding-card ${finding.severity.toLowerCase()}">
        <h3>${idx + 1}. [${finding.severity}] ${escapeHtml(finding.title)}</h3>
        <p><strong>Rule ID:</strong> <code>${escapeHtml(finding.rule_id)}</code> | <strong>File:</strong> <code>${escapeHtml(finding.path)}</code> (Line ${finding.line})</p>
        <p><strong>CWE:</strong> ${escapeHtml(finding.cwe)} | <strong>OWASP:</strong> ${escapeHtml(finding.owasp)}</p>
        
        <div class="section-title">Vulnerability Description</div>
        <p class="section-content">${escapeHtml(finding.message).replace(/\n/g, '<br>')}</p>
        
        ${finding.codeSnippet ? `
          <div class="section-title">Vulnerable Snippet</div>
          <div class="codeblock"><pre style="margin:0;"><code>${escapeHtml(finding.codeSnippet)}</code></pre></div>
        ` : ''}
        
        <div class="section-title">Remediation Steps</div>
        <p class="section-content">${escapeHtml(finding.remediation)}</p>
        
        ${finding.suggestedDiff ? `
          <div class="section-title">Suggested Security Fix</div>
          ${formatDiffHtml(finding.suggestedDiff)}
        ` : ''}
      </div>
      <br>
    `;
  }).join('');

  return `
    <html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
    <head>
      <meta charset="utf-8">
      <title>AI-Detective Security Assessment - ${report.projectName}</title>
      <!--[if gte mso 9]>
      <xml>
        <o:OfficeDocumentSettings>
          <o:AllowPNG/>
          <o:PixelsPerInch>96</o:PixelsPerInch>
        </o:OfficeDocumentSettings>
        <w:WordDocument>
          <w:View>Print</w:View>
          <w:Zoom>100</w:Zoom>
          <w:DoNotOptimizeForBrowser/>
        </w:WordDocument>
      </xml>
      <![endif]-->
      <style>
        body {
          font-family: Arial, sans-serif;
          font-size: 11pt;
          line-height: 1.4;
          color: #1e293b;
          margin: 40px;
        }
        h1 {
          font-family: Arial, sans-serif;
          font-size: 24pt;
          font-weight: bold;
          color: #0f172a;
          border-bottom: 2px solid #cbd5e1;
          padding-bottom: 5px;
          margin-bottom: 20px;
        }
        h2 {
          font-family: Arial, sans-serif;
          font-size: 16pt;
          font-weight: bold;
          color: #0f172a;
          margin-top: 30px;
          border-bottom: 1px solid #e2e8f0;
          padding-bottom: 5px;
        }
        h3 {
          font-family: Arial, sans-serif;
          font-size: 12pt;
          font-weight: bold;
          color: #1e293b;
          margin: 0 0 8px 0;
        }
        p {
          margin: 6px 0;
        }
        code {
          font-family: Consolas, "Courier New", monospace;
          background-color: #f1f5f9;
          padding: 2px 4px;
          font-size: 9.5pt;
          border-radius: 3px;
        }
        .header-meta {
          margin-bottom: 30px;
        }
        .meta-table {
          width: 100%;
          border-collapse: collapse;
          margin-bottom: 20px;
        }
        .meta-table td {
          border: 1px solid #cbd5e1;
          padding: 10px;
          font-size: 10pt;
        }
        .meta-table td.label {
          background-color: #f1f5f9;
          font-weight: bold;
          width: 20%;
        }
        .finding-card {
          border-left: 6px solid #cbd5e1;
          padding: 15px;
          margin-bottom: 25px;
          background-color: #f8fafc;
          border-top: 1px solid #e2e8f0;
          border-right: 1px solid #e2e8f0;
          border-bottom: 1px solid #e2e8f0;
        }
        .finding-card.critical { border-left-color: #ef4444; background-color: #fef2f2; }
        .finding-card.high { border-left-color: #f97316; background-color: #fff7ed; }
        .finding-card.medium { border-left-color: #eab308; background-color: #fefdf0; }
        .finding-card.low { border-left-color: #3b82f6; background-color: #eff6ff; }
        
        .section-title {
          font-size: 9pt;
          font-weight: bold;
          text-transform: uppercase;
          color: #475569;
          margin-top: 15px;
          margin-bottom: 4px;
          letter-spacing: 0.5px;
        }
        .section-content {
          font-size: 10.5pt;
          color: #334155;
          margin-bottom: 10px;
        }
        .codeblock {
          background-color: #f1f5f9;
          color: #0f172a;
          border: 1px solid #cbd5e1;
          font-family: Consolas, "Courier New", monospace;
          padding: 12px;
          font-size: 9.5pt;
          margin: 6px 0;
        }
        .diff-box {
          border: 1px solid #cbd5e1;
          font-family: Consolas, "Courier New", monospace;
          font-size: 9pt;
          margin: 8px 0;
          background-color: #ffffff;
        }
        .diff-header {
          background-color: #f1f5f9;
          padding: 6px 12px;
          font-weight: bold;
          border-bottom: 1px solid #cbd5e1;
        }
        .diff-line {
          padding: 4px 12px;
        }
        .deletion {
          background-color: #fee2e2;
          color: #991b1b;
        }
        .addition {
          background-color: #dcfce7;
          color: #166534;
        }
        .info {
          background-color: #f8fafc;
          color: #475569;
          text-align: center;
        }
      </style>
    </head>
    <body>
      <h1>AI-Detective Security Assessment Report</h1>
      <div class="header-meta">
        <table class="meta-table">
          <tr>
            <td class="label">Project:</td>
            <td><strong>${escapeHtml(report.projectName)}</strong></td>
            <td class="label">Date:</td>
            <td>${new Date(report.scanTime).toUTCString()}</td>
          </tr>
          <tr>
            <td class="label">Security Grade:</td>
            <td><strong>${m.grade} (${m.rating})</strong></td>
            <td class="label">Security Score:</td>
            <td><strong>${m.securityScore} / 100</strong></td>
          </tr>
          <tr>
            <td class="label">Files Scanned:</td>
            <td>${report.filesScannedCount}</td>
            <td class="label">Semgrep Status:</td>
            <td>${escapeHtml(report.semgrepStatus)}</td>
          </tr>
        </table>
      </div>

      <h2>Severity Breakdown</h2>
      <table class="meta-table" style="width: 50%;">
        <tr style="background-color: #f1f5f9; font-weight: bold;">
          <td>Severity</td>
          <td>Count</td>
        </tr>
        <tr>
          <td style="color: #ef4444; font-weight: bold;">🔴 Critical</td>
          <td><strong>${sev.Critical}</strong></td>
        </tr>
        <tr>
          <td style="color: #f97316; font-weight: bold;">🟠 High</td>
          <td><strong>${sev.High}</strong></td>
        </tr>
        <tr>
          <td style="color: #eab308; font-weight: bold;">🟡 Medium</td>
          <td><strong>${sev.Medium}</strong></td>
        </tr>
        <tr>
          <td style="color: #3b82f6; font-weight: bold;">🔵 Low</td>
          <td><strong>${sev.Low}</strong></td>
        </tr>
      </table>

      <h2>Detailed Vulnerability Catalog</h2>
      ${listItems.length > 0 ? listItems : '<p>No vulnerabilities found.</p>'}
    </body>
    </html>
  `;
}

module.exports = {
  buildReport,
  buildMarkdownReport,
  buildHtmlReport,
  buildDocReport
};
