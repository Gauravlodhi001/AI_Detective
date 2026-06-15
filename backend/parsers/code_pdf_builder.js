const PDFDocument = require('pdfkit');

/**
 * Builds a high-fidelity corporate SAST/Semgrep PDF report and pipes it directly to the response.
 */
function buildCodePdfReport(reportData, res) {
  const doc = new PDFDocument({ margin: 50, bufferPages: true });

  // Pipe output
  doc.pipe(res);

  const m = reportData.metrics || {};
  const c = m.severityCounts || { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  const findings = reportData.findings || [];
  const ai = reportData.aiAnalysis || {};

  // Theme Colors
  const colors = {
    primary: '#0f172a',    // Dark Slate
    secondary: '#1e293b',  // Slate Medium
    accent: '#0284c7',     // Sky Blue Accent
    accentLight: '#e0f2fe',// Light Sky Blue
    border: '#cbd5e1',     // Gray border
    text: '#334155',       // Dark text
    textLight: '#64748b',  // Muted text
    white: '#ffffff',
    Critical: '#ef4444',   // Red
    High: '#f97316',       // Orange
    Medium: '#f59e0b',     // Yellow
    Low: '#3b82f6',        // Light Blue
    Info: '#0ea5e9'        // Sky Blue
  };

  // Helper: Header & Footer decoration
  function addPageDecorations() {
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      
      // Don't add header/footer on cover page (page 0)
      if (i === 0) continue;

      // Temporarily remove bottom margin to prevent footer text from triggering automatic page breaks
      const oldBottom = doc.page.margins.bottom;
      doc.page.margins.bottom = 0;

      // Header
      doc.rect(0, 0, doc.page.width, 30).fill(colors.primary);
      doc.fillColor(colors.white).fontSize(8).font('Helvetica-Bold')
         .text('AI-DETECTIVE SECURITY INTELLIGENCE REPORT', 50, 10, { width: 500, align: 'left' });
      doc.text('SAST & COMPOSITION ENGINE', 50, 10, { width: 500, align: 'right' });

      // Footer
      doc.rect(0, doc.page.height - 30, doc.page.width, 30).fill(colors.secondary);
      doc.fillColor(colors.white).fontSize(8).font('Helvetica')
         .text(`CONFIDENTIAL - SECURITY AUDIT REPORT`, 50, doc.page.height - 20, { width: 400, align: 'left' });
      doc.text(`Page ${i + 1} of ${pages.count}`, 50, doc.page.height - 20, { width: 500, align: 'right' });

      // Restore original bottom margin
      doc.page.margins.bottom = oldBottom;
    }
  }

  // Helper: Section Header
  function sectionHeader(title) {
    doc.moveDown(2);
    doc.fontSize(14).font('Helvetica-Bold').fillColor(colors.primary).text(title.toUpperCase());
    doc.moveDown(0.3);
    doc.strokeColor(colors.border).lineWidth(1).moveTo(doc.x, doc.y).lineTo(540, doc.y).stroke();
    doc.moveDown(1);
  }

  // ==========================================
  // PAGE 1: COVER PAGE
  // ==========================================
  doc.rect(0, 0, doc.page.width, doc.page.height).fill(colors.primary);
  
  // Large Title
  doc.fillColor(colors.white).fontSize(26).font('Helvetica-Bold')
     .text('APPLICATION SOURCE CODE', 50, 180, { width: 500 })
     .text('SECURITY AUDIT REPORT', 50, 215, { width: 500 });

  doc.fillColor(colors.accentLight).fontSize(13).font('Helvetica')
     .text('Static Application Security Testing (SAST) & Composition Analysis', 50, 255, { width: 500 });

  // Accent Line
  doc.rect(50, 290, 120, 5).fill(colors.accentLight);

  // Metadata Card
  doc.fillColor(colors.white).fontSize(10).font('Helvetica-Bold')
     .text('AUDIT ASSESSMENT SCOPE', 50, 460);
  
  const formattedDate = reportData.scanTime ? new Date(reportData.scanTime).toUTCString() : new Date().toUTCString();
  doc.font('Helvetica').fontSize(9).fillColor(colors.border)
     .text(`Project Name: ${reportData.projectName || 'Unnamed Project'}`, 50, 480)
     .text(`Report ID: ${reportData.id || 'N/A'}`, 50, 495)
     .text(`Assessment Date: ${formattedDate}`, 50, 510)
     .text(`Files Scanned: ${reportData.filesScannedCount || 0} source files`, 50, 525)
     .text(`Scanner Status: ${reportData.semgrepStatus || 'Active'}`, 50, 540)
     .text(`Vulnerabilities Found: ${findings.length} issues`, 50, 555);

  doc.addPage();

  // ==========================================
  // PAGE 2: TABLE OF CONTENTS (INDEX)
  // ==========================================
  sectionHeader('Table of Contents (Index)');
  
  doc.fontSize(9.5).font('Helvetica').fillColor(colors.text)
     .text('This index provides a map of the security assessment parts and compliance metrics compiled in this corporate audit document:', { lineGap: 3 });
  
  doc.moveDown(1.5);
  
  const tocItems = [
    { title: '1. Executive Summary', page: '3', desc: 'Summary of the codebase security grade, posture score, and risk assessment rating.' },
    { title: '2. Assessment Scope & Vulnerability Demographics', page: '4', desc: 'Visual distribution of findings grouped by Severity, CWE weaknesses, and OWASP references.' },
    { title: '3. AI Threat Narrative & Chained Exploit Vector', page: '5', desc: 'Threat scenarios modeled dynamically showing chain vulnerabilities (if compiled).' },
    { title: '4. Detailed Technical Findings', page: '6', desc: 'Monospace code snippet analysis, lines mapping, and suggested diff mitigations.' },
    { title: '5. Remediation Roadmap & Priority action plan', page: 'Last Page', desc: 'Phased checklist separating immediate fixes from short and long-term resolutions.' }
  ];

  let tocY = doc.y;
  tocItems.forEach((item) => {
    doc.fontSize(10).font('Helvetica-Bold').fillColor(colors.primary).text(item.title, 50, tocY);
    doc.fontSize(10).font('Helvetica-Bold').fillColor(colors.accent).text(item.page, 480, tocY, { align: 'right', width: 50 });
    
    // Draw dot leaders
    doc.fontSize(9).font('Helvetica').fillColor(colors.textLight)
       .text('. '.repeat(55), 180, tocY - 1, { width: 300 });

    doc.fontSize(8.5).font('Helvetica').fillColor(colors.text)
       .text(item.desc, 65, tocY + 14, { width: 450 });
    
    doc.moveDown(0.3);
    tocY = doc.y + 10;
  });

  doc.addPage();

  // ==========================================
  // PAGE 3: EXECUTIVE SUMMARY
  // ==========================================
  sectionHeader('1. Executive Summary');

  doc.fontSize(10).font('Helvetica').fillColor(colors.text)
     .text('This report summarizes the static application security testing (SAST) and composition analysis (SCA) findings. Our security checks traverse application source files to identify hardcoded credentials, input validation failures (injection sinks), insecure cryptographic constructs, and vulnerable third-party library dependencies.', { lineGap: 3 });

  doc.moveDown(1.5);

  const startY = doc.y;
  
  // Security Posture Box
  doc.rect(50, startY, 150, 80).fill(colors.secondary);
  doc.fillColor(colors.white).fontSize(10).font('Helvetica-Bold').text('SECURITY SCORE', 60, startY + 15, { width: 130, align: 'center' });
  doc.fontSize(22).text(`${m.securityScore !== undefined ? m.securityScore : 100}/100`, 60, startY + 35, { width: 130, align: 'center' });
  doc.fontSize(10).text(`GRADE: ${m.grade || 'A'}`, 60, startY + 60, { width: 130, align: 'center' });

  // Threat Risk Box
  doc.rect(215, startY, 150, 80).fill('#27272a');
  doc.fillColor(colors.white).fontSize(10).font('Helvetica-Bold').text('RISK LEVEL', 225, startY + 15, { width: 130, align: 'center' });
  doc.fontSize(22).text(m.rating || 'Low Risk', 225, startY + 35, { width: 130, align: 'center' });
  doc.fontSize(10).text(`Penalty Score: ${m.penaltyPoints || 0}`, 225, startY + 60, { width: 130, align: 'center' });

  // Scan Coverage Box
  doc.rect(380, startY, 160, 80).fill('#18181b');
  doc.fillColor(colors.white).fontSize(10).font('Helvetica-Bold').text('TOTAL FINDINGS', 390, startY + 15, { width: 140, align: 'center' });
  doc.fontSize(22).text(`${findings.length}`, 390, startY + 35, { width: 140, align: 'center' });
  doc.fontSize(10).text(`Across ${reportData.filesScannedCount || 0} Files`, 390, startY + 60, { width: 140, align: 'center' });

  doc.y = startY + 100;
  
  // Executive Overview Paragraph
  doc.fontSize(11).font('Helvetica-Bold').fillColor(colors.primary).text('SECURITY OVERVIEW & COMPLIANCE STATEMENT');
  doc.moveDown(0.5);
  doc.fontSize(9.5).font('Helvetica').fillColor(colors.text);
  
  if (ai.executiveSummary) {
    const cleanSummary = ai.executiveSummary.replace(/###\s+[^\n]+/g, '').trim();
    doc.text(cleanSummary, { lineGap: 3 });
  } else {
    doc.text(`The source code audit evaluated ${reportData.filesScannedCount || 0} files. The project was assigned a Security Grade ${m.grade || 'A'} (${m.rating || 'Low Risk'}) based on ${findings.length} findings. Outdated dependencies or credential storage configurations constitute the primary areas of exposure. Standard remediation roadmaps are detailed inside this report.`, { lineGap: 3 });
  }

  doc.addPage();

  // ==========================================
  // PAGE 4: ASSESSMENT SCOPE & VULNERABILITY DEMOGRAPHICS
  // ==========================================
  sectionHeader('2. Assessment Scope & Vulnerability Demographics');

  doc.fontSize(9.5).font('Helvetica-Bold').fillColor(colors.primary).text('FINDINGS BY SEVERITY');
  doc.moveDown(0.5);

  const tableTop = doc.y;
  doc.fontSize(9).font('Helvetica-Bold');
  // Table Header
  doc.rect(50, tableTop, 490, 20).fill(colors.accentLight);
  doc.fillColor(colors.primary);
  doc.text('CRITICAL', 60, tableTop + 6, { width: 110, align: 'center' });
  doc.text('HIGH', 180, tableTop + 6, { width: 110, align: 'center' });
  doc.text('MEDIUM', 300, tableTop + 6, { width: 110, align: 'center' });
  doc.text('TOTAL', 420, tableTop + 6, { width: 110, align: 'center' });

  // Table Data
  doc.rect(50, tableTop + 20, 490, 22).strokeColor(colors.border).stroke();
  doc.fontSize(10).font('Helvetica');
  doc.text(String(c.Critical || 0), 60, tableTop + 27, { width: 110, align: 'center' });
  doc.text(String(c.High || 0), 180, tableTop + 27, { width: 110, align: 'center' });
  doc.text(String(c.Medium || 0), 300, tableTop + 27, { width: 110, align: 'center' });
  doc.text(String(findings.length), 420, tableTop + 27, { width: 110, align: 'center' });

  doc.y = tableTop + 60;

  // OWASP Top 10 Breakdown Table
  doc.fontSize(10).font('Helvetica-Bold').fillColor(colors.primary).text('OWASP TOP 10 COMPLIANCE BREAKDOWN');
  doc.moveDown(0.5);

  const owaspCounts = m.owaspCounts || {};
  const owaspEntries = Object.entries(owaspCounts);
  if (owaspEntries.length === 0) {
    doc.fontSize(9).font('Helvetica').fillColor(colors.textLight).text('No OWASP weaknesses mapped.');
  } else {
    let owaspY = doc.y;
    owaspEntries.forEach(([cat, count], idx) => {
      if (idx % 2 === 0) {
        doc.rect(50, owaspY, 490, 16).fill('#f8fafc');
      }
      doc.fillColor(colors.primary).fontSize(8.5).font('Helvetica').text(cat, 60, owaspY + 4);
      doc.font('Helvetica-Bold').text(`${count} Finding(s)`, 350, owaspY + 4, { width: 180, align: 'right' });
      owaspY += 16;
    });
    doc.y = owaspY;
  }

  doc.moveDown(1.5);

  // Weakness (CWE) Summary
  doc.fontSize(10).font('Helvetica-Bold').fillColor(colors.primary).text('TOP CWE WEAKNESS CATEGORIES');
  doc.moveDown(0.5);

  const cweCounts = m.cweCounts || {};
  const cweEntries = Object.entries(cweCounts);
  if (cweEntries.length === 0) {
    doc.fontSize(9).font('Helvetica').fillColor(colors.textLight).text('No CWE weakness codes mapped.');
  } else {
    doc.fontSize(8.5).font('Helvetica').fillColor(colors.text);
    const cweStr = cweEntries.slice(0, 8).map(([cwe, count]) => `${cwe}: ${count}`).join(' | ');
    doc.text(cweStr, { lineGap: 3 });
  }

  doc.addPage();

  // ==========================================
  // PAGE 5: AI THREAT NARRATIVE (CHAIN VECTORS)
  // ==========================================
  sectionHeader('3. AI Threat Narrative & Chained Exploit Vector');

  if (ai.attackNarrative) {
    doc.fontSize(9.5).font('Helvetica').fillColor(colors.text);
    
    // Clean up title markers from markdown output
    const cleanNarrative = ai.attackNarrative
      .replace(/###\s+[^\n]+/g, '')
      .replace(/\*\*Step\s+\d+:[^*]+\*\*/g, (match) => `\n\n${match}\n`)
      .trim();

    doc.text(cleanNarrative, { lineGap: 3 });
  } else {
    doc.rect(50, doc.y, 490, 70).fill('#f8fafc');
    doc.fillColor(colors.textLight).fontSize(10).font('Helvetica')
       .text('No dynamic threat narrative was compiled for this scan. Run the AI Security Detective feature to chain code findings and map exploit paths.', 60, doc.y + 20, { width: 470, align: 'center' });
    doc.y += 90;
  }

  doc.addPage();

  // ==========================================
  // PAGE 6+: DETAILED TECHNICAL FINDINGS
  // ==========================================
  sectionHeader('4. Detailed Technical Findings');

  if (findings.length === 0) {
    doc.fontSize(10).font('Helvetica').fillColor(colors.text).text('No code vulnerabilities or dependency hotspots were observed.');
  } else {
    findings.forEach((f, index) => {
      // Set actual font size and family before calculating description height
      doc.fontSize(8.5).font('Helvetica');
      const titleHeight = 25;
      const descHeight = doc.heightOfString(`Description: ${f.message || f.description || 'N/A'}`, { width: 490, lineGap: 2 });
      
      // Metadata Grid height (measured using grid's exact font)
      doc.fontSize(7.5).font('Helvetica-Bold');
      const h1 = doc.heightOfString(`Rule Identifier: ${f.rule_id || 'N/A'}`, { width: 220 });
      const h2 = doc.heightOfString(`OWASP Match: ${f.owasp || 'N/A'}`, { width: 220 });
      const h3 = doc.heightOfString(`CWE Association: ${f.cwe || 'N/A'}`, { width: 220 });
      const leftHeight = h1 + h2 + h3 + 6;

      const r1 = doc.heightOfString(`File Path: ${f.path || 'N/A'}`, { width: 220 });
      const r2 = doc.heightOfString(`Line Number: ${f.line || 'N/A'}`, { width: 220 });
      const r3 = doc.heightOfString(`Remediation Type: Source Code Hardening`, { width: 220 });
      const rightHeight = r1 + r2 + r3 + 6;
      const gridHeight = Math.max(leftHeight, rightHeight) + 12;

      // Evidence and remediation heights (measured using actual fonts/sizes)
      const codeHeight = (f.codeSnippet && f.codeSnippet !== 'requires login') ? 100 : 0;
      
      doc.fontSize(8).font('Helvetica-Bold');
      const remedTitleHeight = doc.heightOfString('Suggested Remediation:');
      doc.fontSize(7.5).font('Helvetica');
      const remedTextHeight = doc.heightOfString(f.remediation || 'Upgrade components or externalize configs.', { width: 490, lineGap: 1.5 });
      const remedHeight = remedTitleHeight + remedTextHeight + 15;
      
      const diffHeight = f.suggestedDiff ? 100 : 0;

      let correlationHeight = 0;
      if (f.isCorrelated && f.endpoint) {
        correlationHeight = 35;
      }

      let taintHeight = 0;
      if (f.taintFlow) {
        taintHeight = 35;
      }

      const totalHeight = titleHeight + descHeight + gridHeight + correlationHeight + taintHeight + codeHeight + remedHeight + diffHeight + 40;


      // Start new page if the entire block does not fit on the current page
      if (doc.y + totalHeight > 720 && doc.y > 60) {
        doc.addPage();
      }

      const fTop = doc.y;
      doc.rect(50, fTop, 490, 20).fill(colors.secondary);
      doc.fillColor(colors.white).fontSize(9).font('Helvetica-Bold')
         .text(`Finding ${index + 1}: ${f.title}`, 60, fTop + 6);
      
      const badgeColor = colors[f.severity] || colors.accent;
      doc.fillColor(badgeColor).text(`[${f.severity}]`, 450, fTop + 6, { align: 'right', width: 80 });

      doc.y = fTop + 25;
      
      doc.fontSize(8.5).font('Helvetica').fillColor(colors.text)
         .text(`Description: ${f.message || f.description || 'N/A'}`, { lineGap: 2 });
      
      // Metadata Grid in finding
      doc.moveDown(0.4);
      const gridTop = doc.y;

      // Draw background box
      doc.rect(50, gridTop, 490, gridHeight).fill('#f8fafc');

      // Print columns line-by-line relatively
      doc.fillColor(colors.primary).fontSize(7.5).font('Helvetica-Bold');
      
      // Left Column
      doc.text(`Rule Identifier: ${f.rule_id || 'N/A'}`, 60, gridTop + 6, { width: 220 });
      const y1 = doc.y;
      doc.text(`OWASP Match: ${f.owasp || 'N/A'}`, 60, y1 + 3, { width: 220 });
      const y2 = doc.y;
      doc.text(`CWE Association: ${f.cwe || 'N/A'}`, 60, y2 + 3, { width: 220 });

      // Right Column
      doc.text(`File Path: ${f.path || 'N/A'}`, 300, gridTop + 6, { width: 220 });
      const ry1 = doc.y;
      doc.text(`Line Number: ${f.line || 'N/A'}`, 300, ry1 + 3, { width: 220 });
      const ry2 = doc.y;
      doc.text(`Remediation Type: Source Code Hardening`, 300, ry2 + 3, { width: 220 });

      doc.y = gridTop + gridHeight + 8;

      if (f.isCorrelated && f.endpoint) {
        const corrTop = doc.y;
        doc.rect(50, corrTop, 490, 24).fill('#e6f7ff'); // light blue background
        doc.lineWidth(1).strokeColor('#bae7ff').rect(50, corrTop, 490, 24).stroke();
        
        doc.fillColor('#0050b3').fontSize(7.5).font('Helvetica-Bold');
        doc.text('WHITE BOX CORRELATION:', 60, corrTop + 8, { width: 120 });
        
        doc.fillColor(colors.text).font('Helvetica').fontSize(7);
        doc.text(`Exposed Endpoint: ${f.endpointMethod || ''} ${f.endpointPath || ''} via controller handler ${f.handler || 'N/A'}()`, 175, corrTop + 8, { width: 350 });
        doc.y = corrTop + 32;
      }

      if (f.taintFlow) {
        const taintTop = doc.y;
        doc.rect(50, taintTop, 490, 26).fill('#f0fdfa'); // light teal background
        doc.lineWidth(1).strokeColor('#ccfbf1').rect(50, taintTop, 490, 26).stroke();
        
        doc.fillColor('#0d9488').fontSize(7.5).font('Helvetica-Bold');
        doc.text('DATA FLOW ANALYSIS:', 60, taintTop + 8, { width: 120 });
        
        doc.fillColor(colors.text).font('Helvetica').fontSize(6.5);
        const flowStr = f.taintFlow.flow.join(' ➔ ');
        doc.text(`Flow Path: ${flowStr}`, 175, taintTop + 8, { width: 350 });
        doc.y = taintTop + 34;
      }

      // Evidence Codebox (Monospace codeSnippet)
      if (f.codeSnippet && f.codeSnippet !== 'requires login') {
        doc.fontSize(8).font('Helvetica-Bold').fillColor(colors.primary).text('Evidence Code Snippet:');
        doc.moveDown(0.25);

        const codeStr = f.codeSnippet.trim();
        const boxTop = doc.y;
        doc.rect(50, boxTop, 490, 80).fill('#1e293b');
        doc.fillColor('#38bdf8').fontSize(7).font('Courier')
           .text(codeStr, 60, boxTop + 6, { width: 470, height: 68 });
        doc.y = boxTop + 90;
      }

      // Remediation / Fix details
      doc.fontSize(8).font('Helvetica-Bold').fillColor(colors.primary).text('Suggested Remediation:');
      doc.fontSize(7.5).font('Helvetica').fillColor(colors.text).text(f.remediation || 'Upgrade components or externalize configs.', { lineGap: 1.5 });
      
      // Suggested Diff Block
      if (f.suggestedDiff) {
        doc.moveDown(0.4);
        const diffStr = f.suggestedDiff.trim();
        const diffTop = doc.y;
        doc.rect(50, diffTop, 490, 80).fill('#0f172a');
        doc.fillColor('#10b981').fontSize(6.5).font('Courier')
           .text(diffStr, 60, diffTop + 6, { width: 470, height: 68 });
        doc.y = diffTop + 90;
      }

      doc.moveDown(1.5);
    });
  }

  // ==========================================
  // PAGE N+1: REMEDIATION ROADMAP
  // ==========================================
  if (doc.y > 60) {
    doc.addPage();
  }
  sectionHeader('5. Remediation Roadmap & Action Plan');

  doc.fontSize(10).font('Helvetica-Bold').fillColor(colors.primary).text('PHASED VULNERABILITY MITIGATION');
  doc.moveDown(0.5);
  doc.fontSize(8.5).font('Helvetica').fillColor(colors.text)
     .text('Security teams should address vulnerabilities in phases based on exploit availability and risk impact:', { lineGap: 2 });
  doc.moveDown(0.8);

  const roadY = doc.y;
  
  // Phase 1
  doc.fontSize(9.5).font('Helvetica-Bold').fillColor(colors.Critical).text('Phase 1: Immediate Action (0-5 Days)', 50, roadY);
  doc.fontSize(8.5).font('Helvetica').fillColor(colors.text)
     .text('Rotate and remove all hardcoded active credentials (AWS keys, database passwords, Slack webhooks). Ensure these parameters are read from environment variables or secure key vaults.', 50, roadY + 14, { width: 490 });
  
  // Phase 2
  doc.fontSize(9.5).font('Helvetica-Bold').fillColor(colors.High).text('Phase 2: Short-Term Hardening (6-20 Days)', 50, roadY + 60);
  doc.fontSize(8.5).font('Helvetica').fillColor(colors.text)
     .text('Remediate remote code execution parameters, avoid using eval(), sanitize commands execution parameters, and upgrade high-severity outdated packages listed in package.json/requirements.txt.', 50, roadY + 74, { width: 490 });

  // Phase 3
  doc.fontSize(9.5).font('Helvetica-Bold').fillColor(colors.Low).text('Phase 3: Ongoing Compliance (21+ Days)', 50, roadY + 120);
  doc.fontSize(8.5).font('Helvetica').fillColor(colors.text)
     .text('Refactor database queries using parametrized bindings, suppress version disclosures, configure anti-CSRF middle-wares, and establish pre-commit hooks to block local credentials leaks.', 50, roadY + 134, { width: 490 });

  // End page decorations helper to add Header/Footer page numbers dynamically
  addPageDecorations();

  doc.end();
}

module.exports = {
  buildCodePdfReport
};
