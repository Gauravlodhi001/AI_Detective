const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { buildHtmlReport, buildDocReport } = require('../parsers/report_builder');
const { buildCodePdfReport } = require('../parsers/code_pdf_builder');
const { buildPdfReport } = require('../parsers/pdf_builder');

const REPORTS_DIR = path.join(__dirname, '../../reports');

/**
 * Helper to check if a report exists and get its path.
 */
function getReportFilePath(id, ext = 'json') {
  const safeId = path.basename(id); // Prevent path traversal
  return path.join(REPORTS_DIR, `${safeId}.${ext}`);
}

/**
 * @route GET /api/reports/list
 * @desc Retrieve list of all reports (metadata only)
 */
router.get('/list', (req, res, next) => {
  try {
    if (!fs.existsSync(REPORTS_DIR)) {
      return res.json([]);
    }

    const files = fs.readdirSync(REPORTS_DIR);
    const reports = [];

    files.forEach(file => {
      if (file.endsWith('.json')) {
        try {
          const filePath = path.join(REPORTS_DIR, file);
          const rawContent = fs.readFileSync(filePath, 'utf8');
          const data = JSON.parse(rawContent);

          reports.push({
            id: data.id || data.reportId,
            projectName: data.projectName,
            scanTime: data.scanTime,
            filesScannedCount: data.type === 'wapt' ? 'N/A' : (data.filesScannedCount || 0),
            semgrepStatus: data.semgrepStatus || 'N/A',
            metrics: data.metrics,
            findingCount: data.findings ? data.findings.length : 0,
            type: data.type || 'sast'
          });
        } catch (e) {
          console.error(`Error reading report file ${file}:`, e);
        }
      }
    });

    // Sort reports by scanTime descending
    reports.sort((a, b) => new Date(b.scanTime) - new Date(a.scanTime));
    res.json(reports);
  } catch (err) {
    next(err);
  }
});

/**
 * @route GET /api/reports/:id
 * @desc Retrieve detailed JSON of a specific report
 */
router.get('/:id', (req, res, next) => {
  const reportPath = getReportFilePath(req.params.id, 'json');

  if (!fs.existsSync(reportPath)) {
    return res.status(404).json({ success: false, message: 'Report not found' });
  }

  try {
    const rawContent = fs.readFileSync(reportPath, 'utf8');
    const data = JSON.parse(rawContent);
    res.json(data);
  } catch (err) {
    next(err);
  }
});

/**
 * @route DELETE /api/reports/:id
 * @desc Delete report files
 */
router.delete('/:id', (req, res, next) => {
  const jsonPath = getReportFilePath(req.params.id, 'json');
  const mdPath = getReportFilePath(req.params.id, 'md');

  let deleted = false;

  try {
    if (fs.existsSync(jsonPath)) {
      fs.unlinkSync(jsonPath);
      deleted = true;
    }
    if (fs.existsSync(mdPath)) {
      fs.unlinkSync(mdPath);
      deleted = true;
    }

    if (deleted) {
      res.json({ success: true, message: 'Report deleted successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Report not found' });
    }
  } catch (err) {
    next(err);
  }
});

/**
 * @route GET /api/reports/:id/download
 * @desc Download report in specified format (html, markdown, json)
 */
router.get('/:id/download', async (req, res, next) => {
  const format = (req.query.format || 'json').toLowerCase();
  const jsonPath = getReportFilePath(req.params.id, 'json');

  if (!fs.existsSync(jsonPath)) {
    return res.status(404).json({ success: false, message: 'Report not found' });
  }

  try {
    const rawContent = fs.readFileSync(jsonPath, 'utf8');
    const reportData = JSON.parse(rawContent);

    if (format === 'markdown' || format === 'md') {
      const mdPath = getReportFilePath(req.params.id, 'md');
      if (fs.existsSync(mdPath)) {
        res.setHeader('Content-Type', 'text/markdown');
        res.setHeader('Content-Disposition', `attachment; filename="${reportData.projectName}-security-report.md"`);
        return res.sendFile(mdPath);
      } else {
        return res.status(404).json({ success: false, message: 'Markdown summary missing' });
      }
    } else if (format === 'html') {
      const htmlContent = buildHtmlReport(reportData);
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('Content-Disposition', `attachment; filename="${reportData.projectName}-security-report.html"`);
      return res.send(htmlContent);
    } else if (format === 'doc' || format === 'docx') {
      const docBuffer = await buildDocReport(reportData);
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.setHeader('Content-Disposition', `attachment; filename="${reportData.projectName}-security-report.docx"`);
      return res.send(docBuffer);
    } else if (format === 'pdf') {
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${reportData.projectName || 'wapt'}-security-report.pdf"`);
      if (reportData.type === 'wapt') {
        return buildPdfReport(reportData, res);
      } else {
        return buildCodePdfReport(reportData, res);
      }
    } else {
      // Default: send raw JSON
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${reportData.projectName}-security-report.json"`);
      return res.send(rawContent);
    }
  } catch (err) {
    next(err);
  }
});

/**
 * @route GET /api/reports/:id/pdf
 * @desc Download PDF report of a Semgrep/Code scan
 */
router.get('/:id/pdf', (req, res, next) => {
  const jsonPath = getReportFilePath(req.params.id, 'json');

  if (!fs.existsSync(jsonPath)) {
    return res.status(404).json({ success: false, message: 'Report not found' });
  }

  try {
    const rawContent = fs.readFileSync(jsonPath, 'utf8');
    const reportData = JSON.parse(rawContent);

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${reportData.projectName || 'wapt'}-security-report.pdf"`);
    if (reportData.type === 'wapt') {
      return buildPdfReport(reportData, res);
    } else {
      return buildCodePdfReport(reportData, res);
    }
  } catch (err) {
    next(err);
  }
});

module.exports = router;
