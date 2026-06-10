const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { runWaptScan } = require('../scanners/wapt_scanner');

const REPORTS_DIR = path.join(__dirname, '../../reports');

// Ensure reports directory exists
if (!fs.existsSync(REPORTS_DIR)) {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

/**
 * @route POST /api/wapt/scan
 * @desc Run WAPT scan on targetUrl
 */
router.post('/scan', async (req, res, next) => {
  try {
    const { targetUrl } = req.body;

    if (!targetUrl) {
      return res.status(400).json({ success: false, message: 'Target URL is required' });
    }

    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      return res.status(400).json({ success: false, message: 'Invalid URL scheme. Must begin with http:// or https://' });
    }

    // Run the scan
    const result = await runWaptScan(targetUrl);

    // Save report
    const scanTime = result.scanTime;
    const reportId = `wapt-${scanTime}`;
    const reportFilename = `${reportId}.json`;
    const reportPath = path.join(REPORTS_DIR, reportFilename);

    const reportData = {
      reportId,
      type: 'wapt',
      ...result
    };

    fs.writeFileSync(reportPath, JSON.stringify(reportData, null, 2), 'utf-8');

    res.json({
      success: true,
      message: 'WAPT scan completed successfully',
      reportId,
      result: reportData
    });

  } catch (err) {
    next(err);
  }
});

/**
 * @route GET /api/wapt/reports
 * @desc Retrieve list of WAPT reports
 */
router.get('/reports', (req, res, next) => {
  try {
    const files = fs.readdirSync(REPORTS_DIR);
    const reports = [];

    files.forEach(file => {
      if (file.startsWith('wapt-') && file.endsWith('.json')) {
        try {
          const filePath = path.join(REPORTS_DIR, file);
          const raw = fs.readFileSync(filePath, 'utf-8');
          const data = JSON.parse(raw);

          reports.push({
            reportId: data.reportId,
            targetUrl: data.targetUrl,
            scanTime: data.scanTime,
            grade: data.metrics.grade,
            score: data.metrics.securityScore,
            findingCount: data.findings ? data.findings.length : 0
          });
        } catch (e) {
          console.error(`Error reading WAPT report ${file}:`, e);
        }
      }
    });

    // Sort by scanTime descending
    reports.sort((a, b) => b.scanTime - a.scanTime);

    res.json({
      success: true,
      reports
    });

  } catch (err) {
    next(err);
  }
});

/**
 * @route GET /api/wapt/reports/:id
 * @desc Retrieve full report JSON
 */
router.get('/reports/:id', (req, res, next) => {
  try {
    const id = path.basename(req.params.id); // Prevent path traversal
    const reportPath = path.join(REPORTS_DIR, `${id}.json`);

    if (!fs.existsSync(reportPath)) {
      return res.status(404).json({ success: false, message: 'WAPT report not found' });
    }

    const raw = fs.readFileSync(reportPath, 'utf-8');
    const data = JSON.parse(raw);

    res.json(data);

  } catch (err) {
    next(err);
  }
});

module.exports = router;
