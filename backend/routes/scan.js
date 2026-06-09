const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
const { cloneRepo } = require('../utils/gitClone');
const { buildReport } = require('../parsers/report_builder');

// Configure multer for temporary zip storage
const upload = multer({
  dest: path.join(__dirname, '../../uploads'),
  limits: { fileSize: 1024 * 1024 * 50 } // Max 50MB zip files
});

/**
 * Utility to safely delete directories and files recursively.
 */
function safeCleanup(targetPath) {
  if (!targetPath || !fs.existsSync(targetPath)) return;
  try {
    fs.rmSync(targetPath, { recursive: true, force: true });
    console.log(`Successfully cleaned up path: ${targetPath}`);
  } catch (err) {
    console.error(`Failed to clean up path ${targetPath}:`, err);
  }
}

/**
 * @route POST /api/scan/paste
 * @desc Scan a single pasted code snippet
 */
router.post('/paste', async (req, res, next) => {
  const { code, filename = 'snippet.js', projectName = 'Pasted Snippet' } = req.body;

  if (!code) {
    return res.status(400).json({ success: false, message: 'Code snippet is required' });
  }

  const timestamp = Date.now();
  const tempDir = path.join(__dirname, `../../uploads/paste-${timestamp}`);
  const tempFilePath = path.join(tempDir, filename);

  try {
    // Write code to temporary file inside a dedicated directory
    fs.mkdirSync(tempDir, { recursive: true });
    fs.writeFileSync(tempFilePath, code, 'utf8');

    // Run scanner pipeline on the temp directory
    const report = await buildReport(tempDir, projectName);

    res.json({
      success: true,
      message: 'Scan completed successfully',
      report
    });
  } catch (err) {
    next(err);
  } finally {
    // Schedule folder deletion after response
    setTimeout(() => safeCleanup(tempDir), 2000);
  }
});

/**
 * @route POST /api/scan/upload
 * @desc Extract uploaded ZIP and scan it
 */
router.post('/upload', upload.single('zipFile'), async (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'Zip file upload is required' });
  }

  const zipPath = req.file.path;
  const timestamp = Date.now();
  const extractDir = path.join(__dirname, `../../uploads/extract-${timestamp}`);
  const projectName = req.body.projectName || req.file.originalname.replace(/\.zip$/i, '');

  try {
    // Decompress zip file
    fs.mkdirSync(extractDir, { recursive: true });
    const zip = new AdmZip(zipPath);
    zip.extractAllTo(extractDir, true);

    console.log(`Extracted zip to: ${extractDir}`);

    // Run scanner pipeline on the extracted folder
    const report = await buildReport(extractDir, projectName);

    res.json({
      success: true,
      message: 'Scan completed successfully',
      report
    });
  } catch (err) {
    next(err);
  } finally {
    // Clean up zip upload and extracted folder
    setTimeout(() => {
      safeCleanup(zipPath);
      safeCleanup(extractDir);
    }, 2000);
  }
});

/**
 * @route POST /api/scan/git
 * @desc Clone Git URL and scan it
 */
router.post('/git', async (req, res, next) => {
  const { gitUrl, branch } = req.body;

  if (!gitUrl) {
    return res.status(400).json({ success: false, message: 'Git repository URL is required' });
  }

  const timestamp = Date.now();
  const tempCloneDir = path.join(__dirname, `../../cloned_repos/git-${timestamp}`);

  try {
    console.log(`Git clone scan initiated. Target URL: ${gitUrl}`);
    const cloneResult = await cloneRepo(gitUrl, tempCloneDir);

    if (!cloneResult.success) {
      return res.status(500).json({
        success: false,
        message: cloneResult.error || 'Failed to clone the Git repository.'
      });
    }

    // Run scanner pipeline on cloned folder
    const report = await buildReport(tempCloneDir, cloneResult.repoName);

    res.json({
      success: true,
      message: 'Scan completed successfully',
      report
    });
  } catch (err) {
    next(err);
  } finally {
    // Clean up cloned folder
    setTimeout(() => safeCleanup(tempCloneDir), 2000);
  }
});

module.exports = router;
